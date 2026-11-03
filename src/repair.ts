/**
 * Self-heal for a local file that fails its checksum: find the pieces that are
 * missing or damaged and fetch only those again, instead of the whole file.
 *
 * The torrent metadata lists a SHA-1 hash per piece of the *ciphertext*. The
 * local file is the plaintext, but CTR is seekable and length-preserving, so
 * each piece of the local file can be encrypted again on its own and checked
 * against its hash. That says exactly which pieces are wrong. Each of those
 * is then fetched from the webseed with a byte range, checked against its
 * hash, decrypted, and written back at its offset. The file ends at exactly
 * the right length.
 */
import crypto from "node:crypto";
import { open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { P2FClient } from "./client.js";
import { BLOCK_LEN, createCtrDecipherAt } from "./crypto.js";
import { P2FError } from "./types.js";

/** The piece layout of a single-file torrent. */
export interface TorrentLayout {
  pieceLength: number;
  length: number;
  /** The SHA-1 (hex) of each piece of the ciphertext. */
  pieceHashes: string[];
}

export type RepairPhase = "verifying" | "downloading";

export interface RepairProgress {
  phase: RepairPhase;
  /** Pieces checked (verifying) or fetched (downloading) so far. */
  done: number;
  total: number;
}

export interface RepairOptions {
  signal?: AbortSignal;
  onProgress?: (progress: RepairProgress) => void;
  /** How many damaged pieces to fetch at once. Default 4. */
  concurrency?: number;
  /** Tries per piece before the repair gives up. Default 4. */
  attempts?: number;
  /** The wait before the first retry; it doubles after each. Default 1000. */
  retryDelayMs?: number;
}

export interface RepairResult {
  pieces: number;
  /** The indices of the pieces that were missing or damaged, and fetched again. */
  damaged: number[];
}

/** Fetches ciphertext bytes [start, end] (inclusive) of the remote file. */
export type FetchRange = (start: number, end: number, signal: AbortSignal) => Promise<Uint8Array>;

// --- .torrent parsing ---------------------------------------------------------

type BValue = number | Buffer | BValue[] | Map<string, BValue>;

function decodeBencode(buf: Buffer): BValue {
  let pos = 0;
  const bad = (): never => {
    throw new Error("malformed torrent");
  };
  const readUntil = (ch: number): string => {
    const end = buf.indexOf(ch, pos);
    if (end === -1) bad();
    const s = buf.toString("latin1", pos, end);
    pos = end + 1;
    return s;
  };
  const next = (): BValue => {
    const c = buf[pos];
    if (c === 0x69) {
      // i<n>e
      pos++;
      const n = Number(readUntil(0x65));
      if (!Number.isSafeInteger(n)) bad();
      return n;
    }
    if (c === 0x6c) {
      // l...e
      pos++;
      const list: BValue[] = [];
      while (buf[pos] !== 0x65) {
        if (pos >= buf.length) bad();
        list.push(next());
      }
      pos++;
      return list;
    }
    if (c === 0x64) {
      // d...e
      pos++;
      const dict = new Map<string, BValue>();
      while (buf[pos] !== 0x65) {
        if (pos >= buf.length) bad();
        const k = next();
        if (!Buffer.isBuffer(k)) bad();
        dict.set((k as Buffer).toString("utf8"), next());
      }
      pos++;
      return dict;
    }
    if (c !== undefined && c >= 0x30 && c <= 0x39) {
      // <len>:<bytes>
      const len = Number(readUntil(0x3a));
      if (!Number.isSafeInteger(len) || pos + len > buf.length) bad();
      const out = buf.subarray(pos, pos + len);
      pos += len;
      return out;
    }
    return bad();
  };
  return next();
}

/** Read the piece layout out of a .torrent file (`torrentBase64`, decoded). */
export function parseTorrentLayout(torrent: Buffer): TorrentLayout {
  const root = decodeBencode(torrent);
  const info = root instanceof Map ? root.get("info") : undefined;
  if (!(info instanceof Map)) throw new Error("torrent has no info dictionary");
  if (info.has("files")) throw new Error("multi-file torrents are not supported");
  const pieceLength = info.get("piece length");
  const length = info.get("length");
  const pieces = info.get("pieces");
  if (
    typeof pieceLength !== "number" || pieceLength <= 0 ||
    typeof length !== "number" || length < 0 ||
    !Buffer.isBuffer(pieces) || pieces.length % 20 !== 0
  ) {
    throw new Error("malformed torrent");
  }
  const pieceHashes: string[] = [];
  for (let i = 0; i < pieces.length; i += 20) pieceHashes.push(pieces.subarray(i, i + 20).toString("hex"));
  if (pieceHashes.length !== Math.ceil(length / pieceLength)) {
    throw new Error("torrent piece count does not match its length");
  }
  return { pieceLength, length, pieceHashes };
}

// --- verify + repair ------------------------------------------------------------

/** Encrypt or decrypt (the same XOR) `data` that sits at byte `offset` of the file. */
export function ctrXorAt(data: Uint8Array, offset: number, key: Buffer, iv: Buffer): Buffer {
  const skip = offset % BLOCK_LEN;
  const cipher = createCtrDecipherAt(key, iv, Math.floor(offset / BLOCK_LEN));
  if (skip) cipher.update(Buffer.alloc(skip));
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function sha1Hex(data: Uint8Array): string {
  return crypto.createHash("sha1").update(data).digest("hex");
}

function pieceRange(layout: TorrentLayout, index: number): { start: number; size: number } {
  const start = index * layout.pieceLength;
  return { start, size: Math.min(layout.pieceLength, layout.length - start) };
}

/**
 * The indices of the pieces of the local (plaintext) file that do not match
 * the torrent. Every piece of a missing file is missing.
 */
export async function findDamagedPieces(
  local: string,
  layout: TorrentLayout,
  key: Buffer,
  iv: Buffer,
  opts: Pick<RepairOptions, "signal" | "onProgress"> = {},
): Promise<number[]> {
  const total = layout.pieceHashes.length;
  let fh: FileHandle;
  try {
    fh = await open(local, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return layout.pieceHashes.map((_h, i) => i);
    throw err;
  }
  const damaged: number[] = [];
  try {
    const { size } = await fh.stat();
    const buf = Buffer.alloc(layout.pieceLength);
    for (let i = 0; i < total; i++) {
      opts.signal?.throwIfAborted();
      const { start, size: pieceSize } = pieceRange(layout, i);
      if (start + pieceSize > size) {
        damaged.push(i);
      } else {
        const { bytesRead } = await fh.read(buf, 0, pieceSize, start);
        const cipher = ctrXorAt(buf.subarray(0, bytesRead), start, key, iv);
        if (bytesRead !== pieceSize || sha1Hex(cipher) !== layout.pieceHashes[i]) damaged.push(i);
      }
      if (i % 16 === 15 || i === total - 1) opts.onProgress?.({ phase: "verifying", done: i + 1, total });
    }
  } finally {
    await fh.close();
  }
  return damaged;
}

async function delay(ms: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function fetchVerifiedPiece(
  index: number,
  layout: TorrentLayout,
  fetchRange: FetchRange,
  signal: AbortSignal,
  attempts: number,
  retryDelayMs: number,
): Promise<Uint8Array> {
  const { start, size } = pieceRange(layout, index);
  let lastErr: unknown;
  for (let attempt = 0; attempt < attempts; attempt++) {
    signal.throwIfAborted();
    if (attempt > 0) await delay(retryDelayMs * 2 ** (attempt - 1), signal);
    try {
      const data = await fetchRange(start, start + size - 1, signal);
      if (data.length !== size) throw new Error(`piece ${index}: got ${data.length} bytes, expected ${size}`);
      if (sha1Hex(data) !== layout.pieceHashes[index]) throw new Error(`piece ${index} failed its hash check`);
      return data;
    } catch (err) {
      if (signal.aborted) throw err;
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(`could not fetch piece ${index}`);
}

/**
 * Fetch the `damaged` pieces again, check each against its hash, decrypt it
 * and write it into the local file at its offset. The file ends at exactly
 * the torrent's length. Pieces that fail for good leave the file as it was.
 */
export async function rewritePieces(
  local: string,
  layout: TorrentLayout,
  key: Buffer,
  iv: Buffer,
  damaged: number[],
  fetchRange: FetchRange,
  opts: RepairOptions = {},
): Promise<void> {
  let fh: FileHandle;
  try {
    fh = await open(local, "r+");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    fh = await open(local, "w+");
  }
  // One piece failing for good stops the rest too.
  const stop = new AbortController();
  const onAbort = (): void => stop.abort(opts.signal?.reason);
  if (opts.signal?.aborted) onAbort();
  else opts.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    let done = 0;
    let cursor = 0;
    opts.onProgress?.({ phase: "downloading", done: 0, total: damaged.length });
    const worker = async (): Promise<void> => {
      try {
        while (cursor < damaged.length) {
          stop.signal.throwIfAborted();
          const index = damaged[cursor++]!;
          const cipher = await fetchVerifiedPiece(
            index, layout, fetchRange, stop.signal, opts.attempts ?? 4, opts.retryDelayMs ?? 1000,
          );
          const { start } = pieceRange(layout, index);
          const plain = ctrXorAt(cipher, start, key, iv);
          await fh.write(plain, 0, plain.length, start);
          opts.onProgress?.({ phase: "downloading", done: ++done, total: damaged.length });
        }
      } catch (err) {
        stop.abort(err);
        throw err;
      }
    };
    const workers = Math.max(1, Math.min(opts.concurrency ?? 4, damaged.length));
    // allSettled, so no worker is still writing once the file is closed.
    const results = await Promise.allSettled(Array.from({ length: workers }, worker));
    const failed = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
    if (failed) throw stop.signal.reason ?? failed.reason;
    await fh.truncate(layout.length);
    await fh.sync();
  } finally {
    opts.signal?.removeEventListener("abort", onAbort);
    await fh.close();
  }
}

/** A FetchRange over the client's authenticated webseed. */
export function webseedFetcher(client: P2FClient, remote: string): FetchRange {
  return async (start, end, signal) => {
    const res = await client.rawRange(remote, { start, end, signal });
    if (res.status !== 206) {
      await res.body?.cancel().catch(() => {});
      throw new P2FError(res.status, `webseed answered HTTP ${res.status} to a range request`);
    }
    return new Uint8Array(await res.arrayBuffer());
  };
}

/**
 * Heal the local copy of a remote file in place: check every piece, fetch
 * only the missing or damaged ones. `torrent` is the decoded `torrentBase64`
 * of the file's metadata, and `key`/`iv` its unwrapped transfer key.
 */
export async function repairFile(
  local: string,
  torrent: Buffer,
  key: Buffer,
  iv: Buffer,
  fetchRange: FetchRange,
  opts: RepairOptions = {},
): Promise<RepairResult> {
  const layout = parseTorrentLayout(torrent);
  const damaged = await findDamagedPieces(local, layout, key, iv, opts);
  if (damaged.length > 0) {
    await rewritePieces(local, layout, key, iv, damaged, fetchRange, opts);
  } else {
    // Every piece is right. Only stray bytes past the end can be wrong.
    const fh = await open(local, "a");
    try {
      await fh.truncate(layout.length);
    } finally {
      await fh.close();
    }
  }
  return { pieces: layout.pieceHashes.length, damaged };
}
