/**
 * Download repair: heal a local copy that fails its checksum by fetching
 * only the pieces that are missing or damaged, instead of the whole file.
 * This entry has no Node-only imports; a file on disk is a `RepairTarget`
 * (see `nodeFileTarget` in "./node"), and a browser app can pass its own
 * (OPFS, the File System Access API).
 *
 * The torrent of a file lists the SHA-1 of each piece of the ciphertext.
 * The local file is the plaintext, but AES-CTR is seekable and keeps the
 * length, so each piece of the local file is encrypted again on its own and
 * checked against its hash (in the C core: the same code the PS4, Android,
 * iOS and desktop builds run). Each bad piece is fetched with a byte range,
 * checked against its hash, decrypted and written back at its offset. Data
 * that fails its hash is never written. The file ends at the right length.
 */
import { P2FClient } from "./client.js";
import { ctrXorAt, initP2F, TorrentLayout } from "./core.js";
import { P2FError } from "./types.js";

/** Random access to the local (plaintext) copy of one file. */
export interface RepairTarget {
  /** The current size in bytes (0 if the file is not there). */
  size(): Promise<number>;
  /** Read up to `length` bytes at `offset`. */
  read(offset: number, length: number): Promise<Uint8Array>;
  /** Write `data` at `offset` (the file grows as needed). */
  write(offset: number, data: Uint8Array): Promise<void>;
  /** Cut or extend the file to `length` bytes. */
  truncate(length: number): Promise<void>;
}

export type RepairPhase = "verifying" | "downloading";

export interface RepairProgress {
  phase: RepairPhase;
  /** Pieces checked (verifying) or fetched again (downloading) so far. */
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
  /** The file was longer than it should be and was cut. */
  trimmed: boolean;
}

/** Fetches ciphertext bytes [start, end] (inclusive) of the remote file. */
export type FetchRange = (start: number, end: number, signal: AbortSignal) => Promise<Uint8Array>;

/** Decode the `torrentBase64` of a file's metadata. */
export function decodeTorrent(torrentBase64: string): Uint8Array {
  const bin = atob(torrentBase64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function aborted(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  return reason instanceof Error ? reason : new DOMException("The operation was aborted.", "AbortError");
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(aborted(signal));
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(aborted(signal));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * The indices of the pieces of the local file that do not match the
 * torrent. Every piece past the end of the file is missing.
 */
export async function findDamagedPieces(
  target: RepairTarget,
  layout: TorrentLayout,
  key: Uint8Array,
  iv: Uint8Array,
  opts: Pick<RepairOptions, "signal" | "onProgress"> = {},
): Promise<number[]> {
  const total = layout.pieceCount;
  const have = await target.size();
  const damaged: number[] = [];
  for (let i = 0; i < total; i++) {
    if (opts.signal?.aborted) throw aborted(opts.signal);
    const { start, size } = layout.piece(i);
    let ok = false;
    if (start + size <= have) {
      const plain = await target.read(start, size);
      ok = plain.length === size && layout.matches(i, ctrXorAt(plain, start, key, iv));
    }
    if (!ok) damaged.push(i);
    if (i % 16 === 15 || i === total - 1) opts.onProgress?.({ phase: "verifying", done: i + 1, total });
  }
  return damaged;
}

async function fetchVerifiedPiece(
  index: number,
  layout: TorrentLayout,
  fetchRange: FetchRange,
  signal: AbortSignal,
  attempts: number,
  retryDelayMs: number,
): Promise<Uint8Array> {
  const { start, size } = layout.piece(index);
  let lastErr: unknown;
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (signal.aborted) throw aborted(signal);
    if (attempt > 0) await delay(retryDelayMs * 2 ** (attempt - 1), signal);
    try {
      const data = await fetchRange(start, start + size - 1, signal);
      if (data.length !== size) throw new Error(`piece ${index}: got ${data.length} bytes, expected ${size}`);
      if (!layout.matches(index, data)) throw new Error(`piece ${index} failed its hash check`);
      return data;
    } catch (err) {
      if (signal.aborted) throw err;
      // A final answer from the server (not a 5xx, 408 or 429) is not retried.
      if (err instanceof P2FError && err.status >= 400 && err.status < 500 && err.status !== 408 && err.status !== 429) {
        throw err;
      }
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(`could not fetch piece ${index}`);
}

/**
 * Heal the local copy of a remote file in place: check every piece and
 * fetch only the missing or damaged ones. `torrent` is the decoded
 * `torrentBase64` of the file's metadata, `key`/`iv` its unwrapped transfer
 * key. A piece that fails for good stops the repair; the pieces already
 * written are right, so a later call has less to do.
 */
export async function repairFile(
  target: RepairTarget,
  torrent: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  fetchRange: FetchRange,
  opts: RepairOptions = {},
): Promise<RepairResult> {
  await initP2F();
  const layout = new TorrentLayout(torrent);
  try {
    const damaged = await findDamagedPieces(target, layout, key, iv, opts);

    // One piece failing for good stops the rest too.
    const stop = new AbortController();
    const onAbort = (): void => stop.abort(opts.signal?.reason);
    if (opts.signal?.aborted) onAbort();
    else opts.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      if (damaged.length > 0) {
        let done = 0;
        let cursor = 0;
        opts.onProgress?.({ phase: "downloading", done: 0, total: damaged.length });
        const worker = async (): Promise<void> => {
          try {
            while (cursor < damaged.length) {
              if (stop.signal.aborted) throw aborted(stop.signal);
              const index = damaged[cursor++] as number;
              const cipher = await fetchVerifiedPiece(
                index, layout, fetchRange, stop.signal, opts.attempts ?? 4, opts.retryDelayMs ?? 1000,
              );
              const { start } = layout.piece(index);
              await target.write(start, ctrXorAt(cipher, start, key, iv));
              opts.onProgress?.({ phase: "downloading", done: ++done, total: damaged.length });
            }
          } catch (err) {
            if (!stop.signal.aborted) stop.abort(err);
            throw err;
          }
        };
        const workers = Math.max(1, Math.min(opts.concurrency ?? 4, damaged.length));
        // allSettled, so no worker is still writing when this returns.
        const results = await Promise.allSettled(Array.from({ length: workers }, worker));
        const failed = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
        if (failed) throw opts.signal?.aborted ? aborted(opts.signal) : failed.reason;
      }
      const trimmed = (await target.size()) > layout.length;
      if (trimmed) await target.truncate(layout.length);
      return { pieces: layout.pieceCount, damaged, trimmed };
    } finally {
      opts.signal?.removeEventListener("abort", onAbort);
    }
  } finally {
    layout.dispose();
  }
}

/** A FetchRange over the client's authenticated webseed. */
export function webseedFetcher(client: P2FClient, remote: string): FetchRange {
  return async (start, end, signal) => {
    const res = await client.rawRange(remote, { start, end, signal });
    // 206, or a 200 with the whole file when the piece starts at 0.
    if (res.status !== 206 && !(res.status === 200 && start === 0)) {
      await res.body?.cancel().catch(() => {});
      throw new P2FError(res.status, `webseed answered HTTP ${res.status} to a range request`);
    }
    if (res.status === 206 || !res.body) return new Uint8Array(await res.arrayBuffer());
    // The whole file came: read only the piece, then stop the stream.
    const want = end + 1;
    const out = new Uint8Array(want);
    let got = 0;
    const reader = res.body.getReader();
    try {
      while (got < want) {
        const { done, value } = await reader.read();
        if (done) break;
        const take = Math.min(value.length, want - got);
        out.set(value.subarray(0, take), got);
        got += take;
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    return out.subarray(0, got);
  };
}
