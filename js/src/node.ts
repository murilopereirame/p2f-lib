/**
 * The resumable download of a file or a folder from a peer-to-file server,
 * for Node (it writes to the local disk). Import it from "…/p2f-lib/node".
 * The protocol work — key unwrap, decryption, checksum, resume plan, retry
 * policy — runs in the shared C core (WebAssembly); the C library's
 * p2f_download_path does the same thing natively.
 *
 * The shape mirrors a plain SFTP fetch on purpose, so a caller can swap one
 * for the other: give it a remote path and a local folder, get progress
 * callbacks, get back the local path. The differences are all inside:
 *
 *   - The bytes on the wire are AES-256-CTR ciphertext. Each file's key is
 *     unwrapped from its torrent metadata (crypto.ts) and the stream is
 *     decrypted as it arrives — nothing is written to disk encrypted.
 *   - The download resumes. Each file goes to the same local path every time.
 *     A stopped copy leaves its bytes on disk; the next try reads the remote
 *     ciphertext from that byte offset (an HTTP Range) and appends the rest.
 *     CTR is seekable, so a whole local file is always a correct prefix of
 *     the plaintext and the resume is safe.
 *   - A finished file is checked against the server's plaintext SHA-256.
 *     One that fails it is repaired: only its missing or damaged pieces are
 *     fetched again (repair.ts). A full-size file on disk is checked the
 *     same way before it is skipped.
 *
 * The remote data is never changed. This client only reads.
 */
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, open, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { P2FClient } from "./client.js";
import { BLOCK_LEN, ClientKeyPair, CtrStream, generateClientKeyPair, initP2F, planResume, Sha256 } from "./core.js";
import { decodeTorrent, repairFile, webseedFetcher } from "./repair.js";
import type { RepairProgress, RepairResult, RepairTarget } from "./repair.js";
import { P2FError } from "./types.js";
import type { PrepareProgress, TorrentMeta } from "./types.js";

export interface Transfer {
  bytesDone: number;
  bytesTotal: number;
  filesDone: number;
  filesTotal: number;
}

export type ProgressHandler = (transfer: Transfer) => void;

export interface DownloadOptions {
  onProgress?: ProgressHandler;
  /** Abort the whole download (a pause or a shutdown). The bytes on disk are
   * kept and a later call resumes from them. */
  signal?: AbortSignal;
  /** Check each finished file against the server's plaintext SHA-256, and
   * check a full-size file already on disk before it is skipped. Default
   * true. */
  verify?: boolean;
  /** When a file fails the checksum, fetch only its missing or damaged
   * pieces again instead of the whole file. Needs `verify`. Default true. */
  repair?: boolean;
  /** Progress of a repair, per file (the path under the local target, or
   * the file name for a single-file download). */
  onRepair?: (file: string, progress: RepairProgress) => void;
  /** Destroy a stalled connection after this many ms with no bytes, so the
   * caller's retry can resume it. Default 60000. Zero turns it off. */
  idleTimeoutMs?: number;
  /** Called while the server prepares a file (a big file takes a while the
   * first time it is asked for). */
  onPreparing?: (progress: PrepareProgress & { remote: string }) => void;
  /** Stop waiting for the server to prepare a file after this many ms (a
   * retryable error). Default: wait until `signal` aborts. */
  prepareTimeoutMs?: number;
}

/** The size of a local file, or 0 if it is not there. */
async function localSize(target: string): Promise<number> {
  try {
    return (await stat(target)).size;
  } catch {
    return 0;
  }
}

interface RemoteFile {
  /** The path on the server, relative to its shared root. */
  remote: string;
  /** The path under the local target. Empty for a single-file download. */
  relative: string;
  size: number;
}

/** A Transform that counts the bytes flowing through it and reports them. */
class Counter extends Transform {
  private seen = 0;

  constructor(private readonly onBytes: (total: number) => void) {
    super();
  }

  override _transform(
    chunk: Buffer,
    _enc: BufferEncoding,
    cb: (err?: Error | null, data?: Buffer) => void,
  ): void {
    this.seen += chunk.length;
    this.onBytes(this.seen);
    cb(null, chunk);
  }
}

/**
 * List a remote path into a flat file list with sizes.
 *   a folder  -> every file under it, with a relative path
 *   a file    -> one entry with an empty relative path
 * The server answers `/api/list` on a file with a 400, which is how the two
 * are told apart.
 */
async function enumerate(
  client: P2FClient,
  remotePath: string,
): Promise<{ files: RemoteFile[]; isDir: boolean }> {
  let listing;
  try {
    listing = await client.list(remotePath);
  } catch (err) {
    if (err instanceof P2FError && (err.status === 400 || err.status === 404)) {
      // Not a directory (or gone) — treat it as a single file. Its size comes
      // from the parent listing so the total is known before the copy starts.
      const parent = path.posix.dirname(remotePath);
      const name = path.posix.basename(remotePath);
      const parentListing = await client.list(parent === "." ? "" : parent);
      const entry = parentListing.entries.find((e) => e.name === name && e.type === "file");
      if (!entry) throw new P2FError(404, `remote path not found: ${remotePath}`);
      return { files: [{ remote: remotePath, relative: "", size: entry.size ?? 0 }], isDir: false };
    }
    throw err;
  }

  const files: RemoteFile[] = [];
  await collect(client, remotePath, "", listing, files);
  return { files, isDir: true };
}

/** Walk one folder listing and all its subfolders. */
async function collect(
  client: P2FClient,
  remoteDir: string,
  base: string,
  listing: { entries: { name: string; type: "dir" | "file"; size: number | null }[] },
  out: RemoteFile[],
): Promise<void> {
  for (const entry of listing.entries) {
    const remote = remoteDir === "" ? entry.name : `${remoteDir}/${entry.name}`;
    const relative = base === "" ? entry.name : `${base}/${entry.name}`;
    if (entry.type === "dir") {
      out.push(...(await subtree(client, remote, relative)));
    } else {
      out.push({ remote, relative, size: entry.size ?? 0 });
    }
  }
}

async function subtree(client: P2FClient, remoteDir: string, base: string): Promise<RemoteFile[]> {
  const files: RemoteFile[] = [];
  await collect(client, remoteDir, base, await client.list(remoteDir), files);
  return files;
}

/** The SHA-256 (hex) of a whole local file. */
async function fileSha256(target: string): Promise<string> {
  const hash = new Sha256();
  for await (const chunk of createReadStream(target, { highWaterMark: 1024 * 1024 })) {
    hash.update(chunk as Buffer);
  }
  return hash.digestHex();
}

/** A RepairTarget over a local file. */
export function nodeFileTarget(file: string): RepairTarget {
  return {
    size: () => localSize(file),
    async read(offset, length) {
      const fh = await open(file, "r");
      try {
        const buf = Buffer.alloc(length);
        let got = 0;
        while (got < length) {
          const { bytesRead } = await fh.read(buf, got, length - got, offset + got);
          if (bytesRead === 0) break;
          got += bytesRead;
        }
        return buf.subarray(0, got);
      } finally {
        await fh.close();
      }
    },
    async write(offset, data) {
      const fh = await open(file, "r+").catch(async (err: NodeJS.ErrnoException) => {
        if (err.code !== "ENOENT") throw err;
        return open(file, "w+");
      });
      try {
        let done = 0;
        while (done < data.length) {
          const { bytesWritten } = await fh.write(data, done, data.length - done, offset + done);
          done += bytesWritten;
        }
      } finally {
        await fh.close();
      }
    },
    async truncate(length) {
      const fh = await open(file, "r+");
      try {
        await fh.truncate(length);
      } finally {
        await fh.close();
      }
    },
  };
}

/** A failure that a later call can get past with the bytes kept: a stop or
 * a network problem. */
function keepsBytes(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  if (!(err instanceof P2FError)) return false;
  return err.status === 0 || err.status === 408 || err.status === 429 || err.status >= 500;
}

/**
 * A local file at full size (or longer) is not known to be right: check it
 * and repair it. `failedSha`: it already failed the SHA-256 check. Returns
 * the repair result when it is right now. A stop or a network error keeps
 * the bytes (and throws); any other failure removes the file and throws.
 */
async function checkAndHeal(
  client: P2FClient,
  file: RemoteFile,
  local: string,
  meta: TorrentMeta,
  key: Uint8Array,
  iv: Uint8Array,
  opts: DownloadOptions,
  failedSha: boolean,
): Promise<RepairResult | null> {
  const name = file.relative || path.basename(local);
  const repair = (opts.repair ?? true) && !!meta.torrentBase64;
  if (repair) {
    let result: RepairResult | null = null;
    try {
      result = await repairFile(
        nodeFileTarget(local),
        decodeTorrent(meta.torrentBase64),
        key,
        iv,
        webseedFetcher(client, file.remote),
        { signal: opts.signal, onProgress: (p) => opts.onRepair?.(name, p) },
      );
    } catch (err) {
      if (keepsBytes(err, opts.signal)) throw err;
    }
    // Every piece right and nothing fetched: the file is right.
    if (result && result.damaged.length === 0 && !failedSha) return result;
    if (result && (await fileSha256(local)) === meta.plainSha256) return result;
  } else if (!failedSha && (await localSize(local)) === meta.length) {
    if ((await fileSha256(local)) === meta.plainSha256) return null;
  }
  await rm(local, { force: true });
  throw new Error(
    `the file '${name}' failed the checksum${repair ? " and could not be repaired" : ""}. ` +
      `It was removed and will be downloaded again.`,
  );
}

/** A Transform that runs the core's AES-256-CTR over the stream. */
class CtrTransform extends Transform {
  constructor(private readonly ctr: CtrStream) {
    super();
  }

  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null, data?: Buffer) => void): void {
    try {
      const out = this.ctr.update(chunk);
      cb(null, Buffer.from(out.buffer, out.byteOffset, out.byteLength));
    } catch (err) {
      cb(err as Error);
    }
  }

  override _flush(cb: (err?: Error | null) => void): void {
    this.ctr.dispose();
    cb();
  }

  override _destroy(err: Error | null, cb: (err?: Error | null) => void): void {
    this.ctr.dispose();
    cb(err);
  }
}

/** Drop the first `count` bytes of a stream (the resume offset inside the
 * first AES block). */
export class DropBytes extends Transform {
  private left: number;

  constructor(count: number) {
    super();
    this.left = count;
  }

  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null, data?: Buffer) => void): void {
    if (this.left <= 0) return cb(null, chunk);
    if (chunk.length <= this.left) {
      this.left -= chunk.length;
      return cb();
    }
    const rest = chunk.subarray(this.left);
    this.left = 0;
    cb(null, rest);
  }
}

/**
 * Download one file into `local`, resuming from whatever is on disk. Returns
 * the new running byte total (`base` plus this file's size).
 */
async function downloadFile(
  client: P2FClient,
  file: RemoteFile,
  local: string,
  keyPair: ClientKeyPair,
  serverPublicKeyBase64: string,
  base: number,
  transfer: Transfer,
  opts: DownloadOptions,
): Promise<number> {
  const onProgress = opts.onProgress;
  const verify = opts.verify ?? true;
  const repair = opts.repair ?? true;
  const idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;

  const existing = await localSize(local);

  // The metadata carries the authoritative plaintext length, the wrapped
  // key, and the checksum. It is cheap (cached server-side after the first).
  // The server reads and hashes the whole file before it answers this; for
  // a big file that takes minutes the first time. torrentMeta waits it out.
  const meta = await client.torrentMeta(file.remote, keyPair.publicKeyBase64, {
    signal: opts.signal,
    prepareTimeoutMs: opts.prepareTimeoutMs,
    onPreparing: (p) => opts.onPreparing?.({ ...p, remote: file.remote }),
  });
  const length = meta.length;
  const { key, iv } = keyPair.unwrap(serverPublicKeyBase64, meta.encKeyWrapped);

  const plan = planResume(existing, length);

  // Check a full-size copy before it is trusted (a bad disk write, a copy
  // cut and padded), and heal one that is too long instead of starting over.
  if (
    verify && meta.plainSha256 && length > 0 &&
    (plan.skip || (existing > length && repair && !!meta.torrentBase64))
  ) {
    await checkAndHeal(client, file, local, meta, key, iv, opts, false);
    plan.skip = true;
  }

  if (plan.skip) {
    key.fill(0);
    // An empty remote file: make sure the local file exists (as the C client does).
    if (length === 0) await writeFile(local, new Uint8Array(0), { flag: "a" });
    transfer.bytesDone = base + length;
    transfer.filesDone += 1;
    onProgress?.(transfer);
    return base + length;
  }

  if (!plan.append && existing > 0) {
    // A bad part is on disk. Remove it and start the file again.
    await rm(local, { force: true });
  }

  // Resume from a block boundary at or before the plaintext offset, then drop
  // the few plaintext bytes between the block start and the real offset.
  let start = plan.start;
  let blockStart = start - (start % BLOCK_LEN);
  let dropCount = start - blockStart;
  let append = plan.append;

  // Show the offset already on disk before the first byte arrives.
  transfer.bytesDone = base + start;
  onProgress?.(transfer);

  // One AbortController that fires on the caller's signal or on a stall.
  const controller = new AbortController();
  const onOuterAbort = (): void => controller.abort((opts.signal as AbortSignal).reason);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort(opts.signal.reason);
    else opts.signal.addEventListener("abort", onOuterAbort, { once: true });
  }
  let idleTimer: NodeJS.Timeout | null = null;
  const bumpIdle = (): void => {
    if (idleTimeoutMs <= 0) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => controller.abort(new Error("idle timeout")), idleTimeoutMs);
  };

  try {
    const res = await client.rawRange(file.remote, {
      start: blockStart > 0 ? blockStart : undefined,
      signal: controller.signal,
    });

    // If a range was asked for but the server sent the whole file (status
    // 200, not 206), the offset assumption is void: decrypt from zero and
    // rewrite the file. Servers honor the range, so this is a safety net.
    if (blockStart > 0 && res.status !== 206) {
      blockStart = 0;
      dropCount = 0;
      append = false;
    }

    if (!res.body) throw new P2FError(0, "webseed response had no body");

    const source = Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]);
    const decipher = new CtrTransform(new CtrStream(key, iv, blockStart / BLOCK_LEN));
    const drop = new DropBytes(dropCount);
    const counter = new Counter((written) => {
      bumpIdle();
      transfer.bytesDone = base + start + written;
      onProgress?.(transfer);
    });
    const writer = createWriteStream(local, { flags: append ? "a" : "w" });

    bumpIdle();
    await pipeline(source, decipher, drop, counter, writer);
  } finally {
    if (idleTimer) clearTimeout(idleTimer);
    if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);
  }

  // Check the size. A short read means the link dropped: throw so the caller
  // retries and the resume finishes the rest.
  const finalSize = await localSize(local);
  if (finalSize !== length) {
    throw new Error(
      `the file '${file.relative || path.basename(local)}' is short: ` +
        `${finalSize} of ${length} bytes. The next try resumes it.`,
    );
  }

  if (verify && meta.plainSha256) {
    const got = await fileSha256(local);
    // Wrong somewhere: fetch only the bad pieces again.
    if (got !== meta.plainSha256) await checkAndHeal(client, file, local, meta, key, iv, opts, true);
  }
  key.fill(0);

  transfer.bytesDone = base + length;
  transfer.filesDone += 1;
  onProgress?.(transfer);
  return base + length;
}

/**
 * Download a remote file or folder into `localDir`. Returns the path of the
 * new local item (`localDir/<basename of remotePath>`), the same convention a
 * plain SFTP fetch uses.
 */
export async function downloadPath(
  client: P2FClient,
  remotePath: string,
  localDir: string,
  opts: DownloadOptions = {},
): Promise<string> {
  await initP2F();
  const info = await client.info(opts.signal);
  const serverPublicKeyBase64 = info.ecdhPublicKey;
  const keyPair = generateClientKeyPair();
  try {
    return await downloadAll(client, remotePath, localDir, opts, keyPair, serverPublicKeyBase64);
  } finally {
    keyPair.dispose();
  }
}

async function downloadAll(
  client: P2FClient,
  remotePath: string,
  localDir: string,
  opts: DownloadOptions,
  keyPair: ClientKeyPair,
  serverPublicKeyBase64: string,
): Promise<string> {
  remotePath = remotePath.replace(/^\/+|\/+$/g, "");

  const { files, isDir } = await enumerate(client, remotePath);

  const bytesTotal = files.reduce((sum, file) => sum + file.size, 0);
  const transfer: Transfer = {
    bytesDone: 0,
    bytesTotal,
    filesDone: 0,
    filesTotal: files.length,
  };
  opts.onProgress?.(transfer);

  const target = path.join(localDir, path.basename(remotePath));
  if (isDir) await mkdir(target, { recursive: true });

  let base = 0;
  for (const file of files) {
    const local = file.relative === "" ? target : path.join(target, file.relative);
    await mkdir(path.dirname(local), { recursive: true });
    base = await downloadFile(client, file, local, keyPair, serverPublicKeyBase64, base, transfer, opts);
  }

  return target;
}

export * from "./index.js";
