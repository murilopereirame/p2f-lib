/**
 * The resumable download of a file or a folder from a peer-to-file server.
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
 *
 * The remote data is never changed. This client only reads.
 */
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { P2FClient } from "./client.js";
import {
  BLOCK_LEN,
  createCtrDecipherAt,
  DropBytes,
  generateClientKeyPair,
  unwrapTransferKey,
} from "./crypto.js";
import { P2FError } from "./types.js";
import type { ClientKeyPair } from "./crypto.js";

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
  /** Check each finished file against the server's plaintext SHA-256.
   * Default true. */
  verify?: boolean;
  /** Destroy a stalled connection after this many ms with no bytes, so the
   * caller's retry can resume it. Default 60000. Zero turns it off. */
  idleTimeoutMs?: number;
}

/** What to do with one file, from the bytes it has on the local disk. */
export interface ResumePlan {
  /** The file is complete. Do not copy it. */
  skip: boolean;
  /** The plaintext byte offset to resume from. */
  start: number;
  /** Add to the local file (a resume), or write it new (from the start). */
  append: boolean;
}

/**
 * Decide how to copy one file, from the local size and the plaintext size.
 *   equal          the file is done. Skip it.
 *   local smaller  a part is there. Resume from the local size.
 *   local bigger   the local file is bad. Write it again from the start.
 */
export function planResume(existing: number, size: number): ResumePlan {
  if (existing === size) return { skip: true, start: size, append: false };
  if (existing > size) return { skip: false, start: 0, append: false };
  return { skip: false, start: existing, append: existing > 0 };
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
  const hash = crypto.createHash("sha256");
  await pipeline(createReadStream(target), hash);
  return hash.digest("hex");
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
  const idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;

  const existing = await localSize(local);

  // The metadata carries the authoritative plaintext length, the wrapped
  // key, and the checksum. It is cheap (cached server-side after the first).
  const meta = await client.torrentMeta(file.remote, keyPair.clientPublicKeyBase64);
  const length = meta.length;
  const { key, iv } = unwrapTransferKey(keyPair.ecdh, serverPublicKeyBase64, meta.encKeyWrapped);

  const plan = planResume(existing, length);

  if (plan.skip) {
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
    const decipher = createCtrDecipherAt(key, iv, blockStart / BLOCK_LEN);
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
    if (got !== meta.plainSha256) {
      // The bytes are wrong end to end. Drop them so the next try starts clean.
      await rm(local, { force: true });
      throw new Error(
        `the file '${file.relative || path.basename(local)}' failed the checksum. ` +
          `It was removed and will be downloaded again.`,
      );
    }
  }

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
  const info = await client.info();
  const serverPublicKeyBase64 = info.ecdhPublicKey;
  const keyPair = generateClientKeyPair();

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
