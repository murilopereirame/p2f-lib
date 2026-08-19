/**
 * p2f-lib — a headless client for the peer-to-file protocol.
 *
 * The public surface a downloader needs: the HTTP client, the crypto that
 * unwraps a transfer key and decrypts the stream, and the resumable
 * download of a file or folder.
 */
export { P2FClient } from "./client.js";
export type { P2FClientOptions, RawRangeOptions, FetchLike } from "./client.js";

export { downloadPath, planResume } from "./download.js";
export type { DownloadOptions, ProgressHandler, Transfer, ResumePlan } from "./download.js";

export {
  BLOCK_LEN,
  createCtrDecipherAt,
  ctrCounter,
  DropBytes,
  generateClientKeyPair,
  unwrapTransferKey,
} from "./crypto.js";
export type { ClientKeyPair, TransferKey } from "./crypto.js";

export { P2FError } from "./types.js";
export type {
  AuthInfo,
  DirEntry,
  Listing,
  ServerInfo,
  TorrentMeta,
} from "./types.js";
