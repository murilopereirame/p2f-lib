/**
 * p2f-lib for JavaScript — runs in Node, browsers and Electron.
 *
 * The protocol core is the p2f-lib C library compiled to WebAssembly, the
 * same code the PS4 app and the desktop CLI link natively. This entry has
 * no Node-only imports; the resumable download to disk is in "./node".
 */
export {
  BLOCK_LEN,
  ClientKeyPair,
  coreVersion,
  CtrStream,
  ctrCounter,
  generateClientKeyPair,
  initP2F,
  planResume,
  retryDelayMs,
  Sha256,
} from "./core.js";
export type { ResumePlan, TransferKey } from "./core.js";

export { P2FClient, waitForTorrentMeta } from "./client.js";
export type { FetchLike, P2FClientOptions, RawRangeOptions, TorrentMetaOptions } from "./client.js";

export { P2FError } from "./types.js";
export type { AuthInfo, DirEntry, Listing, PrepareProgress, ServerInfo, TorrentMeta } from "./types.js";
