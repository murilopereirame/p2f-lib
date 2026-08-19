/**
 * The wire types of the peer-to-file HTTP API that a headless client needs.
 *
 * These mirror the fields the server returns (see the peer-to-file repo,
 * packages/shared/src/types.ts and src/server). Only the subset a download
 * client reads is kept here — no upload, no history, no browser-only shapes.
 */

export interface DirEntry {
  name: string;
  type: "dir" | "file";
  /** The size in bytes for a file, or null for a folder. */
  size: number | null;
  mtime: number;
}

export interface Listing {
  path: string;
  entries: DirEntry[];
}

export interface AuthInfo {
  required: boolean;
  needsSetup: boolean;
  authenticated: boolean;
}

export interface ServerInfo {
  name: string;
  version: string;
  webrtcSeeding: boolean;
  /** Base64 raw ECDH (P-256) public key. Used to unwrap the transfer key. */
  ecdhPublicKey: string;
  auth: AuthInfo;
}

export interface TorrentMeta {
  name: string;
  /** The plaintext length in bytes. The ciphertext has the same length. */
  length: number;
  infoHash: string;
  pieceLength: number;
  announce: string[];
  webseed: string;
  magnet: string;
  torrentBase64: string;
  /**
   * Base64 ECDH-wrapped AES-256-CTR key+IV for the ciphertext this file is
   * served as. Unwrap it with the same keypair whose public key was sent as
   * the `ck` query parameter on this request. See crypto.ts.
   */
  encKeyWrapped: string;
  /** SHA-256 (hex) of the original plaintext. Lets a finished download be
   * checked for correctness, independent of the transport. */
  plainSha256: string;
}

/** Thrown for any non-2xx response, or a network-level failure (status 0). */
export class P2FError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "P2FError";
    this.status = status;
  }
}
