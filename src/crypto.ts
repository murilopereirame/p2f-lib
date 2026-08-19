/**
 * The client-side crypto of the peer-to-file protocol, for Node.
 *
 * A shared file is served as AES-256-CTR ciphertext. The key never crosses
 * the wire in the clear: the server wraps it under a secret derived from
 * ECDH (P-256) between its stable keypair and a fresh keypair this client
 * makes for the transfer. This file is the Node half of that exchange, and
 * the streaming decrypt that turns the ciphertext back into the file.
 *
 * The derivations match the server exactly (see the peer-to-file repo,
 * src/server/keyExchange.ts and src/server/cipher.ts), so the bytes line up:
 *   - ECDH P-256, HKDF-SHA256, info "p2f-key-wrap"  -> the 32-byte wrap key
 *   - AES-256-GCM (nonce 12, tag 16)                -> unwrap the key+IV
 *   - AES-256-CTR, a full 128-bit big-endian counter -> decrypt the file
 */
import crypto from "node:crypto";
import { Transform } from "node:stream";

const CURVE = "prime256v1"; // NIST P-256, byte-identical to Web Crypto's "P-256".
const HKDF_INFO = "p2f-key-wrap";
const CIPHER_ALGO = "aes-256-ctr";
const GCM_NONCE_LEN = 12;
const GCM_TAG_LEN = 16;

/** The AES block size, and the unit the CTR counter steps in. */
export const BLOCK_LEN = 16;

export interface ClientKeyPair {
  /** Holds the private key. Kept to compute the shared secret on unwrap. */
  ecdh: crypto.ECDH;
  /** The raw uncompressed public point, base64. Send it as `ck`. */
  clientPublicKeyBase64: string;
}

/**
 * A fresh ephemeral ECDH keypair for one download session. A new keypair per
 * session, so each transfer's key-wrap is independent.
 */
export function generateClientKeyPair(): ClientKeyPair {
  const ecdh = crypto.createECDH(CURVE);
  ecdh.generateKeys();
  return { ecdh, clientPublicKeyBase64: ecdh.getPublicKey().toString("base64") };
}

/** ECDH(this client, the server) -> HKDF-SHA256 -> the 32-byte AES-GCM wrap key. */
function deriveWrapKey(ecdh: crypto.ECDH, serverPublicKeyBase64: string): Buffer {
  let serverPublicKey: Buffer;
  try {
    serverPublicKey = Buffer.from(serverPublicKeyBase64, "base64");
  } catch {
    throw new Error("invalid server public key");
  }
  const shared = ecdh.computeSecret(serverPublicKey);
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), HKDF_INFO, 32));
}

export interface TransferKey {
  /** The 32-byte AES-256 key. */
  key: Buffer;
  /** The 16-byte initial counter block (the CTR IV). */
  iv: Buffer;
}

/**
 * Reverse the server's key wrap: recover the AES-256-CTR key+IV from the
 * `encKeyWrapped` blob on a torrent-metadata response. Throws if the GCM tag
 * does not verify (a wrong keypair, a tampered blob).
 *
 * Wire format of the blob: nonce(12) || ciphertext || tag(16), base64. The
 * plaintext inside is key(32) || iv(16) = 48 bytes.
 */
export function unwrapTransferKey(
  ecdh: crypto.ECDH,
  serverPublicKeyBase64: string,
  wrappedBase64: string,
): TransferKey {
  const wrapKey = deriveWrapKey(ecdh, serverPublicKeyBase64);
  const blob = Buffer.from(wrappedBase64, "base64");
  if (blob.length < GCM_NONCE_LEN + GCM_TAG_LEN) throw new Error("invalid wrapped key");

  const nonce = blob.subarray(0, GCM_NONCE_LEN);
  const tag = blob.subarray(blob.length - GCM_TAG_LEN);
  const ciphertext = blob.subarray(GCM_NONCE_LEN, blob.length - GCM_TAG_LEN);

  let material: Buffer;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, nonce);
    decipher.setAuthTag(tag);
    material = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("key unwrap failed");
  }
  if (material.length < 48) throw new Error("unexpected key material length");
  return { key: material.subarray(0, 32), iv: material.subarray(32, 48) };
}

/**
 * The CTR counter block `blockIndex` blocks past `iv`: a big-endian 128-bit
 * add. Starting a decrypt at this counter yields the same keystream a
 * from-zero pass would produce at that block, which is what makes seeking
 * into the ciphertext byte-exact. Matches the server's ctrCounter.
 */
export function ctrCounter(iv: Buffer, blockIndex: number): Buffer {
  const c = Buffer.from(iv);
  let carry = blockIndex;
  for (let i = BLOCK_LEN - 1; i >= 0 && carry > 0; i--) {
    const sum = c[i]! + (carry % 256);
    c[i] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum > 255 ? 1 : 0);
  }
  return c;
}

/**
 * A CTR decipher whose keystream is positioned at the start of block
 * `blockIndex`. Feed it ciphertext that begins at that block; it returns the
 * matching plaintext. (CTR decrypt and encrypt are the same XOR, so this
 * works with createDecipheriv either way.)
 */
export function createCtrDecipherAt(
  key: Buffer,
  iv: Buffer,
  blockIndex: number,
): crypto.Decipher {
  return crypto.createDecipheriv(CIPHER_ALGO, key, ctrCounter(iv, blockIndex));
}

/** A Transform that drops the first `n` bytes it sees, then passes the rest. */
export class DropBytes extends Transform {
  private left: number;

  constructor(n: number) {
    super();
    this.left = n;
  }

  override _transform(
    chunk: Buffer,
    _enc: BufferEncoding,
    cb: (err?: Error | null, data?: Buffer) => void,
  ): void {
    if (this.left > 0) {
      const drop = Math.min(this.left, chunk.length);
      this.left -= drop;
      chunk = chunk.subarray(drop);
    }
    cb(null, chunk);
  }
}
