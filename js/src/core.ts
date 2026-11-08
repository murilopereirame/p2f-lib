/**
 * The p2f-lib C core, compiled to WebAssembly (see src/wasm/exports.c in the
 * repository root). Everything protocol-specific runs in that one core — the
 * key exchange, the stream decryption, the checksum, the resume plan and the
 * retry policy — so the JavaScript clients and the native clients (PS4,
 * desktop) behave the same way.
 *
 * Call `initP2F()` once (it is cheap to call again). The high-level helpers
 * (P2FClient, downloadPath) call it for you.
 */
import { WASM_BASE64 } from "./wasm-bytes.js";
import { P2FError } from "./types.js";

interface Exports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  p2f_alloc(n: number): number;
  p2f_free(p: number): void;
  p2f_version(): number;
  p2f_retry_delay_ms(status: number, fromP2f: number, attempt: number, retryAfterMs: number): number;
  p2f_plan_resume(existing: number, size: number, out: number): void;
  p2f_keypair_new(): number;
  p2f_keypair_public(kp: number): number;
  p2f_keypair_free(kp: number): void;
  p2f_unwrap(kp: number, serverPub: number, wrapped: number, out: number): number;
  p2f_ctr_new(key: number, iv: number, blockIndex: bigint): number;
  p2f_ctr_update(ctr: number, buf: number, len: number): number;
  p2f_ctr_free(ctr: number): void;
  p2f_sha256_new(): number;
  p2f_sha256_update(h: number, buf: number, len: number): void;
  p2f_sha256_final(h: number, out: number): void;
  p2f_torrent_new(buf: number, len: number): number;
  p2f_torrent_info(t: number, out: number): void;
  p2f_torrent_free(t: number): void;
  p2f_piece_matches(t: number, index: number, buf: number, len: number): number;
  p2f_ctr_xor_at(key: number, iv: number, offset: number, buf: number, len: number): number;
}

let core: Exports | null = null;
let loading: Promise<void> | null = null;

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Load the WebAssembly core. Safe to call many times. */
export function initP2F(): Promise<void> {
  if (core) return Promise.resolve();
  if (!loading) {
    loading = (async () => {
      let memory: WebAssembly.Memory | null = null;
      const imports = {
        wasi_snapshot_preview1: {
          // The only host call: secure random bytes for the ECDH key.
          random_get(ptr: number, len: number): number {
            if (!memory) return 52; // ENOSYS
            globalThis.crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
            return 0;
          },
        },
      };
      const { instance } = await WebAssembly.instantiate(decodeBase64(WASM_BASE64) as BufferSource, imports);
      const exp = instance.exports as unknown as Exports;
      memory = exp.memory;
      exp._initialize();
      core = exp;
    })();
    loading.catch(() => {
      loading = null;
    });
  }
  return loading;
}

function c(): Exports {
  if (!core) throw new Error("p2f-lib: call `await initP2F()` before using the core");
  return core;
}

// ---- memory helpers -------------------------------------------------------

function bytes(): Uint8Array {
  return new Uint8Array(c().memory.buffer);
}

function readCString(ptr: number): string {
  const mem = bytes();
  let end = ptr;
  while (mem[end] !== 0) end++;
  return new TextDecoder().decode(mem.subarray(ptr, end));
}

/** Copy bytes into a new block of core memory. The caller frees it. */
function put(data: Uint8Array): number {
  const p = c().p2f_alloc(data.length);
  if (!p) throw new P2FError(0, "p2f-lib: out of memory");
  bytes().set(data, p);
  return p;
}

function putCString(s: string): number {
  const enc = new TextEncoder().encode(s);
  const p = c().p2f_alloc(enc.length + 1);
  if (!p) throw new P2FError(0, "p2f-lib: out of memory");
  const mem = bytes();
  mem.set(enc, p);
  mem[p + enc.length] = 0;
  return p;
}

// Free core memory that a caller forgot to dispose of.
const finalizer = new FinalizationRegistry<() => void>((free) => free());

// ---- policy ---------------------------------------------------------------

/** The library (C core) version. */
export function coreVersion(): string {
  return readCString(c().p2f_version());
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
  const k = c();
  const out = k.p2f_alloc(24);
  try {
    k.p2f_plan_resume(existing, size, out);
    const v = new Float64Array(k.memory.buffer, out, 3);
    return { skip: v[0] === 1, start: v[1] ?? 0, append: v[2] === 1 };
  } finally {
    k.p2f_free(out);
  }
}

/**
 * The metadata request did not give the metadata yet. Milliseconds to wait
 * before the next try, or -1 when the answer is final. See `p2f.h`.
 *   status        HTTP status, or 0 for a network error / timeout
 *   fromP2f       the body is a peer-to-file JSON answer (a 404 from the
 *                 server is final; a 404 page from a proxy is retried)
 *   attempt       1 for the first failure, 2 for the second, ...
 *   retryAfterMs  the Retry-After header in ms, or 0
 */
export function retryDelayMs(status: number, fromP2f: boolean, attempt: number, retryAfterMs = 0): number {
  return c().p2f_retry_delay_ms(status, fromP2f ? 1 : 0, attempt, retryAfterMs);
}

// ---- key exchange ---------------------------------------------------------

/** The AES-256-CTR key and initial counter block of one file. */
export interface TransferKey {
  key: Uint8Array;
  iv: Uint8Array;
}

/**
 * A fresh ephemeral ECDH (P-256) keypair. Send `publicKeyBase64` as the `ck`
 * of a metadata request; the server wraps the file's transfer key under it.
 */
export class ClientKeyPair {
  readonly publicKeyBase64: string;
  private ptr: number;

  constructor() {
    const k = c();
    const ptr = k.p2f_keypair_new();
    if (!ptr) throw new P2FError(0, "p2f-lib: key generation failed");
    this.ptr = ptr;
    this.publicKeyBase64 = readCString(k.p2f_keypair_public(ptr));
    finalizer.register(this, () => k.p2f_keypair_free(ptr), this);
  }

  /**
   * Unwrap a transfer key: ECDH with the server's public key -> HKDF-SHA256
   * ("p2f-key-wrap") -> AES-256-GCM. Throws if the wrap does not verify.
   */
  unwrap(serverPublicKeyBase64: string, encKeyWrapped: string): TransferKey {
    if (!this.ptr) throw new Error("p2f-lib: this keypair was disposed");
    const k = c();
    const pub = putCString(serverPublicKeyBase64);
    const wrapped = putCString(encKeyWrapped);
    const out = k.p2f_alloc(48);
    try {
      const rc = k.p2f_unwrap(this.ptr, pub, wrapped, out);
      if (rc !== 0) throw new P2FError(0, "the transfer key did not unwrap (wrong key or tampered)");
      const material = bytes().slice(out, out + 48);
      bytes().fill(0, out, out + 48);
      return { key: material.slice(0, 32), iv: material.slice(32, 48) };
    } finally {
      k.p2f_free(pub);
      k.p2f_free(wrapped);
      k.p2f_free(out);
    }
  }

  dispose(): void {
    if (!this.ptr) return;
    finalizer.unregister(this);
    c().p2f_keypair_free(this.ptr);
    this.ptr = 0;
  }
}

export function generateClientKeyPair(): ClientKeyPair {
  return new ClientKeyPair();
}

// ---- AES-256-CTR ----------------------------------------------------------

/** The AES block size. A resume starts at a block boundary. */
export const BLOCK_LEN = 16;

/**
 * AES-256-CTR from a given block, with the full 128-bit big-endian counter
 * the server uses. Encrypt and decrypt are the same operation.
 */
export class CtrStream {
  private ptr: number;
  private buf = 0;
  private bufLen = 0;

  constructor(key: Uint8Array, iv: Uint8Array, blockIndex = 0) {
    if (key.length !== 32 || iv.length !== 16) throw new Error("p2f-lib: key must be 32 bytes, iv 16 bytes");
    const k = c();
    const kp = put(key);
    const ivp = put(iv);
    try {
      this.ptr = k.p2f_ctr_new(kp, ivp, BigInt(blockIndex));
    } finally {
      bytes().fill(0, kp, kp + 32);
      k.p2f_free(kp);
      k.p2f_free(ivp);
    }
    if (!this.ptr) throw new P2FError(0, "p2f-lib: AES init failed");
    const ptr = this.ptr;
    const self = { buf: 0 };
    finalizer.register(this, () => {
      k.p2f_ctr_free(ptr);
      if (self.buf) k.p2f_free(self.buf);
    }, this);
  }

  /** Transform a chunk. Returns a new array; the input is not changed. */
  update(chunk: Uint8Array): Uint8Array {
    if (!this.ptr) throw new Error("p2f-lib: this stream was disposed");
    const k = c();
    if (chunk.length > this.bufLen) {
      if (this.buf) k.p2f_free(this.buf);
      this.bufLen = Math.max(chunk.length, 64 * 1024);
      this.buf = k.p2f_alloc(this.bufLen);
      if (!this.buf) throw new P2FError(0, "p2f-lib: out of memory");
    }
    bytes().set(chunk, this.buf);
    if (k.p2f_ctr_update(this.ptr, this.buf, chunk.length) !== 0) throw new P2FError(0, "p2f-lib: AES failed");
    return bytes().slice(this.buf, this.buf + chunk.length);
  }

  dispose(): void {
    if (!this.ptr) return;
    finalizer.unregister(this);
    const k = c();
    k.p2f_ctr_free(this.ptr);
    if (this.buf) k.p2f_free(this.buf);
    this.ptr = 0;
    this.buf = 0;
  }
}

/** The 16-byte counter block `blockIndex` blocks after `iv`. */
export function ctrCounter(iv: Uint8Array, blockIndex: number): Uint8Array {
  const out = Uint8Array.from(iv);
  let carry = BigInt(blockIndex);
  for (let i = 15; i >= 0 && carry > 0n; i--) {
    const sum = BigInt(out[i] ?? 0) + (carry & 0xffn);
    out[i] = Number(sum & 0xffn);
    carry = (carry >> 8n) + (sum >> 8n);
  }
  return out;
}

// ---- SHA-256 --------------------------------------------------------------

/** Incremental SHA-256 (the end-to-end plaintext checksum). */
export class Sha256 {
  private ptr: number;
  private buf = 0;
  private bufLen = 0;

  constructor() {
    const k = c();
    this.ptr = k.p2f_sha256_new();
    if (!this.ptr) throw new P2FError(0, "p2f-lib: out of memory");
  }

  update(chunk: Uint8Array): this {
    if (!this.ptr) throw new Error("p2f-lib: digest already taken");
    const k = c();
    if (chunk.length > this.bufLen) {
      if (this.buf) k.p2f_free(this.buf);
      this.bufLen = Math.max(chunk.length, 64 * 1024);
      this.buf = k.p2f_alloc(this.bufLen);
      if (!this.buf) throw new P2FError(0, "p2f-lib: out of memory");
    }
    bytes().set(chunk, this.buf);
    k.p2f_sha256_update(this.ptr, this.buf, chunk.length);
    return this;
  }

  /** The digest as lowercase hex. Frees the hash. */
  digestHex(): string {
    if (!this.ptr) throw new Error("p2f-lib: digest already taken");
    const k = c();
    const out = k.p2f_alloc(32);
    k.p2f_sha256_final(this.ptr, out);
    const d = bytes().slice(out, out + 32);
    k.p2f_free(out);
    if (this.buf) k.p2f_free(this.buf);
    this.ptr = 0;
    this.buf = 0;
    return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
  }
}

// ---- repair ---------------------------------------------------------------

/**
 * AES-256-CTR over `data`, which sits at byte `offset` of the file (any
 * offset). Encrypt and decrypt are the same. Returns a new array.
 */
export function ctrXorAt(data: Uint8Array, offset: number, key: Uint8Array, iv: Uint8Array): Uint8Array {
  if (key.length !== 32 || iv.length !== 16) throw new Error("p2f-lib: key must be 32 bytes, iv 16 bytes");
  const k = c();
  const kp = put(key);
  const ivp = put(iv);
  const buf = put(data);
  try {
    if (k.p2f_ctr_xor_at(kp, ivp, offset, buf, data.length) !== 0) throw new P2FError(0, "p2f-lib: AES failed");
    return bytes().slice(buf, buf + data.length);
  } finally {
    bytes().fill(0, kp, kp + 32);
    bytes().fill(0, buf, buf + data.length);
    k.p2f_free(kp);
    k.p2f_free(ivp);
    k.p2f_free(buf);
  }
}

/**
 * The piece layout of a file's torrent (`torrentBase64` of its metadata,
 * decoded). The torrent lists the SHA-1 of each piece of the ciphertext;
 * `matches` checks one piece against it. Call `dispose` when done.
 */
export class TorrentLayout {
  readonly pieceLength: number;
  readonly length: number;
  readonly pieceCount: number;
  private ptr: number;
  // Scratch memory in the core; a separate object so the finalizer does not
  // hold on to `this`.
  private readonly scratch = { buf: 0, len: 0 };

  constructor(torrent: Uint8Array) {
    const k = c();
    const tp = put(torrent);
    try {
      this.ptr = k.p2f_torrent_new(tp, torrent.length);
    } finally {
      k.p2f_free(tp);
    }
    if (!this.ptr) throw new P2FError(0, "p2f-lib: not a usable single-file torrent");
    const out = k.p2f_alloc(24);
    try {
      k.p2f_torrent_info(this.ptr, out);
      const v = new Float64Array(k.memory.buffer, out, 3);
      this.pieceLength = v[0] ?? 0;
      this.length = v[1] ?? 0;
      this.pieceCount = v[2] ?? 0;
    } finally {
      k.p2f_free(out);
    }
    const ptr = this.ptr;
    const scratch = this.scratch;
    finalizer.register(this, () => {
      k.p2f_torrent_free(ptr);
      if (scratch.buf) k.p2f_free(scratch.buf);
    }, this);
  }

  /** The byte offset and size of piece `index`. */
  piece(index: number): { start: number; size: number } {
    const start = index * this.pieceLength;
    return { start, size: Math.max(0, Math.min(this.pieceLength, this.length - start)) };
  }

  /** True if `cipher` is piece `index` of the ciphertext (size and SHA-1). */
  matches(index: number, cipher: Uint8Array): boolean {
    if (!this.ptr) throw new Error("p2f-lib: this torrent was disposed");
    const k = c();
    const m = this.scratch;
    if (cipher.length > m.len) {
      if (m.buf) k.p2f_free(m.buf);
      m.len = Math.max(cipher.length, 64 * 1024);
      m.buf = k.p2f_alloc(m.len);
      if (!m.buf) {
        m.len = 0;
        throw new P2FError(0, "p2f-lib: out of memory");
      }
    }
    bytes().set(cipher, m.buf);
    return k.p2f_piece_matches(this.ptr, index, m.buf, cipher.length) === 1;
  }

  dispose(): void {
    if (!this.ptr) return;
    finalizer.unregister(this);
    const k = c();
    k.p2f_torrent_free(this.ptr);
    if (this.scratch.buf) k.p2f_free(this.scratch.buf);
    this.ptr = 0;
    this.scratch.buf = 0;
    this.scratch.len = 0;
  }
}
