/**
 * A thin client for the peer-to-file HTTP API, for a headless (no browser)
 * caller. Authentication is a Bearer API token — the mechanism the server
 * documents for scripts. Token clients carry no cookies and are exempt from
 * the CSRF header the cookie clients need, so there is no session state to
 * manage here.
 *
 * Make a token on the server:  node src/server/cli.ts add-token <user> <name>
 */
import { P2FError } from "./types.js";
import type { Listing, ServerInfo, TorrentMeta } from "./types.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface P2FClientOptions {
  /** e.g. `http://10.0.0.1:8000` — no trailing slash, no path. */
  baseUrl: string;
  /** An API token that starts with `p2f_`. */
  token: string;
  /** Override the global `fetch`, e.g. for a test. */
  fetchImpl?: FetchLike;
  /** The timeout of a short request (info, list, metadata). The file body is
   * not bound by this — a long download must not be cut off mid-stream. */
  timeoutMs?: number;
}

/** Options for one range request against the webseed. */
export interface RawRangeOptions {
  /** The first byte to fetch. Omit for the whole file. */
  start?: number;
  /** Abort the stream (a pause, a stall watchdog, a shutdown). */
  signal?: AbortSignal;
}

export class P2FClient {
  readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;

  constructor(opts: P2FClientOptions) {
    this.baseUrl = opts.baseUrl.trim().replace(/\/+$/, "");
    this.token = opts.token;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private authHeaders(): Record<string, string> {
    return { Authorization: `Bearer ${this.token}` };
  }

  /** A short request with a timeout. Non-2xx becomes a P2FError. */
  private async request(pathname: string, init?: RequestInit): Promise<Response> {
    const signal = init?.signal ?? AbortSignal.timeout(this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${pathname}`, {
        ...init,
        headers: { ...this.authHeaders(), ...(init?.headers as Record<string, string> | undefined) },
        signal,
      });
    } catch (err) {
      throw new P2FError(0, err instanceof Error ? err.message : "network request failed");
    }
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const body = (await res.clone().json()) as { error?: string };
        if (body.error) detail = body.error;
      } catch {
        /* non-JSON error body */
      }
      throw new P2FError(res.status, detail);
    }
    return res;
  }

  async info(): Promise<ServerInfo> {
    return (await this.request("/api/info")).json() as Promise<ServerInfo>;
  }

  async list(path = ""): Promise<Listing> {
    return (await this.request(`/api/list?path=${encodeURIComponent(path)}`)).json() as Promise<Listing>;
  }

  /**
   * The torrent metadata for one file. `clientPublicKeyBase64` is this
   * session's ephemeral ECDH public key; the server wraps the transfer key
   * under it (see crypto.ts). Returns the wrapped key, the plaintext length
   * and the plaintext SHA-256.
   */
  async torrentMeta(path: string, clientPublicKeyBase64: string): Promise<TorrentMeta> {
    return (await this.request(
      `/api/torrent?path=${encodeURIComponent(path)}&ck=${encodeURIComponent(clientPublicKeyBase64)}`,
    )).json() as Promise<TorrentMeta>;
  }

  /**
   * The webseed: the file's ciphertext, over a byte range. This is NOT bound
   * by the short timeout — the body streams for as long as the download
   * takes; the caller's `signal` (a pause or a stall watchdog) is the only
   * thing that stops it. Returns the raw Response; the caller streams and
   * decrypts `res.body`.
   */
  async rawRange(path: string, opts: RawRangeOptions = {}): Promise<Response> {
    const headers: Record<string, string> = { ...this.authHeaders() };
    if (opts.start !== undefined && opts.start > 0) {
      headers["Range"] = `bytes=${opts.start}-`;
    }
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/api/raw?path=${encodeURIComponent(path)}`, {
        headers,
        signal: opts.signal,
      });
    } catch (err) {
      throw new P2FError(0, err instanceof Error ? err.message : "network request failed");
    }
    if (!res.ok) {
      throw new P2FError(res.status, `webseed returned HTTP ${res.status}`);
    }
    return res;
  }
}
