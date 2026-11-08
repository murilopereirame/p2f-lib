/**
 * A client for the peer-to-file HTTP API, on `fetch`. It runs in Node (20+),
 * browsers and Electron.
 *
 * Authentication: a Bearer API token (`p2f_…`, for scripts and services), or
 * none — a browser app that signs in with session cookies passes
 * `credentials: "include"` and its own headers through `requestInit`.
 */
import { initP2F, retryDelayMs } from "./core.js";
import { P2FError } from "./types.js";
import type { Listing, PrepareProgress, ServerInfo, TorrentMeta } from "./types.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface P2FClientOptions {
  /** e.g. `http://10.0.0.1:8000`. A path prefix is kept; a trailing slash is dropped. */
  baseUrl: string;
  /** An API token that starts with `p2f_`. Omit for a cookie session. */
  token?: string;
  /** Override the global `fetch` (a test, an Electron main-process fetch). */
  fetchImpl?: FetchLike;
  /** Extra `fetch` options for every request (headers, credentials). */
  requestInit?: RequestInit;
  /** The timeout of a short request (info, list). The file body is not bound
   * by this — a long download must not be cut off mid-stream. */
  timeoutMs?: number;
  /** The mount to use (multi-mount servers). Omit for the default mount. */
  mount?: string | number;
}

export interface TorrentMetaOptions {
  /** Stop waiting (a cancel). */
  signal?: AbortSignal;
  /** Called while the server prepares the file, and before each retry. */
  onPreparing?: (progress: PrepareProgress) => void;
  /** Give up after this many ms (a retryable P2FError, status 0). Default:
   * wait until `signal` aborts. */
  prepareTimeoutMs?: number;
}

/** Options for one range request against the webseed. */
export interface RawRangeOptions {
  /** The first byte to fetch. Omit for the whole file. */
  start?: number;
  /** The last byte to fetch (inclusive). Omit for "to the end". */
  end?: number;
  /** Abort the stream (a pause, a stall watchdog, a shutdown). */
  signal?: AbortSignal;
}

/**
 * The time one metadata request may take. A current server answers at once
 * (202 while it prepares); an older one holds the request open while it
 * hashes the file, so this is long, and a timeout is simply retried — the
 * server keeps hashing and caches the result.
 */
const META_REQUEST_TIMEOUT_MS = 120_000;

function anySignal(signals: (AbortSignal | undefined)[]): AbortSignal {
  const list = signals.filter((s): s is AbortSignal => s !== undefined);
  const any = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (any) return any(list);
  const ctl = new AbortController();
  for (const s of list) {
    if (s.aborted) {
      ctl.abort(s.reason);
      break;
    }
    s.addEventListener("abort", () => ctl.abort(s.reason), { once: true });
  }
  return ctl.signal;
}

function abortError(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  return reason instanceof Error ? reason : new DOMException("The operation was aborted.", "AbortError");
}

async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) throw abortError(signal);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(abortError(signal as AbortSignal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function parseRetryAfter(value: string | null): number {
  if (!value) return 0;
  const sec = Number(value);
  return Number.isFinite(sec) && sec > 0 && sec < 3600 ? sec * 1000 : 0;
}

/**
 * Ask for a file's metadata until the server has it. This is the fix for
 * large downloads that failed while "preparing": the server reads and
 * hashes a whole file before it can answer, which takes minutes for a big
 * file the first time. The request asks with `async=1`; the server answers
 * 202 with its progress until it is ready. Network errors, timeouts, 5xx,
 * 429 and proxy error pages are retried with a backoff (the policy is the
 * shared C core's `p2f_retry_delay_ms`, the same one the PS4 app uses). A
 * real answer from the server (a 404 for a missing file, a 403) is final.
 *
 * `request` makes one attempt; P2FClient passes its own, and an app with its
 * own transport (cookies, session refresh) can call this directly.
 */
export async function waitForTorrentMeta(
  request: (signal: AbortSignal) => Promise<Response>,
  opts: TorrentMetaOptions = {},
): Promise<TorrentMeta> {
  await initP2F();
  const started = Date.now();
  let fails = 0;
  for (;;) {
    if (opts.signal?.aborted) throw abortError(opts.signal);
    let status = 0;
    let retryAfter = 0;
    let body: Record<string, unknown> | null = null;
    try {
      const res = await request(anySignal([opts.signal, AbortSignal.timeout(META_REQUEST_TIMEOUT_MS)]));
      status = res.status;
      retryAfter = parseRetryAfter(res.headers.get("retry-after"));
      const text = await res.text();
      try {
        const parsed: unknown = JSON.parse(text);
        if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
      } catch {
        /* not JSON: a proxy page or a cut body */
      }
      if (res.ok && status !== 202) {
        if (!body || typeof body.encKeyWrapped !== "string" || typeof body.length !== "number") {
          throw new P2FError(status, "bad torrent metadata");
        }
        return body as unknown as TorrentMeta;
      }
    } catch (err) {
      if (opts.signal?.aborted) throw abortError(opts.signal);
      if (err instanceof P2FError) throw err;
      status = 0; // network error or timeout
    }

    const fromP2f = body !== null && (typeof body.error === "string" || typeof body.preparing === "boolean");
    let delay: number;
    if (status === 202) {
      fails = 0;
      opts.onPreparing?.({
        bytesDone: typeof body?.bytesDone === "number" ? body.bytesDone : 0,
        bytesTotal: typeof body?.bytesTotal === "number" ? body.bytesTotal : 0,
      });
      delay = retryDelayMs(202, true, 1, retryAfter);
    } else {
      fails += 1;
      delay = retryDelayMs(status, fromP2f, fails, retryAfter);
      if (delay < 0) {
        const detail = typeof body?.error === "string" ? body.error : `HTTP ${status}`;
        throw new P2FError(status, detail);
      }
      opts.onPreparing?.({ bytesDone: 0, bytesTotal: 0 });
    }
    const limit = opts.prepareTimeoutMs ?? 0;
    if (limit > 0 && Date.now() - started + delay > limit) {
      throw new P2FError(0, `the server is still preparing the file (gave up after ${Math.round(limit / 1000)} s)`);
    }
    await sleep(delay, opts.signal);
  }
}

export class P2FClient {
  readonly baseUrl: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: FetchLike;
  private readonly requestInit: RequestInit;
  private readonly timeoutMs: number;
  private readonly mount: string | undefined;

  constructor(opts: P2FClientOptions) {
    this.baseUrl = opts.baseUrl.trim().replace(/\/+$/, "");
    this.token = opts.token;
    this.fetchImpl = opts.fetchImpl ?? ((url, init) => fetch(url, init));
    this.requestInit = opts.requestInit ?? {};
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.mount = opts.mount === undefined ? undefined : String(opts.mount);
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = { ...(this.requestInit.headers as Record<string, string> | undefined) };
    if (this.token) h.Authorization = `Bearer ${this.token}`;
    return { ...h, ...extra };
  }

  private url(pathname: string, query: Record<string, string> = {}): string {
    const q = new URLSearchParams(query);
    if (this.mount !== undefined) q.set("mount", this.mount);
    const qs = q.toString().replace(/\+/g, "%20");
    return `${this.baseUrl}${pathname}${qs ? `?${qs}` : ""}`;
  }

  /** A short request with a timeout. Non-2xx becomes a P2FError. */
  private async request(url: string, signal?: AbortSignal): Promise<Response> {
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        ...this.requestInit,
        headers: this.headers(),
        signal: anySignal([signal, AbortSignal.timeout(this.timeoutMs)]),
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

  async info(signal?: AbortSignal): Promise<ServerInfo> {
    return (await this.request(this.url("/api/info"), signal)).json() as Promise<ServerInfo>;
  }

  async list(path = "", signal?: AbortSignal): Promise<Listing> {
    return (await this.request(this.url("/api/list", { path }), signal)).json() as Promise<Listing>;
  }

  /**
   * The torrent metadata for one file, waiting while the server prepares it
   * (see `waitForTorrentMeta`). `clientPublicKeyBase64` is this session's
   * ephemeral ECDH public key; the server wraps the transfer key under it.
   */
  async torrentMeta(path: string, clientPublicKeyBase64: string, opts: TorrentMetaOptions = {}): Promise<TorrentMeta> {
    const url = this.url("/api/torrent", { path, ck: clientPublicKeyBase64, async: "1" });
    return waitForTorrentMeta(
      (signal) => this.fetchImpl(url, { ...this.requestInit, headers: this.headers(), signal }),
      opts,
    );
  }

  /**
   * The webseed: the file's ciphertext, over a byte range. Not bound by the
   * short timeout; the caller's `signal` (a pause or a stall watchdog) is
   * the only thing that stops it. The caller streams and decrypts `res.body`.
   */
  async rawRange(path: string, opts: RawRangeOptions = {}): Promise<Response> {
    const extra: Record<string, string> = {};
    const start = opts.start ?? 0;
    if (opts.end !== undefined && opts.end >= start) extra.Range = `bytes=${start}-${opts.end}`;
    else if (start > 0) extra.Range = `bytes=${start}-`;
    let res: Response;
    try {
      res = await this.fetchImpl(this.url("/api/raw", { path }), {
        ...this.requestInit,
        headers: this.headers(extra),
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
