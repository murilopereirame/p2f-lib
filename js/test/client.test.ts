import assert from "node:assert/strict";
import { test } from "node:test";
import { P2FClient, P2FError } from "../src/index.js";

const meta = { name: "f", length: 3, infoHash: "x", pieceLength: 1, announce: [], webseed: "", magnet: "",
  torrentBase64: "", encKeyWrapped: "abc", plainSha256: "" };

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

/** A fetch that plays back answers in order and records the URLs. */
function script(answers: (() => Response | Promise<Response>)[]) {
  const urls: string[] = [];
  const fetchImpl = async (url: string): Promise<Response> => {
    urls.push(url);
    const next = answers.shift();
    if (!next) throw new Error("no more answers");
    return next();
  };
  return { urls, fetchImpl };
}

test("metadata: waits through 202 'preparing' with progress", async () => {
  const { urls, fetchImpl } = script([
    () => json(202, { preparing: true, bytesDone: 10, bytesTotal: 100 }, { "Retry-After": "1" }),
    () => json(202, { preparing: true, bytesDone: 60, bytesTotal: 100 }, { "Retry-After": "1" }),
    () => json(200, meta),
  ]);
  const seen: number[] = [];
  const client = new P2FClient({ baseUrl: "http://s/", token: "p2f_x", fetchImpl });
  const got = await client.torrentMeta("a b/c+d.mkv", "ck==", { onPreparing: (p) => seen.push(p.bytesDone) });
  assert.equal(got.encKeyWrapped, "abc");
  assert.deepEqual(seen, [10, 60]);
  assert.match(urls[0] ?? "", /\/api\/torrent\?path=a%20b%2Fc%2Bd\.mkv&ck=ck%3D%3D&async=1$/);
});

test("metadata: a dropped connection and a proxy 404 page are retried", async () => {
  const { fetchImpl } = script([
    () => { throw new TypeError("fetch failed"); },
    () => new Response("<html>404 page not found</html>", { status: 404 }),
    () => json(200, meta),
  ]);
  const client = new P2FClient({ baseUrl: "http://s", token: "p2f_x", fetchImpl });
  const t = Date.now();
  assert.equal((await client.torrentMeta("f", "ck")).length, 3);
  assert.ok(Date.now() - t >= 5900, "backs off 2 s then 4 s");
});

test("metadata: the server's own 404 is final", async () => {
  const { fetchImpl } = script([() => json(404, { error: "no such file or directory" })]);
  const client = new P2FClient({ baseUrl: "http://s", token: "p2f_x", fetchImpl });
  await assert.rejects(client.torrentMeta("f", "ck"), (e: unknown) => e instanceof P2FError && e.status === 404);
});

test("metadata: prepareTimeoutMs gives up with a retryable error", async () => {
  const answers = Array.from({ length: 20 }, () => () => json(202, { preparing: true }, { "Retry-After": "1" }));
  const { fetchImpl } = script(answers);
  const client = new P2FClient({ baseUrl: "http://s", token: "p2f_x", fetchImpl });
  await assert.rejects(client.torrentMeta("f", "ck", { prepareTimeoutMs: 2500 }),
    (e: unknown) => e instanceof P2FError && e.status === 0 && /still preparing/.test(e.message));
});

test("metadata: abort while preparing", async () => {
  const answers = Array.from({ length: 20 }, () => () => json(202, { preparing: true }));
  const { fetchImpl } = script(answers);
  const client = new P2FClient({ baseUrl: "http://s", token: "p2f_x", fetchImpl });
  const ctl = new AbortController();
  setTimeout(() => ctl.abort(new Error("stopped")), 300);
  await assert.rejects(client.torrentMeta("f", "ck", { signal: ctl.signal }), /stopped/);
});

test("mount and cookie options reach the request", async () => {
  let init: RequestInit | undefined;
  let url = "";
  const client = new P2FClient({
    baseUrl: "http://s",
    mount: 2,
    requestInit: { credentials: "include", headers: { "X-P2F-Csrf": "1" } },
    fetchImpl: async (u, i) => { url = u; init = i; return json(200, { path: "", entries: [] }); },
  });
  await client.list("x");
  assert.equal(url, "http://s/api/list?path=x&mount=2");
  assert.equal(init?.credentials, "include");
  assert.equal((init?.headers as Record<string, string>)["X-P2F-Csrf"], "1");
  assert.equal((init?.headers as Record<string, string>).Authorization, undefined);
});
