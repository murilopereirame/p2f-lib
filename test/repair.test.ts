import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { P2FClient } from "../src/client.js";
import { downloadPath } from "../src/download.js";
import { parseTorrentLayout, repairFile, webseedFetcher } from "../src/repair.js";
import type { FetchRange } from "../src/repair.js";

// A small stand-in for a peer-to-file server: the same key wrap, the same
// AES-256-CTR ciphertext on the webseed (with byte ranges), and a real
// .torrent whose piece hashes cover that ciphertext.

const PIECE = 16 * 1024;
const content = crypto.randomBytes(PIECE * 10 + PIECE / 2); // a short last piece
const PIECES = Math.ceil(content.length / PIECE);
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const ciphertext = (() => {
  const c = crypto.createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([c.update(content), c.final()]);
})();
const plainSha256 = crypto.createHash("sha256").update(content).digest("hex");

function bencode(v: unknown): Buffer {
  if (typeof v === "number") return Buffer.from(`i${v}e`);
  if (Buffer.isBuffer(v)) return Buffer.concat([Buffer.from(`${v.length}:`), v]);
  if (typeof v === "string") return bencode(Buffer.from(v));
  if (Array.isArray(v)) return Buffer.concat([Buffer.from("l"), ...v.map(bencode), Buffer.from("e")]);
  const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1));
  return Buffer.concat([Buffer.from("d"), ...entries.flatMap(([k, x]) => [bencode(k), bencode(x)]), Buffer.from("e")]);
}

const torrent = bencode({
  announce: "ws://example/tracker",
  info: {
    length: content.length,
    name: "f.bin",
    "piece length": PIECE,
    pieces: Buffer.concat(
      Array.from({ length: PIECES }, (_v, i) =>
        crypto.createHash("sha1").update(ciphertext.subarray(i * PIECE, (i + 1) * PIECE)).digest(),
      ),
    ),
    private: 1,
  },
});

const serverEcdh = crypto.createECDH("prime256v1");
serverEcdh.generateKeys();

function wrapFor(clientPublicKeyBase64: string): string {
  const shared = serverEcdh.computeSecret(Buffer.from(clientPublicKeyBase64, "base64"));
  const wrapKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), "p2f-key-wrap", 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", wrapKey, nonce);
  const ct = Buffer.concat([c.update(Buffer.concat([key, iv])), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]).toString("base64");
}

/** Every Range header the webseed was asked for, in order ("full" for none). */
let ranges: string[] = [];
/** Flip a byte at this offset in an open-ended (download) response, once. */
let corruptStreamAt: number | null = null;

let server: http.Server;
let client: P2FClient;
let dir: string;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const json = (status: number, body: unknown): void => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.headers.authorization !== "Bearer p2f_test") return json(401, { error: "auth" });
    if (url.pathname === "/api/info") {
      return json(200, { ecdhPublicKey: serverEcdh.getPublicKey().toString("base64") });
    }
    if (url.pathname === "/api/list") {
      if (url.searchParams.get("path") !== "") return json(400, { error: "not a directory" });
      return json(200, { path: "", entries: [{ name: "f.bin", type: "file", size: content.length, mtime: 0 }] });
    }
    if (url.pathname === "/api/torrent") {
      return json(200, {
        name: "f.bin",
        length: content.length,
        infoHash: "x",
        pieceLength: PIECE,
        announce: [],
        webseed: "",
        magnet: "",
        torrentBase64: torrent.toString("base64"),
        encKeyWrapped: wrapFor(url.searchParams.get("ck") ?? ""),
        plainSha256,
      });
    }
    if (url.pathname === "/api/raw") {
      const range = req.headers.range;
      ranges.push(range ?? "full");
      const m = range ? /^bytes=(\d+)-(\d*)$/.exec(range) : null;
      const start = m ? Number(m[1]) : 0;
      const end = m && m[2] ? Number(m[2]) : ciphertext.length - 1;
      let body = Buffer.from(ciphertext.subarray(start, end + 1));
      if (corruptStreamAt !== null && !(m && m[2]) && corruptStreamAt >= start) {
        body[corruptStreamAt - start]! ^= 0xff;
        corruptStreamAt = null;
      }
      const headers: Record<string, string> = { "Content-Length": String(body.length) };
      if (m) headers["Content-Range"] = `bytes ${start}-${end}/${ciphertext.length}`;
      res.writeHead(m ? 206 : 200, headers);
      return res.end(body);
    }
    json(404, { error: "not found" });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  client = new P2FClient({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, token: "p2f_test" });
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(async () => {
  ranges = [];
  corruptStreamAt = null;
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = await mkdtemp(path.join(os.tmpdir(), "p2f-lib-repair-"));
});

const piecesFetched = (): number[] =>
  ranges.map((r) => Number(/^bytes=(\d+)-\d+$/.exec(r)?.[1] ?? NaN) / PIECE).sort((a, b) => a - b);

async function heal(local: string, fetchRange: FetchRange = webseedFetcher(client, "f.bin")) {
  return repairFile(local, torrent, key, iv, fetchRange, { retryDelayMs: 1 });
}

test("it reads the piece layout out of the torrent", () => {
  const layout = parseTorrentLayout(torrent);
  assert.equal(layout.pieceLength, PIECE);
  assert.equal(layout.length, content.length);
  assert.equal(layout.pieceHashes.length, PIECES);
});

test("damaged bytes get only their pieces fetched again", async () => {
  const local = path.join(dir, "f.bin");
  const bad = Buffer.from(content);
  bad[PIECE * 2 + 5]! ^= 1;
  bad.fill(0, PIECE * 6 + 100, PIECE * 7 + 1);
  await writeFile(local, bad);
  const result = await heal(local);
  assert.deepEqual(result.damaged, [2, 6, 7]);
  assert.deepEqual(piecesFetched(), [2, 6, 7]);
  assert.deepEqual(await readFile(local), content);
});

test("a truncated file gets only its missing tail", async () => {
  const local = path.join(dir, "f.bin");
  await writeFile(local, content.subarray(0, PIECE * 8 + 10));
  const result = await heal(local);
  assert.deepEqual(result.damaged, [8, 9, 10]);
  assert.deepEqual(await readFile(local), content);
});

test("a missing file is rebuilt, and trailing junk is cut off", async () => {
  const local = path.join(dir, "f.bin");
  assert.equal((await heal(local)).damaged.length, PIECES);
  assert.deepEqual(await readFile(local), content);

  ranges = [];
  await writeFile(local, Buffer.concat([content, Buffer.from("junk")]));
  assert.deepEqual((await heal(local)).damaged, []);
  assert.deepEqual(ranges, []);
  assert.deepEqual(await readFile(local), content);
});

test("data that fails its piece hash is never written", async () => {
  const local = path.join(dir, "f.bin");
  const partial = content.subarray(0, PIECE * 3);
  await writeFile(local, partial);
  await assert.rejects(heal(local, async (s, e) => Buffer.alloc(e - s + 1)), /hash check/);
  assert.deepEqual(await readFile(local), partial);
});

test("downloadPath heals a full-size file on disk instead of skipping it", async () => {
  const bad = Buffer.from(content);
  bad[PIECE * 4 + 9]! ^= 0x80;
  await writeFile(path.join(dir, "f.bin"), bad);
  const healed: string[] = [];
  const local = await downloadPath(client, "f.bin", dir, { onRepair: (file) => healed.push(file) });
  assert.deepEqual(await readFile(local), content);
  assert.deepEqual(piecesFetched(), [4], "only the damaged piece is fetched");
  assert.ok(healed.includes("f.bin"));
});

test("downloadPath heals a download that came out wrong without fetching it all again", async () => {
  corruptStreamAt = PIECE * 9 + 3;
  const local = await downloadPath(client, "f.bin", dir);
  assert.deepEqual(await readFile(local), content);
  assert.deepEqual(ranges, ["full", `bytes=${PIECE * 9}-${PIECE * 10 - 1}`]);
});

test("with repair off, a bad file is removed for a clean download", async () => {
  const bad = Buffer.from(content);
  bad[10]! ^= 1;
  await writeFile(path.join(dir, "f.bin"), bad);
  await assert.rejects(downloadPath(client, "f.bin", dir, { repair: false }), /failed the checksum/);
  await assert.rejects(readFile(path.join(dir, "f.bin")), { code: "ENOENT" });
  assert.deepEqual(ranges, []);
});
