// Download repair, end to end against tools/mock_server.mjs (its torrent has
// 256 KiB pieces over the ciphertext, like the real server's).
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { ctrXorAt, downloadPath, initP2F, P2FClient, TorrentLayout } from "../src/node.js";
import type { RepairProgress } from "../src/node.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const mock = path.resolve(here, "../../../tools/mock_server.mjs");
const PORT = 18772;
const TOKEN = "p2f_test";
const PIECE = 262144;
const root = mkdtempSync(path.join(os.tmpdir(), "p2f-js-repair-"));
const log = path.join(root, "ranges.log");
const big = randomBytes(PIECE * 10 + 12345); // 11 pieces, the last one short
const src = path.join(root, "share", "big.bin");
let srv: ChildProcess;

before(async () => {
  mkdirSync(path.join(root, "share"), { recursive: true });
  writeFileSync(src, big);
  srv = spawn(process.execPath, [mock, path.join(root, "share"), String(PORT), TOKEN], {
    env: { ...process.env, RANGE_LOG: log },
    stdio: "ignore",
  });
  await new Promise((r) => setTimeout(r, 500));
});

after(() => {
  srv.kill();
});

beforeEach(() => writeFileSync(log, ""));

const client = (): P2FClient => new P2FClient({ baseUrl: `http://127.0.0.1:${PORT}`, token: TOKEN });
const ranges = (): string[] => readFileSync(log, "utf8").split("\n").filter(Boolean);

function flip(file: string, offset: number): void {
  const b = readFileSync(file);
  b[offset] = (b[offset] ?? 0) ^ 0xff;
  writeFileSync(file, b);
}

function place(dir: string): string {
  mkdirSync(dir, { recursive: true });
  const local = path.join(dir, "big.bin");
  copyFileSync(src, local);
  return local;
}

test("core: ctrXorAt at any offset matches a stream from zero", async () => {
  await initP2F();
  const key = randomBytes(32), iv = randomBytes(16);
  const plain = randomBytes(1000);
  const c = createCipheriv("aes-256-ctr", key, iv);
  const whole = Buffer.concat([c.update(plain), c.final()]);
  for (const off of [0, 1, 15, 16, 17, 333]) {
    assert.deepEqual(Buffer.from(ctrXorAt(plain.subarray(off), off, key, iv)), whole.subarray(off));
  }
});

test("core: TorrentLayout parses and checks pieces", async () => {
  await initP2F();
  const data = randomBytes(40000);
  const hashes = [0, 16384, 32768].map((s) => createHash("sha1").update(data.subarray(s, s + 16384)).digest());
  const pieces = Buffer.concat(hashes);
  const t = Buffer.concat([
    Buffer.from(`d4:infod6:lengthi40000e4:name1:x12:piece lengthi16384e6:pieces${pieces.length}:`),
    pieces,
    Buffer.from("ee"),
  ]);
  const layout = new TorrentLayout(t);
  assert.equal(layout.pieceCount, 3);
  assert.equal(layout.length, 40000);
  assert.deepEqual(layout.piece(2), { start: 32768, size: 40000 - 32768 });
  assert.ok(layout.matches(2, data.subarray(32768)));
  assert.ok(!layout.matches(1, data.subarray(32768)));
  layout.dispose();
  assert.throws(() => new TorrentLayout(Buffer.from("d4:infod4:filesleee")));
});

test("a full-size file with one bad byte: one piece fetched again", async () => {
  const dir = path.join(root, "r1");
  const local = place(dir);
  flip(local, PIECE * 3 + 7);
  const seen: RepairProgress[] = [];
  await downloadPath(client(), "big.bin", dir, { onRepair: (_f, p) => seen.push(p) });
  assert.deepEqual(readFileSync(local), big);
  assert.deepEqual(ranges(), [`bytes=${PIECE * 3}-${PIECE * 4 - 1}`]);
  assert.ok(seen.some((p) => p.phase === "downloading" && p.done === 1 && p.total === 1));
});

test("a damaged partial is healed after the download, not removed", async () => {
  const dir = path.join(root, "r2");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "big.bin"), randomBytes(PIECE * 2 + 5)); // junk prefix
  await downloadPath(client(), "big.bin", dir);
  assert.deepEqual(readFileSync(path.join(dir, "big.bin")), big);
  const bounded = ranges().filter((r) => /-\d+$/.test(r));
  assert.equal(bounded.length, 3); // pieces 0, 1, 2
});

test("the short last piece, and trailing junk trimmed", async () => {
  const dir = path.join(root, "r3");
  const local = place(dir);
  flip(local, big.length - 1);
  writeFileSync(local, Buffer.concat([readFileSync(local), randomBytes(999)]));
  await downloadPath(client(), "big.bin", dir);
  assert.deepEqual(readFileSync(local), big);
  assert.deepEqual(ranges(), [`bytes=${PIECE * 10}-${big.length - 1}`]);
});

test("trailing junk only: trimmed, nothing fetched", async () => {
  const dir = path.join(root, "r4");
  const local = place(dir);
  writeFileSync(local, Buffer.concat([big, randomBytes(10)]));
  await downloadPath(client(), "big.bin", dir);
  assert.deepEqual(readFileSync(local), big);
  assert.deepEqual(ranges(), []);
});

test("a good full-size file is checked, not fetched or rewritten", async () => {
  const dir = path.join(root, "r5");
  const local = place(dir);
  const before = statSync(local).mtimeMs;
  await downloadPath(client(), "big.bin", dir);
  assert.equal(statSync(local).mtimeMs, before);
  assert.deepEqual(ranges(), []);
});

test("repair: false removes a bad full-size file", async () => {
  const dir = path.join(root, "r6");
  const local = place(dir);
  flip(local, 10);
  await assert.rejects(downloadPath(client(), "big.bin", dir, { repair: false }), /checksum/);
  assert.throws(() => statSync(local));
});

test("a stop while checking keeps the file; the next call heals it", async () => {
  const dir = path.join(root, "r7");
  const local = place(dir);
  flip(local, PIECE * 5);
  const ctl = new AbortController();
  await assert.rejects(downloadPath(client(), "big.bin", dir, {
    signal: ctl.signal,
    onRepair: () => ctl.abort(new Error("pause")),
  }));
  assert.equal(statSync(local).size, big.length);
  await downloadPath(client(), "big.bin", dir);
  assert.deepEqual(readFileSync(local), big);
});
