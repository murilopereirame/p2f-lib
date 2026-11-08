// End to end against tools/mock_server.mjs (the same crypto as the server).
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { downloadPath, P2FClient } from "../src/node.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const mock = path.resolve(here, "../../../tools/mock_server.mjs");
const PORT = 18771;
const TOKEN = "p2f_test";
const root = mkdtempSync(path.join(os.tmpdir(), "p2f-js-"));
const big = randomBytes(5_000_003);
let srv: ChildProcess;

before(async () => {
  mkdirSync(path.join(root, "share", "Dir A"), { recursive: true });
  writeFileSync(path.join(root, "share", "Dir A", "big.bin"), big);
  writeFileSync(path.join(root, "share", "small.txt"), "hello");
  writeFileSync(path.join(root, "share", "empty"), "");
  srv = spawn(process.execPath, [mock, path.join(root, "share"), String(PORT), TOKEN], {
    env: { ...process.env, PREPARE_MS: "2500" },
    stdio: "ignore",
  });
  await new Promise((r) => setTimeout(r, 500));
});

after(() => {
  srv.kill();
});

const client = (): P2FClient => new P2FClient({ baseUrl: `http://127.0.0.1:${PORT}`, token: TOKEN });

test("folder download waits while the server prepares, then verifies", async () => {
  let preparing = 0;
  const out = path.join(root, "out1");
  const local = await downloadPath(client(), "/", out, { onPreparing: () => preparing++ });
  assert.ok(preparing > 0, "saw the preparing phase");
  assert.deepEqual(readFileSync(path.join(local, "Dir A", "big.bin")), big);
  assert.equal(readFileSync(path.join(local, "small.txt"), "utf8"), "hello");
  assert.equal(readFileSync(path.join(local, "empty")).length, 0);
});

test("resume from an odd offset inside an AES block", async () => {
  const out = path.join(root, "out2");
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, "big.bin"), big.subarray(0, 1_234_567));
  const local = await downloadPath(client(), "Dir A/big.bin", out);
  assert.deepEqual(readFileSync(local), big);
});

test("abort keeps the bytes; the next call finishes the file", async () => {
  const out = path.join(root, "out3");
  const ctl = new AbortController();
  await assert.rejects(downloadPath(client(), "Dir A/big.bin", out, {
    signal: ctl.signal,
    onProgress: (t) => { if (t.bytesDone > 2_000_000) ctl.abort(new Error("pause")); },
  }));
  const local = await downloadPath(client(), "Dir A/big.bin", out);
  assert.deepEqual(readFileSync(local), big);
});
