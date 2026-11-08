import assert from "node:assert/strict";
import crypto from "node:crypto";
import { before, test } from "node:test";
import {
  BLOCK_LEN,
  coreVersion,
  CtrStream,
  ctrCounter,
  generateClientKeyPair,
  initP2F,
  planResume,
  retryDelayMs,
  Sha256,
} from "../src/index.js";

before(async () => {
  await initP2F();
});

// The server's key wrap (peer-to-file src/server/keyExchange.ts), so the test
// proves the core unwraps exactly what the real server produces.
function serverWrap(serverEcdh: crypto.ECDH, clientPublicKeyBase64: string, plaintext: Buffer): string {
  const shared = serverEcdh.computeSecret(Buffer.from(clientPublicKeyBase64, "base64"));
  const wrapKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), "p2f-key-wrap", 32));
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString("base64");
}

test("the core reports its version", () => {
  assert.match(coreVersion(), /^\d+\.\d+\.\d+/);
});

test("it unwraps the transfer key the server wrapped", () => {
  const server = crypto.createECDH("prime256v1");
  server.generateKeys();
  const kp = generateClientKeyPair();
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const wrapped = serverWrap(server, kp.publicKeyBase64, Buffer.concat([key, iv]));
  const got = kp.unwrap(server.getPublicKey().toString("base64"), wrapped);
  assert.deepEqual(Buffer.from(got.key), key);
  assert.deepEqual(Buffer.from(got.iv), iv);
  kp.dispose();
});

test("each keypair is fresh", () => {
  assert.notEqual(generateClientKeyPair().publicKeyBase64, generateClientKeyPair().publicKeyBase64);
});

test("a tampered wrapped key is rejected", () => {
  const server = crypto.createECDH("prime256v1");
  server.generateKeys();
  const kp = generateClientKeyPair();
  const bytes = Buffer.from(serverWrap(server, kp.publicKeyBase64, crypto.randomBytes(48)), "base64");
  bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0xff;
  assert.throws(() => kp.unwrap(server.getPublicKey().toString("base64"), bytes.toString("base64")));
});

for (const offset of [0, 5, 16, 37, 256, 1000]) {
  test(`CTR decrypt matches Node's aes-256-ctr from offset ${offset}`, () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const plain = crypto.randomBytes(1024);
    const c = crypto.createCipheriv("aes-256-ctr", key, iv);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    const blockStart = offset - (offset % BLOCK_LEN);
    const ctr = new CtrStream(key, iv, blockStart / BLOCK_LEN);
    // in uneven chunks, as a network stream arrives
    const rest = ct.subarray(blockStart);
    const out = Buffer.concat([ctr.update(rest.subarray(0, 7)), ctr.update(rest.subarray(7))]);
    ctr.dispose();
    assert.deepEqual(out.subarray(offset - blockStart), plain.subarray(offset));
  });
}

test("the CTR counter carries across bytes", () => {
  const iv = Buffer.alloc(16, 0xff);
  iv[0] = 0;
  assert.deepEqual(Buffer.from(ctrCounter(iv, 1)), Buffer.from("01000000000000000000000000000000", "hex"));
});

test("SHA-256 matches Node", () => {
  const data = crypto.randomBytes(300_000);
  const h = new Sha256();
  h.update(data.subarray(0, 1000)).update(data.subarray(1000));
  assert.equal(h.digestHex(), crypto.createHash("sha256").update(data).digest("hex"));
});

test("resume plan", () => {
  assert.deepEqual(planResume(10, 10), { skip: true, start: 10, append: false });
  assert.deepEqual(planResume(0, 10), { skip: false, start: 0, append: false });
  assert.deepEqual(planResume(4, 10), { skip: false, start: 4, append: true });
  assert.deepEqual(planResume(20, 10), { skip: false, start: 0, append: false });
  assert.deepEqual(planResume(5_000_000_001, 9_000_000_000), { skip: false, start: 5_000_000_001, append: true });
});

test("retry policy: preparing, transient and final answers", () => {
  assert.equal(retryDelayMs(202, true, 1, 0), 2000);
  assert.equal(retryDelayMs(202, true, 1, 1000), 1000);
  assert.equal(retryDelayMs(0, false, 1), 2000);
  assert.equal(retryDelayMs(0, false, 2), 4000);
  assert.equal(retryDelayMs(503, true, 9), 30000);
  assert.equal(retryDelayMs(429, true, 1, 45000), 45000);
  assert.equal(retryDelayMs(404, false, 1), 2000); // a proxy page
  assert.equal(retryDelayMs(404, false, 6), -1);
  assert.equal(retryDelayMs(404, true, 1), -1); // the server: the file is gone
  assert.equal(retryDelayMs(401, true, 1), -1);
  assert.equal(retryDelayMs(403, true, 1), -1);
});
