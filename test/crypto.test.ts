import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import {
  BLOCK_LEN,
  createCtrDecipherAt,
  ctrCounter,
  generateClientKeyPair,
  unwrapTransferKey,
} from "../src/crypto.js";

// Replicate the server's key wrap (peer-to-file src/server/keyExchange.ts) so
// the test proves the lib unwraps exactly what the real server produces.
function serverWrap(
  serverEcdh: crypto.ECDH,
  clientPublicKeyBase64: string,
  plaintext: Buffer,
): string {
  const shared = serverEcdh.computeSecret(Buffer.from(clientPublicKeyBase64, "base64"));
  const wrapKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), "p2f-key-wrap", 32));
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString("base64");
}

test("it unwraps the transfer key the server wrapped", () => {
  const serverEcdh = crypto.createECDH("prime256v1");
  serverEcdh.generateKeys();
  const serverPublicKeyBase64 = serverEcdh.getPublicKey().toString("base64");

  const keyPair = generateClientKeyPair();
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const wrapped = serverWrap(serverEcdh, keyPair.clientPublicKeyBase64, Buffer.concat([key, iv]));
  const recovered = unwrapTransferKey(keyPair.ecdh, serverPublicKeyBase64, wrapped);

  assert.deepEqual(recovered.key, key);
  assert.deepEqual(recovered.iv, iv);
});

test("a tampered wrapped key is rejected", () => {
  const serverEcdh = crypto.createECDH("prime256v1");
  serverEcdh.generateKeys();
  const serverPublicKeyBase64 = serverEcdh.getPublicKey().toString("base64");
  const keyPair = generateClientKeyPair();

  const wrapped = serverWrap(
    serverEcdh,
    keyPair.clientPublicKeyBase64,
    Buffer.concat([crypto.randomBytes(32), crypto.randomBytes(16)]),
  );
  const bytes = Buffer.from(wrapped, "base64");
  const last = bytes.length - 1;
  bytes[last] = (bytes[last] ?? 0) ^ 0xff; // break the GCM tag
  assert.throws(() => unwrapTransferKey(keyPair.ecdh, serverPublicKeyBase64, bytes.toString("base64")));
});

// Decrypting a range of the ciphertext must match the same slice of the
// plaintext, for any offset — the property the resumable download relies on.
for (const offset of [0, 5, 16, 37, 256, 1000]) {
  test(`CTR decrypt is byte-exact from offset ${offset}`, () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const plain = crypto.randomBytes(1024);

    const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);

    const blockStart = offset - (offset % BLOCK_LEN);
    const dropCount = offset - blockStart;
    const decipher = createCtrDecipherAt(key, iv, blockStart / BLOCK_LEN);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext.subarray(blockStart)),
      decipher.final(),
    ]);

    assert.deepEqual(decrypted.subarray(dropCount), plain.subarray(offset));
  });
}

test("ctrCounter adds across a byte boundary with carry", () => {
  const iv = Buffer.alloc(16, 0);
  iv[15] = 0xff;
  const stepped = ctrCounter(iv, 1);
  assert.equal(stepped[15], 0x00);
  assert.equal(stepped[14], 0x01);
});
