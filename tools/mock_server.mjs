// A mock peer-to-file server for testing the C client.
// Same crypto as the real server (see js/test/core.test.ts).
//
//   node tools/mock_server.mjs <root_dir> <port> <token>
// Env: CUT_AFTER=N    drop the first /api/raw stream after N bytes
//      IGNORE_RANGE=1 answer Range requests with 200 and the whole file
//      TLS_CERT=cert.pem TLS_KEY=key.pem  serve HTTPS (TLS 1.2 max, as on many servers)
//      PREPARE_MS=N   a file needs N ms of "preparing" before /api/torrent
//                     has its metadata (like the real server hashing a big
//                     file). With async=1: 202 + progress. Without: the
//                     request waits.
//      OLD_SERVER=1   ignore async=1 (a server from before the 202 answer)
//      TORRENT_FAIL=a,b,...  the first /api/torrent requests fail, in order:
//                     drop (close the connection), 404html (a proxy page),
//                     404json (the server's own 404), 503
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [root, port, token] = process.argv.slice(2);
const cutAfter = process.env.CUT_AFTER ? Number(process.env.CUT_AFTER) : -1;
const ignoreRange = process.env.IGNORE_RANGE === "1";
let cutDone = false;
const prepareMs = Number(process.env.PREPARE_MS ?? 0);
const oldServer = process.env.OLD_SERVER === "1";
const torrentFail = (process.env.TORRENT_FAIL ?? "").split(",").filter(Boolean);
const prepareStart = new Map(); // path -> ms

const server = crypto.createECDH("prime256v1");
server.generateKeys();
const serverPub = server.getPublicKey().toString("base64");
const fileKeys = new Map(); // path -> { key, iv, sha }

function keysFor(rel, abs) {
  if (!fileKeys.has(rel)) {
    const sha = crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
    fileKeys.set(rel, { key: crypto.randomBytes(32), iv: crypto.randomBytes(16), sha });
  }
  return fileKeys.get(rel);
}

function ctrCounter(iv, blockIndex) {
  const c = Buffer.from(iv);
  let carry = BigInt(blockIndex);
  for (let i = 15; i >= 0 && carry > 0n; i--) {
    const sum = BigInt(c[i]) + (carry & 0xffn);
    c[i] = Number(sum & 0xffn);
    carry = (carry >> 8n) + (sum >> 8n);
  }
  return c;
}

function wrap(clientPubB64, plain) {
  const shared = server.computeSecret(Buffer.from(clientPubB64, "base64"));
  const wk = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), "p2f-key-wrap", 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", wk, nonce);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]).toString("base64");
}

// JSON sent in two writes, so Node uses chunked transfer encoding.
function json(res, status, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json" });
  const mid = Math.floor(s.length / 2);
  res.write(s.slice(0, mid));
  res.end(s.slice(mid));
}

function resolve(rel) {
  const abs = path.resolve(root, rel || ".");
  if (!abs.startsWith(path.resolve(root))) return null;
  return abs;
}

const handler = (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.headers.authorization !== `Bearer ${token}`) return json(res, 401, { error: "unauthorized" });
  const rel = url.searchParams.get("path") ?? "";
  const abs = resolve(rel);

  if (url.pathname === "/api/info") {
    return json(res, 200, { name: "mock", version: "0", webrtcSeeding: false, ecdhPublicKey: serverPub,
      auth: { required: true, needsSetup: false, authenticated: true } });
  }
  if (!abs || !fs.existsSync(abs)) return json(res, 404, { error: "not found" });
  const st = fs.statSync(abs);

  if (url.pathname === "/api/list") {
    if (!st.isDirectory()) return json(res, 400, { error: "not a directory" });
    const entries = fs.readdirSync(abs).sort().map((name) => {
      const s = fs.statSync(path.join(abs, name));
      return { name, type: s.isDirectory() ? "dir" : "file", size: s.isDirectory() ? null : s.size, mtime: s.mtimeMs };
    });
    return json(res, 200, { path: rel, entries });
  }
  if (url.pathname === "/api/torrent") {
    const fail = torrentFail.shift();
    if (fail === "drop") return req.socket.destroy();
    if (fail === "404html") {
      res.writeHead(404, { "Content-Type": "text/html" });
      return res.end("<html><body>404 page not found</body></html>");
    }
    if (fail === "404json") return json(res, 404, { error: "no such file or directory" });
    if (fail === "503") return json(res, 503, { error: "busy" });
    if (!st.isFile()) return json(res, 400, { error: "not a file" });
    if (prepareMs > 0) {
      if (!prepareStart.has(rel)) prepareStart.set(rel, Date.now());
      const left = prepareStart.get(rel) + prepareMs - Date.now();
      if (left > 0) {
        if (url.searchParams.get("async") === "1" && !oldServer) {
          res.setHeader("Retry-After", "1");
          const done = Math.floor(st.size * (1 - left / prepareMs));
          return json(res, 202, { preparing: true, bytesDone: done, bytesTotal: st.size });
        }
        return setTimeout(() => handler(Object.assign(req, {}), res), left + 5);
      }
    }
    const k = keysFor(rel, abs);
    return json(res, 200, { name: path.basename(abs), length: st.size, infoHash: "x", pieceLength: 16384,
      announce: [], webseed: "", magnet: "", torrentBase64: "",
      encKeyWrapped: wrap(url.searchParams.get("ck"), Buffer.concat([k.key, k.iv])), plainSha256: k.sha });
  }
  if (url.pathname === "/api/raw") {
    const k = keysFor(rel, abs);
    let start = 0;
    const m = /bytes=(\d+)-/.exec(req.headers.range ?? "");
    if (m && !ignoreRange) start = Number(m[1]);
    const blockStart = start - (start % 16);
    const drop = start - blockStart;
    const cipher = crypto.createCipheriv("aes-256-ctr", k.key, ctrCounter(k.iv, blockStart / 16));
    const headers = { "Content-Type": "application/octet-stream", "Content-Length": st.size - start, "Accept-Ranges": "bytes" };
    if (start > 0) headers["Content-Range"] = `bytes ${start}-${st.size - 1}/${st.size}`;
    res.writeHead(start > 0 ? 206 : 200, headers);
    let sent = 0, dropLeft = drop;
    const cut = cutAfter >= 0 && !cutDone;
    if (cut) cutDone = true;
    const rs = fs.createReadStream(abs, { start: blockStart });
    rs.on("data", (chunk) => {
      let out = cipher.update(chunk);
      if (dropLeft > 0) { const d = Math.min(dropLeft, out.length); out = out.subarray(d); dropLeft -= d; }
      if (cut && sent + out.length > cutAfter) {
        res.write(out.subarray(0, cutAfter - sent));
        rs.destroy();
        res.socket.destroy();
        return;
      }
      sent += out.length;
      res.write(out);
    });
    rs.on("end", () => res.end());
    return;
  }
  json(res, 404, { error: "no route" });
};

const srv = process.env.TLS_CERT
  ? https.createServer({ cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY),
      maxVersion: "TLSv1.2" }, handler)
  : http.createServer(handler);
srv.listen(Number(port), "127.0.0.1", () => console.log(`mock on ${port}`));
