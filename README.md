# p2f-lib

A small, dependency-free client library for the
[peer-to-file](https://github.com/murilopereirame/peer-to-file) protocol,
built for **headless (no browser) Node clients** that need to fetch files
from a peer-to-file server.

The browser and desktop apps in the peer-to-file repo download files with
WebTorrent (WebRTC + an HTTP webseed) running in a browser engine. A
background service can't run that, but it doesn't need to: the server also
serves every file as a plain, authenticated, **resumable HTTP webseed**
(`/api/raw`, byte ranges), and the transfer encryption is seekable. This
library talks to that path directly — no WebTorrent, no WebRTC, no native
modules — and gives you the same resilience:

- **Authenticated** with an API token (`Authorization: Bearer p2f_…`).
- **Resumable.** A stopped download leaves its bytes on disk; the next call
  resumes from that byte offset with an HTTP `Range` request. A whole local
  file is always a correct prefix of the plaintext.
- **Decrypted end to end.** Files are AES-256-CTR ciphertext on the wire. The
  key never crosses the wire in the clear — it's ECDH-wrapped per transfer and
  unwrapped here (P-256 / HKDF-SHA256 / AES-256-GCM), then the stream is
  decrypted as it arrives. Nothing is written to disk encrypted.
- **Verified.** A finished file is checked against the server's plaintext
  SHA-256.
- **Pausable.** Pass an `AbortSignal`; aborting stops the transfer and keeps
  the bytes for a later resume. A built-in idle watchdog drops a stalled
  connection so a retry can pick it back up.

The derivations match the server byte for byte (see the peer-to-file repo's
`src/server/keyExchange.ts` and `src/server/cipher.ts`), so the same file
decrypts identically whether a browser or this library fetches it.

## Install

It has no runtime dependencies (Node ≥ 20 built-ins only). As a git
dependency:

```json
{
  "dependencies": {
    "p2f-lib": "github:murilopereirame/p2f-lib"
  }
}
```

## Usage

```ts
import { P2FClient, downloadPath } from "p2f-lib";

const client = new P2FClient({
  baseUrl: "http://10.0.0.1:8000", // the peer-to-file server, over your VPN
  token: process.env.P2F_TOKEN!,   // a p2f_… API token (server: cli add-token)
});

// Fetch a file or a whole folder into ./downloads, resuming if interrupted.
const local = await downloadPath(client, "movies/Film.2024", "./downloads", {
  onProgress: (t) => {
    const pct = t.bytesTotal ? (100 * t.bytesDone) / t.bytesTotal : 0;
    console.log(`${pct.toFixed(1)}%  file ${t.filesDone}/${t.filesTotal}`);
  },
});
console.log("saved to", local);
```

Make a token on the server:

```sh
node src/server/cli.ts add-token <user> <name>   # prints a p2f_… token once
```

## API

- `new P2FClient({ baseUrl, token, fetchImpl?, timeoutMs? })` — `info()`,
  `list(path)`, `torrentMeta(path, ck)`, `rawRange(path, { start, signal })`.
- `downloadPath(client, remotePath, localDir, options?)` — the high-level
  resumable download of a file or folder. Returns the local path.
  Options: `onProgress`, `signal`, `verify` (default `true`),
  `idleTimeoutMs` (default `60000`).
- Crypto building blocks (`generateClientKeyPair`, `unwrapTransferKey`,
  `createCtrDecipherAt`, `DropBytes`, `ctrCounter`) and the wire types, for a
  caller that wants to drive the transfer itself.

## Development

```sh
npm install       # also builds via the prepare script
npm run build     # compile to dist/
npm test          # crypto round-trip + resume-plan tests (node:test)
npm run typecheck # types only
```
