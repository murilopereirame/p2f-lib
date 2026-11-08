# p2f-lib

The client library of the [peer-to-file](https://github.com/murilopereirame/peer-to-file)
protocol. **One C code base, five builds:**

| Build | Used by | Output |
|---|---|---|
| Desktop (Linux, macOS) | `p2f-cli`, native apps | `build/host/libp2f.a` |
| PS4 (OpenOrbis) | [P2PS](https://github.com/murilopereirame/p2ps) | `build/ps4/libp2f.a` |
| WebAssembly | the JavaScript package (`js/`): peer-to-file's web, desktop and server code, Node scripts | `build/wasm/p2f.wasm` |
| Android (NDK) | Android apps, through JNI | `build/android/<abi>/libp2f.a` (arm64-v8a, armeabi-v7a, x86_64; API 24+) |
| iOS (Xcode) | iOS apps (Swift or Objective-C) | `build/ios/P2F.xcframework` (device + simulator; iOS 13+) |

The PS4 can't run JavaScript and a browser can't run native code, so the
protocol lives in portable C and the JavaScript package wraps the
WebAssembly build of the same code. A fix in `src/` reaches every client.

What the library does:

- **Authenticated** with an API token (`Authorization: Bearer p2f_…`), or a
  cookie session in a browser.
- **Resumable.** A stopped file keeps its bytes. The next try continues from
  that byte with an HTTP `Range` request on the `/api/raw` webseed.
- **Decrypted end to end.** Files are AES-256-CTR ciphertext on the wire. The
  key is ECDH-wrapped per transfer (P-256 / HKDF-SHA256 / AES-256-GCM).
- **Verified.** A finished file is checked against the server's plaintext SHA-256.
- **Self-repairing.** A file that fails the checksum is not downloaded again
  from scratch. Each piece of the local copy is encrypted again (CTR is
  seekable) and checked against the torrent's SHA-1 piece hashes; only the
  missing or damaged pieces are fetched again, with bounded `Range`
  requests, checked against their hash, decrypted and written in place.
  Data that fails its hash is never written. A full-size copy on disk is
  checked the same way before it is skipped, and a copy that is too long is
  trimmed. The pure parts (torrent parser, piece check) are
  `src/p2f_repair.c`, in every build.
- **Patient with big files.** The server reads and hashes a whole file before
  it can describe it; for a big file that takes minutes the first time. The
  client asks with `async=1`, the server answers `202` with its progress, and
  the client waits. Dropped connections, timeouts, `429`/`5xx` and error
  pages from a reverse proxy are retried with a backoff (2 s … 30 s). A real
  answer from the server (a `404` for a missing file) is final. This policy
  is `p2f_retry_delay_ms()` in `src/p2f_policy.c`.
- HTTP or HTTPS (TLS 1.2, mbedTLS, built-in Mozilla CA list or your own CA),
  and a small DNS client for consoles with a weak resolver (native builds).

## Layout

| Path | Contents |
|---|---|
| `include/p2f.h` | The public C API. |
| `include/p2f_platform.h` | The platform hooks (random, resolver, sleep, clock). The PS4 app provides them; other builds have POSIX defaults. |
| `src/` | The library. `p2f_policy.c` (resume plan, retry policy) and `p2f_crypto.c` have no I/O and are in every build. |
| `src/platform/` | `posix.c` (desktop, Android, iOS; weak, so an app can replace a hook) and `wasm.c` (random only, for the JS package). No console code: the PS4 hooks are in P2PS. |
| `src/wasm/exports.c` | The WebAssembly exports. |
| `js/` | The JavaScript package (`@murilopereirame/p2f-lib`). |
| `tools/` | `p2f-cli`, the mock server and the end-to-end tests. |

## Build

```sh
scripts/fetch_deps.sh                 # mbedTLS 3.6.2, cJSON 1.7.19 -> third_party/
make                                  # desktop: build/host/libp2f.a + p2f-cli
make test                             # desktop build + 45 end-to-end tests (Node 20+, python3-cryptography)

scripts/install_toolchains.sh ps4 wasm android   # OpenOrbis v0.5.2, wasi-sdk 25, NDK r27c -> toolchains/
export OO_PS4_TOOLCHAIN=$PWD/toolchains/PS4Toolchain WASI_SDK_PATH=$PWD/toolchains/wasi-sdk
export ANDROID_NDK_HOME=$PWD/toolchains/android-ndk
make ps4 PS4_AR=llvm-ar               # build/ps4/libp2f.a
make wasm                             # build/wasm/p2f.wasm
make android                          # build/android/<abi>/libp2f.a
make ios                              # build/ios/P2F.xcframework (on a Mac with Xcode)
make dist PS4_AR=llvm-ar              # desktop, PS4, wasm bundles in dist/
make dist-android                     # dist/p2f-lib-<v>-android.tar.gz
make dist-ios                         # dist/p2f-lib-<v>-ios.zip (Mac)

cd js && npm ci && npm test           # JS package (needs build/wasm/p2f.wasm)
```

`libp2f.a` already contains mbedTLS and cJSON: link only `libp2f.a`.
The PS4 `libp2f.a` has no platform layer; the app links its own
implementation of `include/p2f_platform.h` (P2PS: `ps4/platform_ps4.c`).
The desktop, Android and iOS libraries include POSIX defaults for those
hooks. They are weak symbols: define one in your app to replace it.

### Mobile apps

- **Android:** add the ABI folders of `p2f-lib-<v>-android.tar.gz` to your
  NDK build (CMake: an `IMPORTED STATIC` library per `${ANDROID_ABI}`) and
  call the C API from your JNI code. Downloads need a writable path such as
  `Context.getFilesDir()`, and the app needs the `INTERNET` permission.
- **iOS:** drag `P2F.xcframework` into Xcode and import `p2f.h` in a
  bridging header (Swift) or directly (Objective-C). Save into the app's
  Documents or Caches folder.
- The library ignores `SIGPIPE` on its own sockets, so a server that closes
  the connection does not end the app.
- Call the blocking functions (`p2f_download_path`, ...) on a background
  thread, never on the main thread.

## C usage

```c
#include "p2f.h"

p2f_client *c;
p2f_client_new(&c, "https://files.example.com", "p2f_...", 0);
p2f_client_set_ca_file(c, "/data/p2f/ca.pem");   /* optional */
p2f_download_opts o = { on_progress, user, 1 /* verify */, 60000 /* idle ms */,
                        0 /* prepare timeout: wait until stopped */,
                        0 /* no_repair: 0 = repair damaged files */ };
int rc = p2f_download_path(c, "movies/Film.2024", "/data/p2f/downloads", &o, NULL, 0);
if (p2f_is_retryable(rc)) { /* call again: it resumes */ }
p2f_client_free(c);
```

While the server prepares a file, the progress callback gets
`p->preparing == 1` with `prepare_done` / `prepare_total`. During a repair
it gets `p->repair_phase` (`P2F_REPAIR_VERIFYING`, then
`P2F_REPAIR_FETCHING`) with `repair_done` / `repair_total` in pieces. Return
non-zero from the callback to stop; a stop or a network error during a
repair keeps the file, and the next call checks it again.
`P2F_ERR_CHECKSUM` now means the repair could not fix the file (or
`no_repair` is set, or the server sent no torrent); the file was removed.

## JavaScript usage

```ts
import { P2FClient } from "p2f-lib";            // Node, browser, Electron
import { downloadPath } from "p2f-lib/node";     // Node: download to disk

const client = new P2FClient({ baseUrl: "http://10.0.0.1:8000", token: process.env.P2F_TOKEN });
const local = await downloadPath(client, "movies/Film.2024", "./downloads", {
  onProgress: (t) => console.log(`${t.bytesDone}/${t.bytesTotal}`),
  onPreparing: (p) => console.log(`server preparing ${p.remote}: ${p.bytesDone}/${p.bytesTotal}`),
  onRepair: (file, p) => console.log(`repair ${file}: ${p.phase} ${p.done}/${p.total}`),
  // repair: false  -> remove a bad file instead (the next call downloads it)
});
```

`repairFile(target, torrent, key, iv, fetchRange)` is exported on its own
for apps with their own storage: `target` is a small random-access
interface (`size`, `read`, `write`, `truncate`), so a browser app can heal a
file in OPFS. `nodeFileTarget(path)` (in `p2f-lib/node`) is the one for
files on disk, and `webseedFetcher(client, remote)` fetches pieces.

The lower-level pieces (`initP2F`, `generateClientKeyPair`, `CtrStream`,
`Sha256`, `planResume`, `retryDelayMs`, `waitForTorrentMeta`) are exported
for apps that drive the transfer themselves, such as a WebTorrent client.

### Install

Each release has the npm tarball attached, so no registry login is needed:

```json
"dependencies": {
  "p2f-lib": "https://github.com/murilopereirame/p2f-lib/releases/download/v0.3.0/murilopereirame-p2f-lib-0.3.0.tgz"
}
```

It is also on GitHub Packages as `@murilopereirame/p2f-lib` (needs an
`.npmrc` with a GitHub token).

## Releases

Every merge to `main` builds and tests everything. If `VERSION` (and
`js/package.json`, which must match) holds a version that has no release yet,
the workflow publishes it: a GitHub Release `v<version>` with the PS4,
desktop, Android and iOS bundles, the WebAssembly core and the npm tarball, plus the npm
package on GitHub Packages. To release, bump both version numbers in the PR.

## Changes from 0.1 (the TypeScript library)

- The implementation is now the C library (it started as the PS4 port of 0.1).
- JS: `generateClientKeyPair()` returns a `ClientKeyPair` with
  `publicKeyBase64` and `unwrap()`; `createCtrDecipherAt` is replaced by
  `CtrStream`; `downloadPath` and `DropBytes` moved to `p2f-lib/node`.
- `torrentMeta` waits while the server prepares a file (see above).
- An empty remote file makes an empty local file.

## Licenses

MIT. Third-party code: see `THIRD_PARTY.md`.
