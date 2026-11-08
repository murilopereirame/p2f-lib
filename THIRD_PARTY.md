# Third-party code

The release libraries (`libp2f.a`, `p2f.wasm`) contain:

| Component | License | Source |
|---|---|---|
| mbedTLS 3.6.2 | Apache-2.0 | https://github.com/Mbed-TLS/mbedtls |
| cJSON 1.7.19 | MIT | https://github.com/DaveGamble/cJSON |
| Mozilla CA list (`src/ca_bundle.c`, via certifi) | MPL-2.0 | https://github.com/certifi/python-certifi |

The WebAssembly build contains only the mbedTLS crypto parts (no cJSON, no CA list).
