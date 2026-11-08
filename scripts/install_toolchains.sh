#!/usr/bin/env bash
# Download the cross toolchains into ./toolchains (Linux x86_64).
#   scripts/install_toolchains.sh ps4 wasm
# Then:
#   export OO_PS4_TOOLCHAIN=$PWD/toolchains/PS4Toolchain
#   export WASI_SDK_PATH=$PWD/toolchains/wasi-sdk
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p toolchains
cd toolchains

OO_VERSION=v0.5.2
WASI_VERSION=25

for what in "$@"; do
  case "$what" in
    ps4)
      if [ ! -d PS4Toolchain ]; then
        curl -fsSL "https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/releases/download/$OO_VERSION/$OO_VERSION.tar.gz" \
          | tar xz
        mv OpenOrbis/PS4Toolchain PS4Toolchain && rm -rf OpenOrbis
      fi
      echo "OO_PS4_TOOLCHAIN=$PWD/PS4Toolchain"
      ;;
    wasm)
      if [ ! -d wasi-sdk ]; then
        curl -fsSL "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$WASI_VERSION/wasi-sdk-$WASI_VERSION.0-x86_64-linux.tar.gz" \
          | tar xz
        mv "wasi-sdk-$WASI_VERSION.0-x86_64-linux" wasi-sdk
      fi
      echo "WASI_SDK_PATH=$PWD/wasi-sdk"
      ;;
    *)
      echo "unknown toolchain: $what (use ps4, wasm)" >&2
      exit 2
      ;;
  esac
done
