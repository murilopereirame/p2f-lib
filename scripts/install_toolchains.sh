#!/usr/bin/env bash
# Download the cross toolchains into ./toolchains (Linux x86_64).
#   scripts/install_toolchains.sh ps4 wasm android
# Then:
#   export OO_PS4_TOOLCHAIN=$PWD/toolchains/PS4Toolchain
#   export WASI_SDK_PATH=$PWD/toolchains/wasi-sdk
#   export ANDROID_NDK_HOME=$PWD/toolchains/android-ndk
# (iOS needs a Mac with Xcode; nothing to download.)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p toolchains
cd toolchains

OO_VERSION=v0.5.2
WASI_VERSION=25
NDK_VERSION=r27c

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
    android)
      if [ ! -d android-ndk ]; then
        curl -fsSL -o ndk.zip "https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-linux.zip"
        unzip -q ndk.zip && mv "android-ndk-$NDK_VERSION" android-ndk && rm ndk.zip
      fi
      echo "ANDROID_NDK_HOME=$PWD/android-ndk"
      ;;
    *)
      echo "unknown toolchain: $what (use ps4, wasm, android)" >&2
      exit 2
      ;;
  esac
done
