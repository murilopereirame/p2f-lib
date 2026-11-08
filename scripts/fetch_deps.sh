#!/usr/bin/env bash
# Download the third-party sources at pinned versions into third_party/.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party
cd third_party

fetch() { # dir url ref
  if [ -d "$1" ]; then echo "have $1"; return; fi
  git clone -q "$2" "$1"
  git -C "$1" checkout -q "$3"
  echo "got $1 @ $3"
}

fetch mbedtls  https://github.com/Mbed-TLS/mbedtls.git  mbedtls-3.6.2      # Apache-2.0
fetch cJSON    https://github.com/DaveGamble/cJSON.git  6d9f2443ab071f86e5d9b43025a40929ec41c46c  # MIT, 1.7.19
