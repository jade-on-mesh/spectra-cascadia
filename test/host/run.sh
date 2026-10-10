#!/usr/bin/env bash
# Host-side tests of the forwarding logic (no hardware needed).
# Usage: CRYPTO_DIR=/path/to/rweather/arduinolibs/libraries/Crypto ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
CR="${CRYPTO_DIR:?set CRYPTO_DIR to rweather Crypto library folder}"
g++ -std=gnu++17 -O1 -w -Istub -I"$CR" test_forwarding.cpp \
  "$CR"/SHA256.cpp "$CR"/SHA512.cpp "$CR"/Hash.cpp "$CR"/Ed25519.cpp "$CR"/Curve25519.cpp \
  "$CR"/BigNumberUtil.cpp "$CR"/Crypto.cpp "$CR"/RNG.cpp "$CR"/NoiseSource.cpp "$CR"/ChaCha.cpp \
  "$CR"/Cipher.cpp -o /tmp/specter_host_test
/tmp/specter_host_test
