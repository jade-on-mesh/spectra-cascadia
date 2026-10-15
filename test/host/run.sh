#!/usr/bin/env bash
# Host-side tests (no hardware needed).
# Usage: CRYPTO_DIR=/path/to/rweather/Crypto MESHCORE_DIR=/path/to/MeshCore ./run.sh
#   MESHCORE_DIR (upstream MeshCore checkout) is only needed for the XL tests,
#   which check our key exchange against upstream's own ed25519 code.
set -euo pipefail
cd "$(dirname "$0")"
CR="${CRYPTO_DIR:?set CRYPTO_DIR to rweather Crypto library folder}"
CSRC=("$CR"/SHA256.cpp "$CR"/SHA512.cpp "$CR"/Hash.cpp "$CR"/Ed25519.cpp "$CR"/Curve25519.cpp
      "$CR"/BigNumberUtil.cpp "$CR"/Crypto.cpp "$CR"/RNG.cpp "$CR"/NoiseSource.cpp "$CR"/ChaCha.cpp "$CR"/Cipher.cpp)
OUT="${TMPDIR:-/tmp}"; mkdir -p "$OUT"
g++ -std=gnu++17 -O1 -w -Istub -I"$CR" test_forwarding.cpp "${CSRC[@]}" -o "$OUT/specter_host_test"
"$OUT/specter_host_test"

if [ -n "${MESHCORE_DIR:-}" ]; then
  ED="$MESHCORE_DIR/lib/ed25519"
  mkdir -p "$OUT/orlp"
  for f in "$ED"/*.c; do gcc -O1 -w -c "$f" -I"$ED" -o "$OUT/orlp/$(basename "$f" .c).o"; done
  g++ -std=gnu++17 -O1 -w -Istub -I"$CR" -I"$ED" test_xl.cpp "${CSRC[@]}" \
    "$CR"/AES128.cpp "$CR"/AESCommon.cpp "$CR"/BlockCipher.cpp "$OUT"/orlp/*.o -o "$OUT/specter_xl_test"
  "$OUT/specter_xl_test"
else
  echo "(XL tests skipped: set MESHCORE_DIR)"
fi
