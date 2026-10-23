#!/usr/bin/env bash
# Full release check: host tests, then all four release builds, then image sanity.
# Used by the upstream-sync task and by GitHub Actions.
#   tools/ci.sh            # offline toolchain (tools/offline/setup.sh)
#   CI_ONLINE=1 tools/ci.sh  # normal PlatformIO registry (GitHub Actions)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
DEPS="${SPECTRA_DEPS:-$HOME/.spectra-deps}"
OUT="${CI_OUT:-$ROOT/dist}"; mkdir -p "$OUT"

# On GitHub Actions, surface failures as annotations (readable without log access).
fail() {  # title file
  echo "FAILED: $1"; tail -40 "$2"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    msg=$(grep -E "error|Error|FAIL|overflow|XL:|No such|not found|undefined" "$2" | head -25 || true)
    [ -n "$msg" ] || msg=$(tail -25 "$2")
    msg=${msg//'%'/'%25'}; msg=${msg//$'\n'/'%0A'}
    echo "::error title=$1::$msg"
  fi
  exit 1
}

if [ -n "${CI_ONLINE:-}" ]; then
  CONF=platformio.ini; ENVS=(specter specter_xl specter_eu specter_xl_eu)
  CRYPTO_DIR="${CRYPTO_DIR:?}"; MESHCORE_DIR="${MESHCORE_DIR:?}"
else
  [ -f platformio-offline.ini ] || tools/offline/setup.sh
  CONF=platformio-offline.ini; ENVS=(us xl eu xl_eu)
  CRYPTO_DIR="$DEPS/libs/Crypto"; MESHCORE_DIR="$DEPS/MeshCore"
fi

echo "== host tests"
TMPDIR="$(mktemp -d)" CRYPTO_DIR="$CRYPTO_DIR" MESHCORE_DIR="$MESHCORE_DIR" timeout 600 test/host/run.sh > "$OUT/tests.log" 2>&1 || fail "host tests (exit $?)" "$OUT/tests.log"
if grep -q "^FAIL" "$OUT/tests.log"; then fail "host tests" "$OUT/tests.log"; fi
echo "   $(grep -c '^PASS' "$OUT/tests.log") checks passed"

echo "== builds"
timeout 1200 pio run -c "$CONF" $(printf -- '-e %s ' "${ENVS[@]}") > "$OUT/build.log" 2>&1 || fail "firmware builds (exit $?)" "$OUT/build.log"
grep -E "^(RAM|Flash):" "$OUT/build.log" | sed 's/^/   /'

VER=$(sed -n 's/^#define FW_VERSION *"\(v[^"]*\)".*/\1/p' src/main.cpp)
B=.pio/build
cp "$B/${ENVS[0]}/firmware.bin" "$OUT/spectra-cascadia-$VER-us.bin"
cp "$B/${ENVS[1]}/firmware.hex" "$OUT/spectra-cascadia-$VER-xl-us.hex"
cp "$B/${ENVS[2]}/firmware.bin" "$OUT/spectra-cascadia-$VER-eu.bin"
cp "$B/${ENVS[3]}/firmware.hex" "$OUT/spectra-cascadia-$VER-xl-eu.hex"

echo "== image checks"
python3 - "$OUT" "$VER" > "$OUT/images.log" 2>&1 <<'PY' || fail "image checks" "$OUT/images.log"
import sys, glob, os
out, ver = sys.argv[1], sys.argv[2]
for hx in glob.glob(f"{out}/spectra-cascadia-{ver}-xl-*.hex"):
    segs, base = [], 0
    for l in open(hx):
        t = int(l[7:9], 16)
        if t == 4: base = int(l[9:13], 16) << 16
        if t == 0:
            a = base + int(l[3:7], 16); segs.append((a, a + int(l[1:3], 16)))
    bad = [s for s in segs if s[0] < 0x08010000 and s[1] > 0x0800F800] + [s for s in segs if s[1] > 0x0801FC00]
    assert not bad, f"{hx}: data in the settings or admin-list pages"
    print(f"{os.path.basename(hx)}: low end {max(b for a,b in segs if a < 0x08010000):#x}, high end {max(b for a,b in segs):#x}")
for bn in glob.glob(f"{out}/spectra-cascadia-{ver}-*.bin"):
    n = os.path.getsize(bn); assert n <= 63488, f"{bn}: {n} > 62 KB"
    assert ver.encode() in open(bn, "rb").read(), f"{bn}: version string missing"
    print(f"{os.path.basename(bn)}: {n} bytes")
PY
sed 's/^/   /' "$OUT/images.log"
echo "OK $VER -> $OUT"
