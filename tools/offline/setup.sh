#!/usr/bin/env bash
# Build Spectra-Cascadia without the PlatformIO package registry (for sandboxes
# where only GitHub, PyPI and apt are reachable). Pins the exact versions the
# releases are built with. Re-running is safe (skips what is already there).
#
#   tools/offline/setup.sh            # installs into ~/.spectra-deps
#   pio run -c platformio-offline.ini -e us -e xl
#
# On GitHub Actions (or any machine with normal internet) just use `pio run`.
set -euo pipefail
DEPS="${SPECTRA_DEPS:-$HOME/.spectra-deps}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$DEPS/libs"

need() { command -v "$1" >/dev/null 2>&1; }
need arm-none-eabi-gcc || { sudo -n true 2>/dev/null && S=sudo || S=; $S apt-get update -qq && $S apt-get install -y -qq gcc-arm-none-eabi binutils-arm-none-eabi libnewlib-arm-none-eabi; }
need pio || pip install -q --break-system-packages platformio==6.1.18 2>/dev/null || pip install -q platformio==6.1.18

clone() {  # url tag dir [extra args]
  [ -d "$3/.git" ] || git clone -q --depth 1 --branch "$2" "${@:4}" "$1" "$3"
}
clone https://github.com/platformio/platform-ststm32.git v20.0.0 "$DEPS/platform-ststm32"
clone https://github.com/stm32duino/Arduino_Core_STM32.git 2.10.1 "$DEPS/core"
clone https://github.com/ARM-software/CMSIS_5.git 5.9.0 "$DEPS/cmsis" --filter=blob:none
clone https://github.com/ARM-software/CMSIS-DSP.git v1.16.2 "$DEPS/cmsisdsp"
clone https://github.com/jgromes/RadioLib.git 7.6.0 "$DEPS/libs/RadioLib"
if [ ! -d "$DEPS/libs/Crypto" ]; then
  git clone -q --depth 1 https://github.com/rweather/arduinolibs.git "$DEPS/arduinolibs"
  cp -r "$DEPS/arduinolibs/libraries/Crypto" "$DEPS/libs/Crypto"
fi

# Host tests also need upstream MeshCore (its ed25519 is the reference for our key exchange)
[ -d "$DEPS/MeshCore/.git" ] || git clone -q --depth 1 https://github.com/meshcore-dev/MeshCore.git "$DEPS/MeshCore"

echo '{"name":"framework-arduinoststm32","version":"4.21001.0"}' > "$DEPS/core/package.json"
echo '{"name":"framework-cmsis","version":"2.50900.0"}'          > "$DEPS/cmsis/package.json"
echo '{"name":"framework-cmsis-dsp","version":"1.16.2"}'         > "$DEPS/cmsisdsp/package.json"

# Toolchain package = symlinks to the distro arm-none-eabi-gcc
mkdir -p "$DEPS/toolchain/bin"
for f in /usr/bin/arm-none-eabi-*; do ln -sf "$f" "$DEPS/toolchain/bin/$(basename "$f")"; done
GCCV=$(arm-none-eabi-gcc -dumpversion | awk -F. '{printf "1.%d%02d%02d.0", $1, $2, $3}')
echo "{\"name\":\"toolchain-gccarmnoneeabi\",\"version\":\"$GCCV\",\"system\":[\"linux_x86_64\"]}" > "$DEPS/toolchain/package.json"

# SCons for PlatformIO's builder (normally downloaded from the registry)
SC="$HOME/.platformio/packages/tool-scons"
if [ ! -f "$SC/scons.py" ]; then
  mkdir -p "$SC" && T=$(mktemp -d)
  pip download -q --no-deps --no-binary :all: scons==4.11.1 -d "$T" 2>/dev/null || pip download -q --no-deps scons==4.11.1 -d "$T"
  (cd "$T" && for a in *; do case "$a" in *.whl) python3 -m zipfile -e "$a" x;; *.tar.gz) tar xzf "$a" && mv [Ss][Cc]ons-*/ x;; esac; done)
  cp -r "$T"/x/SCons "$SC/" && printf 'import sys\nfrom SCons.Script.Main import main\nif __name__ == "__main__":\n    sys.exit(main())\n' > "$SC/scons.py"
  echo '{"name":"tool-scons","version":"4.41101.0"}' > "$SC/package.json"
  echo '{"type": "tool", "name": "tool-scons", "version": "4.41101.0", "spec": {"owner": "platformio", "id": 4919, "name": "tool-scons", "requirements": null, "uri": null}}' > "$SC/.piopm"
  rm -rf "$T"
fi

sed "s#@DEPS@#$DEPS#g" "$ROOT/tools/offline/platformio-offline.ini.in" > "$ROOT/platformio-offline.ini"
echo "Ready: cd $ROOT && pio run -c platformio-offline.ini -e us -e xl"
