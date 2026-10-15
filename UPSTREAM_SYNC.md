# Upstream sync

Spectra-Cascadia is a from-scratch re-implementation (20 KB RAM, 62/128 KB flash), not a fork, so upstream
changes are **ported by hand**, never merged. This file is the policy the scheduled upstream-sync task follows.

## Sources
| Source | What counts as a new release | Range to review |
|---|---|---|
| Official [meshcore-dev/MeshCore](https://github.com/meshcore-dev/MeshCore) | a new `repeater-vX.Y.Z` tag | previous tag → new tag |
| [mikecarper/MeshCore](https://github.com/mikecarper/MeshCore) `keymindCascade` (Halo Keymind Cascade) | a new version number `vX.Y.Z.N` in any tag (previews included; one sync per version) | `last_commit` → the newest tagged commit of that version |

State lives in `.upstream-sync.json`. If neither source has something new, the run does nothing.

## What to port
In scope: behaviour a **repeater** shows on the air or to the app.
- forwarding/routing rules, dedup, flood/direct retries, hop and region (scope) logic
- packet and wire formats: adverts, ACKs, TRACE, CONTROL/discovery, OTA relay
- app compatibility: login/REQ/RESPONSE formats, CLI commands and reply text the apps parse, repeater settings keys
- security fixes in anything we implement (crypto, login, replay, signature checks)
- radio defaults and timing (txdelay, airtime budget, LBT/CAD, AGC)

Out of scope: companion/room-server/sensor roles, Wi-Fi/BLE/USB host features, GPS, displays, file systems,
nRF52/ESP32-only drivers and bootloaders, OTA install, build tooling, docs-only changes.

## Budget rules
- **Standard (64 KB) build:** ≈200 bytes of flash left. Only security fixes and wire-compatibility fixes; if one
  doesn't fit, ship it XL-only and note it.
- **XL build:** ≈52/62 KB low flash, 29/63 KB high flash, ≈13/20 KB static RAM. Keep ≥3 KB RAM for the stack. A
  feature that would push static RAM above 15 KB is declined.
- Prefer upstream's exact CLI names, reply text and defaults. Don't invent formats.

## Each run
1. `tools/offline/setup.sh` (registry-free toolchain), clone both upstreams.
2. Review the new range; classify every repeater-relevant change as **port**, **already have**, or **decline (reason)**.
3. Port; add host tests for each ported behaviour (`test/host/`).
4. `tools/ci.sh` must pass: all tests, all four builds, image checks.
5. Version (see below), `CHANGELOG.md` entry ("Upstream sync" section listing ported and declined items with
   upstream commit links), update `.upstream-sync.json`.
6. Commit, tag `vX.Y.Z.N`, push. GitHub Actions builds and publishes the release.
7. If a check fails or a port is unsafe, push nothing to `main`. Put the work on a `sync/<version>` branch and report why.

## Versioning
- The first three numbers follow official MeshCore. A new official release `X.Y.Z` → `vX.Y.Z.1`.
- Otherwise bump the fourth number.
- mikecarper also uses four-part versions. Ours are independent; the changelog names the upstream versions each
  release covers.
