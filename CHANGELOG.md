# Changelog

All notable changes to Spectra-Cascadia (formerly SPECTER) firmware are documented here.

Version numbers follow the official MeshCore firmware release this one tracks
(the first three numbers, currently 1.18.0, as on meshcore.io/flasher), plus a
fourth number for our own releases on that base. That number resets to 1 when
upstream moves. Releases before 1.17.1.1 used internal numbers 2.0–2.6.

## [1.18.0.3] - 2026-10-23

Adds Halo Keymind Cascade's **radio2** (a second LoRa profile, time-shared on the one SX1262), aimed at relaying MediaMesh next to the normal network. XL only.
Not yet tested on hardware; the scanner's real switch time on the DX-LR30 is still to be measured (`get radio2.status`).

### Added (XL)
- `set radio2 MHz,kHz,SF,CR,rx|rxtx[,preamble]`, `set radio2 mediamesh` (911.150 / 250 kHz / SF7 / CR5, rxtx), `mediamesh-range` (125 kHz), `set radio2 off`; `get radio2` warns when radio2 is within 6 kHz of radio's channel and suggests a centre
- Scanning: 4.6 symbols on the slower profile, then the rest of half its preamble on the faster one; a packet being received holds the profile. The first four hops each way measure the switch time (largest + 10%), which sizes the automatic preambles (radio 32, MediaMesh 48 on the default pair)
- Relays on the profile a packet arrived on; `set radio2.cross off|auto|on` (default off) copies relays and own adverts to the other profile. A radio2 copy has its own retry slot, and an echo only cancels the retry on its own profile
- `set tx.reply both|radio|radio2|auto|off [force]` (default both): which profiles replies to logins, requests, CLI and discovery use
- Discovery: a request with flag `0x02` gets the version-1 radio2 trailer (configured, mode, frequency, bandwidth, SF, CR)
- `get radio2.status`, `get radio2.scan`, `get radio2.timing` (alias `radio.timing`)

### Fixed
- Preamble length follows official 1.18 (`preambleLengthForSF`): 32 symbols at SF5–8, 16 above (was always 16). Both builds

### Changed (XL)
- The CLI and remote-admin handlers moved to the upper 64 KB (`XL_HI`), freeing ~14 KB in the lower 62 KB (14.7 KB now free there)
- Send queue: 8 slots (was 6) so each profile can hold copies

### Upstream sync
Ported from mikecarper's `docs/radio_profiles.md` (Halo Keymind Cascade 1.18.0.1): `radio2` / `rx` / `rxtx`, MediaMesh presets, `radio2.cross`, `tx.reply` (+ force), scan timing and automatic preambles, switch self-test, discovery trailer, spacing warning, status/scan/timing getters.
Left out: `tempradio2`, scheduled profiles (`radioat2`, `tempradioat2`), Meshtext, Ethernet over LoRa, Companion per-contact/channel/media routing, the two-minute advice delay.

Size: standard 63,316-byte image (+56: preamble rule); XL lower 62 KB 48.8 KB used, upper 44.6 KB of 63 KB, RAM +640 bytes.

## [1.18.0.2] - 2026-10-22

Rolls in mikecarper Halo Keymind Cascade 1.18.0.1 changes from after the last sync (up to [e34e83e6](https://github.com/mikecarper/MeshCore/commit/e34e83e6b), 2026-10-22). XL only; the standard build is unchanged.
Not yet tested on hardware.

### Added (XL)
- `set repeat.battery off|on|1-100` and `set flood.battery off|on|1-100`: stop relaying (everything, or floods only) when the battery drops below a percentage. `on` uses 10 % and 20 %; a number sets the threshold and turns it on. Relaying resumes 2 points above the threshold. Own adverts, replies and alerts still go out; pending relay retries are dropped while paused. Needs `battery.pin`: without it there is no battery reading and nothing is paused. Both off by default
- `get battery.forward` (`> battery=55% mv=3660 repeat=allowed flood=allowed`), and `set battery.empty` / `battery.full` (mV for 0 % / 100 %, default 3000 / 4200)
- `get guest` / `set guest on|off`: guest logins have a switch. `off` ends guest sessions at once. With `on` and an empty guest password, guests need no password (as Halo Keymind Cascade)
- `get guests [page]`: live guest sessions, one full key and last activity per page
- `get logins [page]`: the 16 keys that most recently tried to log in, newest first: 12-hex key prefix, attempt count, time and result (`accepted`, `wrong-password`, `guests-disabled`, `replay/state`). RAM only

### Changed (XL)
- Guest logins default to **off** on new installs. Nodes upgrading with a guest password already set keep guests on; nodes without one stay as they were (no guest access)
- `set guest.password` while guests are off replies `OK - guest logins are off (set guest on)`
- A cached guest can no longer log back in with a blank password; it must pass the current guest policy. Admins still can. A blank password doesn't count toward the login lockout
- A blank-password admin reconnect now gets the same replay (timestamp) check as a password login

### Upstream sync
Ported:
- [af106a0e](https://github.com/mikecarper/MeshCore/commit/af106a0ee) battery thresholds for repeat and flood forwarding (same commands, defaults, 2-point recovery and reply text; percentage from our battery.pin reading)
- [c433b40e](https://github.com/mikecarper/MeshCore/commit/c433b40e5) guest login switch and `get guests`
- [f68d4ca5](https://github.com/mikecarper/MeshCore/commit/f68d4ca54) `get logins` (we keep 8-byte key prefixes, not full keys, to save RAM; the display is the same)

Already have / not applicable:
- [862260de](https://github.com/mikecarper/MeshCore/commit/862260de1) AGC interval range: we follow official 1.18 (clamp to 1020 s)
- [e980d983](https://github.com/mikecarper/MeshCore/commit/e980d983b), [4dc3b43f](https://github.com/mikecarper/MeshCore/commit/4dc3b43f1) flood retry bucket CLI checks: we have no `flood.retry.bucket`
- [e4119a12](https://github.com/mikecarper/MeshCore/commit/e4119a120), [41564bf6](https://github.com/mikecarper/MeshCore/commit/41564bf6b) SX126x driver fixes: his RadioLib wrappers, not used here
- [21ab0b9d](https://github.com/mikecarper/MeshCore/commit/21ab0b9d4), [ca67494f](https://github.com/mikecarper/MeshCore/commit/ca67494f8) and other radio-profile work: needs a second radio profile

Declined:
- [f4ade738](https://github.com/mikecarper/MeshCore/commit/f4ade738d) noise-floor history: part of his telemetry history/upload system, which he also leaves out of STM32 repeaters
- [ab6412e7](https://github.com/mikecarper/MeshCore/commit/ab6412e73) battery ADC calibration: `battery.divider` already does this here
- [953ad6de](https://github.com/mikecarper/MeshCore/commit/953ad6def) flood filters / moderation rules engine: large, and we don't have the base feature
- Solar/MPPT, regulator modes, LED controls, ESP-NOW/UDP/RS232 bridges, Wi-Fi, BLE, MQTT, displays, new boards: other hardware

Size: standard build unchanged (63,260-byte image); XL +4.0 KB flash (≈3.5 KB left in the lower 62 KB), +356 bytes RAM.

## [1.18.0.1] - 2026-10-16

Covers official MeshCore `repeater-v1.18.0` and mikecarper Halo Keymind Cascade `v1.18.0.1` (preview1, incl. `v1.17.1.10`).
This release was ported automatically by the upstream-sync task and has **not yet been tested on hardware**.

### Fixed
- Floods with transport code 0 are treated as un-scoped (were dropped): the un-scoped hop limit and the wildcard's flood policy apply, as in Halo Keymind Cascade
- Packets with a payload version above 1 are no longer parsed or relayed (as upstream `Dispatcher`). This keeps Halo Keymind Cascade's new negotiated direct LoRa OTA frames (`F2 00 …`) off the mesh
- Forwarded direct ACKs now wait the random direct retransmit delay like other direct packets (upstream sent them at once). Multipart ACKs add it to their (remaining + 1) × 300 ms
- XL: `multi.acks` copies start after that delay, 300 ms apart, with the plain ACK last
- XL: encrypted requests and messages whose ciphertext isn't whole AES blocks are rejected before the MAC check (upstream stack overflow fix; our decrypt already ignored partial blocks)

### Changed
- Discover requests aren't answered when both `advert.interval` and `flood.advert.interval` are 0 (node doesn't want to be discoverable)
- `set af` accepts 0-9 and replies `ERROR: af must be 0-9` otherwise, as upstream
- XL: `set agc.reset.interval` above 1020 s is clamped to 1020 instead of refused, as upstream
- XL: remote CLI accepts the new `TXT_TYPE_CLI_COMMAND` (3) text type
- Offline toolchain: SCons pinned to 4.8.1, the version PlatformIO 6.1.18 asks for

### Added (XL)
- `power` (upstream 1.18): `batt:<mV> mV usb:n/a solar_chg:n/a ext:no charger:no` (this board has no USB, solar or charger sensing)

### Upstream sync
Ported:
- [9c9a2ba2](https://github.com/meshcore-dev/MeshCore/commit/9c9a2ba2db59) / [b74ba545](https://github.com/meshcore-dev/MeshCore/commit/b74ba545308f) MACThenDecrypt block-alignment check
- [6df5aaed](https://github.com/meshcore-dev/MeshCore/commit/6df5aaed4335) ACK forwarding (direct) had zero delay
- [01f9293b](https://github.com/meshcore-dev/MeshCore/commit/01f9293be073) transport code 0 = un-scoped, with keymind's [b842438e](https://github.com/mikecarper/MeshCore/commit/b842438e6469) (wildcard deny + hop limits apply; official alone would forward it even when the wildcard denies flood)
- [f19733e4](https://github.com/meshcore-dev/MeshCore/commit/f19733e47879) don't answer DISCOVER when adverts are off
- [0c3fe356](https://github.com/meshcore-dev/MeshCore/commit/0c3fe356d06e) `agc.reset.interval` clamp (the 1020 s range we already had)
- [41588d80](https://github.com/meshcore-dev/MeshCore/commit/41588d805253) `set af` 0-9 range and reply text (CommonRadioPrefs refactor; other CLI names and replies unchanged)
- [2c0ace25](https://github.com/meshcore-dev/MeshCore/commit/2c0ace2519d9) `TXT_TYPE_CLI_COMMAND`
- [77057aef](https://github.com/meshcore-dev/MeshCore/commit/77057aefdd39) / [6b696a4e](https://github.com/meshcore-dev/MeshCore/commit/6b696a4ef6db) `power` command
- keymind [938f6374](https://github.com/mikecarper/MeshCore/commit/938f63748799) direct LoRa OTA frames must not be relayed → payload-version filter

Already have:
- [95214e8c](https://github.com/meshcore-dev/MeshCore/commit/95214e8c4026) serial command buffer NUL-termination (our reader is bounded)
- [1d5283de](https://github.com/meshcore-dev/MeshCore/commit/1d5283de7678) StaticPoolPacketManager null/index checks (no packet pool here)

Declined:
- [2db4b406](https://github.com/meshcore-dev/MeshCore/commit/2db4b40617c3) `loop.detect` default `minimal`: we already default to `moderate` (stricter)
- [9bc60608](https://github.com/meshcore-dev/MeshCore/commit/9bc6060831a0) and follow-ups: REQ_TYPE_SUBSCRIBE / region load-save / DynamicConfigSerializer: sensor role and file-system prefs
- LR1110/LR1121/LR2021 radio fixes, new boards, FEM prefs, board loop hook, LED off, RadioLib pin, `gps diag`: other hardware or out of scope
- keymind: OTA install and identity restamping ([39eaf8d8](https://github.com/mikecarper/MeshCore/commit/39eaf8d8b7ef)), direct OTA transport itself, Ethernet/Wi-Fi/BLE/MQTT/Meshtext/MeshTalk, SD seeder, new variants: out of scope (OTA install stays paused, see Cheapeater OTA design)

Size: standard build 62,948 / 63,488 bytes (8 bytes smaller than 1.17.1.3); XL +128 bytes, RAM unchanged.

## [1.17.1.3] - 2026-10-15

### Added (XL)
- Relays mikecarper/MeshCore LoRa OTA packets (`PAYLOAD_TYPE_OTA` 0x0C) during a `tempradio` window, as his relay-only repeaters do, so Cheapeaters can sit between an OTA source and a destination. Packets are carried opaquely and ignored outside the window. Ordinary flood limits and region rules apply. Duplicates use a time-limited cache, so a copy re-sent after a loss is forwarded again while echoes are not. Active-transfer messages go at top priority and discovery at background priority; discovery is dropped first when the send queue is nearly full
- `normalradio`: ends a `tempradio` window early (2 s after the reply goes out)

## [1.17.1.2] - 2026-10-11

### Added (XL)
- `tempradio <freq>,<bw>,<sf>,<cr>,<minutes>` (upstream): try radio settings for N minutes, then switch back by itself. They're applied 2 s after the reply goes out. Saves made meanwhile keep the real settings, `get radio` shows both, and `set radio` cancels it
- `cad on|off` (upstream): before transmitting, ask the SX1262 whether a LoRa preamble is on the air (Channel Activity Detection) and hold back if so. `get cad` shows how often it found the channel busy
- `rxdelay <0-20>` (upstream, default 0 = off): weaker copies of a flood wait longer, so when the same packet arrives over several paths the copy received best is forwarded with its own path (Dispatcher::calcRxDelay, packetScoreInt). Instead of an inbound queue, a better duplicate replaces the queued forward. `get rxdelay` counts replacements
- `radio.watchdog <1-48 h|off>` (default 6 h): if nothing has been received for that long, re-initialise the radio and send an alert (when alerts are set up)
- Login attempt limits: 5 per minute (each costs a key exchange). After 3 wrong passwords in a row, logins are locked out for 1 min, doubling each time up to 16 min; a successful login resets it. Admins already logged in, or saved across reboots, are unaffected
- Neighbour RSSI and how many times each was heard: `neighbors.detail [page]` → `key:secs_ago:snr×4:rssi:times_heard`. `neighbors` keeps the upstream format
- libm (powf) linked into the upper half

## [1.17.1.1] - 2026-10-11

### Changed
- Version scheme: `ver` reports `Spectra-Cascadia v1.17.1.1` (official MeshCore 1.17.1 + our release 1). Same firmware as internal 2.6.0

## [2.6.0] - 2026-10-11

### Added (XL)
- Alerts to a channel you choose: `set alert.channel #name | public | <32/64-hex key> | off`, `set alerts on|off`, `alert test`. Nothing is sent until a channel is set. Messages use the standard channel-message format (`<node name>: <text>`), are sent as floods scoped to the default region, and are limited to one every 5 minutes:
  - low battery (`alert.battery <mV>|auto|off`; auto = cutoff + 150 mV), once until it recovers by 100 mV
  - low-battery shutdown, sent before going to standby
  - restart a minute after boot, with the reason and watchdog count (skipped after a `reboot` command)
  - back on after a low-battery shutdown
- `flood.ratelimit <1-60|off>` (default off): floods forwarded per minute from one source. The source is the sender hash for DMs, requests and paths, the key prefix for anonymous requests, and channel + first hop for channel messages. Adverts and ACKs are never limited. `get flood.ratelimit` shows how many were dropped

## [2.5.0] - 2026-10-11

### Added
- `discover.neighbors` (XL): one-time zero-hop "who's there?" sent to repeaters (upstream `sendNodeDiscoverReq`); answers are added to the neighbour list for 60 s. All builds now answer other nodes' discover requests (format, rate limit of 4 per 2 min and `since` filter as upstream)
- 128-entry neighbour list (XL; upstream keeps 50), stored as 8-byte key prefixes, which is more than the app requests. `neighbor.remove <hex>`
- Admin list kept across reboots (XL): admins and other non-guest roles go in the last 1 KB page of flash, saved 5 s after a change, as upstream `ClientACL`. 12 login slots (was 6). `setperm <pubkey> <perms>`, plus `get acl` over USB
- Region hierarchy as upstream: `region put <name> [parent]`, tree export with `^` marking home and `F` marking flood-allowed, `region get` shows the parent, `region home`, `region remove` refuses regions that still have children. `region def` and `region load` (indented import, also from the app's command screen) are XL-only
- Private `$` region names are accepted and listed but never match, as upstream, where their keys can't be set yet
- `get reset.reason`: power-on/brownout, watchdog (with a count since power-on), reboot command, software, reset pin, low-power or low-battery standby. Also printed at boot

### Changed
- `region list allowed` includes `*` first when un-scoped flooding is allowed (upstream `exportNamesTo`)
- Smaller `strcmp` (saves ~420 bytes, so the standard build still fits)

## [2.4.2] - 2026-10-11

### Fixed (XL)
- `multi.acks` now does what it does on upstream repeaters (`Mesh::routeDirectRecvAcks`): a forwarded direct ACK is sent as N extra multipart ACKs, 300 ms apart and counting down, then the plain ACK. v2.4.1 only stored the setting
- `allow.read.only` stays stored-only: upstream uses it only in room servers

## [2.4.1] - 2026-10-11

### Fixed
- The app's repeater settings screen: command tags (`XX|get name`) are now echoed on the reply as upstream does. The tag is removed before the USB-only check, so it can't be used to get around it

### Added (XL)
- Settings the app's screen reads and writes: `owner.info` (also in owner queries), `radio.rxgain` (SX1262 boosted RX gain), `int.thresh` (RSSI above the noise floor counts as a busy channel), `agc.reset.interval` (periodic warm reset of the radio front end), plus `allow.read.only` and `multi.acks` (stored only; fixed in 2.4.2)
- `neighbors` CLI command (upstream text format)
- `get/set dutycycle` (both builds), which maps to `af` as upstream does

## [2.4.0] - 2026-10-11

### Added
- XL build (`env:specter_xl`, `env:specter_xl_eu`) for chips with 128 KB flash. RadioLib and Crypto are linked into the upper 64 KB (`specter_xl.ld`) and shipped as a `.hex` that skips the settings pages
- Login from the MeshCore app: admin/guest passwords (`password`, `set/get guest.password`). Login stays off until a password is set
- Status, telemetry (LPP voltage and temperature), neighbours, access list, owner info and anonymous clock/owner/regions queries
- Remote CLI over the air for admins, plus upstream's `clock sync`. `prv.key`, `erase` and `log` are USB only, and remote `reboot` is delayed until the reply is sent
- Boot-time check that the upper half was flashed; build check that no global constructor lives there
- `test/host/test_xl.cpp`: key exchange checked against upstream's ed25519, plus an end-to-end protocol test

### Changed
- Firmware renamed **Spectra-Cascadia**. `ver` now reports `Spectra-Cascadia v2.4.0`, and the default name for new nodes is `Spectra-XXXX`

## [2.3.1-cascadia] - 2026-10-11

### Changed
- Default advert timing: periodic zero-hop adverts off (was 2 min), flood advert every 83 h (was 47 h)
- Upgrades from older versions migrate the old defaults (2 min / 47 h) to the new ones; custom values are kept

## [2.3.0-cascadia] - 2026-10-11

### Added
- `powersaving on|off`: 16 MHz core clock chosen at boot (SystemClock_Config reads the saved flag)
- Battery voltage: VDD via VREFINT, or a PB0/PB1 divider (`battery.pin`, `battery.divider`); `get battery`
- 7-day, 30-minute battery and temperature history: `get telemetry.volt|temp [page]`
- Low-voltage cutoff with standby and automatic resume: `battery.cutoff`, `battery.resume`
- Advert echo guard (6 h), counted as `advguard` in `stats`
- Upstream-format `stats-core`, `stats-radio` (noise floor, last RSSI/SNR, airtime), `stats-packets`

### Changed
- sprintf replaced by a minimal formatter; `-fsingle-precision-constant` added (~4 KB freed)
- Extended settings block v2 (`SPX2`): retry and clock settings reset to defaults on upgrade from v2.2

## [2.2.0-cascadia] - 2026-10-10

### Added (after mikecarper/MeshCore Halo/Keymind)
- Echo-cancelled automatic retries for forwarded floods and direct packets: `retry.preset`, `direct.retry.*`, `flood.retry.*`
- Adaptive/escalating coding rate on direct retries; next-hop SNR gate from a recent-repeater table (`get recent.repeater`)
- Mesh clock sync by consensus of signed advert timestamps: `clock.sync.mesh`, `clock.sync.samples`, `clock.sync.drift`, `clock.sync.mesh now`, `get clock.sync.status`; can correct backwards
- `stats` shows retry and echo counts

### Changed
- Replaces v2.1's forward-only "median of 3 adverts" clock learning
- Clock journal now resumes from the last record written, not the largest
- Manual `time` suppresses mesh clock sync until reboot
- New settings stored after the v2.1 config in the same page; upgrade keeps existing settings and identity
- RadioLib LR-FHSS code stubbed out to fit the 62 KB image

## [2.1.0-cascadia] - 2026-10-09

### Added
- USB serial CLI with upstream MeshCore repeater syntax and reply style: `get/set name, lat, lon, radio, freq, tx, repeat, advert.interval, flood.advert.interval, flood.max*, txdelay, direct.txdelay, af, path.hash.mode, loop.detect, public.key, prv.key, role`, `region …`, `advert`, `clock`, `time`, `ver`, `board`, `reboot`, `erase`, `log start/stop`, `stats`
- Settings stored in a dedicated flash page; build flags are first-boot defaults only
- Random identity generated from radio noise on first boot (replaces UID-derived key and `IDENTITY_SALT`)
- Region allow/deny flood flags, `*` wildcard, default scope for own flood adverts

### Changed
- Packet logging is off by default (`log start`) so serial tools see clean replies
- Image capped at 62 KB; unused HAL modules disabled to fit
- SNR/RSSI read from raw packet status (drops double-precision math)
- Build flag names: `LORA_FREQ_KHZ`, `LORA_BW_HZ`, `PATH_HASH_MODE`, `DEFAULT_SCOPE`

## [2.0.0-cascadia] - 2026-10-09

Forwarding rewritten to follow upstream MeshCore (Mesh.cpp + simple_repeater).

### Fixed
- Zero-hop adverts were sent as FLOOD and relayed mesh-wide every 2 minutes; now DIRECT with an empty path
- TRANSPORT_FLOOD / TRANSPORT_DIRECT packets were mis-parsed (transport codes treated as path length) and corrupted on relay
- DIRECT packets were relayed when our hash appeared anywhere in the path, without removing ourselves or deduplicating (broken DMs/acks, possible ping-pong between two SPECTER nodes)
- Advert timestamps went backwards after every reboot and wrapped at 49.7 days of uptime
- Preamble length 8 → 16 to match upstream
- Blocking `delay()` before every transmit left the radio deaf

### Added
- Region scoping: `REGIONS` (forward scoped floods for these hashtag regions) and `ADVERT_SCOPE`
- Flood hop limits, loop detection, payload-type filter, Ed25519 verification of forwarded adverts
- ACK, multipart ACK and TRACE direct forwarding
- Listen-before-talk, randomized retransmit delays, TX queue, airtime budget
- Flash journal for monotonic time and last flood-advert time; clock learning from verified adverts
- All radio/advert/policy settings as build flags; US/Canada preset by default, `env:specter_eu` for the old settings
- TCXO auto-detect with plain-crystal fallback
- `IDENTITY_SALT` option
- WFI sleep between polls
- Host-side tests in `test/host/`

## [1.1.0]

### Added
- **Ed25519 cryptographic signing** of ADVERT packets using rweather/Crypto library
- Deterministic key derivation from STM32 UID via SHA256
- Non-blocking receive mode using `startReceive()` + IRQ flag polling
- Comprehensive documentation in `docs/development-notes.md`
- Critical bootloader baud rate documentation (57600, not 115200)

### Changed
- Node identity now based on Ed25519 public key (not pseudo-random)
- Node name: `SPECTER-XXXX` derived from UID (e.g., `SPECTER-1811`)
- Memory usage: 51.7 KB flash (39.5%), 3.1 KB RAM (15.3%)
- Updated `flash.sh` and `platformio.ini` with correct 57600 baud rate

### Fixed
- **CRITICAL**: MeshCore companions now recognize the repeater (Ed25519 validation)
- **CRITICAL**: Receive no longer blocks forever (DIO1=RADIOLIB_NC polling fix)
- Radio configuration matches Heltec companion: 869.618 MHz, SF8, BW62.5 kHz

### Documentation
- Added `docs/development-notes.md`, critical lessons learned
- Updated `docs/protocol.md`, Ed25519 signature format
- Updated `docs/flashing.md`, 57600 baud requirement
- Updated `README.md`, dependencies, troubleshooting, Ed25519 overview

---

## [1.0.0] - Initial Release

### Added
- Basic MeshCore flood repeater implementation
- SX1262 driver via RadioLib 7.6.0
- STM32F103C8T6 support with CH340 USB-serial
- Auto-generated node name from UID
- Dedup cache (64 slots, circular buffer)
- ADVERT generation (every 12 hours + initial at boot)
- Flood relay with hop limiting and loop prevention

### Known Issues (Fixed in v1.1.0)
- ADVERT signature field was all zeros → companions ignored the node
- Blocking `radio.receive()` with DIO1=RADIOLIB_NC → no packets received
- Documentation stated 115200 baud → bootloader actually requires 57600

---

## Development Timeline

### Phase 1: Initial Hardware Bringup
- Pin mapping discovery from original DX-LR30 AT firmware
- RadioLib integration with SPI1 + RF switch pins
- Serial console via USART1 (ENABLE_HWSERIAL1 flag required)

### Phase 2: MeshCore Protocol Implementation
- Packet header parsing (route_type, payload_type, hop_count)
- Path hash tracking for loop prevention
- Dedup cache to avoid relay storms
- ADVERT payload format (flags, node name)

### Phase 3: Radio Parameter Tuning
- Discovered companion was configured at 869.618 MHz (not default 869.525)
- Confirmed SF=8, BW=62.5 kHz, CR=4/5, SyncWord=0x12

### Phase 4: Critical Fixes
- **Day 1**: "0 repeaters" in app → suspected radio params
- **Day 2**: Radio params matched, still not visible → suspected signature validation
- **Day 3**: Implemented Ed25519 signing → **REPEATER APPEARED!**
- **Day 4**: Discovered receive blocking issue → switched to polling mode
- **Day 5**: Flash failures at 115200 → discovered 57600 baud requirement

### Phase 5: Documentation & Polish
- Created comprehensive docs/ directory
- Documented all critical discoveries in development-notes.md
- Updated README with troubleshooting and Ed25519 overview
- Added warnings about baud rate and polling mode throughout codebase

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- MAJOR version: Breaking protocol or hardware changes
- MINOR version: New features, backward-compatible
- PATCH version: Bug fixes, documentation updates

---

## Contributing

See `docs/development-notes.md` for critical implementation details.

When reporting issues, include:
- Firmware version (check serial output on boot)
- Companion device and firmware version
- Radio parameters in use
- Serial monitor output showing the issue
- Whether `stm32flash -b 57600` succeeded or failed

---

## License

MIT License, see LICENSE file for details.
