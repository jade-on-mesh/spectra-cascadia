# Changelog

All notable changes to Spectra-Cascadia (formerly SPECTER) firmware are documented here.

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
