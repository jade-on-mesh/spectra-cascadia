# SPECTER Native MeshCore Repeater for DX-LR30

> The DX-LR30 is a cheap Chinese LoRa shell device. MeshCore has no official
> firmware for STM32F103 + SX1262.

---

## v2.0 (CascadiaMesh fork): what changed and why

v1.1 relayed traffic but behaved in ways that hurt a shared regional mesh. v2.0
rewrites the forwarding logic to follow upstream MeshCore
(`src/Mesh.cpp` + `examples/simple_repeater`) as closely as a 20 KB-RAM,
no-filesystem part allows.

| Problem in v1.1 | v2.0 behaviour |
|---|---|
| The 2-minute "local" advert was sent as `FLOOD`, so every repeater relayed it mesh-wide | Zero-hop adverts are `DIRECT` with an empty path (upstream `sendZeroHop`). Flood adverts every 47 h, as upstream |
| `TRANSPORT_*` packets parsed without their 4 transport-code bytes → corrupted on relay | Parsed per `Packet::readFrom`; codes preserved |
| Region scoping ignored | Scoped floods forwarded only for regions in `REGIONS` (same HMAC check as `RegionMap::findMatch`). Own flood adverts can be scoped with `ADVERT_SCOPE` |
| `DIRECT` relayed if our hash appeared *anywhere* in the path, unchanged, no dedup → broken DMs, possible ping-pong | Forwarded only when we are the next hop, self removed from path, deduplicated. ACK / multipart ACK / TRACE handled as upstream |
| Every payload type flooded | Only types upstream floods; adverts signature-verified first; hop limits `flood.max`, `flood.max.unscoped`, `flood.max.advert` (8); loop detection |
| Blind 300–800 ms `delay()` with the radio deaf | Listen-before-talk on SX1262 preamble/header IRQs, randomized `tx_delay_factor` delays, TX queue with RX running, airtime budget |
| Advert timestamp = build time + uptime → goes backwards on every reboot (nodes ignore it as a replay); wraps at 49 days | Flash journal keeps time monotonic across reboots; clock pulled forward to the median of verified neighbour adverts |
| EU frequency hard-coded, preamble 8 | US/Canada preset by default, everything a build flag; preamble 16 as upstream; TCXO/crystal auto-detected |
| Busy-polling at 72 MHz | MCU sleeps (`WFI`) between polls |

Still **not** included (no room / no storage): CLI, remote admin login, telemetry,
private (`$`) regions, path-return / neighbour tables. It is a dumb, well-behaved
repeater: configure at build time, flash, deploy.

**Status:** compiles (≈60 KB of the 63 KB budget) and passes the host-side tests in
`test/host/` (forwarding rules, region codes cross-checked against a Python HMAC
reference, journal wear/rollover). **Not yet RF-tested on hardware.** Test on the bench
next to a known-good MeshCore repeater before deploying.

### Configuring (platformio.ini `build_flags`)

| Flag | Default | Meaning |
|---|---|---|
| `LORA_FREQ` / `LORA_BW` / `LORA_SF` / `LORA_CR` | 910.525 / 62.5 / 7 / 5 | Radio preset (`env:specter_eu` has the old EU values) |
| `LORA_TX_POWER` | 20 | dBm (DX-LR30 max 22) |
| `NODE_NAME_STR` | `SPECTER-XXXX` | Callsign, ≤ 23 chars |
| `NODE_LAT_I` / `NODE_LON_I` | — | Location × 1e6 |
| `REGIONS` | `""` | Comma list of hashtag regions whose scoped floods we forward. **Empty = scoped floods are dropped**, same as an unconfigured upstream repeater |
| `ADVERT_SCOPE` | — | Region to scope our own flood adverts to |
| `ALLOW_UNSCOPED_FLOOD` | 1 | Forward plain `FLOOD` packets (0 = wildcard deny) |
| `FLOOD_MAX` / `FLOOD_MAX_UNSCOPED` / `FLOOD_MAX_ADVERT` | 64 / 64 / 8 | Hop limits |
| `ADVERT_INTERVAL_MIN` / `FLOOD_ADVERT_INTERVAL_H` | 2 / 47 | Advert timing (upstream defaults) |
| `PATH_HASH_SIZE` | 1 | Path hash bytes for packets we originate |
| `TX_DELAY_FACTOR` / `DIRECT_TX_DELAY_FACTOR` / `AIRTIME_FACTOR` | 0.5 / 0.3 / 1.0 | Upstream repeater defaults |
| `IDENTITY_SALT` | old v1 salt | Secret mixed into the UID-derived key. The default keeps v1 identities but means anyone who learns a board's UID can derive its key; set a private salt for new deployments (changes the node's identity) |
| `FIXED_PRIVKEY_HEX` | — | Use an explicit key instead (see `tools/gen_identity.py`) |

The serial log prints the active preset, regions, and whether the radio came up in
TCXO or plain-crystal mode.

---

## What is this?

A fully autonomous **MeshCore flood repeater** running native C++ firmware on a
**DX-LR30** hardware module, an STM32F103C8T6 microcontroller paired with an
SX1262 LoRa transceiver. No Linux, no Python, no host PC required after flashing.
Plug in USB power and it joins the MeshCore network.

Each device automatically gets a unique node name (`SPECTER-XXXX`) derived from
its STM32 hardware UID. No configuration needed. To use a custom callsign, add
one line to `platformio.ini` (see [Customizing the node name](#customizing-the-node-name)).

```mermaid
flowchart LR
    classDef hw fill:#1e3a5f,stroke:#4a90d9,color:#e8f4fd
    classDef fw fill:#163316,stroke:#5cb85c,color:#e8f5e9
    classDef net fill:#3a1a1a,stroke:#d9534f,color:#fde8e8
    classDef io fill:#2d2000,stroke:#f0ad4e,color:#fff8e1

    USB(["USB Power\n5V · 500mA"]):::io

    subgraph DX30["  DX-LR30 Module  "]
        STM["STM32F103C8T6\n72 MHz Cortex-M3\n64 KB Flash · 20 KB RAM"]:::hw
        SX["SX1262\nLoRa Transceiver\n910.525 MHz"]:::hw
        STM -- "SPI1 + RF switch" --> SX
    end

    FW(["SPECTER\nFirmware"]):::fw
    ANT(["LoRa\nAntenna"]):::io
    NET["MeshCore\nFlood Mesh"]:::net

    USB --> STM
    FW -. "runs on" .-> STM
    SX --> ANT
    ANT <--> NET
```

---

## Hardware

![DX-LR30](docs/img/dx-lr30.jpg)

| Component | Part | Notes |
|-----------|------|-------|
| MCU | STM32F103C8T6 | 72 MHz Cortex-M3, 64KB Flash, 20KB RAM |
| Radio | SX1262 | Sub-GHz LoRa, up to +22 dBm |
| USB-Serial | CH340 | Bootloader access via physical BOOT0+RESET buttons |
| LED | PB11 | Active HIGH — 1 blink = RX · 2 fast blinks = relay · solid = ADVERT TX |

### Pin Map

```mermaid
flowchart LR
    classDef pin fill:#2d2000,stroke:#f0ad4e,color:#fff8e1
    classDef radio fill:#2a1a3a,stroke:#9b59b6,color:#f5eaff
    classDef serial fill:#163316,stroke:#5cb85c,color:#e8f5e9

    subgraph STM["STM32F103C8T6"]
        SPI["PA4 NSS\nPA5 SCK\nPA6 MISO\nPA7 MOSI"]:::pin
        CTRL["PA2 BUSY\nPA3 NRST"]:::pin
        RFPINS["PA0 TXEN\nPA1 RXEN"]:::pin
        USART["PA9 TX\nPA10 RX"]:::pin
    end

    SX(["SX1262\nLoRa Radio"]):::radio
    CH(["CH340G\nUSB-Serial"]):::serial

    SPI -- "SPI bus" --> SX
    CTRL -- "control" --> SX
    RFPINS -- "RF switch" --> SX
    USART -- "USART1" --> CH
```

> SPI bus: **SPI1** (PA5/PA6/PA7). Serial console: **USART1** (PA9/PA10).
> DIO1 is not exposed on the DX-LR30 module, RadioLib runs in **polling mode**.

---

## Firmware Architecture

```mermaid
flowchart TD
    classDef init fill:#1e3a5f,stroke:#4a90d9,color:#e8f4fd
    classDef loop fill:#163316,stroke:#5cb85c,color:#e8f5e9
    classDef radio fill:#2a1a3a,stroke:#9b59b6,color:#f5eaff
    classDef proto fill:#2d2000,stroke:#f0ad4e,color:#fff8e1
    classDef drop fill:#3a1a1a,stroke:#d9534f,color:#fde8e8

    BOOT([Power On]):::init
    ID["Identity Init\nUID → pubkey · hash"]:::init
    RADIO["Radio Init\n910.525 MHz · SF7 · BW62.5\nSyncWord=0x12 · 20 dBm"]:::init
    OK{Init OK?}:::init
    HALT(["⚠ Halt, LED blinks"]):::drop

    subgraph MAIN["── Main Loop ──"]
        ADV{ADVERT\ntimer?}:::loop
        BUILD["Build ADVERT\npubkey · name · flags"]:::proto
        TX1["TX ADVERT\nRF → TXEN"]:::radio
        RX["radio.receive\nRF → RXEN"]:::radio
        PKT{Packet\narrived?}:::loop
        PARSE["Parse header\nroute · hops · path"]:::proto
        RTYPE{route type?}:::proto
        DIRECT["DIRECT/TRANSPORT_DIRECT\nCheck hash in path"]:::proto
        INHASH{My hash\nin path?}:::proto
        RELAYD["TX unchanged"]:::radio
        HOP{hops ≥ 64?}:::drop
        DEDUP{Seen\nbefore?}:::drop
        OWN{My hash\nin path?}:::drop
        RELAY["Append my hash\nhops++"]:::proto
        TX2["TX relay\nRF → TXEN"]:::radio
    end

    BOOT --> ID --> RADIO --> OK
    OK -- No --> HALT
    OK -- Yes --> ADV
    ADV -- Yes --> BUILD --> TX1 --> ADV
    ADV -- No --> RX --> PKT
    PKT -- No --> ADV
    PKT -- Yes --> PARSE --> RTYPE
    RTYPE -- "FLOOD / TRANSPORT_FLOOD" --> HOP
    RTYPE -- "DIRECT / TRANSPORT_DIRECT" --> DIRECT
    DIRECT --> INHASH
    INHASH -- No --> ADV
    INHASH -- Yes --> RELAYD --> ADV
    HOP -- Yes --> ADV
    HOP -- No --> DEDUP
    DEDUP -- Yes --> ADV
    DEDUP -- No --> OWN
    OWN -- Yes --> ADV
    OWN -- No --> RELAY --> TX2 --> ADV
```

---

## MeshCore Protocol

SPECTER implements the **MeshCore v1 flood routing** protocol.

```mermaid
sequenceDiagram
    participant A as Node A (0xAB)
    participant S as SPECTER (0xF4)
    participant C as Node C (0xC3)

    Note over S: Boot complete
    S->>A: ADVERT · hops=0 · path=[] · name="SPECTER-A3F2"
    S->>C: ADVERT · hops=0 · path=[] · name="SPECTER-A3F2"

    Note over A: Node A sends a message
    A->>S: FLOOD · hops=1 · path=[AB] · payload
    Note over S: ✓ FLOOD route<br/>✓ not in dedup cache<br/>✓ 0xAB ≠ own hash 0xF4<br/>✓ hops 1 < 64
    S->>C: FLOOD · hops=2 · path=[AB·F4] · payload

    Note over A: Same packet re-sent
    A-->>S: FLOOD · hops=1 · path=[AB] · payload
    Note over S: ✗ Already in dedup cache → Drop
```

### Packet Header Format

```
Byte 0:  [ver(2)] [payload_type(4)] [route_type(2)]
           ↑                              ↑
           0x00              TRANSPORT_FLOOD = 0x00
                                     FLOOD = 0x01
                                    DIRECT = 0x02
                          TRANSPORT_DIRECT = 0x03

Byte 1:  [hash_size_code(2)] [hop_count(6)]

Bytes 2..N: path hashes (hop_count × hash_size bytes)
Bytes N..:  payload (ADVERT / MESSAGE / etc.)
```

### Routing Behaviour

| Route type | Value | SPECTER action |
|---|---|---|
| `TRANSPORT_FLOOD` | `0x00` | Relay only if the transport code matches a region in `REGIONS`; codes kept, own hash appended |
| `FLOOD` | `0x01` | Relay if `ALLOW_UNSCOPED_FLOOD`; own hash appended |
| `DIRECT` | `0x02` | Relay only if own hash is the **first** (next-hop) entry; own hash removed |
| `TRANSPORT_DIRECT` | `0x03` | Same as `DIRECT`, transport codes kept |

Floods also pass hop limits, loop detection, a payload-type check, dedup, and (for
adverts) Ed25519 verification. Direct packets are deduplicated too. See the v2.0
table above.

### Radio Configuration

| Parameter | Value | Why |
|-----------|-------|-----|
| Frequency | 910.525 MHz | MeshCore USA/Canada (Recommended) |
| Spreading Factor | SF7 | |
| Bandwidth | 62.5 kHz | Narrow preset |
| Coding Rate | 4/5 | |
| Preamble | 16 symbols | Matches upstream MeshCore |
| Sync Word | 0x12 | LoRa private network |
| TX Power | 20 dBm | Override with `LORA_TX_POWER` |
| CRC | on | |

`pio run -e specter_eu` builds the original EU/UK narrow settings (869.618 MHz, SF8, CR4/8, 14 dBm).

---

## Building

### Prerequisites

```bash
pip install platformio
# or: brew install platformio
```

### Dependencies

Managed automatically by PlatformIO via `lib_deps` in `platformio.ini`:

| Library | Version | Purpose |
|---------|---------|---------|
| [RadioLib](https://github.com/jgromes/RadioLib) | ^7.6.0 | SX1262 driver (polling mode, RADIOLIB_NC) |
| [rweather/Crypto](https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto) | ^0.4.0 | SHA256 + Ed25519 for deterministic key derivation and ADVERT signing |
| IWatchdog (STM32duino built-in) | 1.0.0 | Independent Watchdog — auto-reset on radio HALT or loop freeze |

No manual installation needed, `pio run` fetches them automatically.

### Build

```bash
cd dx-lr30-fw
pio run -e specter
# Output: .pio/build/specter/firmware.bin  (~50KB)
```

### Memory Usage

```
RAM:   ███░░░░░░░  29.6%  (6068 / 20480 bytes)
Flash: █████████░  92.9%  (59948 / 64512 bytes)
```

The image is capped at 63 KB (`board_upload.maximum_size`) because the last 1 KB page
of the first 64 KB holds the clock journal, so it works on genuine 64 KB C8 chips.

### Host tests

```bash
git clone https://github.com/rweather/arduinolibs
CRYPTO_DIR=$PWD/arduinolibs/libraries/Crypto ./test/host/run.sh
```

---

## Flashing

The DX-LR30's CH340 USB-serial chip does **not** support automatic bootloader
entry via DTR/RTS in software. Use the **physical buttons**.

```mermaid
sequenceDiagram
    participant You
    participant HW as DX-LR30
    participant PC as stm32flash

    You->>HW: 1. Hold BOOT0 button
    You->>HW: 2. Press RESET → release
    You->>HW: 3. Release BOOT0
    Note over HW: Bootloader active (LED stays ON)

    PC->>HW: Connect @ 115200 8E1
    HW-->>PC: ACK 0x79 · Chip ID 0x0410
    PC->>HW: Erase · Write 42 KB · Verify
    HW-->>PC: Verify OK ✓
    PC->>HW: Execute @ 0x08000000
    Note over HW: SPECTER starts
    HW->>You: Serial: "=== SPECTER MeshCore Repeater [SPECTER-XXXX] ==="
```

### Quick flash

```bash
./flash.sh            # build + flash (prompts you to enter bootloader)
./flash.sh --no-build # flash only
./flash.sh --monitor  # flash + open serial monitor
```

### Manual flash

```bash
# 1. Enter bootloader: hold BOOT0, press RESET, release BOOT0
# 2. Flash:
stm32flash \
  -w .pio/build/specter/firmware.bin \
  -v -R -b 57600 \
  /dev/ttyUSB0
```

> ⚠️ **CRITICAL:** Use `-b 57600` (not 115200) on this board. See [docs/development-notes.md](docs/development-notes.md#critical-stm32-bootloader-baud-rate) for why.

---

## Serial Monitor

Connect at **115200 8N1** on `/dev/ttyUSB0`. Press RESET to see startup:

```
=== SPECTER MeshCore Repeater v1.1.0 [SPECTER-A3F2] ===
Hash: 0xF4
Radio init... OK
ADVERT initial
ALIVE uptime=10s
ALIVE uptime=20s
RX RSSI=-87 SNR=7 len=110
Relay hop=2
Drop: dedup
ALIVE uptime=30s
```

> The node name (`SPECTER-A3F2`) and hash are unique per device.

```bash
# Quick monitor
python3 -m serial.tools.miniterm /dev/ttyUSB0 115200

# Or
./flash.sh --monitor
```

---

## Identity

SPECTER derives each node's identity from the **STM32 unique device ID**
(96-bit UID at `0x1FFFF7E8`). This guarantees a stable, unique identity
without EEPROM or external storage.

### Cryptographic Identity

Each node has a unique **Ed25519 keypair** derived deterministically:

```cpp
private_key = SHA256("SPECTER-MESHCORE-KEY-V1" || 96-bit_UID)
public_key  = Ed25519::derivePublicKey(private_key)
path_hash   = public_key[0]  // 1-byte routing hash
```

- **Deterministic**: Same keys on every boot (no storage needed)
- **Unique**: Factory-unique UID ensures different keys per chip
- **Secure**: Ed25519 provides 128-bit security level

### Node Name

Auto-generated from UID:
```cpp
name = "SPECTER-" + hex(uid[2] & 0xFFFF)  // e.g., "SPECTER-1811"
```

### ADVERT Signing

MeshCore companions **validate Ed25519 signatures** on ADVERT packets. SPECTER
signs every ADVERT:

```
signature = Ed25519.sign(private_key, public_key, pubkey || timestamp || appdata)
```

Without a valid signature, the repeater is silently ignored by the network.

**Library:** [rweather/Crypto](https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto) v0.4.0 (SHA256 + Ed25519)

---

## Customizing the node

Edit `platformio.ini` and add flags to `build_flags`:

```ini
build_flags =
    -D HAL_UART_MODULE_ENABLED
    -D ENABLE_HWSERIAL1
    -D RADIOLIB_STATIC_ONLY=1
    -O2
    -D NODE_NAME_STR=\"SPECTER-7419\"      # custom callsign
    -D NODE_LAT_I=51478700                  # latitude  × 1 000 000 (optional)
    -D NODE_LON_I=-3186700                  # longitude × 1 000 000 (optional)
```

### GPS coordinates

When `NODE_LAT_I` and `NODE_LON_I` are defined, the ADVERT includes
`FLAG_HAS_LOCATION` (`0x10`) and the coordinates as two `int32_t` values
(degrees × 10⁶). The node will appear on MeshCore map clients.

```
latitude  =  51.4787° N  →  NODE_LAT_I=51478700
longitude =  -3.1867° W  →  NODE_LON_I=-3186700
```

Omit both flags to send an ADVERT without GPS data.

Then rebuild and reflash. The auto-generated `SPECTER-XXXX` default name is used
when `NODE_NAME_STR` is absent.

---

## Project Structure

```
dx-lr30-fw/
├── platformio.ini           # Build config (ststm32, RadioLib, Crypto)
├── flash.sh                 # Build + flash helper script (uses 57600 baud)
├── flash_stm32.py           # Pure Python bootloader flasher (fallback)
├── src/
│   └── main.cpp             # Full firmware (~380 lines, Ed25519 + polling RX)
└── docs/
    ├── hardware.md          # Pin map, schematic notes, UID reference
    ├── protocol.md          # MeshCore packet format, Ed25519 signing
    ├── flashing.md          # Detailed flashing guide (57600 baud)
    └── development-notes.md # Critical lessons learned (baud rate, Ed25519, polling)
```

---

## Why This Matters

| | Official MeshCore | SPECTER |
|---|---|---|
| Hardware | Heltec / RAK / T-Beam | DX-LR30 (STM32F103 + SX1262) |
| OS required | None (native) | None (native) |
| Protocol | Full MeshCore v1 | Full MeshCore v1 flood |
| Cryptography | Ed25519 signing | Ed25519 signing (deterministic from UID) |
| Cost | $25–$60 | ~$8 |
| MCU Flash used | varies | 50KB / 128KB (38.5%) |
| Runs standalone | ✅ | ✅ |

The DX-LR30 was designed as a LoRa **AT-command shell** (similar to a Hayes
modem). There is no publicly documented native MeshCore port for this hardware.
This firmware implements the complete flood routing stack, dedup cache, hop
counting, path tracking, Ed25519 signing, and ADVERT generation.

---

## Documentation

### Quick Start
- [README.md](README.md), This file: overview, build, flash
- [docs/flashing.md](docs/flashing.md), Step-by-step flashing guide

### Technical Details
- [docs/hardware.md](docs/hardware.md), Pin assignments, bootloader specs, UID
- [docs/protocol.md](docs/protocol.md), MeshCore packet format, Ed25519 signing
- [docs/development-notes.md](docs/development-notes.md), **Critical lessons learned**

### Troubleshooting

**"Failed to init device" when flashing:**
→ Use `-b 57600` baud (not 115200). See [development-notes.md](docs/development-notes.md#critical-stm32-bootloader-baud-rate)

**Board stuck in fast LED blink (radio HALT):**
→ The IWDG watchdog auto-resets the board in ≤ 8 s and retries. Transient SX1262 SPI glitches recover without intervention. See [development-notes.md](docs/development-notes.md#independent-watchdog-iwdg)

**Repeater doesn't appear in MeshCore app:**
→ Verify Ed25519 signing is enabled and radio params match exactly. See [development-notes.md](docs/development-notes.md#ed25519-signature-requirement)

**"Listening..." prints once then silence:**
→ RadioLib polling mode issue. See [development-notes.md](docs/development-notes.md#radiolib-polling-mode-dio1-not-connected)

**Radio params mismatch:**
→ All params must match: frequency, SF, BW, CR, sync word. See [development-notes.md](docs/development-notes.md#radio-configuration-mismatch-symptoms)

---

## License

MIT License, see LICENSE file for details.

---

