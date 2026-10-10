/*
 * SPECTER — Native MeshCore Repeater for STM32F103C8T6 + SX1262 (DX-LR30)
 * Version: 2.0.0-cascadia
 *
 * Fork of MaliosDark/meshcore-specter-dx-lr30 (MIT). The forwarding rules
 * below follow upstream MeshCore's Mesh.cpp + simple_repeater as closely as a
 * 20 KB-RAM, no-filesystem target allows:
 *
 *   - Zero-hop adverts are sent DIRECT with an empty path (never flooded).
 *   - Flood adverts every FLOOD_ADVERT_INTERVAL_H hours (default 47, as upstream),
 *     optionally region-scoped via ADVERT_SCOPE.
 *   - TRANSPORT_* packets are parsed with their 4 bytes of transport codes.
 *     Scoped floods are forwarded only for regions listed in REGIONS
 *     (same HMAC transport-code check as upstream RegionMap::findMatch).
 *   - DIRECT packets are forwarded only when this node is the NEXT hop, with
 *     itself removed from the path, and deduplicated. TRACE is supported.
 *   - Flood hop limits (flood.max / unscoped / advert) and loop detection.
 *   - Only payload types upstream would forward are flooded.
 *   - Advert signatures are verified before forwarding.
 *   - Listen-before-talk using the SX1262 preamble/header IRQs, randomized
 *     retransmit delays (tx_delay_factor), and an airtime budget.
 *   - Advert timestamps never go backwards across reboots (flash journal), and
 *     the clock is pulled forward to the median of verified neighbor adverts.
 *   - MCU sleeps (WFI) between polls.
 *
 * Pin mapping (DX-LR30):
 *   SPI1 : SCK=PA5  MISO=PA6  MOSI=PA7
 *   SX1262: NSS=PA4  BUSY=PA2  NRST=PA3   (DIO1 not exposed → IRQ polling)
 *   RF switch: TXEN=PA0  RXEN=PA1
 *   LED  : PB11 (active HIGH)
 *   UART1: TX=PA9  RX=PA10  → CH340 USB @ 115200 8N1
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <SHA256.h>
#include <Ed25519.h>
#include <IWatchdog.h>

#define FW_VERSION "2.0.0-cascadia"

// ═════════════════════════════════════════════════════════════════════════════
//  Configuration — every value can be overridden with -D in platformio.ini
// ═════════════════════════════════════════════════════════════════════════════

// Radio. Defaults = MeshCore "USA/Canada (Recommended)" preset.
#ifndef LORA_FREQ
#define LORA_FREQ 910.525f
#endif
#ifndef LORA_BW
#define LORA_BW 62.5f
#endif
#ifndef LORA_SF
#define LORA_SF 7
#endif
#ifndef LORA_CR
#define LORA_CR 5
#endif
#ifndef LORA_TX_POWER
#define LORA_TX_POWER 20          // dBm; DX-LR30 max is 22
#endif
#ifndef LORA_PREAMBLE
#define LORA_PREAMBLE 16          // upstream MeshCore uses 16
#endif
#ifndef LORA_SYNC
#define LORA_SYNC 0x12            // RADIOLIB_SX126X_SYNC_WORD_PRIVATE
#endif
#ifndef LORA_TCXO_VOLTAGE
#define LORA_TCXO_VOLTAGE 1.6f    // retried at 0.0 (plain crystal) if init fails
#endif

// Adverts
#ifndef ADVERT_INTERVAL_MIN
#define ADVERT_INTERVAL_MIN 2     // zero-hop advert interval (upstream default); 0 = off
#endif
#ifndef FLOOD_ADVERT_INTERVAL_H
#define FLOOD_ADVERT_INTERVAL_H 47
#endif
#ifndef PATH_HASH_SIZE
#define PATH_HASH_SIZE 1          // 1..3 bytes per hop for packets we originate
#endif
// #define ADVERT_SCOPE "se-wa"   // send flood adverts scoped to this region

// Forwarding policy
#ifndef FLOOD_MAX
#define FLOOD_MAX 64
#endif
#ifndef FLOOD_MAX_UNSCOPED
#define FLOOD_MAX_UNSCOPED 64
#endif
#ifndef FLOOD_MAX_ADVERT
#define FLOOD_MAX_ADVERT 8
#endif
#ifndef ALLOW_UNSCOPED_FLOOD
#define ALLOW_UNSCOPED_FLOOD 1    // forward plain (un-scoped) FLOOD packets
#endif
#ifndef REGIONS
#define REGIONS ""                // e.g. "se-wa,seattle" — scoped floods to forward
#endif
#ifndef TX_DELAY_FACTOR
#define TX_DELAY_FACTOR 0.5f
#endif
#ifndef DIRECT_TX_DELAY_FACTOR
#define DIRECT_TX_DELAY_FACTOR 0.3f
#endif
#ifndef AIRTIME_FACTOR
#define AIRTIME_FACTOR 1.0f       // duty cycle = 1/(1+factor) → 50%
#endif
#ifndef VERIFY_ADVERTS
#define VERIFY_ADVERTS 1          // check Ed25519 before forwarding adverts
#endif

// Clock
#ifndef LEARN_TIME
#define LEARN_TIME 1              // pull clock forward from verified neighbor adverts
#endif
#ifndef PERSIST_INTERVAL_MIN
#define PERSIST_INTERVAL_MIN 15   // flash journal write interval
#endif

// Identity
#ifndef IDENTITY_SALT
#define IDENTITY_SALT "SPECTER-MESHCORE-KEY-V1"   // keep default to preserve old identities
#endif

// Misc
#ifndef HEARTBEAT_S
#define HEARTBEAT_S 60
#endif
#ifndef LED_ENABLE
#define LED_ENABLE 1
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  Hardware
// ═════════════════════════════════════════════════════════════════════════════
#define PIN_NSS   PA4
#define PIN_DIO1  RADIOLIB_NC
#define PIN_NRST  PA3
#define PIN_BUSY  PA2
#define PIN_TXEN  PA0
#define PIN_RXEN  PA1
#define PIN_LED   PB11

// Flash journal: last 1 KB page of the first 64 KB (safe on genuine 64 KB parts).
// platformio.ini caps the image at 63 KB so code can never overlap it.
#ifndef JOURNAL_ADDR
#define JOURNAL_ADDR  0x0800FC00UL
#endif
#define JOURNAL_SIZE  1024U
#ifndef UID_BASE
#define UID_BASE      0x1FFFF7E8UL    // 96-bit factory unique ID
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  MeshCore protocol constants (src/Packet.h, src/MeshCore.h)
// ═════════════════════════════════════════════════════════════════════════════
#define ROUTE_TRANSPORT_FLOOD   0x00
#define ROUTE_FLOOD             0x01
#define ROUTE_DIRECT            0x02
#define ROUTE_TRANSPORT_DIRECT  0x03

#define PT_REQ        0x00
#define PT_RESPONSE   0x01
#define PT_TXT_MSG    0x02
#define PT_ACK        0x03
#define PT_ADVERT     0x04
#define PT_GRP_TXT    0x05
#define PT_GRP_DATA   0x06
#define PT_ANON_REQ   0x07
#define PT_PATH       0x08
#define PT_TRACE      0x09
#define PT_MULTIPART  0x0A
#define PT_CONTROL    0x0B
#define PT_RAW_CUSTOM 0x0F

#define MAX_PATH_SIZE        64
#define MAX_PKT              256
#define MAX_ADVERT_DATA_SIZE 32
#define CIPHER_MAC_SIZE      2

#define ADV_TYPE_REPEATER 0x02
#define ADV_LATLON_MASK   0x10
#define ADV_NAME_MASK     0x80

// ═════════════════════════════════════════════════════════════════════════════
//  Small utilities
// ═════════════════════════════════════════════════════════════════════════════
static uint32_t rng_state = 0x9E3779B9;
static uint32_t rnd(void) {                 // xorshift32
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}
static uint32_t rnd_range(uint32_t lo, uint32_t hi) {   // [lo, hi)
    return (hi <= lo) ? lo : lo + (rnd() % (hi - lo));
}

static void led(bool on) {
#if LED_ENABLE
    digitalWrite(PIN_LED, on ? HIGH : LOW);
#else
    (void)on;
#endif
}
static void led_blink(uint8_t n, uint16_t ms) {
#if LED_ENABLE
    for (uint8_t i = 0; i < n; i++) { led(true); delay(ms); led(false); if (i + 1 < n) delay(ms); }
#else
    (void)n; (void)ms;
#endif
}

// ═════════════════════════════════════════════════════════════════════════════
//  Identity
// ═════════════════════════════════════════════════════════════════════════════
#ifdef NODE_NAME_STR
static const char node_name[] = NODE_NAME_STR;
#else
static char node_name[14];
#endif
static uint8_t own_privkey[32];
static uint8_t own_pubkey[32];

#ifdef FIXED_PRIVKEY_HEX
static void hex2bin(const char* hex, uint8_t* out, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t hi = hex[2*i], lo = hex[2*i+1];
        hi = (hi >= 'a') ? hi-'a'+10 : (hi >= 'A') ? hi-'A'+10 : hi-'0';
        lo = (lo >= 'a') ? lo-'a'+10 : (lo >= 'A') ? lo-'A'+10 : lo-'0';
        out[i] = (hi << 4) | lo;
    }
}
#endif

static void identity_init(void) {
    const uint32_t uid[3] = {
        ((volatile uint32_t*)UID_BASE)[0],
        ((volatile uint32_t*)UID_BASE)[1],
        ((volatile uint32_t*)UID_BASE)[2],
    };
    rng_state ^= uid[0] ^ (uid[1] << 7) ^ (uid[2] << 13);
#ifndef NODE_NAME_STR
    snprintf(node_name, sizeof(node_name), "SPECTER-%04X", (unsigned)(uid[2] & 0xFFFF));
#endif
#ifdef FIXED_PRIVKEY_HEX
    hex2bin(FIXED_PRIVKEY_HEX, own_privkey, 32);
#else
    SHA256 sha;
    sha.reset();
    sha.update(IDENTITY_SALT, sizeof(IDENTITY_SALT) - 1);
    sha.update((const uint8_t*)uid, 12);
    sha.finalize(own_privkey, 32);
#endif
    Ed25519::derivePublicKey(own_pubkey, own_privkey);
}

static inline bool is_own_hash(const uint8_t* h, uint8_t len) {
    return memcmp(h, own_pubkey, len) == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Regions (transport codes) — mirrors TransportKey::calcTransportCode
// ═════════════════════════════════════════════════════════════════════════════
#define MAX_REGIONS 8
static uint8_t region_keys[MAX_REGIONS][16];
static char    region_names[MAX_REGIONS][24];
static uint8_t num_regions = 0;

// Key for a public hashtag region = first 16 bytes of SHA256("#name").
static void region_key_for(const char* name, uint8_t key[16]) {
    char tmp[26];
    if (name[0] == '#') snprintf(tmp, sizeof(tmp), "%s", name);
    else                snprintf(tmp, sizeof(tmp), "#%s", name);
    uint8_t full[32];
    SHA256 sha;
    sha.reset();
    sha.update(tmp, strlen(tmp));
    sha.finalize(full, 32);
    memcpy(key, full, 16);
}

static void regions_init(void) {
    const char* p = REGIONS;
    while (*p && num_regions < MAX_REGIONS) {
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        char name[24]; int n = 0;
        while (*p && *p != ',' && *p != ' ' && n < (int)sizeof(name) - 1) name[n++] = *p++;
        name[n] = 0;
        while (*p && *p != ',') p++;
        if (name[0] == '$') continue;       // private regions need a keystore — unsupported
        const char* bare = (name[0] == '#') ? name + 1 : name;
        strcpy(region_names[num_regions], bare);
        region_key_for(name, region_keys[num_regions]);
        num_regions++;
    }
}

static uint16_t transport_code(const uint8_t key[16], uint8_t ptype,
                               const uint8_t* payload, int plen) {
    SHA256 sha;
    sha.resetHMAC(key, 16);
    sha.update(&ptype, 1);
    sha.update(payload, plen);
    uint8_t out[2];
    sha.finalizeHMAC(key, 16, out, 2);
    uint16_t code;
    memcpy(&code, out, 2);
    if (code == 0) code++;
    else if (code == 0xFFFF) code--;
    return code;
}

// Returns region index, or -1 if this scoped packet belongs to no configured region.
static int region_match(uint16_t code0, uint8_t ptype, const uint8_t* payload, int plen) {
    for (int i = 0; i < num_regions; i++) {
        if (transport_code(region_keys[i], ptype, payload, plen) == code0) return i;
    }
    return -1;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Clock — monotonic across reboots, learns forward from verified adverts
// ═════════════════════════════════════════════════════════════════════════════
static bool is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static uint32_t build_unix_ts(void) {
    const char* d = __DATE__;   // "Oct  9 2026"
    const char* t = __TIME__;   // "18:30:00"
    static const char mn[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    int month = 1;
    for (int m = 0; m < 12; m++)
        if (d[0]==mn[m*3] && d[1]==mn[m*3+1] && d[2]==mn[m*3+2]) { month = m+1; break; }
    int day  = (d[4]==' ' ? 0 : d[4]-'0')*10 + (d[5]-'0');
    int year = (d[7]-'0')*1000+(d[8]-'0')*100+(d[9]-'0')*10+(d[10]-'0');
    int hour = (t[0]-'0')*10+(t[1]-'0');
    int min  = (t[3]-'0')*10+(t[4]-'0');
    int sec  = (t[6]-'0')*10+(t[7]-'0');
    uint32_t days = 0;
    for (int y = 1970; y < year; y++) days += is_leap(y) ? 366 : 365;
    static const uint8_t md[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    for (int m = 1; m < month; m++) days += md[m-1] + ((m == 2 && is_leap(year)) ? 1 : 0);
    days += day - 1;
    return days * 86400UL + hour*3600UL + min*60UL + sec;
}

static uint32_t clk_base = 0;       // epoch seconds at uptime 0
static uint32_t clk_uptime_s = 0;   // wrap-safe uptime in seconds
static uint32_t clk_last_ms = 0;
static uint32_t clk_ms_accum = 0;

static uint32_t uptime_s(void) {
    uint32_t now = millis();
    clk_ms_accum += now - clk_last_ms;    // unsigned math survives the 49.7-day wrap
    clk_last_ms = now;
    while (clk_ms_accum >= 1000) { clk_ms_accum -= 1000; clk_uptime_s++; }
    return clk_uptime_s;
}
static uint32_t clock_now(void) { return clk_base + uptime_s(); }

// ── Flash journal ───────────────────────────────────────────────────────────
// Records of 3 words: { now_ts, last_flood_advert_ts, ~(now_ts ^ last_flood) }.
// Appended until the page is full, then the page is erased (≈1 erase per
// 85 writes → decades of endurance at a 15-minute interval).
#define JREC_WORDS 3
#define JREC_COUNT (JOURNAL_SIZE / (JREC_WORDS * 4))

static uint32_t j_last_flood_ts = 0;
static int      j_next_slot = 0;

static bool journal_read(uint32_t* ts, uint32_t* flood_ts) {
    bool found = false;
    j_next_slot = 0;
    for (int i = 0; i < (int)JREC_COUNT; i++) {
        const volatile uint32_t* r = (const volatile uint32_t*)(JOURNAL_ADDR + i * JREC_WORDS * 4);
        if (r[0] == 0xFFFFFFFFUL && r[1] == 0xFFFFFFFFUL && r[2] == 0xFFFFFFFFUL) break;
        j_next_slot = i + 1;
        if (r[2] == ~(r[0] ^ r[1])) {             // skip torn writes
            if (!found || r[0] >= *ts) { *ts = r[0]; *flood_ts = r[1]; found = true; }
        }
    }
    return found;
}

static void journal_write(uint32_t ts, uint32_t flood_ts) {
    HAL_FLASH_Unlock();
    if (j_next_slot >= (int)JREC_COUNT) {
        FLASH_EraseInitTypeDef er = {};
        er.TypeErase   = FLASH_TYPEERASE_PAGES;
        er.PageAddress = JOURNAL_ADDR;
        er.NbPages     = 1;
        uint32_t err = 0;
        IWatchdog.reload();
        HAL_FLASHEx_Erase(&er, &err);
        j_next_slot = 0;
    }
    uint32_t addr = JOURNAL_ADDR + j_next_slot * JREC_WORDS * 4;
    uint32_t w[3] = { ts, flood_ts, ~(ts ^ flood_ts) };
    for (int i = 0; i < 3; i++) HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr + i * 4, w[i]);
    HAL_FLASH_Lock();
    j_next_slot++;
}

static void clock_init(void) {
    uint32_t stored = 0, flood = 0;
    uint32_t start = build_unix_ts();
    if (journal_read(&stored, &flood)) {
        // We may have advertised up to one persist interval past the last record.
        uint32_t resume = stored + PERSIST_INTERVAL_MIN * 60UL + 1;
        if (resume > start) start = resume;
        j_last_flood_ts = flood;
    }
    clk_last_ms = millis();
    clk_base = start;
    journal_write(clock_now(), j_last_flood_ts);
}

#if LEARN_TIME
// Median of recent verified-advert timestamps from distinct senders.
#define TSAMPLES 5
static uint32_t ts_samples[TSAMPLES];
static uint8_t  ts_sender[TSAMPLES][4];
static uint8_t  ts_count = 0, ts_head = 0;

static void clock_learn(const uint8_t* pubkey, uint32_t ts) {
    bool known = false;
    for (int i = 0; i < ts_count; i++)
        if (memcmp(ts_sender[i], pubkey, 4) == 0) { ts_samples[i] = ts; known = true; break; }
    if (!known) {
        memcpy(ts_sender[ts_head], pubkey, 4);
        ts_samples[ts_head] = ts;
        ts_head = (ts_head + 1) % TSAMPLES;
        if (ts_count < TSAMPLES) ts_count++;
    }
    if (ts_count < 3) return;

    uint32_t s[TSAMPLES];
    memcpy(s, ts_samples, sizeof(s));
    for (int i = 1; i < ts_count; i++)            // insertion sort
        for (int j = i; j > 0 && s[j-1] > s[j]; j--) { uint32_t t = s[j]; s[j] = s[j-1]; s[j-1] = t; }
    uint32_t median = s[ts_count / 2];
    uint32_t now = clock_now();
    // Only move forward, and ignore anything implausibly far ahead (10 years).
    if (median > now + 120 && median < build_unix_ts() + 315360000UL) {
        clk_base += median - now;
        Serial1.print("Clock advanced to "); Serial1.println(clock_now());
        journal_write(clock_now(), j_last_flood_ts);
    }
}
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  Dedup table — 8-byte prefix of SHA256(type [‖ path_len for TRACE] ‖ payload)
// ═════════════════════════════════════════════════════════════════════════════
#define DEDUP_SIZE 128
static uint8_t dedup_buf[DEDUP_SIZE][8];
static uint8_t dedup_head = 0;

static void packet_hash(uint8_t out[8], uint8_t ptype, uint8_t path_len_byte,
                        const uint8_t* payload, int plen) {
    SHA256 sha;
    sha.reset();
    sha.update(&ptype, 1);
    if (ptype == PT_TRACE) { uint16_t pl = path_len_byte; sha.update(&pl, 2); }
    sha.update(payload, plen);
    uint8_t full[32];
    sha.finalize(full, 32);
    memcpy(out, full, 8);
}
static bool was_seen(const uint8_t h[8]) {
    for (int i = 0; i < DEDUP_SIZE; i++) if (memcmp(dedup_buf[i], h, 8) == 0) return true;
    return false;
}
static void mark_seen(const uint8_t h[8]) {
    memcpy(dedup_buf[dedup_head], h, 8);
    dedup_head = (dedup_head + 1) % DEDUP_SIZE;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Radio
// ═════════════════════════════════════════════════════════════════════════════
SX1262 radio = new Module(PIN_NSS, PIN_DIO1, PIN_NRST, PIN_BUSY, SPI);

static float    tcxo_used = LORA_TCXO_VOLTAGE;
static uint32_t preamble_ms = 0;     // how long a preamble-only detection may block TX
static uint32_t max_pkt_ms = 0;      // longest possible packet on air

static uint32_t airtime_ms(int len) {
    return (uint32_t)(radio.getTimeOnAir(len) / 1000UL) + 1;
}

static bool radio_init(void) {
    SPI.begin();
    int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, LORA_SYNC,
                            LORA_TX_POWER, LORA_PREAMBLE, tcxo_used, false);
    if (state == RADIOLIB_ERR_SPI_CMD_FAILED || state == RADIOLIB_ERR_SPI_CMD_INVALID) {
        tcxo_used = 0.0f;               // board has a plain crystal, not a TCXO
        state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, LORA_SYNC,
                            LORA_TX_POWER, LORA_PREAMBLE, tcxo_used, false);
    }
    if (state != RADIOLIB_ERR_NONE) {
        Serial1.print(" FAILED: "); Serial1.println(state);
        return false;
    }
    radio.setRfSwitchPins(PIN_RXEN, PIN_TXEN);
    radio.setCRC(1);
    float sym_ms = (float)(1UL << LORA_SF) / LORA_BW;          // BW in kHz → ms
    preamble_ms = (uint32_t)((LORA_PREAMBLE + 4.25f) * sym_ms * 1.5f) + 5;
    max_pkt_ms  = airtime_ms(255) + 50;
    return true;
}

static void rx_start(void) {
    radio.startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF,
                       RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED),
                       RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
}

// Listen-before-talk: same logic as upstream CustomSX1262::isReceiving().
static uint32_t activity_at = 0;
static bool     header_seen = false;
#define IRQ_ACTIVITY_CLEAR (RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | \
                            RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID)

static bool channel_busy(uint32_t irq) {
    uint32_t now = millis();
    if (irq & RADIOLIB_SX126X_IRQ_HEADER_ERR) {
        radio.clearIrqFlags(IRQ_ACTIVITY_CLEAR);
        activity_at = 0; header_seen = false;
        return false;
    }
    if (!(irq & RADIOLIB_SX126X_IRQ_HEADER_VALID) && header_seen) {
        activity_at = 0; header_seen = false;
        return false;
    }
    if (irq & RADIOLIB_SX126X_IRQ_HEADER_VALID) {
        if (!header_seen) { header_seen = true; activity_at = now; }
        if (now - activity_at > max_pkt_ms) {
            radio.clearIrqFlags(IRQ_ACTIVITY_CLEAR);
            activity_at = 0; header_seen = false;
            return false;
        }
        return true;
    }
    if (irq & RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED) {
        if (activity_at == 0) activity_at = now;
        if (now - activity_at > preamble_ms) {
            radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED);
            activity_at = 0;
            return false;
        }
        return true;
    }
    activity_at = 0; header_seen = false;
    return false;
}

// ── Airtime budget (Dispatcher::updateTxBudget, 1-hour window) ──────────────
#define DUTY_CYCLE (1.0f / (1.0f + (AIRTIME_FACTOR)))
static const uint32_t budget_max = (uint32_t)(3600000UL * DUTY_CYCLE);
static uint32_t budget_ms = 0;
static uint32_t budget_updated = 0;

static void budget_refill(void) {
    uint32_t now = millis();
    uint32_t add = (uint32_t)((now - budget_updated) * DUTY_CYCLE);
    budget_updated = now;
    budget_ms = (budget_ms + add > budget_max) ? budget_max : budget_ms + add;
}

static bool transmit(const uint8_t* buf, int len) {
    uint32_t toa = airtime_ms(len);
    radio.standby();
    led(true);
    int state = radio.startTransmit(buf, len);
    if (state == RADIOLIB_ERR_NONE) {
        uint32_t t0 = millis();
        while (!(radio.getIrqFlags() & RADIOLIB_SX126X_IRQ_TX_DONE)) {
            if (millis() - t0 > toa * 2 + 200) { state = RADIOLIB_ERR_TX_TIMEOUT; break; }
            IWatchdog.reload();
        }
    }
    radio.finishTransmit();
    led(false);
    budget_ms = (budget_ms > toa) ? budget_ms - toa : 0;
    activity_at = 0; header_seen = false;
    rx_start();
    if (state != RADIOLIB_ERR_NONE) { Serial1.print("TX err: "); Serial1.println(state); }
    return state == RADIOLIB_ERR_NONE;
}

// ═════════════════════════════════════════════════════════════════════════════
//  TX queue — delayed, prioritized retransmits (RX keeps running while waiting)
// ═════════════════════════════════════════════════════════════════════════════
#define TXQ_SIZE 6
struct TxItem {
    bool     used;
    uint8_t  pri;          // lower = sooner (0 = direct-routed traffic)
    uint8_t  len;
    uint32_t due;
    uint32_t busy_since;   // when LBT first deferred it
    uint8_t  buf[MAX_PKT];
};
static TxItem txq[TXQ_SIZE];

static bool txq_push(const uint8_t* buf, int len, uint8_t pri, uint32_t delay_ms) {
    if (len <= 0) return false;
    int slot = -1;
    for (int i = 0; i < TXQ_SIZE; i++) if (!txq[i].used) { slot = i; break; }
    if (slot < 0) {                                  // full: evict the lowest-priority entry
        for (int i = 0; i < TXQ_SIZE; i++)
            if (txq[i].pri > pri && (slot < 0 || txq[i].pri > txq[slot].pri)) slot = i;
        if (slot < 0) { Serial1.println("  txq full"); return false; }
    }
    TxItem& t = txq[slot];
    t.used = true; t.pri = pri; t.len = (uint8_t)len;
    t.due = millis() + delay_ms; t.busy_since = 0;
    memcpy(t.buf, buf, len);
    return true;
}

static uint32_t stat_rx = 0, stat_fwd = 0, stat_drop = 0, stat_tx = 0, stat_lbt = 0;

static void txq_service(uint32_t irq) {
    uint32_t now = millis();
    int best = -1;
    for (int i = 0; i < TXQ_SIZE; i++) {
        if (!txq[i].used || (int32_t)(now - txq[i].due) < 0) continue;
        if (best < 0 || txq[i].pri < txq[best].pri ||
            (txq[i].pri == txq[best].pri && (int32_t)(txq[i].due - txq[best].due) < 0)) best = i;
    }
    if (best < 0) return;
    TxItem& t = txq[best];

    if (channel_busy(irq)) {
        if (t.busy_since == 0) t.busy_since = now;
        if (now - t.busy_since < 4000) {             // upstream getCADFailMaxDuration()
            t.due = now + rnd_range(1, 5) * 120;     // upstream getCADFailRetryDelay()
            stat_lbt++;
            return;
        }
    }
    budget_refill();
    uint32_t toa = airtime_ms(t.len);
    if (budget_ms < toa / 2) {                       // MIN_TX_BUDGET_AIRTIME_DIV
        t.due = now + (uint32_t)((toa / 2 - budget_ms) / DUTY_CYCLE) + 1;
        return;
    }
    if (transmit(t.buf, t.len)) stat_tx++;
    t.used = false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Packet parsing (Packet::readFrom)
// ═════════════════════════════════════════════════════════════════════════════
struct Pkt {
    uint8_t        header, route, ptype;
    bool           has_tc;
    uint16_t       tc[2];
    uint8_t        path_len;     // raw wire byte: [hash_size-1 : 2][count : 6]
    uint8_t        hash_size, hash_count;
    const uint8_t* path;
    const uint8_t* payload;
    int            payload_len;
};

static bool parse(const uint8_t* d, int len, Pkt& p) {
    int i = 0;
    if (len < 3) return false;
    p.header = d[i++];
    p.route  = p.header & 0x03;
    p.ptype  = (p.header >> 2) & 0x0F;
    p.has_tc = (p.route == ROUTE_TRANSPORT_FLOOD || p.route == ROUTE_TRANSPORT_DIRECT);
    if (p.has_tc) {
        if (len < 7) return false;
        memcpy(&p.tc[0], d + i, 2); i += 2;
        memcpy(&p.tc[1], d + i, 2); i += 2;
    } else {
        p.tc[0] = p.tc[1] = 0;
    }
    p.path_len   = d[i++];
    p.hash_size  = (p.path_len >> 6) + 1;
    p.hash_count = p.path_len & 0x3F;
    if (p.hash_size == 4) return false;                              // reserved
    int pbytes = p.hash_count * p.hash_size;
    if (pbytes > MAX_PATH_SIZE) return false;
    p.path = d + i; i += pbytes;
    if (i >= len) return false;                                      // no payload
    p.payload = d + i;
    p.payload_len = len - i;
    return true;
}

// Serialize a packet with an explicit header/path (Packet::writeTo).
static int build(uint8_t* out, uint8_t header, const uint16_t* tc,
                 uint8_t path_len, const uint8_t* path, int path_bytes,
                 const uint8_t* payload, int plen) {
    int i = 0;
    out[i++] = header;
    uint8_t route = header & 0x03;
    if (route == ROUTE_TRANSPORT_FLOOD || route == ROUTE_TRANSPORT_DIRECT) {
        memcpy(out + i, &tc[0], 2); i += 2;
        memcpy(out + i, &tc[1], 2); i += 2;
    }
    out[i++] = path_len;
    if (path_bytes) { memcpy(out + i, path, path_bytes); i += path_bytes; }
    if (i + plen > 255) return -1;                                   // MAX_TRANS_UNIT
    memcpy(out + i, payload, plen); i += plen;
    return i;
}

static uint32_t delay_for(const Pkt& p, float factor) {
    uint32_t t = (uint32_t)(airtime_ms(p.hash_count * p.hash_size + p.payload_len + 2) * factor);
    return rnd_range(0, 5 * t + 1);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Advert verification (+ clock learning)
// ═════════════════════════════════════════════════════════════════════════════
static bool advert_verify(const uint8_t* payload, int plen) {
    if (plen < 32 + 4 + 64) return false;
    if (memcmp(payload, own_pubkey, 32) == 0) return false;   // our own advert echoed back
    int app_len = plen - 100;
    if (app_len > MAX_ADVERT_DATA_SIZE) app_len = MAX_ADVERT_DATA_SIZE;
    uint8_t msg[32 + 4 + MAX_ADVERT_DATA_SIZE];
    memcpy(msg, payload, 36);
    if (app_len > 0) memcpy(msg + 36, payload + 100, app_len);
    IWatchdog.reload();
    if (!Ed25519::verify(payload + 36, payload, msg, 36 + app_len)) return false;
#if LEARN_TIME
    uint32_t ts;
    memcpy(&ts, payload + 32, 4);
    clock_learn(payload, ts);
#endif
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Forwarding (Mesh::onRecvPacket + simple_repeater::allowPacketForward)
// ═════════════════════════════════════════════════════════════════════════════
static uint8_t out_buf[MAX_PKT];

// DIRECT / TRANSPORT_DIRECT
static const char* handle_direct(const Pkt& p, int8_t snr4) {
    uint8_t h[8];

    if (p.ptype == PT_TRACE) {
        if (p.path_len >= MAX_PATH_SIZE || p.payload_len < 9) return "trace bad";
        uint8_t flags   = p.payload[8];
        uint8_t path_sz = flags & 0x03;
        int     tlen    = p.payload_len - 9;
        uint16_t offset = (uint16_t)p.path_len << path_sz;
        if (offset >= tlen) return "trace end";
        if (offset + (1 << path_sz) > tlen) return "trace bad";
        if (!is_own_hash(p.payload + 9 + offset, 1 << path_sz)) return "trace not ours";
        packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
        if (was_seen(h)) return "dedup";
        mark_seen(h);
        uint8_t newpath[MAX_PATH_SIZE];
        memcpy(newpath, p.path, p.path_len);
        newpath[p.path_len] = (uint8_t)snr4;               // TRACE path carries SNRs
        int n = build(out_buf, p.header, p.tc, p.path_len + 1, newpath, p.path_len + 1,
                      p.payload, p.payload_len);
        if (n < 0) return "too big";
        txq_push(out_buf, n, 5, delay_for(p, DIRECT_TX_DELAY_FACTOR));
        return NULL;
    }

    if (p.ptype == PT_CONTROL && (p.payload[0] & 0x80)) return "zero-hop control";
    if (p.hash_count == 0) {
#if LEARN_TIME
        if (p.ptype == PT_ADVERT) {                        // neighbor's zero-hop advert
            packet_hash(h, p.ptype, 0, p.payload, p.payload_len);
            if (!was_seen(h)) { mark_seen(h); advert_verify(p.payload, p.payload_len); }
        }
#endif
        return "zero-hop";
    }
    if (!is_own_hash(p.path, p.hash_size)) return "not next hop";

    // Remove ourselves from the front of the path (Mesh::removeSelfFromPath).
    uint8_t new_path_len = (p.path_len & 0xC0) | ((p.hash_count - 1) & 0x3F);
    const uint8_t* rest  = p.path + p.hash_size;
    int rest_bytes       = (p.hash_count - 1) * p.hash_size;
    const uint8_t hdr_ack = (PT_ACK << 2) | ROUTE_DIRECT;

    if (p.ptype == PT_MULTIPART) {                         // Mesh::forwardMultipartDirect
        if (p.payload_len < 5 || (p.payload[0] & 0x0F) != PT_ACK) return "multipart";
        uint8_t remaining = p.payload[0] >> 4;
        packet_hash(h, PT_ACK, 0, p.payload + 1, p.payload_len - 1);
        if (was_seen(h)) return "dedup";
        mark_seen(h);
        int n = build(out_buf, hdr_ack, p.tc, new_path_len, rest, rest_bytes,
                      p.payload + 1, p.payload_len - 1);
        if (n < 0) return "too big";
        txq_push(out_buf, n, 0, ((uint32_t)remaining + 1) * 300);
        return NULL;
    }

    packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
    if (was_seen(h)) return "dedup";
    mark_seen(h);

    if (p.ptype == PT_ACK) {                               // routeDirectRecvAcks: plain DIRECT ACK
        int n = build(out_buf, hdr_ack, p.tc, new_path_len, rest, rest_bytes,
                      p.payload, p.payload_len);
        if (n < 0) return "too big";
        txq_push(out_buf, n, 0, 0);
        return NULL;
    }

    int n = build(out_buf, p.header, p.tc, new_path_len, rest, rest_bytes, p.payload, p.payload_len);
    if (n < 0) return "too big";
    txq_push(out_buf, n, 0, delay_for(p, DIRECT_TX_DELAY_FACTOR));
    return NULL;
}

// Payload sanity per upstream switch(); unknown/unsupported types are never flooded.
static bool flood_type_ok(const Pkt& p) {
    switch (p.ptype) {
        case PT_ACK:        return p.payload_len >= 4;
        case PT_PATH:
        case PT_REQ:
        case PT_RESPONSE:
        case PT_TXT_MSG:    return 2 + CIPHER_MAC_SIZE < p.payload_len;
        case PT_ANON_REQ:   return 1 + 32 + 2 < p.payload_len;
        case PT_GRP_DATA:
        case PT_GRP_TXT:    return 1 + 2 < p.payload_len;
        case PT_ADVERT:     return p.payload_len >= 32 + 4 + 64;
        default:            return false;
    }
}

// FLOOD / TRANSPORT_FLOOD
static const char* handle_flood(const Pkt& p) {
    // allowPacketForward(): hop limits
    if (p.hash_count >= FLOOD_MAX) return "flood.max";
    if (p.route == ROUTE_FLOOD && p.hash_count >= FLOOD_MAX_UNSCOPED) return "flood.max.unscoped";
    if (p.ptype == PT_ADVERT && p.hash_count >= FLOOD_MAX_ADVERT) return "flood.max.advert";

    // allowPacketForward(): region scope
    if (p.route == ROUTE_TRANSPORT_FLOOD) {
        if (p.tc[0] == 0 && p.tc[1] == 0) return "share";          // {0,0} = send to nowhere
        if (region_match(p.tc[0], p.ptype, p.payload, p.payload_len) < 0) return "region";
    } else if (!ALLOW_UNSCOPED_FLOOD) {
        return "unscoped";
    }

    // allowPacketForward(): loop detection (LOOP_DETECT_MODERATE)
    static const uint8_t max_loop[4] = { 0, 2, 1, 1 };
    uint8_t seen_self = 0;
    for (int k = 0; k < p.hash_count; k++)
        if (is_own_hash(p.path + k * p.hash_size, p.hash_size)) seen_self++;
    if (seen_self >= max_loop[p.hash_size]) return "loop";

    if (!flood_type_ok(p)) return "type";

    uint8_t h[8];
    packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
    if (was_seen(h)) return "dedup";
    mark_seen(h);

#if VERIFY_ADVERTS
    if (p.ptype == PT_ADVERT && !advert_verify(p.payload, p.payload_len)) return "advert sig";
#else
    if (p.ptype == PT_ADVERT && memcmp(p.payload, own_pubkey, 32) == 0) return "own advert";
#endif

    // routeRecvPacket(): append our hash
    int pbytes = p.hash_count * p.hash_size;
    if (pbytes + p.hash_size > MAX_PATH_SIZE) return "path full";
    uint8_t newpath[MAX_PATH_SIZE];
    memcpy(newpath, p.path, pbytes);
    memcpy(newpath + pbytes, own_pubkey, p.hash_size);
    uint8_t new_len = (p.path_len & 0xC0) | ((p.hash_count + 1) & 0x3F);
    int n = build(out_buf, p.header, p.tc, new_len, newpath, pbytes + p.hash_size,
                  p.payload, p.payload_len);
    if (n < 0) return "too big";
    txq_push(out_buf, n, p.hash_count + 1, delay_for(p, TX_DELAY_FACTOR));
    return NULL;
}

static void on_receive(const uint8_t* d, int len, int8_t snr4) {
    Pkt p;
    const char* why;
    if (!parse(d, len, p)) why = "malformed";
    else if (p.route == ROUTE_DIRECT || p.route == ROUTE_TRANSPORT_DIRECT) why = handle_direct(p, snr4);
    else why = handle_flood(p);

    if (why) { stat_drop++; Serial1.print("  drop: "); Serial1.println(why); }
    else     { stat_fwd++;  Serial1.println("  fwd"); led_blink(2, 30); }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Adverts (Mesh::createAdvert + sendZeroHop / sendFloodScoped)
// ═════════════════════════════════════════════════════════════════════════════
static void send_advert(bool flood) {
    uint8_t payload[32 + 4 + 64 + MAX_ADVERT_DATA_SIZE];
    int i = 0;
    memcpy(payload + i, own_pubkey, 32); i += 32;
    uint32_t ts = clock_now();
    memcpy(payload + i, &ts, 4); i += 4;
    int sig_at = i; i += 64;

    int app_at = i;
#if defined(NODE_LAT_I) && defined(NODE_LON_I)
    payload[i++] = ADV_TYPE_REPEATER | ADV_LATLON_MASK | ADV_NAME_MASK;
    int32_t lat = (int32_t)(NODE_LAT_I), lon = (int32_t)(NODE_LON_I);
    memcpy(payload + i, &lat, 4); i += 4;
    memcpy(payload + i, &lon, 4); i += 4;
#else
    payload[i++] = ADV_TYPE_REPEATER | ADV_NAME_MASK;
#endif
    int room = MAX_ADVERT_DATA_SIZE - (i - app_at);
    int nlen = strlen(node_name);
    if (nlen > room) nlen = room;
    memcpy(payload + i, node_name, nlen); i += nlen;
    int app_len = i - app_at;

    uint8_t msg[32 + 4 + MAX_ADVERT_DATA_SIZE];
    memcpy(msg, payload, 36);
    memcpy(msg + 36, payload + app_at, app_len);
    IWatchdog.reload();
    Ed25519::sign(payload + sig_at, own_privkey, own_pubkey, msg, 36 + app_len);

    uint8_t h[8];
    packet_hash(h, PT_ADVERT, 0, payload, i);
    mark_seen(h);                                        // ignore our own echoes

    int n;
    if (!flood) {
        n = build(out_buf, (PT_ADVERT << 2) | ROUTE_DIRECT, NULL, 0, NULL, 0, payload, i);
        txq_push(out_buf, n, 3, 0);
        Serial1.println("ADVERT zero-hop");
        return;
    }
    uint8_t path_len = (uint8_t)((PATH_HASH_SIZE - 1) << 6);
#ifdef ADVERT_SCOPE
    uint8_t key[16];
    region_key_for(ADVERT_SCOPE, key);
    uint16_t tc[2] = { transport_code(key, PT_ADVERT, payload, i), 0 };
    n = build(out_buf, (PT_ADVERT << 2) | ROUTE_TRANSPORT_FLOOD, tc, path_len, NULL, 0, payload, i);
    Serial1.println("ADVERT flood (scoped " ADVERT_SCOPE ")");
#else
    n = build(out_buf, (PT_ADVERT << 2) | ROUTE_FLOOD, NULL, path_len, NULL, 0, payload, i);
    Serial1.println("ADVERT flood");
#endif
    txq_push(out_buf, n, 3, 0);
    j_last_flood_ts = ts;
    journal_write(ts, j_last_flood_ts);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Arduino entry points
// ═════════════════════════════════════════════════════════════════════════════
static uint32_t next_local_advert_s = 0;
static uint32_t next_flood_advert_s = 0;
static uint32_t next_persist_s = 0;
static uint32_t next_beat_s = 0;

void setup(void) {
    pinMode(PIN_LED, OUTPUT);
    led(true);
    pinMode(PIN_TXEN, OUTPUT); digitalWrite(PIN_TXEN, LOW);
    pinMode(PIN_RXEN, OUTPUT); digitalWrite(PIN_RXEN, LOW);

    Serial1.begin(115200);
    delay(200);
    IWatchdog.begin(8000000);   // 8 s

    identity_init();
    regions_init();
    clock_init();

    Serial1.println();
    Serial1.print("=== SPECTER MeshCore Repeater v" FW_VERSION " [");
    Serial1.print(node_name); Serial1.println("] ===");
    Serial1.print("Hash: 0x"); Serial1.println(own_pubkey[0], HEX);
    Serial1.print("Clock: "); Serial1.println(clock_now());
    Serial1.print("Radio: "); Serial1.print(LORA_FREQ, 3); Serial1.print(" MHz BW");
    Serial1.print(LORA_BW, 1); Serial1.print(" SF"); Serial1.print(LORA_SF);
    Serial1.print(" CR4/"); Serial1.print(LORA_CR); Serial1.print(" ");
    Serial1.print(LORA_TX_POWER); Serial1.println(" dBm");
    Serial1.print("Regions:");
    if (num_regions == 0) Serial1.print(" (none - scoped floods are not forwarded)");
    for (int i = 0; i < num_regions; i++) { Serial1.print(" #"); Serial1.print(region_names[i]); }
    Serial1.println();
    Serial1.print("Unscoped flood: "); Serial1.println(ALLOW_UNSCOPED_FLOOD ? "forward" : "drop");

    Serial1.print("Radio init...");
    if (!radio_init()) {
        while (true) { led(true); delay(100); led(false); delay(100); }  // IWDG resets & retries
    }
    Serial1.print(" OK (");
    Serial1.print(tcxo_used > 0 ? "TCXO" : "crystal");
    Serial1.println(")");

    for (int i = 0; i < 4; i++) rng_state ^= (uint32_t)radio.randomByte() << (i * 8);
    if (rng_state == 0) rng_state = 0x9E3779B9;

    budget_ms = budget_max / 2;
    budget_updated = millis();
    rx_start();

    uint32_t up = uptime_s();
    next_local_advert_s = up + 16;                       // upstream: zero-hop at 16 s
    uint32_t since_flood = clock_now() - j_last_flood_ts;
    uint32_t flood_iv = FLOOD_ADVERT_INTERVAL_H * 3600UL;
    next_flood_advert_s = (j_last_flood_ts == 0 || since_flood >= flood_iv)
                              ? up + rnd_range(20, 60)    // overdue: flood soon after boot
                              : up + (flood_iv - since_flood);
    next_persist_s = up + PERSIST_INTERVAL_MIN * 60UL;
    next_beat_s = up + HEARTBEAT_S;
    led(false);
}

void loop(void) {
    IWatchdog.reload();
    uint32_t up = uptime_s();

    // ── Receive ──────────────────────────────────────────────────────────────
    uint32_t irq = radio.getIrqFlags();
    if (irq & RADIOLIB_SX126X_IRQ_RX_DONE) {
        uint8_t rxbuf[MAX_PKT];
        int len = (int)radio.getPacketLength();
        int state = (len > 0 && len < MAX_PKT) ? radio.readData(rxbuf, len) : RADIOLIB_ERR_PACKET_TOO_LONG;
        float snr = radio.getSNR();
        int rssi = (int)radio.getRSSI();
        activity_at = 0; header_seen = false;
        rx_start();
        if (state == RADIOLIB_ERR_NONE) {
            stat_rx++;
            Serial1.print("RX RSSI="); Serial1.print(rssi);
            Serial1.print(" SNR="); Serial1.print(snr, 1);
            Serial1.print(" len="); Serial1.println(len);
            led_blink(1, 20);
            on_receive(rxbuf, len, (int8_t)(snr * 4));
        } else if (state != RADIOLIB_ERR_CRC_MISMATCH) {
            Serial1.print("readData err: "); Serial1.println(state);
        }
        return;
    }

    // ── Adverts ──────────────────────────────────────────────────────────────
    if ((int32_t)(up - next_flood_advert_s) >= 0) {
        send_advert(true);
        next_flood_advert_s = up + FLOOD_ADVERT_INTERVAL_H * 3600UL;
        if (ADVERT_INTERVAL_MIN) next_local_advert_s = up + ADVERT_INTERVAL_MIN * 60UL;
    } else if (ADVERT_INTERVAL_MIN && (int32_t)(up - next_local_advert_s) >= 0) {
        send_advert(false);
        next_local_advert_s = up + ADVERT_INTERVAL_MIN * 60UL;
    }

    // ── Transmit queue ───────────────────────────────────────────────────────
    txq_service(irq);

    // ── Housekeeping ─────────────────────────────────────────────────────────
    if ((int32_t)(up - next_persist_s) >= 0) {
        journal_write(clock_now(), j_last_flood_ts);
        next_persist_s = up + PERSIST_INTERVAL_MIN * 60UL;
    }
    if ((int32_t)(up - next_beat_s) >= 0) {
        next_beat_s = up + HEARTBEAT_S;
        Serial1.print("ALIVE up="); Serial1.print(up);
        Serial1.print("s rx="); Serial1.print(stat_rx);
        Serial1.print(" fwd="); Serial1.print(stat_fwd);
        Serial1.print(" drop="); Serial1.print(stat_drop);
        Serial1.print(" tx="); Serial1.print(stat_tx);
        Serial1.print(" lbt="); Serial1.print(stat_lbt);
        Serial1.print(" budget="); Serial1.println(budget_ms);
    }

    __WFI();   // sleep until the next SysTick (1 ms) or UART interrupt
}
