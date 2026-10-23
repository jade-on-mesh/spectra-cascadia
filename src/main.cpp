/*
 * Spectra-Cascadia — Native MeshCore Repeater for STM32F103C8T6 + SX1262 (DX-LR30)
 * Version: 1.18.0.1 (official MeshCore 1.18.0 + Spectra-Cascadia release 1)
 *
 * Built with -DSPECTER_XL (the "XL" 128 KB build) it also accepts logins from the
 * normal MeshCore app: status, telemetry, neighbours and the full CLI over the air.
 *
 * Fork of MaliosDark/meshcore-specter-dx-lr30 (MIT). Forwarding follows upstream
 * MeshCore (src/Mesh.cpp + examples/simple_repeater) as closely as a 20 KB-RAM,
 * no-filesystem target allows, and the USB serial console speaks the same
 * command language as an upstream MeshCore repeater ("set name …", "get radio",
 * "region put …", replies prefixed with "  -> ").
 *
 * Settings live in a 1 KB flash page and survive reboots. The -D build flags
 * below are only the defaults used on first boot or after "erase".
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
#ifdef SPECTER_XL
#include <math.h>
#include <AES.h>
#include <SHA512.h>
#include <BigNumberUtil.h>
#include "utility/LimbUtil.h"
#define private public            // the field arithmetic we need for X25519 is private
#include <Curve25519.h>
#undef private
#endif

#define FW_NAME    "Spectra-Cascadia"
#define FW_VERSION "v1.18.0.2"   // upstream MeshCore version + our release number

// ═════════════════════════════════════════════════════════════════════════════
//  First-boot defaults — override with -D in platformio.ini (or change at
//  runtime over USB serial; runtime settings win once saved).
// ═════════════════════════════════════════════════════════════════════════════
#ifndef LORA_FREQ_KHZ
#define LORA_FREQ_KHZ 910525      // MeshCore "USA/Canada (Recommended)"
#endif
#ifndef LORA_BW_HZ
#define LORA_BW_HZ 62500
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
#define LORA_SYNC 0x12
#endif
#ifndef LORA_TCXO_VOLTAGE
#define LORA_TCXO_VOLTAGE 1.6f    // retried at 0.0 (plain crystal) if init fails
#endif
#ifndef ADVERT_INTERVAL_MIN
#define ADVERT_INTERVAL_MIN 0     // periodic zero-hop adverts off (CascadiaMesh airtime policy)
#endif
#ifndef FLOOD_ADVERT_INTERVAL_H
#define FLOOD_ADVERT_INTERVAL_H 83
#endif
#ifndef PATH_HASH_MODE
#define PATH_HASH_MODE 0          // 0..2 → 1..3 byte path hashes for packets we originate
#endif
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
#define ALLOW_UNSCOPED_FLOOD 1    // wildcard region "*" allows flood
#endif
#ifndef REGIONS
#define REGIONS ""                // e.g. "se-wa,seattle"
#endif
#ifndef DEFAULT_SCOPE
#define DEFAULT_SCOPE ""          // region our flood adverts are scoped to ("" = un-scoped)
#endif
#ifndef TX_DELAY_X100
#define TX_DELAY_X100 50          // txdelay 0.50
#endif
#ifndef DIRECT_TX_DELAY_X100
#define DIRECT_TX_DELAY_X100 30   // direct.txdelay 0.30
#endif
#ifndef AF_X100
#define AF_X100 100               // af 1.00 → 50 % duty cycle
#endif
#ifndef LOOP_DETECT
#define LOOP_DETECT 2             // 0 off, 1 minimal, 2 moderate, 3 strict
#endif
#ifndef PERSIST_INTERVAL_MIN
#define PERSIST_INTERVAL_MIN 15
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

// Two 1 KB pages at the top of the first 64 KB (safe on genuine 64 KB parts).
// platformio.ini caps the image at 62 KB so code can never overlap them.
#ifndef CONFIG_ADDR
#define CONFIG_ADDR   0x0800F800UL
#endif
#ifndef JOURNAL_ADDR
#define JOURNAL_ADDR  0x0800FC00UL
#endif
#define PAGE_SIZE     1024U
#ifndef UID_BASE
#define UID_BASE      0x1FFFF7E8UL
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  MeshCore protocol constants
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
#define PT_OTA        0x0C      // mikecarper/MeshCore LoRa OTA (docs/ota_protocol.md)
#define PT_RAW_CUSTOM 0x0F

#define MAX_PATH_SIZE        64
#define MAX_PKT              256
#define MAX_ADVERT_DATA_SIZE 32
#define CIPHER_MAC_SIZE      2

#define ADV_TYPE_REPEATER 0x02
#define ADV_LATLON_MASK   0x10
#define ADV_NAME_MASK     0x80

// ═════════════════════════════════════════════════════════════════════════════
//  Persistent configuration
// ═════════════════════════════════════════════════════════════════════════════
#define CFG_MAGIC    0x32435053UL   // "SPC2"
#define MAX_REGIONS  8
#define REGION_NAME  20
#define REGION_DENY_FLOOD 0x01

struct Config {
    uint32_t magic;
    uint32_t freq_khz;
    uint32_t bw_hz;
    int32_t  lat_e6, lon_e6;
    uint8_t  sf, cr, path_hash_mode, loop_detect;
    int8_t   tx_dbm;
    uint8_t  repeat, wildcard_flags, advert_interval_min;
    uint8_t  flood_advert_h, flood_max, flood_max_unscoped, flood_max_advert;
    uint8_t  txdelay_x100, direct_txdelay_x100;
    uint16_t af_x100;
    uint8_t  num_regions, default_region;     // default_region 0xFF = none
    uint8_t  region_flags[MAX_REGIONS];
    char     regions[MAX_REGIONS][REGION_NAME];
    char     name[32];
    uint8_t  privkey[32];
    uint32_t check;
};
static Config cfg;

static uint32_t fnv_words(const void* p, unsigned words) {
    const uint32_t* w = (const uint32_t*)p;
    uint32_t h = 0x811C9DC5UL;
    for (unsigned i = 0; i < words; i++) { h ^= w[i]; h *= 16777619UL; }
    return h;
}
static uint32_t cfg_checksum(const Config& c) { return fnv_words(&c, offsetof(Config, check) / 4); }

// v2.2 settings live right after Config in the same flash page, with their own
// magic/checksum, so upgrading keeps the saved name, regions and identity.
#define EXT_MAGIC 0x32585053UL   // "SPX2"
struct ConfigExt {
    uint32_t magic;
    uint32_t clk_drift_s;                     // clock.sync.drift
    uint16_t d_base_ms, d_step_ms;            // direct.retry.base / step
    uint8_t  clk_on, clk_samples;             // clock.sync.mesh / samples
    uint8_t  preset;                          // retry.preset (0 infra, 1 rooftop, 2 mobile, 255 custom)
    uint8_t  d_count, d_margin, d_heard, d_cr; // direct.retry.count / margin / heard / cr (adaptive on)
    uint8_t  f_count, f_path, f_gpath, f_advert;
    uint8_t  power;                           // powersaving (16 MHz core), applied at boot
    uint8_t  bat_pin;                         // 0 = none (use VDD), 1 = PB0, 2 = PB1
    uint8_t  pad;
    uint16_t bat_div_x100;                    // battery.divider × 100
    uint16_t cut_mv, resume_mv;               // battery.cutoff / battery.resume (0 = off / auto)
    uint32_t check;
};
static ConfigExt ext;
static_assert(sizeof(Config) % 4 == 0 && sizeof(ConfigExt) % 4 == 0, "word-aligned config");
static_assert(sizeof(Config) + sizeof(ConfigExt) <= PAGE_SIZE, "config must fit one flash page");
static uint32_t ext_checksum(const ConfigExt& e) { return fnv_words(&e, offsetof(ConfigExt, check) / 4); }

#ifdef SPECTER_XL
// XL: login passwords, stored after ConfigExt in the same page. An empty admin
// password means remote login is off until one is set over USB.
#define AUTH_MAGIC 0x32415053UL  // "SPA2"
struct ConfigAuth {
    uint32_t magic;
    char     admin_pw[16];
    char     guest_pw[16];
    uint32_t check;
};
static ConfigAuth auth;
#define AUTH_ADDR (CONFIG_ADDR + sizeof(Config) + sizeof(ConfigExt))
static_assert(sizeof(ConfigAuth) % 4 == 0, "word-aligned config");
static_assert(sizeof(Config) + sizeof(ConfigExt) + sizeof(ConfigAuth) <= PAGE_SIZE, "config must fit one flash page");
static uint32_t auth_checksum(const ConfigAuth& a) { return fnv_words(&a, offsetof(ConfigAuth, check) / 4); }

// XL: the remaining settings the app's repeater settings screen reads and writes.
#define APP_MAGIC 0x324F5053UL   // "SPO2"
struct ConfigApp {
    uint32_t magic;
    char     owner_info[120];                 // owner.info ('|' on the wire = newline)
    uint8_t  allow_ro, multi_acks, rxgain;    // allow.read.only (stored; room servers only upstream) / multi.acks / radio.rxgain
    int8_t   int_thresh;                      // int.thresh dB above noise floor = channel busy (0 = off)
    uint16_t agc_s;                           // agc.reset.interval seconds (0 = off)
    uint16_t radio_wd_h;                      // radio.watchdog hours (0 = default 6, 0xFFFF = off)
    uint32_t check;
};
static ConfigApp app;
#define APP_ADDR (AUTH_ADDR + sizeof(ConfigAuth))
static_assert(sizeof(ConfigApp) % 4 == 0, "word-aligned config");
static_assert(sizeof(Config) + sizeof(ConfigExt) + sizeof(ConfigAuth) + sizeof(ConfigApp) <= PAGE_SIZE, "config must fit one flash page");
static uint32_t app_checksum(const ConfigApp& a) { return fnv_words(&a, offsetof(ConfigApp, check) / 4); }

// XL: alert channel and flood rate limit.
#define MORE_MAGIC 0x334D5053UL  // "SPM3"
struct ConfigMore {
    uint32_t magic;
    uint8_t  secret[32];                      // channel key (16 or 32 bytes used)
    char     label[24];                       // what "get alert.channel" shows
    uint8_t  key_len;                         // 0 = no alert channel
    uint8_t  alerts;                          // alerts on/off
    uint8_t  flood_rl;                        // flood.ratelimit: floods per minute per source (0 = off)
    uint8_t  cad;                             // cad on/off: channel activity detection before TX
    uint16_t alert_mv;                        // alert.battery (0 = auto: cutoff + 150 mV)
    uint16_t rxdelay_x10;                     // rxdelay base × 10 (0 = off, as upstream default)
    uint32_t check;
};
static ConfigMore more;
#define MORE_ADDR (APP_ADDR + sizeof(ConfigApp))
static_assert(sizeof(ConfigMore) % 4 == 0, "word-aligned config");
static_assert(sizeof(Config) + sizeof(ConfigExt) + sizeof(ConfigAuth) + sizeof(ConfigApp) + sizeof(ConfigMore) <= PAGE_SIZE, "config must fit one flash page");
static uint32_t more_checksum(const ConfigMore& m) { return fnv_words(&m, offsetof(ConfigMore, check) / 4); }

// XL: battery-gated forwarding and the guest login switch (Halo Keymind Cascade 1.18.0.1).
#define POW_MAGIC 0x31425053UL   // "SPB1"
struct ConfigPow {
    uint32_t magic;
    uint8_t  rep_on, rep_pct;                 // repeat.battery: pause all forwarding below rep_pct %
    uint8_t  fl_on, fl_pct;                   // flood.battery: pause flood forwarding below fl_pct %
    uint8_t  guest_on, pad[3];                // guest on/off
    uint16_t empty_mv, full_mv;               // battery.empty / battery.full (0 % / 100 %)
    uint32_t check;
};
static ConfigPow bp;
#define POW_ADDR (MORE_ADDR + sizeof(ConfigMore))
static_assert(sizeof(ConfigPow) % 4 == 0, "word-aligned config");
static_assert(sizeof(Config) + sizeof(ConfigExt) + sizeof(ConfigAuth) + sizeof(ConfigApp) + sizeof(ConfigMore) + sizeof(ConfigPow) <= PAGE_SIZE, "config must fit one flash page");
static uint32_t pow_checksum(const ConfigPow& p) { return fnv_words(&p, offsetof(ConfigPow, check) / 4); }
#endif

// retry.preset values (mikecarper/MeshCore Halo/Keymind defaults)
static void ext_apply_preset(uint8_t pr) {
    static const uint16_t base[3] = { 275, 175, 175 }, step[3] = { 150, 100, 50 };
    static const uint8_t dcount[3] = { 4, 15, 15 }, margin[3] = { 15, 5, 0 };
    static const uint8_t fcount[3] = { 1, 3, 15 }, fpath[3] = { 1, 2, 1 };
    ext.preset = pr;
    ext.d_base_ms = base[pr]; ext.d_step_ms = step[pr];
    ext.d_count = dcount[pr]; ext.d_margin = margin[pr];
    ext.f_count = fcount[pr]; ext.f_path = fpath[pr]; ext.f_gpath = 1;
}

static void ext_defaults(void) {
    memset(&ext, 0, sizeof(ext));
    ext.magic = EXT_MAGIC;
    ext.clk_on = 1; ext.clk_samples = 9; ext.clk_drift_s = 600;
    ext.d_heard = 1; ext.d_cr = 1; ext.f_advert = 0;
    ext.bat_div_x100 = 200;
    ext_apply_preset(1);                      // rooftop
}

// ═════════════════════════════════════════════════════════════════════════════
//  Small utilities
// ═════════════════════════════════════════════════════════════════════════════
static bool log_on = false;
#define LOG(x)    do { if (log_on) Serial1.print(x); } while (0)
#define LOGLN(x)  do { if (log_on) Serial1.println(x); } while (0)

static uint32_t rng_state = 0x9E3779B9;
static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}
static uint32_t rnd_range(uint32_t lo, uint32_t hi) {
    return (hi <= lo) ? lo : lo + (rnd() % (hi - lo));
}

static void led(bool on) { digitalWrite(PIN_LED, on ? HIGH : LOW); }

static const char* skip_ws(const char* s) { while (*s == ' ') s++; return s; }

// Tiny sprintf replacement (newlib's printf costs ~1.8 KB of the 62 KB budget).
// Supports %s %c %d %u %ld %lu %% and a zero-pad width digit (%02d). Returns length.
#include <stdarg.h>
static int fmtx(char* out, const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    char* o = out;
    while (*f) {
        if (*f != '%') { *o++ = *f++; continue; }
        f++;
        if (*f == '%') { *o++ = *f++; continue; }
        int width = 0;
        if (*f == '0') f++;
        while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        bool lng = (*f == 'l');
        if (lng) f++;
        char c = *f++;
        if (c == 's') { const char* str = va_arg(ap, const char*); while (*str) *o++ = *str++; continue; }
        if (c == 'c') { *o++ = (char)va_arg(ap, int); continue; }
        unsigned long v;
        if (c == 'd') {
            long sv = lng ? va_arg(ap, long) : va_arg(ap, int);
            if (sv < 0) { *o++ = '-'; v = (unsigned long)(-sv); } else v = (unsigned long)sv;
        } else v = lng ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int);
        char tmp[11]; int n = 0;
        do { tmp[n++] = '0' + v % 10; v /= 10; } while (v);
        while (n < width) tmp[n++] = '0';
        while (n) *o++ = tmp[--n];
    }
    *o = 0;
    va_end(ap);
    return (int)(o - out);
}
#define sprintf fmtx

#if defined(ARDUINO_ARCH_STM32)
// newlib's word-at-a-time strcmp is 442 bytes; this one is ~20 and plenty fast here.
extern "C" int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
#endif

// Parse "[-]123.456" into an integer scaled by 10^dec. Returns false on junk.
static bool parse_fixed(const char* s, int dec, int32_t* out) {
    s = skip_ws(s);
    bool neg = false;
    if (*s == '-') { neg = true; s++; } else if (*s == '+') s++;
    if (!(*s >= '0' && *s <= '9') && *s != '.') return false;
    int64_t v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    int d = 0;
    if (*s == '.') { s++; while (*s >= '0' && *s <= '9') { if (d < dec) { v = v * 10 + (*s - '0'); d++; } s++; } }
    while (d++ < dec) v *= 10;
    s = skip_ws(s);
    if (*s && *s != ',') return false;
    *out = (int32_t)(neg ? -v : v);
    return true;
}

// Format an integer scaled by 10^dec, trimming trailing zeros ("62500",3 → "62.5").
static char* fmt_fixed(char* out, int32_t v, int dec) {
    char* p = out;
    if (v < 0) { *p++ = '-'; v = -v; }
    uint32_t div = 1;
    for (int i = 0; i < dec; i++) div *= 10;
    p += sprintf(p, "%lu", (unsigned long)(v / div));
    uint32_t frac = v % div;
    if (dec && frac) {
        *p++ = '.';
        for (uint32_t d = div / 10; d && frac; d /= 10) { *p++ = '0' + frac / d; frac %= d; }
    }
    *p = 0;
    return out;
}

static void to_hex(char* out, const uint8_t* b, int n) {
    static const char hx[] = "0123456789ABCDEF";
    for (int i = 0; i < n; i++) { *out++ = hx[b[i] >> 4]; *out++ = hx[b[i] & 15]; }
    *out = 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Flash helpers
// ═════════════════════════════════════════════════════════════════════════════
static void flash_erase(uint32_t addr) {
    FLASH_EraseInitTypeDef er = {};
    er.TypeErase   = FLASH_TYPEERASE_PAGES;
    er.PageAddress = addr;
    er.NbPages     = 1;
    uint32_t err = 0;
    IWatchdog.reload();
    HAL_FLASHEx_Erase(&er, &err);
}

#ifdef SPECTER_XL
// tempradio: while temporary radio params are live, cfg holds them; saves write the real ones.
static bool     tr_active = false;
static uint32_t tr_apply_at = 0, tr_revert_at = 0;
static uint32_t tr_freq, tr_bw; static uint8_t tr_sf, tr_cr;      // the other set (pending or original)
static void tr_swap(void) {
    uint32_t f = cfg.freq_khz, b = cfg.bw_hz; uint8_t s = cfg.sf, c = cfg.cr;
    cfg.freq_khz = tr_freq; cfg.bw_hz = tr_bw; cfg.sf = tr_sf; cfg.cr = tr_cr;
    tr_freq = f; tr_bw = b; tr_sf = s; tr_cr = c;
}
#endif
static void cfg_save(void) {
#ifdef SPECTER_XL
    if (tr_active) tr_swap();
#endif
    cfg.check = cfg_checksum(cfg);
    ext.check = ext_checksum(ext);
    HAL_FLASH_Unlock();
    flash_erase(CONFIG_ADDR);
    const uint32_t* w = (const uint32_t*)&cfg;
    for (unsigned i = 0; i < sizeof(Config) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, CONFIG_ADDR + i * 4, w[i]);
    w = (const uint32_t*)&ext;
    for (unsigned i = 0; i < sizeof(ConfigExt) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, CONFIG_ADDR + sizeof(Config) + i * 4, w[i]);
#ifdef SPECTER_XL
    auth.check = auth_checksum(auth);
    w = (const uint32_t*)&auth;
    for (unsigned i = 0; i < sizeof(ConfigAuth) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, AUTH_ADDR + i * 4, w[i]);
    app.check = app_checksum(app);
    w = (const uint32_t*)&app;
    for (unsigned i = 0; i < sizeof(ConfigApp) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, APP_ADDR + i * 4, w[i]);
    more.check = more_checksum(more);
    w = (const uint32_t*)&more;
    for (unsigned i = 0; i < sizeof(ConfigMore) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, MORE_ADDR + i * 4, w[i]);
    bp.check = pow_checksum(bp);
    w = (const uint32_t*)&bp;
    for (unsigned i = 0; i < sizeof(ConfigPow) / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, POW_ADDR + i * 4, w[i]);
#endif
    HAL_FLASH_Lock();
#ifdef SPECTER_XL
    if (tr_active) tr_swap();
#endif
}

// ═════════════════════════════════════════════════════════════════════════════
//  Identity
// ═════════════════════════════════════════════════════════════════════════════
static uint8_t own_pubkey[32];

static inline bool is_own_hash(const uint8_t* h, uint8_t len) {
    return memcmp(h, own_pubkey, len) == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Regions — mirrors RegionMap / TransportKey::calcTransportCode
// ═════════════════════════════════════════════════════════════════════════════
static uint8_t region_keys[MAX_REGIONS][16];

static void region_key_for(const char* name, uint8_t key[16]) {
    char tmp[REGION_NAME + 2];
    tmp[0] = '#';
    strncpy(tmp + 1, name[0] == '#' ? name + 1 : name, REGION_NAME);
    tmp[REGION_NAME + 1] = 0;
    uint8_t full[32];
    SHA256 sha;
    sha.reset();
    sha.update(tmp, strlen(tmp));
    sha.finalize(full, 32);
    memcpy(key, full, 16);
}

static void regions_rekey(void) {
    for (int i = 0; i < cfg.num_regions; i++) region_key_for(cfg.regions[i], region_keys[i]);
}

static int region_find(const char* name) {
    if (name[0] == '#') name++;
    for (int i = 0; i < cfg.num_regions; i++) if (!strcmp(cfg.regions[i], name)) return i;
    return -1;
}

static uint16_t transport_code(const uint8_t key[16], uint8_t ptype, const uint8_t* payload, int plen) {
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

// Index of the flood-allowed region this scoped packet belongs to, or -1.
static int region_match(uint16_t code0, uint8_t ptype, const uint8_t* payload, int plen) {
    for (int i = 0; i < cfg.num_regions; i++) {
        if ((cfg.region_flags[i] & REGION_DENY_FLOOD) || cfg.regions[i][0] == '$') continue;   // '$' private: no key (as upstream)
        if (transport_code(region_keys[i], ptype, payload, plen) == code0) return i;
    }
    return -1;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Clock — monotonic across reboots, learns forward from verified adverts
// ═════════════════════════════════════════════════════════════════════════════
static uint32_t airtime_ms(int len);
static bool is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static const uint8_t month_days[] = {31,28,31,30,31,30,31,31,30,31,30,31};

static uint32_t build_unix_ts(void) {
    const char* d = __DATE__;
    const char* t = __TIME__;
    static const char mn[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    int month = 1;
    for (int m = 0; m < 12; m++)
        if (d[0]==mn[m*3] && d[1]==mn[m*3+1] && d[2]==mn[m*3+2]) { month = m+1; break; }
    int day  = (d[4]==' ' ? 0 : d[4]-'0')*10 + (d[5]-'0');
    int year = (d[7]-'0')*1000+(d[8]-'0')*100+(d[9]-'0')*10+(d[10]-'0');
    uint32_t days = 0;
    for (int y = 1970; y < year; y++) days += is_leap(y) ? 366 : 365;
    for (int m = 1; m < month; m++) days += month_days[m-1] + ((m == 2 && is_leap(year)) ? 1 : 0);
    days += day - 1;
    return days * 86400UL + ((t[0]-'0')*10+(t[1]-'0'))*3600UL + ((t[3]-'0')*10+(t[4]-'0'))*60UL
           + (t[6]-'0')*10+(t[7]-'0');
}

static uint32_t clk_base = 0, clk_uptime_s = 0, clk_last_ms = 0, clk_ms_accum = 0;

static uint32_t uptime_s(void) {
    uint32_t now = millis();
    clk_ms_accum += now - clk_last_ms;     // wrap-safe
    clk_last_ms = now;
    while (clk_ms_accum >= 1000) { clk_ms_accum -= 1000; clk_uptime_s++; }
    return clk_uptime_s;
}
static uint32_t clock_now(void) { return clk_base + uptime_s(); }

// "HH:MM - d/m/yyyy UTC", same as upstream "clock"
static void fmt_clock(char* out, uint32_t ts) {
    uint32_t days = ts / 86400, rem = ts % 86400;
    int y = 1970;
    while (days >= (uint32_t)(is_leap(y) ? 366 : 365)) { days -= is_leap(y) ? 366 : 365; y++; }
    int m = 0;
    while (days >= (uint32_t)(month_days[m] + (m == 1 && is_leap(y)))) { days -= month_days[m] + (m == 1 && is_leap(y)); m++; }
    sprintf(out, "%02d:%02d - %d/%d/%d UTC", (int)(rem / 3600), (int)(rem / 60 % 60), (int)days + 1, m + 1, y);
}

// Journal: records { now_ts, last_flood_ts, ~(a^b) } appended until the page fills.
#define JREC_COUNT (PAGE_SIZE / 12)
static uint32_t j_last_flood_ts = 0;
static int      j_next_slot = 0;

static bool journal_read(uint32_t* ts, uint32_t* flood_ts) {
    bool found = false;
    j_next_slot = 0;
    for (int i = 0; i < (int)JREC_COUNT; i++) {
        const volatile uint32_t* r = (const volatile uint32_t*)(JOURNAL_ADDR + i * 12);
        if (r[0] == 0xFFFFFFFFUL && r[1] == 0xFFFFFFFFUL && r[2] == 0xFFFFFFFFUL) break;
        j_next_slot = i + 1;
        if (r[2] == ~(r[0] ^ r[1])) { *ts = r[0]; *flood_ts = r[1]; found = true; }   // last valid wins
    }
    return found;
}

static void journal_write(uint32_t ts, uint32_t flood_ts) {
    HAL_FLASH_Unlock();
    if (j_next_slot >= (int)JREC_COUNT) { flash_erase(JOURNAL_ADDR); j_next_slot = 0; }
    uint32_t addr = JOURNAL_ADDR + j_next_slot * 12;
    uint32_t w[3] = { ts, flood_ts, ~(ts ^ flood_ts) };
    for (int i = 0; i < 3; i++) HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr + i * 4, w[i]);
    HAL_FLASH_Lock();
    j_next_slot++;
}

static void clock_init(void) {
    uint32_t stored = 0, flood = 0;
    uint32_t start = build_unix_ts();
    if (journal_read(&stored, &flood)) {
        uint32_t resume = stored + PERSIST_INTERVAL_MIN * 60UL + 1;   // may have advertised up to here
        if (resume > start) start = resume;
        j_last_flood_ts = flood;
    }
    clk_last_ms = millis();
    clk_base = start;
    journal_write(clock_now(), j_last_flood_ts);
}

static void clock_set(uint32_t ts) {
    clk_base = ts - uptime_s();
    journal_write(clock_now(), j_last_flood_ts);
}

// ── Mesh clock sync (after mikecarper/MeshCore clock.sync.mesh, edge mode) ──
// Signed-advert timestamps from distinct senders are collected for up to 2 h.
// Once clock.sync.samples are fresh, the median is used if a strict majority
// (and at least the configured count) agree within 10 minutes. The clock is
// corrected only when it is off by more than clock.sync.drift, then sync
// sleeps for 7 days. A manual "time" set suppresses mesh sync until reboot.
#define CS_SLOTS      16
#define CS_MAX_AGE_S  (2UL * 3600UL)
#define CS_WINDOW_S   600UL
struct ClockSample { uint32_t est, rx_up; uint8_t key[4]; };
static ClockSample cs[CS_SLOTS];
static uint8_t  cs_count = 0;
static bool     cs_manual = false;
static uint32_t cs_next_up = 0;               // uptime (s) before which sync sleeps
static uint8_t  cs_last_agree = 0, cs_last_fresh = 0;
static int32_t  cs_last_delta = 0;
static uint32_t cs_last_up = 0;
static char     cs_reason = 'w';              // w waiting, s set, k in-sync, n no-consensus, m manual, o off

static bool cs_active(void) {
    return ext.clk_on && !cs_manual && (int32_t)(uptime_s() - cs_next_up) >= 0;
}

static void cs_prune(void) {
    uint32_t up = uptime_s();
    uint8_t n = 0;
    for (uint8_t i = 0; i < cs_count; i++)
        if (up - cs[i].rx_up <= CS_MAX_AGE_S) cs[n++] = cs[i];
    cs_count = n;
}

// Returns true if a consensus was reached (clock set or already in sync).
static bool clock_sync_eval(void) {
    cs_prune();
    cs_last_fresh = cs_count;
    if (!cs_active()) {
        if (!ext.clk_on) cs_reason = 'o';
        else if (cs_manual) cs_reason = 'm';
        else if (cs_reason != 's' && cs_reason != 'k') cs_reason = 'w';   // sleeping after a sync
        return false;
    }
    if (cs_count < ext.clk_samples) { cs_reason = 'w'; return false; }
    uint32_t up = uptime_s(), v[CS_SLOTS];
    for (uint8_t i = 0; i < cs_count; i++) v[i] = cs[i].est + (up - cs[i].rx_up);
    for (uint8_t i = 1; i < cs_count; i++)
        for (uint8_t j = i; j > 0 && v[j-1] > v[j]; j--) { uint32_t t = v[j]; v[j] = v[j-1]; v[j-1] = t; }
    uint32_t med = v[cs_count / 2];
    uint8_t agree = 0;
    for (uint8_t i = 0; i < cs_count; i++)
        if ((v[i] > med ? v[i] - med : med - v[i]) <= CS_WINDOW_S) agree++;
    uint8_t need = cs_count / 2 + 1;
    if (need < ext.clk_samples) need = ext.clk_samples;
    cs_last_agree = agree;
    if (agree < need) { cs_reason = 'n'; return false; }
    uint32_t now = clock_now();
    cs_last_delta = (int32_t)(med - now);
    cs_last_up = up;
    uint32_t off = med > now ? med - now : now - med;
    if (off > ext.clk_drift_s) { clock_set(med); cs_reason = 's'; LOGLN("clock set from mesh consensus"); }
    else cs_reason = 'k';
    cs_count = 0;
    cs_next_up = up + 7UL * 86400UL;
    return true;
}

static void clock_sample(const uint8_t* pubkey, uint32_t ts, uint8_t hops, int pkt_len) {
    if (!cs_active()) return;
    uint32_t build = build_unix_ts();
    if (ts < build || ts > build + 315360000UL) return;          // build time .. +10 years
    // Estimated flood transit: each relay waits ~2.5 × txdelay airtimes, then transmits.
    ts += (uint32_t)((uint64_t)hops * airtime_ms(pkt_len) * (100 + cfg.txdelay_x100 * 5 / 2) / 100000UL);
    cs_prune();
    int slot = -1;
    for (uint8_t i = 0; i < cs_count; i++) if (!memcmp(cs[i].key, pubkey, 4)) { slot = i; break; }
    if (slot < 0) {
        if (cs_count < CS_SLOTS) slot = cs_count++;
        else { slot = 0; for (uint8_t i = 1; i < CS_SLOTS; i++) if (cs[i].rx_up < cs[slot].rx_up) slot = i; }
        memcpy(cs[slot].key, pubkey, 4);
    }
    cs[slot].est = ts;
    cs[slot].rx_up = uptime_s();
    clock_sync_eval();
}

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
// Thin subclass: raw packet status gives SNR in MeshCore's ×4 units without
// pulling in RadioLib's double-precision getSNR()/getRSSI().
class Radio : public SX1262 {
public:
    Radio(Module* m) : SX1262(m) {}
    uint32_t packetStatus() { return getPacketStatus(); }
    int rssiInst() { uint8_t r = 0; getMod()->SPIreadStream(RADIOLIB_SX126X_CMD_GET_RSSI_INST, &r, 1); return -(int)r / 2; }
};
#ifdef SPECTER_XL
// XL keeps RadioLib in the upper 64 KB, so nothing may run its code (including
// a global constructor) before setup() has checked that half was flashed.
static Radio* radio_p = NULL;
#define radio (*radio_p)
// Linked last into the upper 64 KB: if it reads back, that half was flashed.
#define XL_MAGIC 0x4C584353UL
__attribute__((section(".xl_magic"), used)) static const volatile uint32_t xl_magic_word = XL_MAGIC;
#else
Radio radio(new Module(PIN_NSS, PIN_DIO1, PIN_NRST, PIN_BUSY, SPI));
#endif

#if defined(ARDUINO_ARCH_STM32)
// Core clock is chosen before setup() runs, from the saved powersaving flag:
//   off → 64 MHz (HSI/2 × 16, stock)   on → 16 MHz (HSI/2 × 4)
// Sleeping between polls at 16 MHz draws roughly a quarter of what it does at 64 MHz.
extern "C" void SystemClock_Config(void) {
    const ConfigExt* e = (const ConfigExt*)(CONFIG_ADDR + sizeof(Config));
    bool low = e->magic == EXT_MAGIC && e->check == fnv_words(e, offsetof(ConfigExt, check) / 4) && e->power;
    RCC_OscInitTypeDef osc = {};
    RCC_ClkInitTypeDef clk = {};
    osc.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    osc.HSIState = RCC_HSI_ON;
    osc.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    osc.PLL.PLLState = RCC_PLL_ON;
    osc.PLL.PLLSource = RCC_PLLSOURCE_HSI_DIV2;
    osc.PLL.PLLMUL = low ? RCC_PLL_MUL4 : RCC_PLL_MUL16;
    if (HAL_RCC_OscConfig(&osc) != HAL_OK) Error_Handler();
    clk.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clk.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = low ? RCC_HCLK_DIV1 : RCC_HCLK_DIV2;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&clk, low ? FLASH_LATENCY_0 : FLASH_LATENCY_2) != HAL_OK) Error_Handler();
}

// We never use the LR-FHSS modem. Defining these members here keeps the linker
// from pulling RadioLib's SX126x_LR_FHSS object (~1.8 KB) into the 62 KB image.
int16_t SX126x::buildLRFHSSPacket(const uint8_t*, size_t, uint8_t*, size_t*, size_t*, size_t*) { return RADIOLIB_ERR_UNSUPPORTED; }
int16_t SX126x::resetLRFHSS() { return RADIOLIB_ERR_UNSUPPORTED; }
uint16_t SX126x::stepLRFHSS() { return 0; }
int16_t SX126x::setLRFHSSHop(uint8_t) { return RADIOLIB_ERR_UNSUPPORTED; }
#endif

static bool     radio_has_tcxo = true;
static uint32_t preamble_ms = 0, max_pkt_ms = 0;

static uint32_t airtime_ms(int len) {
    return (uint32_t)(radio.getTimeOnAir(len) / 1000UL) + 1;
}

static bool radio_init(void) {
    SPI.begin();
    float freq = cfg.freq_khz / 1000.0f, bw = cfg.bw_hz / 1000.0f;
    int state = radio.begin(freq, bw, cfg.sf, cfg.cr, LORA_SYNC, cfg.tx_dbm, LORA_PREAMBLE, LORA_TCXO_VOLTAGE, false);
    if (state == RADIOLIB_ERR_SPI_CMD_FAILED || state == RADIOLIB_ERR_SPI_CMD_INVALID) {
        radio_has_tcxo = false;          // plain crystal
        state = radio.begin(freq, bw, cfg.sf, cfg.cr, LORA_SYNC, cfg.tx_dbm, LORA_PREAMBLE, 0.0f, false);
    }
    if (state != RADIOLIB_ERR_NONE) {
        Serial1.print("ERROR: radio init failed: "); Serial1.println(state);
        return false;
    }
    radio.setRfSwitchPins(PIN_RXEN, PIN_TXEN);
    radio.setCRC(1);
    uint32_t sym_us = (1000000UL << cfg.sf) / cfg.bw_hz;
    preamble_ms = (uint32_t)((LORA_PREAMBLE * 4 + 17) * sym_us * 3 / 8000) + 5;   // ×1.5 margin
    max_pkt_ms  = airtime_ms(255) + 50;
#ifdef SPECTER_XL
    if (app.rxgain) radio.setRxBoostedGainMode(true);
#endif
    return true;
}

static void rx_start(void) {
    radio.startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF,
                       RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED),
                       RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
}

static int      last_rssi = 0, last_snr4 = 0, noise_floor = 0;
#ifdef SPECTER_XL
static uint32_t stat_cad_busy = 0, stat_better = 0, stat_radio_wd = 0, last_rx_ms = 0;
#endif

// Listen-before-talk: upstream CustomSX1262::isReceiving()
static uint32_t activity_at = 0;
static bool     header_seen = false;
#define IRQ_ACTIVITY_CLEAR (RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID | \
                            RADIOLIB_SX126X_IRQ_HEADER_ERR | RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID)

static bool channel_busy(uint32_t irq) {
    uint32_t now = millis();
#ifdef SPECTER_XL
    // int.thresh: RSSI above the noise floor counts as busy (RadioLibWrapper::isChannelActive)
    if (app.int_thresh && noise_floor && radio.rssiInst() > noise_floor + app.int_thresh) return true;
    // cad: ask the SX1262 whether a LoRa preamble is on the air right now (only when idle)
    if (more.cad && !(irq & (RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID))) {
        int16_t r = radio.scanChannel();
        rx_start();
        if (r == RADIOLIB_LORA_DETECTED) { stat_cad_busy++; return true; }
    }
#endif
    if (irq & RADIOLIB_SX126X_IRQ_HEADER_ERR) {
        radio.clearIrqFlags(IRQ_ACTIVITY_CLEAR);
    } else if (irq & RADIOLIB_SX126X_IRQ_HEADER_VALID) {
        if (!header_seen) { header_seen = true; activity_at = now; }
        if (now - activity_at <= max_pkt_ms) return true;
        radio.clearIrqFlags(IRQ_ACTIVITY_CLEAR);
    } else if (!header_seen && (irq & RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED)) {
        if (activity_at == 0) activity_at = now;
        if (now - activity_at <= preamble_ms) return true;
        radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED);
    }
    activity_at = 0; header_seen = false;
    return false;
}

// Airtime budget (Dispatcher::updateTxBudget, 1-hour window); duty = 1/(1+af)
static uint32_t budget_ms = 0, budget_updated = 0;
static uint32_t stat_tx_air_ms = 0, stat_rx_air_ms = 0, stat_rx_err = 0;
static uint32_t stat_flood_tx = 0, stat_direct_tx = 0, stat_flood_rx = 0, stat_direct_rx = 0;
static uint32_t budget_max(void) { return (uint32_t)(3600000ULL * 100 / (100 + cfg.af_x100)); }

static void budget_refill(void) {
    uint32_t now = millis();
    uint32_t add = (uint32_t)((uint64_t)(now - budget_updated) * 100 / (100 + cfg.af_x100));
    budget_updated = now;
    budget_ms += add;
    if (budget_ms > budget_max()) budget_ms = budget_max();
}

static bool transmit(const uint8_t* buf, int len, uint8_t cr) {
    uint32_t toa = airtime_ms(len);
    radio.standby();
    if (cr && cr != cfg.cr) radio.setCodingRate(cr);
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
    if (cr && cr != cfg.cr) radio.setCodingRate(cfg.cr);
    led(false);
    budget_ms = (budget_ms > toa) ? budget_ms - toa : 0;
    stat_tx_air_ms += toa;
    activity_at = 0; header_seen = false;
    rx_start();
    if (state != RADIOLIB_ERR_NONE) { LOG("TX err: "); LOGLN(state); }
    return state == RADIOLIB_ERR_NONE;
}

// ═════════════════════════════════════════════════════════════════════════════
//  TX queue — delayed, prioritized retransmits (RX keeps running while waiting)
// ═════════════════════════════════════════════════════════════════════════════
#define TXQ_SIZE 6
struct TxItem {
    bool     used;
    uint8_t  pri, len, cr;
    int8_t   rslot;            // retry slot to arm after this TX, or -1
    uint8_t  score;            // XL rxdelay: reception score ×100 of the copy queued
    uint32_t due, busy_since;
    uint8_t  buf[MAX_PKT];
};
static TxItem txq[TXQ_SIZE];

static int txq_push(const uint8_t* buf, int len, uint8_t pri, uint32_t delay_ms) {
    if (len <= 0) return -1;
    int slot = -1;
    for (int i = 0; i < TXQ_SIZE; i++) if (!txq[i].used) { slot = i; break; }
    if (slot < 0) {
        for (int i = 0; i < TXQ_SIZE; i++)
            if (txq[i].pri > pri && (slot < 0 || txq[i].pri > txq[slot].pri)) slot = i;
        if (slot < 0) { LOGLN("  txq full"); return -1; }
    }
    TxItem& t = txq[slot];
    t.used = true; t.pri = pri; t.len = (uint8_t)len; t.cr = 0; t.rslot = -1; t.score = 0;
    t.due = millis() + delay_ms; t.busy_since = 0;
    memcpy(t.buf, buf, len);
    return slot;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Recent repeaters — last-hop prefix + SNR, learned from received floods and
//  zero-hop repeater adverts. Gates direct retries (direct.retry.heard) and
//  picks the starting coding rate for them.
// ═════════════════════════════════════════════════════════════════════════════
#define RR_SLOTS 16
struct RecentRpt { uint8_t pfx[3], len; int8_t snr4; uint32_t up; };
static RecentRpt rr[RR_SLOTS];

static void rr_note(const uint8_t* pfx, uint8_t len, int8_t snr4) {
    if (len > 3) len = 3;
    uint32_t up = uptime_s();
    int slot = 0;
    bool match = false;
    for (int i = 0; i < RR_SLOTS && !match; i++) {
        if (rr[i].len && !memcmp(rr[i].pfx, pfx, len < rr[i].len ? len : rr[i].len)) { slot = i; match = true; }
        else if (!rr[i].len || rr[i].up < rr[slot].up) slot = i;
    }
    if (!match || rr[slot].len < len) { memcpy(rr[slot].pfx, pfx, len); rr[slot].len = len; }
    rr[slot].snr4 = snr4;
    rr[slot].up = up;
}

// SNR×4 of a repeater heard in the last 24 h, or -128 if unknown.
static int rr_snr4(const uint8_t* pfx, uint8_t len) {
    uint32_t up = uptime_s();
    for (int i = 0; i < RR_SLOTS; i++) {
        if (!rr[i].len || up - rr[i].up > 86400UL) continue;
        if (!memcmp(rr[i].pfx, pfx, len < rr[i].len ? len : rr[i].len)) return rr[i].snr4;
    }
    return -128;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Automatic retries (after mikecarper/MeshCore flood.retry / direct.retry)
//  After forwarding, keep a copy. If no qualifying echo is heard (the next hop
//  forwarding a direct packet, or anyone forwarding our flood further) before
//  the wait expires, resend it, escalating the coding rate on direct retries.
// ═════════════════════════════════════════════════════════════════════════════
#define RT_SLOTS 4
struct RetrySlot {
    bool     used, direct, armed;
    uint8_t  hash[8];
    uint8_t  hops;             // path count in the packet we sent
    uint8_t  left, attempt, cr0, len, pri;
    uint32_t due;
    uint8_t  buf[MAX_PKT];
};
static RetrySlot rt[RT_SLOTS];
static uint32_t stat_retry = 0, stat_echo = 0;

// repeat.battery / flood.battery (Halo Keymind Cascade 1.18.0.1): below the set
// battery percentage, stop forwarding (all, or floods only). Our own packets and
// replies still go out. Re-evaluated every 30 s and when a setting changes.
#ifdef SPECTER_XL
static bool bf_rep_paused = false, bf_fl_paused = false;
static uint32_t stat_bf_drop = 0;
static bool fwd_paused(bool flood) {
    bool p = bf_rep_paused || (flood && bf_fl_paused);
    if (p) stat_bf_drop++;
    return p;
}
#else
static inline bool fwd_paused(bool) { return false; }
#endif

static uint32_t rt_wait(const RetrySlot& r) {
    uint32_t a = airtime_ms(r.len);
    if (r.direct) {
        uint8_t ptype = (r.buf[0] >> 2) & 0x0F;
        uint32_t k = (ptype == PT_TXT_MSG) ? 7 : (ptype == PT_TRACE || ptype == PT_ANON_REQ) ? 3 : 6;
        return ext.d_base_ms + k * a + (uint32_t)r.attempt * ext.d_step_ms + rnd_range(0, a + 1);
    }
    return max_pkt_ms + 20 * a + rnd_range(0, 2 * a + 1);
}

// Coding-rate ladder 4/5, 4/7, 4/7, 4/8: retry n (1-based) steps along it from the start CR.
static uint8_t rt_cr(uint8_t start, uint8_t n) {
    static const uint8_t ladder[4] = { 5, 7, 7, 8 };
    uint8_t i = 0;
    while (i < 3 && ladder[i] < start) i++;
    i += n - 1;
    return ladder[i > 3 ? 3 : i];
}

static void rt_free(int i) {
    rt[i].used = false;
    for (int k = 0; k < TXQ_SIZE; k++) if (txq[k].used && txq[k].rslot == i) txq[k].used = false;
}

static void rt_create(const uint8_t h[8], int qslot, bool direct, uint8_t hops, uint8_t count, uint8_t cr0) {
    if (qslot < 0 || !count) return;
    int i = 0;
    for (int k = 0; k < RT_SLOTS; k++) {
        if (!rt[k].used) { i = k; break; }
        if (rt[k].pri > rt[i].pri) i = k;              // evict the farthest-from-source flood
    }
    if (rt[i].used) rt_free(i);
    RetrySlot& r = rt[i];
    r.used = true; r.armed = false; r.direct = direct;
    memcpy(r.hash, h, 8);
    r.hops = hops; r.left = count; r.attempt = 0; r.cr0 = cr0;
    r.len = txq[qslot].len; r.pri = txq[qslot].pri;
    memcpy(r.buf, txq[qslot].buf, r.len);
    txq[qslot].rslot = i;
}

// Called for every duplicate we hear. Returns true if it cancelled a retry.
static bool rt_echo(const uint8_t h[8], bool direct, uint8_t hops) {
    for (int i = 0; i < RT_SLOTS; i++) {
        if (!rt[i].used || memcmp(rt[i].hash, h, 8)) continue;
        bool ok = rt[i].direct ? (direct && hops < rt[i].hops) : (!direct && hops > rt[i].hops);
        if (!ok) return false;
        rt_free(i);
        stat_echo++;
        LOGLN("  echo: retry cancelled");
        return true;
    }
    return false;
}

static void rt_service(void) {
    uint32_t now = millis();
    for (int i = 0; i < RT_SLOTS; i++) {
        RetrySlot& r = rt[i];
        if (!r.used || !r.armed || (int32_t)(now - r.due) < 0) continue;
        if (!r.left) { r.used = false; continue; }    // final echo window expired
        if (fwd_paused(!r.direct)) { r.used = false; continue; }   // battery pause: no more relay retries
        r.left--; r.attempt++; r.armed = false;
        int q = txq_push(r.buf, r.len, r.pri, 0);
        if (q < 0) { r.used = false; continue; }
        txq[q].rslot = i;
        txq[q].cr = r.direct || r.hops == 0 ? rt_cr(r.cr0, r.attempt) : 0;
        stat_retry++;
        LOGLN("  retry");
    }
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
        if (now - t.busy_since < 4000) {             // getCADFailMaxDuration()
            t.due = now + rnd_range(1, 5) * 120;     // getCADFailRetryDelay()
            stat_lbt++;
            return;
        }
    }
    budget_refill();
    uint32_t toa = airtime_ms(t.len);
    if (budget_ms < toa / 2) {
        t.due = now + (toa / 2 - budget_ms) * (100 + cfg.af_x100) / 100 + 1;
        return;
    }
    if (transmit(t.buf, t.len, t.cr)) {
        stat_tx++;
        if ((t.buf[0] & 3) == ROUTE_FLOOD || (t.buf[0] & 3) == ROUTE_TRANSPORT_FLOOD) stat_flood_tx++; else stat_direct_tx++;
    }
    t.used = false;
    if (t.rslot >= 0 && rt[t.rslot].used) {          // start this retry slot's echo window
        rt[t.rslot].armed = true;
        rt[t.rslot].due = millis() + rt_wait(rt[t.rslot]);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Packet parsing / building (Packet::readFrom / writeTo)
// ═════════════════════════════════════════════════════════════════════════════
struct Pkt {
    uint8_t        header, route, ptype;
    uint16_t       tc[2];
    uint8_t        path_len, hash_size, hash_count;
    const uint8_t* path;
    const uint8_t* payload;
    int            payload_len;
};

static bool parse(const uint8_t* d, int len, Pkt& p) {
    int i = 0;
    if (len < 3) return false;
    p.header = d[i++];
    if (p.header & 0x80) return false;         // payload version > 1: not ours to parse or relay (Dispatcher)
    p.route  = p.header & 0x03;
    p.ptype  = (p.header >> 2) & 0x0F;
    if (p.route == ROUTE_TRANSPORT_FLOOD || p.route == ROUTE_TRANSPORT_DIRECT) {
        if (len < 7) return false;
        memcpy(p.tc, d + i, 4); i += 4;
    } else {
        p.tc[0] = p.tc[1] = 0;
    }
    p.path_len   = d[i++];
    p.hash_size  = (p.path_len >> 6) + 1;
    p.hash_count = p.path_len & 0x3F;
    if (p.hash_size == 4) return false;
    int pbytes = p.hash_count * p.hash_size;
    if (pbytes > MAX_PATH_SIZE) return false;
    p.path = d + i; i += pbytes;
    if (i >= len) return false;
    p.payload = d + i;
    p.payload_len = len - i;
    return true;
}

static int build(uint8_t* out, uint8_t header, const uint16_t* tc, uint8_t path_len,
                 const uint8_t* path, int path_bytes, const uint8_t* payload, int plen) {
    int i = 0;
    out[i++] = header;
    uint8_t route = header & 0x03;
    if (route == ROUTE_TRANSPORT_FLOOD || route == ROUTE_TRANSPORT_DIRECT) { memcpy(out + i, tc, 4); i += 4; }
    out[i++] = path_len;
    if (path_bytes) { memcpy(out + i, path, path_bytes); i += path_bytes; }
    if (i + plen > 255) return -1;
    memcpy(out + i, payload, plen); i += plen;
    return i;
}

static uint32_t delay_for(const Pkt& p, uint8_t factor_x100) {
    uint32_t t = airtime_ms(p.hash_count * p.hash_size + p.payload_len + 2) * factor_x100 / 100;
    return rnd_range(0, 5 * t + 1);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Advert verification (+ clock learning)
// ═════════════════════════════════════════════════════════════════════════════
static bool advert_verify(const uint8_t* payload, int plen, uint8_t hops) {
    if (plen < 100) return false;
    if (memcmp(payload, own_pubkey, 32) == 0) return false;
    int app_len = plen - 100;
    if (app_len > MAX_ADVERT_DATA_SIZE) app_len = MAX_ADVERT_DATA_SIZE;
    uint8_t msg[36 + MAX_ADVERT_DATA_SIZE];
    memcpy(msg, payload, 36);
    memcpy(msg + 36, payload + 100, app_len);
    IWatchdog.reload();
    if (!Ed25519::verify(payload + 36, payload, msg, 36 + app_len)) return false;
    uint32_t ts;
    memcpy(&ts, payload + 32, 4);
    clock_sample(payload, ts, hops, plen + 2 + hops);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Forwarding (Mesh::onRecvPacket + simple_repeater::allowPacketForward)
// ═════════════════════════════════════════════════════════════════════════════
static uint8_t out_buf[MAX_PKT];

// ═════════════════════════════════════════════════════════════════════════════
//  Advert echo guard (after mikecarper/MeshCore): once a downstream echo shows an
//  advert we forwarded went further, never forward that exact advert again while
//  its signed timestamp is under 6 h old — even after the dedup table forgets it.
// ═════════════════════════════════════════════════════════════════════════════
#define AG_SLOTS 32
#define AG_WINDOW_S (6UL * 3600UL)
struct AdvGuard { uint8_t h[8]; uint8_t hops, echoed; uint32_t up; };
static AdvGuard ag[AG_SLOTS];
static uint32_t stat_adv_guard = 0;

static AdvGuard* ag_find(const uint8_t h[8]) {
    for (int i = 0; i < AG_SLOTS; i++) if (ag[i].hops && !memcmp(ag[i].h, h, 8)) return &ag[i];   // hops ≥ 1 marks a used slot
    return NULL;
}
static void ag_add(const uint8_t h[8], uint8_t hops, uint32_t adv_ts) {
    uint32_t now = clock_now();
    if (adv_ts + AG_WINDOW_S < now || ag_find(h)) return;
    int s = 0;                                   // replace: empty, else oldest un-echoed, else oldest
    for (int i = 1; i < AG_SLOTS; i++) {
        if (!ag[s].hops) break;
        if (!ag[i].hops || (ag[i].echoed < ag[s].echoed) || (ag[i].echoed == ag[s].echoed && ag[i].up < ag[s].up)) s = i;
    }
    memcpy(ag[s].h, h, 8); ag[s].hops = hops; ag[s].echoed = 0; ag[s].up = uptime_s();
}
static void ag_echo(const uint8_t h[8], uint8_t hops) {
    AdvGuard* g = ag_find(h);
    if (g && hops > g->hops && !g->echoed) { g->echoed = 1; g->up = uptime_s(); }
}
static bool ag_blocked(const uint8_t h[8]) {
    AdvGuard* g = ag_find(h);
    return g && g->echoed && uptime_s() - g->up < AG_WINDOW_S;
}

static bool rt_any(void) { for (int i = 0; i < RT_SLOTS; i++) if (rt[i].used) return true; return false; }

// SNR floor per spreading factor (dB×4): SF7 -7.5 … SF12 -20
static int snr_floor4(void) { return -30 - ((int)cfg.sf - 7) * 10; }

#ifdef SPECTER_XL
static bool xl_handle_for_us(const Pkt& p, int8_t snr4, int scope);
static void xl_note_neighbour(const uint8_t* pub, int8_t snr4);
static uint32_t stat_for_us = 0;
static bool xl_type(uint8_t t) { return t == PT_REQ || t == PT_TXT_MSG || t == PT_ANON_REQ || t == PT_PATH; }
#endif

// Node discovery (simple_repeater onControlDataRecv / sendNodeDiscoverReq), zero-hop CONTROL
#define CTL_DISCOVER_REQ  0x80
#define CTL_DISCOVER_RESP 0x90
static uint32_t disc_tag = 0, disc_until = 0, disc_win = 0;
static uint8_t  disc_count = 0;
#ifdef SPECTER_XL
static uint32_t xl_disc_mod(void);
static void xl_acl_touch_regions(void);
#endif

static const char* handle_control(const Pkt& p, int8_t snr4) {
    uint8_t type = p.payload[0] & 0xF0;
    // not answered when adverts are off: the node wishes not to be discoverable (isHiddenNode)
    if (type == CTL_DISCOVER_REQ && p.payload_len >= 6 && cfg.repeat && (cfg.advert_interval_min || cfg.flood_advert_h)) {
        uint32_t now = millis();
        if (now - disc_win > 120000UL) { disc_win = now; disc_count = 0; }    // max 4 per 2 minutes
        if (disc_count >= 4) return "discover limit";
        uint32_t since = 0;
        if (p.payload_len >= 10) memcpy(&since, p.payload + 6, 4);
#ifdef SPECTER_XL
        uint32_t mod = xl_disc_mod();
#else
        uint32_t mod = 0;
#endif
        if (!(p.payload[1] & (1 << ADV_TYPE_REPEATER)) || mod < since) return "discover filtered";
        disc_count++;
        uint8_t d[6 + 32];
        d[0] = CTL_DISCOVER_RESP | ADV_TYPE_REPEATER;
        d[1] = (uint8_t)snr4;                            // inbound SNR ×4
        memcpy(d + 2, p.payload + 2, 4);                 // tag
        memcpy(d + 6, own_pubkey, 32);
        int len = (p.payload[0] & 1) ? 6 + 8 : 6 + 32;   // prefix_only
        int n = build(out_buf, (PT_CONTROL << 2) | ROUTE_DIRECT, NULL, 0, NULL, 0, d, len);
        uint32_t t = airtime_ms(n) * cfg.txdelay_x100 / 100;
        if (n > 0) txq_push(out_buf, n, 0, rnd_range(0, 5 * t + 2) * 4);   // widened ×4: many may answer
        return "discover answered";
    }
#ifdef SPECTER_XL
    if (type == CTL_DISCOVER_RESP && p.payload_len >= 6 + 32 && (p.payload[0] & 0x0F) == ADV_TYPE_REPEATER) {
        uint32_t tag; memcpy(&tag, p.payload + 2, 4);
        if (!disc_tag || (int32_t)(millis() - disc_until) > 0 || tag != disc_tag) return "discover stale";
        if (!memcmp(p.payload + 6, own_pubkey, 32)) return "discover self";
        xl_note_neighbour(p.payload + 6, snr4);
        return "discover reply";
    }
#endif
    return "control";
}

static const char* handle_direct(const Pkt& p, int8_t snr4) {
    uint8_t h[8];

    if (p.ptype == PT_TRACE) {
        if (p.path_len >= MAX_PATH_SIZE || p.payload_len < 9) return "trace bad";
        uint8_t path_sz = p.payload[8] & 0x03;
        int     tlen    = p.payload_len - 9;
        int     offset  = (int)p.path_len << path_sz;
        if (offset >= tlen) return "trace end";
        if (offset + (1 << path_sz) > tlen) return "trace bad";
        if (!is_own_hash(p.payload + 9 + offset, 1 << path_sz)) return "trace not ours";
        if (!cfg.repeat) return "repeat off";
        if (fwd_paused(false)) return "battery";
        packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
        if (was_seen(h)) return "dedup";
        mark_seen(h);
        uint8_t newpath[MAX_PATH_SIZE];
        memcpy(newpath, p.path, p.path_len);
        newpath[p.path_len] = (uint8_t)snr4;
        int n = build(out_buf, p.header, p.tc, p.path_len + 1, newpath, p.path_len + 1, p.payload, p.payload_len);
        if (n < 0) return "too big";
        txq_push(out_buf, n, 5, delay_for(p, cfg.direct_txdelay_x100));
        return NULL;
    }

    if (p.ptype == PT_CONTROL && (p.payload[0] & 0x80)) return p.hash_count == 0 ? handle_control(p, snr4) : "zero-hop control";
    if (p.hash_count == 0) {
        if (p.ptype == PT_ADVERT) {                    // neighbour advert: verify, learn time
            packet_hash(h, p.ptype, 0, p.payload, p.payload_len);
            if (!was_seen(h)) {
                mark_seen(h);
                if (advert_verify(p.payload, p.payload_len, 0) && (p.payload[100] & 0x0F) == ADV_TYPE_REPEATER) {
                    rr_note(p.payload, 3, snr4);
#ifdef SPECTER_XL
                    xl_note_neighbour(p.payload, snr4);
#endif
                }
            }
        }
#ifdef SPECTER_XL
        else if (xl_type(p.ptype)) {                   // addressed to us (last hop removed)
            packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
            if (was_seen(h)) return "dedup";
            if (xl_handle_for_us(p, snr4, -1)) { mark_seen(h); stat_for_us++; return "for us"; }
        }
#endif
        return "zero-hop";
    }
    if (!is_own_hash(p.path, p.hash_size)) {
        if (rt_any()) {                                // is this the next hop forwarding our packet?
            if (p.ptype == PT_MULTIPART && p.payload_len >= 5) packet_hash(h, PT_ACK, 0, p.payload + 1, p.payload_len - 1);
            else packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
            if (rt_echo(h, true, p.hash_count)) return "echo";
        }
        return "not next hop";
    }
    if (!cfg.repeat) return "repeat off";
    if (fwd_paused(false)) return "battery";

    uint8_t new_path_len  = (p.path_len & 0xC0) | ((p.hash_count - 1) & 0x3F);
    const uint8_t* rest   = p.path + p.hash_size;
    int rest_bytes        = (p.hash_count - 1) * p.hash_size;
    const uint8_t hdr_ack = (PT_ACK << 2) | ROUTE_DIRECT;
    const uint8_t* pl = p.payload;
    int plen = p.payload_len;
    uint8_t header = p.header, pri = 0;
    uint32_t delay = delay_for(p, cfg.direct_txdelay_x100);   // ACKs too (upstream 1.18: they had none)

    if (p.ptype == PT_MULTIPART) {                     // forwardMultipartDirect
        if (plen < 5 || (pl[0] & 0x0F) != PT_ACK) return "multipart";
        delay += ((uint32_t)(pl[0] >> 4) + 1) * 300;
        pl++; plen--;
        packet_hash(h, PT_ACK, 0, pl, plen);
        header = hdr_ack;
    } else {
        packet_hash(h, p.ptype, p.path_len, pl, plen);
        if (p.ptype == PT_ACK) header = hdr_ack;      // routeDirectRecvAcks
    }
    if (was_seen(h)) return "dedup";
    mark_seen(h);
#ifdef SPECTER_XL
    // multi.acks (Mesh::routeDirectRecvAcks): send N extra copies as multipart ACKs
    // 300 ms apart from the retransmit delay, counting down, then the plain ACK last.
    if (header == hdr_ack && app.multi_acks && plen <= 16) {
        for (uint8_t extra = app.multi_acks; extra > 0; extra--) {
            uint8_t mp[17];
            mp[0] = (uint8_t)((extra << 4) | PT_ACK);
            memcpy(mp + 1, pl, plen);
            int m = build(out_buf, (PT_MULTIPART << 2) | ROUTE_DIRECT, p.tc, new_path_len, rest, rest_bytes, mp, plen + 1);
            if (m > 0) { txq_push(out_buf, m, pri, delay); delay += 300; }
        }
    }
#endif
    int n = build(out_buf, header, p.tc, new_path_len, rest, rest_bytes, pl, plen);
    if (n < 0) return "too big";
    int q = txq_push(out_buf, n, pri, delay);

    // Direct retry: only when the next hop will forward again (so we can hear the
    // echo) and, with direct.retry.heard, when we have recently heard it well enough.
    if (p.hash_count > 1 && ext.d_count) {
        int snr = rr_snr4(rest, p.hash_size);
        bool ok = !ext.d_heard || (snr != -128 && snr >= snr_floor4() + ext.d_margin * 4);
        uint8_t cr0 = cfg.cr;
        if (ext.d_cr && snr != -128) { if (snr <= 10) cr0 = 8; else if (snr < 30) cr0 = 7; }
        if (cr0 < cfg.cr) cr0 = cfg.cr;
        if (ok) rt_create(h, q, true, p.hash_count - 1, ext.d_count, cr0);
    }
    return NULL;
}

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
        case PT_ADVERT:     return p.payload_len >= 100;
        default:            return false;
    }
}

static uint8_t flood_retry_count(const Pkt& p) {
    if (!ext.f_count || (ext.f_path != 255 && p.hash_count > ext.f_path)) return 0;
    uint8_t c = ext.f_count;
    switch (p.ptype) {
        case PT_REQ:       return 0;
        case PT_GRP_TXT:   return c;
        case PT_RESPONSE: case PT_TXT_MSG: case PT_ANON_REQ: case PT_PATH:
            return (p.hash_count == 0 || c < 2) ? c : 2;
        case PT_ADVERT:    return ext.f_advert ? 1 : 0;
        case PT_GRP_DATA:  if (ext.f_gpath != 255 && p.hash_count > ext.f_gpath) return 0;
        /* fall through */
        default:           return 1;
    }
}

#ifdef SPECTER_XL
// flood.ratelimit: token bucket per source, so one noisy node can't monopolise
// the channel. The source is the best identity a repeater can see: the sender's
// hash for DMs/requests/paths, the key prefix for anonymous requests, and the
// channel + first hop for channel messages (their sender is encrypted).
#define RL_SLOTS 32
struct RlSlot { uint32_t key; uint16_t last_s; uint8_t tokens, used; };
static RlSlot rl[RL_SLOTS];
static uint32_t stat_rl_drop = 0;
static bool flood_rate_ok(const Pkt& p) {
    uint8_t n = more.flood_rl;
    if (!n) return true;
    uint32_t key;
    switch (p.ptype) {
        case PT_TXT_MSG: case PT_REQ: case PT_RESPONSE: case PT_PATH:
            key = p.payload[1] | (uint32_t)p.payload[0] << 8; break;              // src, dest
        case PT_ANON_REQ:
            key = p.payload[1] | (uint32_t)p.payload[2] << 8 | (uint32_t)p.payload[3] << 16; break;
        case PT_GRP_TXT: case PT_GRP_DATA:
            key = p.payload[0] | (uint32_t)(p.hash_count ? p.path[0] : 0) << 8 | 0x10000UL; break;
        default:
            return true;                                                         // adverts (own guard), ACKs …
    }
    key |= (uint32_t)p.ptype << 24;
    uint16_t now = (uint16_t)uptime_s();
    int s = -1, old = 0;
    for (int i = 0; i < RL_SLOTS; i++) {
        if (rl[i].used && rl[i].key == key) { s = i; break; }
        if (!rl[i].used || (rl[old].used && (uint16_t)(now - rl[i].last_s) > (uint16_t)(now - rl[old].last_s))) old = i;
    }
    if (s < 0) { s = old; rl[s].key = key; rl[s].used = 1; rl[s].tokens = n; rl[s].last_s = now; }
    RlSlot& r = rl[s];
    uint32_t refill = (uint32_t)(uint16_t)(now - r.last_s) * n / 60;              // n per minute
    if (refill) { r.tokens = (uint8_t)(r.tokens + refill > n ? n : r.tokens + refill); r.last_s = now; }
    if (!r.tokens) { stat_rl_drop++; return false; }
    r.tokens--;
    return true;
}
#endif

#ifdef SPECTER_XL
// rxdelay (Dispatcher::calcRxDelay with simple_repeater's base): weaker copies wait
// longer, so when the same flood arrives over several paths the strongest copy is
// the one we forward. Score: RadioLibWrapper::packetScoreInt.
static uint32_t rx_delay_ms(const Pkt& p, int8_t snr4, uint8_t* score_out) {
    int raw = 2 + (p.route == ROUTE_TRANSPORT_FLOOD ? 4 : 0) + p.hash_count * p.hash_size + p.payload_len;
    float sc = 0;
    if (cfg.sf >= 7 && snr4 >= snr_floor4()) {
        sc = (snr4 - snr_floor4()) / 40.0f * (1.0f - raw / 256.0f);
        if (sc > 1) sc = 1;
    }
    *score_out = (uint8_t)(sc * 100);
    if (!more.rxdelay_x10) return 0;
    float d = (powf(more.rxdelay_x10 / 10.0f, 0.85f - sc) - 1.0f) * airtime_ms(raw);
    if (d < 50) return 0;
    return d > 32000 ? 32000 : (uint32_t)d;
}
// A duplicate of a flood still waiting in our queue: if this copy was received
// better, forward it instead (its path), at its own, shorter delay.
static bool better_copy(const Pkt& p, int8_t snr4) {
    for (int i = 0; i < TXQ_SIZE; i++) {
        TxItem& t = txq[i];
        if (!t.used || t.len < p.payload_len || (t.buf[0] & 3) != p.route || ((t.buf[0] >> 2) & 15) != p.ptype) continue;
        if (memcmp(t.buf + t.len - p.payload_len, p.payload, p.payload_len)) continue;
        uint8_t score;
        uint32_t d = rx_delay_ms(p, snr4, &score);
        if (score <= t.score || p.hash_count + 1 >= cfg.flood_max) return false;
        int pbytes = p.hash_count * p.hash_size;
        if (pbytes + p.hash_size > MAX_PATH_SIZE) return false;
        for (int k = 0; k < p.hash_count; k++) if (is_own_hash(p.path + k * p.hash_size, p.hash_size)) return false;
        uint8_t newpath[MAX_PATH_SIZE];
        memcpy(newpath, p.path, pbytes);
        memcpy(newpath + pbytes, own_pubkey, p.hash_size);
        int n = build(out_buf, p.header, p.tc, (p.path_len & 0xC0) | ((p.hash_count + 1) & 0x3F), newpath, pbytes + p.hash_size, p.payload, p.payload_len);
        if (n < 0) return false;
        memcpy(t.buf, out_buf, n); t.len = (uint8_t)n; t.score = score;
        uint32_t due = millis() + delay_for(p, cfg.txdelay_x100) + d;
        if ((int32_t)(due - t.due) < 0) t.due = due;
        stat_better++;
        return true;
    }
    return false;
}
#endif

#ifdef SPECTER_XL
// LoRa OTA relay (mikecarper/MeshCore Mesh::onRecvPacket, PAYLOAD_TYPE_OTA): carried
// opaquely, and only while a tempradio window is running. Ordinary flood limits and
// region rules apply; duplicates use a time-bounded cache instead of the seen table so
// a re-sent request or block after a loss is forwarded again (allowOtaForwardRetry).
#define OTA_FWD_SLOTS 16
struct OtaFwd { uint8_t h[4]; uint32_t at; uint8_t min_hops, used; };
static OtaFwd ota_fwd[OTA_FWD_SLOTS];
static uint8_t ota_fwd_next = 0;
static uint32_t stat_ota_relay = 0;
static bool ota_is_transfer(uint8_t t) { return t >= 0x04 && t <= 0x0B; }   // GET_MANIFEST … LEAVES
static const char* handle_ota_flood(const Pkt& p) {
    if (!tr_active) return "ota (no tempradio)";                  // invisible outside the window
    if (p.payload_len < 1) return "ota short";
    if (!cfg.repeat) return "repeat off";
    if (fwd_paused(true)) return "battery";
    if (p.hash_count >= cfg.flood_max) return "flood.max";
    if (!p.tc[0] && p.hash_count >= cfg.flood_max_unscoped) return "flood.max.unscoped";   // tc 0 = un-scoped
    if (p.tc[0]) {
        if (region_match(p.tc[0], p.ptype, p.payload, p.payload_len) < 0) return "region";
    } else if (cfg.wildcard_flags & REGION_DENY_FLOOD) return "unscoped denied";
    for (int k = 0; k < p.hash_count; k++) if (is_own_hash(p.path + k * p.hash_size, p.hash_size)) return "loop";
    int pbytes = p.hash_count * p.hash_size;
    if (pbytes + p.hash_size > MAX_PATH_SIZE) return "path full";
    // an identical copy is already waiting to go out
    for (int i = 0; i < TXQ_SIZE; i++)
        if (txq[i].used && ((txq[i].buf[0] >> 2) & 15) == PT_OTA && txq[i].len >= p.payload_len
            && !memcmp(txq[i].buf + txq[i].len - p.payload_len, p.payload, p.payload_len)) return "ota queued";
    uint8_t h[8];
    packet_hash(h, p.ptype, 0, p.payload, p.payload_len);
    int raw = 2 + (p.route == ROUTE_TRANSPORT_FLOOD ? 4 : 0) + pbytes + p.payload_len;
    uint32_t air = airtime_ms(raw), quiet = air > 500 ? air * 2 : 1000, now = millis();
    OtaFwd* e = NULL;
    for (int i = 0; i < OTA_FWD_SLOTS; i++) if (ota_fwd[i].used && !memcmp(ota_fwd[i].h, h, 4)) { e = &ota_fwd[i]; break; }
    if (e) {
        uint32_t age = now - e->at;
        if (!(age >= 30000 && age >= quiet * 4)) {
            if (p.hash_count > e->min_hops) return "ota echo";       // a downstream copy of ours
            if (age < quiet) return "ota dup";
        }
    }
    bool transfer = ota_is_transfer(p.payload[0]);
    if (!transfer) {                                              // discovery sheds load first
        int free_slots = 0; for (int i = 0; i < TXQ_SIZE; i++) free_slots += !txq[i].used;
        if (free_slots < 2) return "ota busy";
    }
    if (!e) { e = &ota_fwd[ota_fwd_next]; ota_fwd_next = (ota_fwd_next + 1) % OTA_FWD_SLOTS; }
    memcpy(e->h, h, 4); e->at = now; e->min_hops = p.hash_count; e->used = 1;
    uint8_t newpath[MAX_PATH_SIZE];
    memcpy(newpath, p.path, pbytes);
    memcpy(newpath + pbytes, own_pubkey, p.hash_size);
    int n = build(out_buf, p.header, p.tc, (p.path_len & 0xC0) | ((p.hash_count + 1) & 0x3F), newpath, pbytes + p.hash_size, p.payload, p.payload_len);
    if (n < 0) return "too big";
    uint32_t d = transfer ? delay_for(p, cfg.txdelay_x100) : rnd_range((air + 3) / 4, air / 2 + 1);
    txq_push(out_buf, n, transfer ? 0 : 250, d);                  // active transfer = primary priority
    stat_ota_relay++;
    return NULL;
}
#endif

static const char* handle_flood(const Pkt& p, int8_t snr4) {
    uint8_t h[8];
#ifdef SPECTER_XL
    if (p.ptype == PT_OTA) return handle_ota_flood(p);
#endif
    packet_hash(h, p.ptype, p.path_len, p.payload, p.payload_len);
    if (p.hash_count) rr_note(p.path + (p.hash_count - 1) * p.hash_size, p.hash_size, snr4);
    if (was_seen(h)) {
#ifdef SPECTER_XL
        if (more.rxdelay_x10 && better_copy(p, snr4)) return "better copy";
#endif
        if (p.ptype == PT_ADVERT) ag_echo(h, p.hash_count);
        return rt_echo(h, false, p.hash_count) ? "echo" : "dedup";
    }
#ifdef SPECTER_XL
    if (xl_type(p.ptype) && p.payload_len > 2 && p.payload[0] == own_pubkey[0]) {
        int scope = -1;
        if (p.tc[0])
            scope = region_match(p.tc[0], p.ptype, p.payload, p.payload_len);
        if (xl_handle_for_us(p, snr4, scope)) { mark_seen(h); stat_for_us++; return "for us"; }
    }
#endif
    if (!cfg.repeat) return "repeat off";
    if (fwd_paused(true)) return "battery";
    if (p.hash_count >= cfg.flood_max) return "flood.max";
    // Transport code 0 counts as un-scoped (RegionMap::findMatch, isFloodHopLimitExceeded):
    // un-scoped hop limit and the wildcard's flood policy apply.
    if (!p.tc[0] && p.hash_count >= cfg.flood_max_unscoped) return "flood.max.unscoped";
    if (p.ptype == PT_ADVERT && p.hash_count >= cfg.flood_max_advert) return "flood.max.advert";

    if (p.tc[0]) {
        if (region_match(p.tc[0], p.ptype, p.payload, p.payload_len) < 0) return "region";
    } else if (cfg.wildcard_flags & REGION_DENY_FLOOD) {
        return "unscoped denied";
    }

    if (cfg.loop_detect) {
        static const uint8_t max_loop[4][4] = { {0}, {0,4,2,1}, {0,2,1,1}, {0,1,1,1} };
        uint8_t n = 0;
        for (int k = 0; k < p.hash_count; k++)
            if (is_own_hash(p.path + k * p.hash_size, p.hash_size)) n++;
        if (n >= max_loop[cfg.loop_detect & 3][p.hash_size]) return "loop";
    }

    if (!flood_type_ok(p)) return "type";
    mark_seen(h);
    if (p.ptype == PT_ADVERT && ag_blocked(h)) { stat_adv_guard++; return "advert guard"; }
#ifdef SPECTER_XL
    if (!flood_rate_ok(p)) return "rate limit";
#endif

    if (p.ptype == PT_ADVERT && !advert_verify(p.payload, p.payload_len, p.hash_count)) return "advert sig";

    int pbytes = p.hash_count * p.hash_size;
    if (pbytes + p.hash_size > MAX_PATH_SIZE) return "path full";
    uint8_t newpath[MAX_PATH_SIZE];
    memcpy(newpath, p.path, pbytes);
    memcpy(newpath + pbytes, own_pubkey, p.hash_size);
    uint8_t new_len = (p.path_len & 0xC0) | ((p.hash_count + 1) & 0x3F);
    int n = build(out_buf, p.header, p.tc, new_len, newpath, pbytes + p.hash_size, p.payload, p.payload_len);
    if (n < 0) return "too big";
#ifdef SPECTER_XL
    uint8_t score = 0;
    uint32_t rxd = rx_delay_ms(p, snr4, &score);
    int q = txq_push(out_buf, n, p.hash_count + 1, delay_for(p, cfg.txdelay_x100) + rxd);
    if (q >= 0) txq[q].score = score;
#else
    int q = txq_push(out_buf, n, p.hash_count + 1, delay_for(p, cfg.txdelay_x100));
#endif
    if (p.ptype == PT_ADVERT) { uint32_t ts; memcpy(&ts, p.payload + 32, 4); ag_add(h, p.hash_count + 1, ts); }
    rt_create(h, q, false, p.hash_count + 1, flood_retry_count(p), 0);
    return NULL;
}

static void on_receive(const uint8_t* d, int len, int8_t snr4) {
    Pkt p;
    const char* why;
    if (!parse(d, len, p)) why = "malformed";
    else if (p.route == ROUTE_DIRECT || p.route == ROUTE_TRANSPORT_DIRECT) { stat_direct_rx++; why = handle_direct(p, snr4); }
    else { stat_flood_rx++; why = handle_flood(p, snr4); }
    if (why) { stat_drop++; LOG("  drop: "); LOGLN(why); }
    else     { stat_fwd++;  LOGLN("  fwd"); }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Adverts (Mesh::createAdvert + sendZeroHop / sendFloodScoped)
// ═════════════════════════════════════════════════════════════════════════════
static void send_advert(bool flood) {
    uint8_t payload[100 + MAX_ADVERT_DATA_SIZE];
    memcpy(payload, own_pubkey, 32);
    uint32_t ts = clock_now();
    memcpy(payload + 32, &ts, 4);
    int i = 100;
    bool has_loc = cfg.lat_e6 || cfg.lon_e6;
    payload[i++] = ADV_TYPE_REPEATER | ADV_NAME_MASK | (has_loc ? ADV_LATLON_MASK : 0);
    if (has_loc) { memcpy(payload + i, &cfg.lat_e6, 4); memcpy(payload + i + 4, &cfg.lon_e6, 4); i += 8; }
    int nlen = strlen(cfg.name), room = 100 + MAX_ADVERT_DATA_SIZE - i;
    if (nlen > room) nlen = room;
    memcpy(payload + i, cfg.name, nlen); i += nlen;

    uint8_t msg[36 + MAX_ADVERT_DATA_SIZE];
    memcpy(msg, payload, 36);
    memcpy(msg + 36, payload + 100, i - 100);
    IWatchdog.reload();
    Ed25519::sign(payload + 36, cfg.privkey, own_pubkey, msg, 36 + i - 100);

    uint8_t h[8];
    packet_hash(h, PT_ADVERT, 0, payload, i);
    mark_seen(h);

    int n;
    if (!flood) {
        n = build(out_buf, (PT_ADVERT << 2) | ROUTE_DIRECT, NULL, 0, NULL, 0, payload, i);
    } else {
        uint8_t path_len = (uint8_t)(cfg.path_hash_mode << 6);
        if (cfg.default_region < cfg.num_regions) {
            uint16_t tc[2] = { transport_code(region_keys[cfg.default_region], PT_ADVERT, payload, i), 0 };
            n = build(out_buf, (PT_ADVERT << 2) | ROUTE_TRANSPORT_FLOOD, tc, path_len, NULL, 0, payload, i);
        } else {
            n = build(out_buf, (PT_ADVERT << 2) | ROUTE_FLOOD, NULL, path_len, NULL, 0, payload, i);
        }
        j_last_flood_ts = ts;
        journal_write(ts, j_last_flood_ts);
    }
    txq_push(out_buf, n, 3, 0);
    LOGLN(flood ? "ADVERT flood" : "ADVERT zero-hop");
}

// ═════════════════════════════════════════════════════════════════════════════
//  Power: ADC (battery / VDD / temperature), low-voltage cutoff, standby
// ═════════════════════════════════════════════════════════════════════════════
#define CUTOFF_FLAG 0xC0FF          // kept in backup register DR1 across standby resets
#if defined(ARDUINO_ARCH_STM32)
static bool adc_ready = false;
static uint16_t adc_read(uint8_t ch) {            // direct registers: no HAL ADC needed
    if (!adc_ready) {
        RCC->CFGR = (RCC->CFGR & ~RCC_CFGR_ADCPRE) | RCC_CFGR_ADCPRE_DIV6;   // ADC clock ≤ 14 MHz
        RCC->APB2ENR |= RCC_APB2ENR_ADC1EN;
        ADC1->SMPR1 = 0x00FFFFFF;                  // 239.5-cycle sampling for all channels
        ADC1->SMPR2 = 0x3FFFFFFF;
        ADC1->CR2 = ADC_CR2_ADON | ADC_CR2_TSVREFE;
        delay(2);
        ADC1->CR2 |= ADC_CR2_RSTCAL; while (ADC1->CR2 & ADC_CR2_RSTCAL) {}
        ADC1->CR2 |= ADC_CR2_CAL;    while (ADC1->CR2 & ADC_CR2_CAL) {}
        adc_ready = true;
    }
    uint32_t sum = 0;
    ADC1->SQR3 = ch;
    for (int i = 0; i < 4; i++) {
        ADC1->CR2 |= ADC_CR2_ADON;                 // ADON again = start conversion
        uint32_t t0 = millis();
        while (!(ADC1->SR & ADC_SR_EOC)) if (millis() - t0 > 5) return 0;
        sum += ADC1->DR;
    }
    return sum / 4;
}
static void bkp_enable(void) {
    RCC->APB1ENR |= RCC_APB1ENR_PWREN | RCC_APB1ENR_BKPEN;
    PWR->CR |= PWR_CR_DBP;
}
static uint16_t bkp_read(void)        { bkp_enable(); return BKP->DR1; }
static void     bkp_write(uint16_t v) { bkp_enable(); BKP->DR1 = v; }
static uint16_t bkp_get(int n)        { bkp_enable(); return (&BKP->DR1)[n - 1]; }     // DR2, DR3 …
static void     bkp_set(int n, uint16_t v) { bkp_enable(); (&BKP->DR1)[n - 1] = v; }
static uint32_t reset_csr(void) { uint32_t c = RCC->CSR; RCC->CSR |= RCC_CSR_RMVF; return c; }
static void enter_standby(void) {                 // woken only by the watchdog reset (~26 s)
    IWatchdog.set(26000000);
    IWatchdog.reload();
    Serial1.flush();
    bkp_enable();
    PWR->CR |= PWR_CR_CWUF | PWR_CR_PDDS;
    SCB->SCR |= SCB_SCR_SLEEPDEEP_Msk;
    while (true) __WFI();
}
#else
uint16_t adc_read(uint8_t ch);                    // host tests provide these
uint16_t bkp_read(void);
void     bkp_write(uint16_t v);
uint16_t bkp_get(int n);
void     bkp_set(int n, uint16_t v);
uint32_t reset_csr(void);
void     enter_standby(void);
#endif

// Why did we (re)start? RCC->CSR flags plus two backup registers: DR2 marks a
// reboot we asked for, DR3 counts watchdog resets since power-on.
#define BKP_REBOOT_MARK 0xB007
static const char* reset_why = "?";
static uint16_t    wdt_resets = 0;
static void reset_reason_capture(bool cutoff_wake) {
    uint32_t c = reset_csr();
    uint16_t mark = bkp_get(2);
    bkp_set(2, 0);
    wdt_resets = bkp_get(3);
    if (c & (1UL << 27)) wdt_resets = 0;           // PORRSTF: backup domain may hold junk
    if (cutoff_wake)                reset_why = "low-battery standby";
    else if (c & (1UL << 27))       reset_why = "power-on / brownout";
    else if (c & (1UL << 29))       { reset_why = "watchdog"; wdt_resets++; }
    else if (c & (1UL << 31))       reset_why = "low-power";
    else if (mark == BKP_REBOOT_MARK) reset_why = "reboot command";
    else if (c & (1UL << 28))       reset_why = "software";
    else if (c & (1UL << 26))       reset_why = "reset pin";
    bkp_set(3, wdt_resets);
}
static void reboot_now(void) { bkp_set(2, BKP_REBOOT_MARK); NVIC_SystemReset(); }

// Put the SX1262 in cold sleep with raw SPI (works before/without radio.begin()).
static void radio_cold_sleep(void) {
    SPI.begin();
    pinMode(PIN_NSS, OUTPUT); digitalWrite(PIN_NSS, HIGH);
    digitalWrite(PIN_TXEN, LOW); digitalWrite(PIN_RXEN, LOW);
    uint32_t t0 = millis();
    while (digitalRead(PIN_BUSY) && millis() - t0 < 20) {}
    digitalWrite(PIN_NSS, LOW);
    SPI.transfer(0x84); SPI.transfer(0x00);       // SetSleep, cold start
    digitalWrite(PIN_NSS, HIGH);
}

static uint32_t vdd_mv(void) {
    uint32_t r = adc_read(17);                     // VREFINT ≈ 1.20 V
    return r ? 1200UL * 4095UL / r : 0;
}
// Battery mV: from the PB0/PB1 divider if configured, else the chip's own supply (VDD).
static uint32_t battery_mv(void) {
    uint32_t vdd = vdd_mv();
    if (!ext.bat_pin || !vdd) return vdd;
    return (uint32_t)adc_read(ext.bat_pin == 1 ? 8 : 9) * vdd / 4095UL * ext.bat_div_x100 / 100UL;
}
static int temp_c(void) {                         // internal sensor: V25 ≈ 1.43 V, 4.3 mV/°C (±several °C)
    int32_t vs = (int32_t)((uint32_t)adc_read(16) * vdd_mv() / 4095UL);
    return (int)((1430 - vs) * 10 / 43 + 25);
}

// Telemetry history: one sample every 30 min, 7 days, newest overwrites oldest.
#define TELE_N 336
#define TELE_IV_S 1800UL
static uint16_t tele_mv[TELE_N];
static int8_t   tele_t[TELE_N];
static uint16_t tele_head = 0, tele_count = 0;
static uint32_t next_tele_s = 60, next_batt_s = 30;
static uint8_t  low_count = 0;
static uint32_t last_batt_mv = 0;

static void tele_sample(void) {
    tele_mv[tele_head] = (uint16_t)battery_mv();
    tele_t[tele_head] = (int8_t)temp_c();
    tele_head = (tele_head + 1) % TELE_N;
    if (tele_count < TELE_N) tele_count++;
}

static uint16_t resume_mv(void) { return ext.resume_mv ? ext.resume_mv : ext.cut_mv + 200; }

#ifdef SPECTER_XL
static bool xl_alert(const char* text, bool urgent);
static void xl_alert_battery(uint32_t mv);
#endif
static void cutoff_shutdown(uint32_t mv) {
    Serial1.print("Battery low ("); Serial1.print(mv); Serial1.println(" mV): sleeping until it recovers");
#ifdef SPECTER_XL
    char t[64];
    sprintf(t, "battery %lu mV: shutting down until %u mV", (unsigned long)mv, resume_mv());
    if (xl_alert(t, true)) {                           // get it on the air before we sleep
        for (int i = 0; i < 20; i++) { delay(200); IWatchdog.reload(); txq_service(radio.getIrqFlags()); }
    }
#endif
    journal_write(clock_now(), j_last_flood_ts);
    bkp_write(CUTOFF_FLAG);
    radio_cold_sleep();
    digitalWrite(PIN_LED, LOW);
    enter_standby();
}

#ifdef SPECTER_XL
// Battery percentage between battery.empty and battery.full; 0xFF = no usable reading
// (no battery.pin set: the chip's own regulated supply says nothing about the battery).
static uint8_t bf_pct = 0xFF;
static uint8_t batt_pct(uint32_t mv) {
    if (bp.full_mv <= bp.empty_mv || mv >= bp.full_mv) return 100;
    if (mv <= bp.empty_mv) return 0;
    return (uint8_t)((mv - bp.empty_mv) * 100UL / (bp.full_mv - bp.empty_mv));
}
// Pause below the threshold; resume 2 points above it (capped at 100) to avoid flapping.
static bool bf_eval(bool was, uint8_t on, uint8_t below) {
    if (!on || bf_pct == 0xFF) return false;
    uint8_t resume = below + 2 > 100 ? 100 : below + 2;
    return was ? bf_pct < resume : bf_pct < below;
}
static void bf_update(uint32_t mv) {
    bf_pct = (ext.bat_pin && mv >= 2000 && mv <= 20000) ? batt_pct(mv) : 0xFF;
    bool r = bf_eval(bf_rep_paused, bp.rep_on, bp.rep_pct), f = bf_eval(bf_fl_paused, bp.fl_on, bp.fl_pct);
    if (r != bf_rep_paused || f != bf_fl_paused) LOGLN(r || f ? "battery: forwarding paused" : "battery: forwarding resumed");
    bf_rep_paused = r; bf_fl_paused = f;
}
#endif

// Every 30 s: three consecutive readings under battery.cutoff → standby.
static void battery_monitor(uint32_t up) {
    if ((int32_t)(up - next_batt_s) < 0) return;
    next_batt_s = up + 30;
    last_batt_mv = battery_mv();
#ifdef SPECTER_XL
    bf_update(last_batt_mv);
    xl_alert_battery(last_batt_mv);
#endif
    if (!ext.cut_mv || !last_batt_mv) { low_count = 0; return; }
    if (last_batt_mv < ext.cut_mv) { if (++low_count >= 3) cutoff_shutdown(last_batt_mv); }
    else low_count = 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Radio stats: noise floor (as upstream RadioLibWrapper: 64 idle RSSI samples,
//  ignoring readings more than 14 dB above the current floor)
// ═════════════════════════════════════════════════════════════════════════════
static uint8_t  nf_n = 0;
static int32_t  nf_sum = 0;
static uint32_t nf_next_ms = 0;
static void noise_floor_sample(uint32_t irq) {
    if ((int32_t)(millis() - nf_next_ms) < 0 || header_seen ||
        (irq & (RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID))) return;
    nf_next_ms = millis() + 250;
    int r = radio.rssiInst();
    if (noise_floor && r >= noise_floor + 14) return;
    nf_sum += r;
    if (++nf_n >= 64) {
        noise_floor = nf_sum / 64;
        if (noise_floor < -120) noise_floor = -120;
        nf_n = 0; nf_sum = 0;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Configuration defaults / load
// ═════════════════════════════════════════════════════════════════════════════
static void cfg_defaults(void) {
    memset(&cfg, 0, sizeof(cfg));
    cfg.magic = CFG_MAGIC;
    cfg.freq_khz = LORA_FREQ_KHZ;  cfg.bw_hz = LORA_BW_HZ;
    cfg.sf = LORA_SF;              cfg.cr = LORA_CR;
    cfg.tx_dbm = LORA_TX_POWER;
#if defined(NODE_LAT_I) && defined(NODE_LON_I)
    cfg.lat_e6 = NODE_LAT_I;       cfg.lon_e6 = NODE_LON_I;
#endif
    cfg.path_hash_mode = PATH_HASH_MODE;
    cfg.loop_detect = LOOP_DETECT;
    cfg.repeat = 1;
    cfg.wildcard_flags = ALLOW_UNSCOPED_FLOOD ? 0 : REGION_DENY_FLOOD;
    cfg.advert_interval_min = ADVERT_INTERVAL_MIN;
    cfg.flood_advert_h = FLOOD_ADVERT_INTERVAL_H;
    cfg.flood_max = FLOOD_MAX;     cfg.flood_max_unscoped = FLOOD_MAX_UNSCOPED;
    cfg.flood_max_advert = FLOOD_MAX_ADVERT;
    cfg.txdelay_x100 = TX_DELAY_X100;
    cfg.direct_txdelay_x100 = DIRECT_TX_DELAY_X100;
    cfg.af_x100 = AF_X100;
    cfg.default_region = 0xFF;

    const char* p = REGIONS;                       // "a,b,#c"
    while (*p && cfg.num_regions < MAX_REGIONS) {
        while (*p == ',' || *p == ' ' || *p == '#') p++;
        int n = 0;
        while (*p && *p != ',' && *p != ' ') { if (n < REGION_NAME - 1) cfg.regions[cfg.num_regions][n++] = *p; p++; }
        if (n) cfg.num_regions++;
    }
    regions_rekey();
    int d = region_find(DEFAULT_SCOPE);
    if (d >= 0) cfg.default_region = d;

    const uint32_t* uid = (const uint32_t*)UID_BASE;
#ifdef NODE_NAME_STR
    strncpy(cfg.name, NODE_NAME_STR, sizeof(cfg.name) - 1);
#else
    sprintf(cfg.name, "Spectra-%04X", (unsigned)(uid[2] & 0xFFFF));
#endif
    // Identity seed: UID only for now; setup() mixes in radio noise before saving.
    SHA256 sha;
    sha.reset();
    sha.update(uid, 12);
    sha.finalize(cfg.privkey, 32);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Serial CLI — same syntax and reply style as upstream MeshCore repeaters
// ═════════════════════════════════════════════════════════════════════════════
static bool reboot_pending = false;
static bool timers_dirty = false;

static bool valid_name(const char* n) {
    if (!*n) return false;
    for (; *n; n++) if (strchr("[]\\:,?*", *n) || *n < 0x20) return false;
    return true;
}

static int atoi_s(const char* s) {
    s = skip_ws(s);
    bool neg = (*s == '-');
    if (neg || *s == '+') s++;
    int v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return neg ? -v : v;
}

static int hexval(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
           (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

static int atoi_u(const char* s, bool* ok) {
    s = skip_ws(s);
    int v = 0; const char* st = s;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    *ok = (s != st) && *skip_ws(s) == 0;
    return v;
}

// Copy the next space-separated token into out; returns the rest of the string.
static const char* next_token(const char* s, char* out, int max) {
    s = skip_ws(s);
    int n = 0;
    while (*s && *s != ' ') { if (n < max - 1) out[n++] = *s; s++; }
    out[n] = 0;
    return s;
}

// Region list for "region list allowed|denied" and the anonymous regions query
// (RegionMap::exportNamesTo: the wildcard first, comma separated).
static void region_list(char* reply, int mask_deny, bool want_deny) {
    char* p = reply;
    if (!mask_deny || (bool)(cfg.wildcard_flags & REGION_DENY_FLOOD) == want_deny) { *p++ = '*'; *p++ = ','; }
    for (int i = 0; i < cfg.num_regions; i++) {
        bool deny = cfg.region_flags[i] & REGION_DENY_FLOOD;
        if (mask_deny && deny != want_deny) continue;
        if (p - reply > 120) break;
        p += sprintf(p, "%s,", cfg.regions[i]);
    }
    if (p > reply) p--;
    *p = 0;
    if (p == reply) strcpy(reply, "-none-");
}

// Hierarchy (RegionMap parent ids): the upper 4 bits of region_flags hold the
// parent's index + 1 (0 = the wildcard). ext.pad holds the home region + 1.
#define RF_PARENT(i)  ((int)(cfg.region_flags[i] >> 4) - 1)
static bool region_name_ok(const char* n) {        // RegionMap::is_name_char
    if (!*n) return false;
    for (; *n; n++) { uint8_t c = *n; if (!(c == '-' || c == '$' || c == '#' || (c >= '0' && c <= '9') || c >= 'A')) return false; }
    return true;
}
// findByNamePrefix: exact match preferred, else the last partial match. -2 = "*".
static int region_find_prefix(const char* nm) {
    if (!strcmp(nm, "*")) return -2;
    if (*nm == '#') nm++;
    int partial = -1, len = strlen(nm);
    for (int i = 0; i < cfg.num_regions; i++) {
        if (!strcmp(cfg.regions[i], nm)) return i;
        if (!strncmp(cfg.regions[i], nm, len)) partial = i;
    }
    return partial;
}
// putRegion: add under parent (-1 = wildcard), or re-parent an existing one. Returns index or -1.
static int region_put(const char* nm, int parent) {
    if (*nm == '#') nm++;
    if (!region_name_ok(nm) || strlen(nm) >= REGION_NAME) return -1;
    int i = region_find(nm);
    if (i >= 0) {
        if (i == parent) return -1;
    } else {
        if (cfg.num_regions >= MAX_REGIONS) return -1;
        i = cfg.num_regions++;
        strcpy(cfg.regions[i], nm);
        cfg.region_flags[i] = REGION_DENY_FLOOD;          // deny by default (putRegion)
        region_key_for(nm, region_keys[i]);
    }
    cfg.region_flags[i] = (uint8_t)(((parent + 1) << 4) | (cfg.region_flags[i] & REGION_DENY_FLOOD));
    return i;
}
static void region_tree(char*& p, int idx, int depth, const char* end) {   // printChildRegions
    if (p + REGION_NAME + 12 > end) return;
    for (int k = 0; k < depth; k++) *p++ = ' ';
    uint8_t f = idx < 0 ? cfg.wildcard_flags : cfg.region_flags[idx];
    p += sprintf(p, "%s%s%s\n", idx < 0 ? "*" : cfg.regions[idx], ext.pad == (uint8_t)(idx + 1) ? "^" : "",
                 (f & REGION_DENY_FLOOD) ? "" : " F");
    for (int i = 0; i < cfg.num_regions; i++) if (RF_PARENT(i) == idx) region_tree(p, i, depth + 1, end);
}
static void region_export(char* reply) {
    char* p = reply;
    region_tree(p, -1, 0, reply + 160);
    if (p > reply) p--;                               // drop the last newline
    *p = 0;
}

static bool    rl_active = false;
#ifdef SPECTER_XL
// "region load": indented lines replace the map, a blank line ends (MyMesh::handleCommand)
static uint8_t rl_n, rl_flags[MAX_REGIONS];
static char    rl_names[MAX_REGIONS][REGION_NAME];
static int8_t  rl_stack[8];                          // index per indent level; -1 wildcard, -2 unset
static bool region_load_line(const char* line, char* reply) {
    reply[0] = 0;
    const char* np = line;
    while (*np == ' ') np++;
    if (!*np) {                                       // finish: swap the new map in
        char def[REGION_NAME], home[REGION_NAME];
        strcpy(def, cfg.default_region < cfg.num_regions ? cfg.regions[cfg.default_region] : "");
        strcpy(home, ext.pad && ext.pad <= cfg.num_regions ? cfg.regions[ext.pad - 1] : "");
        cfg.num_regions = rl_n;
        memcpy(cfg.regions, rl_names, sizeof(rl_names));
        memcpy(cfg.region_flags, rl_flags, sizeof(rl_flags));
        regions_rekey();
        int d = def[0] ? region_find(def) : -1, h = home[0] ? region_find(home) : -1;
        cfg.default_region = d >= 0 ? d : 0xFF;
        ext.pad = h >= 0 ? h + 1 : 0;
        rl_active = false;
        sprintf(reply, "OK - loaded %d regions", rl_n);
        return true;
    }
    int indent = np - line;
    char nm[REGION_NAME + 2]; int n = 0;
    const char* ep = np;
    while (*ep && *ep != ' ' && n < REGION_NAME + 1) nm[n++] = *ep++;
    nm[n] = 0;
    while (*ep && *ep != 'F') ep++;
    const char* name = nm[0] == '#' ? nm + 1 : nm;
    if (indent > 0 && indent < 8 && rl_stack[indent - 1] != -2 && region_name_ok(name) && strlen(name) < REGION_NAME) {
        int i = 0;
        while (i < rl_n && strcmp(rl_names[i], name)) i++;
        if (i == rl_n && rl_n < MAX_REGIONS) {
            int old = region_find(name);
            strcpy(rl_names[i], name);
            rl_flags[i] = old >= 0 ? (cfg.region_flags[old] & REGION_DENY_FLOOD) : (*ep == 'F' ? 0 : REGION_DENY_FLOOD);
            rl_n++;
        }
        if (i < rl_n) {
            rl_flags[i] = (uint8_t)(((rl_stack[indent - 1] + 1) << 4) | (rl_flags[i] & REGION_DENY_FLOOD));
            rl_stack[indent] = i;
            for (int k = indent + 1; k < 8; k++) rl_stack[k] = -2;
        }
    }
    return true;
}
#endif

static void handle_region(const char* args, char* reply) {
    char a1[16], a2[REGION_NAME + 2], a3[REGION_NAME + 2];
    const char* rest = next_token(args, a1, sizeof(a1));
#ifdef SPECTER_XL
    if (!strcmp(a1, "def")) {                        // region def a b|jump c,jump …
        const char* q = skip_ws(rest);
        if (!*q) { strcpy(reply, "Err - empty def"); return; }
        int cur = -1;
        while (*(q = skip_ws(q))) {
            char tok[2 * REGION_NAME + 4]; int n = 0;
            while (*q && *q != ' ') { if (n < (int)sizeof(tok) - 1) tok[n++] = *q; q++; }
            tok[n] = 0;
            char* jump = NULL;
            for (char* c = tok; *c; c++) if (*c == '|' || *c == ',') { *c = 0; jump = c + 1; break; }
            if (!tok[0]) { strcpy(reply, "Err - empty name"); return; }
            if (jump && !*jump) { strcpy(reply, "Err - empty jump"); return; }
            int r = region_put(tok, cur);
            if (r < 0) { sprintf(reply, "Err - put failed: %s", tok); return; }
            cfg.region_flags[r] &= ~REGION_DENY_FLOOD;
            if (jump) {
                int j = region_find_prefix(jump);
                if (j == -1) { sprintf(reply, "Err - unknown jump: %s", jump); return; }
                cur = j == -2 ? -1 : j;
            } else cur = r;
        }
        region_export(reply);
        return;
    }
#endif
    rest = next_token(rest, a2, sizeof(a2));
    next_token(rest, a3, sizeof(a3));
    int idx = region_find_prefix(a2);

    if (!a1[0]) {
        region_export(reply);
#ifdef SPECTER_XL
    } else if (!strcmp(a1, "load")) {
        rl_active = true; rl_n = 0;
        memset(rl_names, 0, sizeof(rl_names)); memset(rl_flags, 0, sizeof(rl_flags));
        memset(rl_stack, -2, sizeof(rl_stack)); rl_stack[0] = -1;
        reply[0] = 0;
#endif
    } else if (!strcmp(a1, "save")) {
        cfg_save();
#ifdef SPECTER_XL
        xl_acl_touch_regions();                     // discovery "modified since" time
#endif
        strcpy(reply, "OK");
    } else if (!strcmp(a1, "put") && a2[0]) {
        int parent = -1;
        if (a3[0]) { parent = region_find_prefix(a3); if (parent == -1) { strcpy(reply, "Err - unknown parent"); return; } if (parent == -2) parent = -1; }
        int r = region_put(a2, parent);
        if (r < 0) { strcpy(reply, "Err - unable to put"); return; }
        cfg.region_flags[r] &= ~REGION_DENY_FLOOD;
        strcpy(reply, "OK - (flood allowed)");
    } else if (!strcmp(a1, "remove") && a2[0]) {
        idx = region_find(a2);
        if (idx < 0) { strcpy(reply, "Err - not found"); return; }
        for (int i = 0; i < cfg.num_regions; i++) if (RF_PARENT(i) == idx) { strcpy(reply, "Err - not empty"); return; }
        for (int i = idx; i + 1 < cfg.num_regions; i++) {
            strcpy(cfg.regions[i], cfg.regions[i + 1]);
            cfg.region_flags[i] = cfg.region_flags[i + 1];
            memcpy(region_keys[i], region_keys[i + 1], 16);
        }
        cfg.num_regions--;
        for (int i = 0; i < cfg.num_regions; i++)
            if (RF_PARENT(i) > idx) cfg.region_flags[i] -= 0x10;
        if (cfg.default_region == idx) cfg.default_region = 0xFF;
        else if (cfg.default_region != 0xFF && cfg.default_region > idx) cfg.default_region--;
        if (ext.pad == idx + 1) ext.pad = 0; else if (ext.pad > idx + 1) ext.pad--;
        strcpy(reply, "OK");
    } else if ((!strcmp(a1, "allowf") || !strcmp(a1, "denyf")) && a2[0]) {
        uint8_t* f = idx == -2 ? &cfg.wildcard_flags : (idx >= 0 ? &cfg.region_flags[idx] : NULL);
        if (!f) { strcpy(reply, "Err - unknown region"); return; }
        if (a1[0] == 'a') *f &= ~REGION_DENY_FLOOD; else *f |= REGION_DENY_FLOOD;
        strcpy(reply, "OK");
    } else if (!strcmp(a1, "get") && a2[0]) {
        if (idx == -2) sprintf(reply, " * %s", (cfg.wildcard_flags & REGION_DENY_FLOOD) ? "" : "F");
        else if (idx < 0) strcpy(reply, "Err - unknown region");
        else if (RF_PARENT(idx) >= 0) sprintf(reply, " %s (%s) %s", cfg.regions[idx], cfg.regions[RF_PARENT(idx)], (cfg.region_flags[idx] & REGION_DENY_FLOOD) ? "" : "F");
        else sprintf(reply, " %s %s", cfg.regions[idx], (cfg.region_flags[idx] & REGION_DENY_FLOOD) ? "" : "F");
    } else if (!strcmp(a1, "home")) {
        if (!a2[0]) { sprintf(reply, " home is %s", ext.pad && ext.pad <= cfg.num_regions ? cfg.regions[ext.pad - 1] : "*"); return; }
        if (idx == -1) { strcpy(reply, "Err - unknown region"); return; }
        ext.pad = idx == -2 ? 0 : idx + 1;
        sprintf(reply, " home is now %s", idx == -2 ? "*" : cfg.regions[idx]);
    } else if (!strcmp(a1, "default")) {
        if (!a2[0]) {
            sprintf(reply, " default scope is %s", cfg.default_region < cfg.num_regions ? cfg.regions[cfg.default_region] : "<null>");
            return;
        }
        if (!strcmp(a2, "<null>")) {
            cfg.default_region = 0xFF;
        } else {
            if (idx < 0) idx = region_put(a2, -1);            // auto-create, as upstream
            if (idx < 0) { strcpy(reply, "Err - region table full"); return; }
            if (cfg.regions[idx][0] == '$') { strcpy(reply, "Err - private region has no key"); return; }
            cfg.region_flags[idx] &= ~REGION_DENY_FLOOD;
            cfg.default_region = idx;
        }
        cfg_save();
        sprintf(reply, " default scope is now %s", cfg.default_region == 0xFF ? "<null>" : cfg.regions[idx]);
    } else if (!strcmp(a1, "list") && (!strcmp(a2, "allowed") || !strcmp(a2, "denied"))) {
        region_list(reply, 1, a2[0] == 'd');
    } else {
        strcpy(reply, "Err - ??");
    }
}

// Retry / clock-sync settings (stored in ConfigExt), same names as mikecarper/MeshCore.
enum { EK_U8, EK_U16, EK_U32, EK_ONOFF, EK_U8OFF };
struct ExtKey { const char* k; uint8_t off, kind; uint16_t lo, hi; bool retry; };
static const ExtKey ext_keys[] = {
    { "direct.retry.heard",     offsetof(ConfigExt, d_heard),     EK_ONOFF, 0, 1,    true  },
    { "direct.retry.margin",    offsetof(ConfigExt, d_margin),    EK_U8,    0, 40,   true  },
    { "direct.retry.count",     offsetof(ConfigExt, d_count),     EK_U8,    0, 15,   true  },
    { "direct.retry.base",      offsetof(ConfigExt, d_base_ms),   EK_U16,   10, 5000, true },
    { "direct.retry.step",      offsetof(ConfigExt, d_step_ms),   EK_U16,   0, 5000, true  },
    { "direct.retry.cr",        offsetof(ConfigExt, d_cr),        EK_ONOFF, 0, 1,    true  },
    { "flood.retry.count",      offsetof(ConfigExt, f_count),     EK_U8,    0, 15,   true  },
    { "flood.retry.path",       offsetof(ConfigExt, f_path),      EK_U8OFF, 0, 63,   true  },
    { "flood.retry.group.path", offsetof(ConfigExt, f_gpath),     EK_U8OFF, 0, 63,   true  },
    { "flood.retry.advert",     offsetof(ConfigExt, f_advert),    EK_ONOFF, 0, 1,    true  },
    { "clock.sync.mesh",        offsetof(ConfigExt, clk_on),      EK_ONOFF, 0, 1,    false },
    { "clock.sync.samples",     offsetof(ConfigExt, clk_samples), EK_U8,    3, 16,   false },
    { "clock.sync.drift",       offsetof(ConfigExt, clk_drift_s), EK_U32,   30, 0,   false },  // hi 0 → 86400
};
static const char* const preset_names[] = { "infra", "rooftop", "mobile" };

static const ExtKey* ext_find(const char* k) {
    for (unsigned i = 0; i < sizeof(ext_keys) / sizeof(ext_keys[0]); i++)
        if (!strcmp(k, ext_keys[i].k)) return &ext_keys[i];
    return NULL;
}

static void ext_get(const ExtKey* e, char* reply) {
    uint8_t* f = (uint8_t*)&ext + e->off;
    uint32_t v = e->kind == EK_U16 ? *(uint16_t*)f : e->kind == EK_U32 ? *(uint32_t*)f : *f;
    if (e->kind == EK_ONOFF) sprintf(reply, "> %s", v ? "on" : "off");
    else if (e->kind == EK_U8OFF && v == 255) strcpy(reply, "> off");
    else sprintf(reply, "> %lu", (unsigned long)v);
}

// Returns false (with reply set) on a bad value.
static bool ext_set(const ExtKey* e, const char* v, char* reply) {
    uint8_t* f = (uint8_t*)&ext + e->off;
    uint32_t hi = e->hi ? e->hi : 86400UL, x;
    if (e->kind == EK_ONOFF) {
        if (!strcmp(v, "on")) x = 1; else if (!strcmp(v, "off")) x = 0;
        else { strcpy(reply, "Error, use on/off"); return false; }
    } else if (e->kind == EK_U8OFF && !strcmp(v, "off")) {
        x = 255;
    } else {
        bool ok; x = (uint32_t)atoi_u(v, &ok);
        if (!ok || x < e->lo || x > hi) { sprintf(reply, "Error, range %u-%lu", e->lo, (unsigned long)hi); return false; }
    }
    if (e->kind == EK_U16) *(uint16_t*)f = x; else if (e->kind == EK_U32) *(uint32_t*)f = x; else *f = x;
    if (e->retry) ext.preset = 255;
    return true;
}

static void clock_status(char* reply) {
    static const char* const why[] = { "waiting", "set", "in-sync", "no-consensus", "manual", "off" };
    const char* codes = "wsknmo";
    clock_sync_eval();
    sprintf(reply, "> %s samples=%u/%u agree=%u", why[strchr(codes, cs_reason) - codes],
            cs_last_fresh, ext.clk_samples, cs_last_agree);
    if (cs_last_up) sprintf(reply + strlen(reply), " last=%lds %lus ago", (long)cs_last_delta,
                            (unsigned long)(uptime_s() - cs_last_up));
}

#ifdef SPECTER_XL
static void handle_command_from(char* cmd, char* reply, uint32_t sender_ts);
#include "xl_admin.inc"
#endif

static void handle_get(const char* k, char* reply) {
    char a[16], b[16];
    const ExtKey* e = ext_find(k);
    if (e) { ext_get(e, reply); return; }
    if (!strcmp(k, "retry.preset")) { sprintf(reply, "> %s", ext.preset < 3 ? preset_names[ext.preset] : "custom"); return; }
    if (!strcmp(k, "clock.sync.status")) { clock_status(reply); return; }
    if (!strcmp(k, "battery")) {
        sprintf(reply, "> %lu mV (%s)", (unsigned long)battery_mv(), ext.bat_pin ? (ext.bat_pin == 1 ? "PB0" : "PB1") : "VDD");
        return;
    }
    if (!strcmp(k, "battery.pin")) { strcpy(reply, ext.bat_pin ? (ext.bat_pin == 1 ? "> pb0" : "> pb1") : "> off"); return; }
    if (!strcmp(k, "battery.divider")) { sprintf(reply, "> %s", fmt_fixed(a, ext.bat_div_x100, 2)); return; }
    if (!strcmp(k, "battery.cutoff")) { if (ext.cut_mv) sprintf(reply, "> %u", ext.cut_mv); else strcpy(reply, "> off"); return; }
    if (!strcmp(k, "battery.resume")) { sprintf(reply, "> %u", resume_mv()); return; }
    if (!strncmp(k, "telemetry.volt", 14) || !strncmp(k, "telemetry.temp", 14)) {
        bool volt = k[10] == 'v';
        int page = atoi_s(k + 14), pages = (tele_count + 19) / 20;
        if (page < 1) page = 1;
        if (!tele_count) { strcpy(reply, "> no samples yet"); return; }
        if (page > pages) { strcpy(reply, "Error, no such page"); return; }
        char* p = reply + sprintf(reply, "> p%d/%d 30min newest-first:", page, pages);
        for (int i = (page - 1) * 20; i < tele_count && i < page * 20; i++) {
            int idx = (tele_head + TELE_N - 1 - i) % TELE_N;
            if (volt) p += sprintf(p, " %s", fmt_fixed(a, tele_mv[idx] / 10, 2));
            else p += sprintf(p, " %d", tele_t[idx]);
        }
        return;
    }
    if (!strcmp(k, "recent.repeater")) {
        char* p = reply; *p++ = '>';
        uint32_t up = uptime_s(), shown = 0;              // newest first, prefix:SNR(dB)
        while (p - reply < 140) {
            int best = -1;
            for (int i = 0; i < RR_SLOTS; i++)
                if (rr[i].len && up - rr[i].up <= 86400UL && !(shown & (1UL << i)) && (best < 0 || rr[i].up > rr[best].up)) best = i;
            if (best < 0) break;
            shown |= 1UL << best;
            *p++ = ' '; to_hex(p, rr[best].pfx, rr[best].len); p += rr[best].len * 2;
            p += sprintf(p, ":%d", rr[best].snr4 / 4);
        }
        *p = 0;
        if (p == reply + 1) strcpy(reply, "> none");
        return;
    }
    if      (!strcmp(k, "name"))   sprintf(reply, "> %s", cfg.name);
    else if (!strcmp(k, "lat"))    sprintf(reply, "> %s", fmt_fixed(a, cfg.lat_e6, 6));
    else if (!strcmp(k, "lon"))    sprintf(reply, "> %s", fmt_fixed(a, cfg.lon_e6, 6));
    else if (!strcmp(k, "radio")) {
#ifdef SPECTER_XL
        if (tr_active) { sprintf(reply, "> %s,%s,%d,%d (temp: ", fmt_fixed(a, tr_freq, 3), fmt_fixed(b, tr_bw, 3), tr_sf, tr_cr);
                         sprintf(reply + strlen(reply), "%s,%s,%d,%d)", fmt_fixed(a, cfg.freq_khz, 3), fmt_fixed(b, cfg.bw_hz, 3), cfg.sf, cfg.cr); }
        else
#endif
        sprintf(reply, "> %s,%s,%d,%d", fmt_fixed(a, cfg.freq_khz, 3), fmt_fixed(b, cfg.bw_hz, 3), cfg.sf, cfg.cr);
    }
    else if (!strcmp(k, "freq"))   sprintf(reply, "> %s", fmt_fixed(a, cfg.freq_khz, 3));
    else if (!strcmp(k, "tx"))     sprintf(reply, "> %d", cfg.tx_dbm);
    else if (!strcmp(k, "repeat")) sprintf(reply, "> %s", cfg.repeat ? "on" : "off");
    else if (!strcmp(k, "advert.interval"))       sprintf(reply, "> %d", cfg.advert_interval_min);
    else if (!strcmp(k, "flood.advert.interval")) sprintf(reply, "> %d", cfg.flood_advert_h);
    else if (!strcmp(k, "flood.max"))             sprintf(reply, "> %d", cfg.flood_max);
    else if (!strcmp(k, "flood.max.unscoped"))    sprintf(reply, "> %d", cfg.flood_max_unscoped);
    else if (!strcmp(k, "flood.max.advert"))      sprintf(reply, "> %d", cfg.flood_max_advert);
    else if (!strcmp(k, "txdelay"))        sprintf(reply, "> %s", fmt_fixed(a, cfg.txdelay_x100, 2));
    else if (!strcmp(k, "direct.txdelay")) sprintf(reply, "> %s", fmt_fixed(a, cfg.direct_txdelay_x100, 2));
    else if (!strcmp(k, "af"))             sprintf(reply, "> %s", fmt_fixed(a, cfg.af_x100, 2));
    else if (!strcmp(k, "path.hash.mode")) sprintf(reply, "> %d", cfg.path_hash_mode);
    else if (!strcmp(k, "loop.detect")) {
        static const char* const ld[] = { "off", "minimal", "moderate", "strict" };
        sprintf(reply, "> %s", ld[cfg.loop_detect & 3]);
    }
    else if (!strcmp(k, "dutycycle")) {
        uint32_t d = (100000UL + (100UL + cfg.af_x100) / 2) / (100UL + cfg.af_x100);   // percent x10
        sprintf(reply, "> %lu.%lu%%", (unsigned long)(d / 10), (unsigned long)(d % 10));
    }
#ifdef SPECTER_XL
    else if (!strcmp(k, "guest.password"))     sprintf(reply, "> %s", auth.guest_pw);
    else if (!strcmp(k, "allow.read.only"))    sprintf(reply, "> %s", app.allow_ro ? "on" : "off");
    else if (!strcmp(k, "radio.rxgain"))       sprintf(reply, "> %s", app.rxgain ? "on" : "off");
    else if (!strcmp(k, "multi.acks"))         sprintf(reply, "> %d", app.multi_acks);
    else if (!strcmp(k, "int.thresh"))         sprintf(reply, "> %d", app.int_thresh);
    else if (!strcmp(k, "agc.reset.interval")) sprintf(reply, "> %u", app.agc_s);
    else if (!strcmp(k, "alert.channel"))      sprintf(reply, "> %s", more.key_len ? more.label : "off");
    else if (!strcmp(k, "alerts"))             sprintf(reply, "> %s%s", more.alerts ? "on" : "off", more.key_len ? "" : " (no alert.channel set)");
    else if (!strcmp(k, "alert.battery")) {
        uint16_t th = xl_alert_threshold();
        if (more.alert_mv == 1) strcpy(reply, "> off");
        else if (more.alert_mv) sprintf(reply, "> %u", th);
        else if (th) sprintf(reply, "> auto (%u)", th);
        else strcpy(reply, "> auto (off until battery.cutoff is set)");
    }
    else if (!strcmp(k, "cad"))     sprintf(reply, "> %s (busy %lu)", more.cad ? "on" : "off", (unsigned long)stat_cad_busy);
    else if (!strcmp(k, "rxdelay")) {
        char a2[12]; sprintf(reply, "> %s (better copies %lu)", fmt_fixed(a2, more.rxdelay_x10, 1), (unsigned long)stat_better);
    }
    else if (!strcmp(k, "radio.watchdog")) {
        if (app.radio_wd_h == 0xFFFF) strcpy(reply, "> off");
        else sprintf(reply, "> %u h (fired %lu)", app.radio_wd_h ? app.radio_wd_h : 6, (unsigned long)stat_radio_wd);
    }
    else if (!strcmp(k, "flood.ratelimit")) {
        if (more.flood_rl) sprintf(reply, "> %u (dropped %lu)", more.flood_rl, (unsigned long)stat_rl_drop);
        else strcpy(reply, "> off");
    }
    else if (!strcmp(k, "owner.info")) {
        char* p = reply; *p++ = '>'; *p++ = ' ';
        for (const char* q = app.owner_info; *q; q++) *p++ = (*q == '\n') ? '|' : *q;
        *p = 0;
    }
    else if (!strcmp(k, "repeat.battery") || !strcmp(k, "flood.battery")) {
        bool r = k[0] == 'r';
        sprintf(reply, "> %s below=%u%%", (r ? bp.rep_on : bp.fl_on) ? "on" : "off", r ? bp.rep_pct : bp.fl_pct);
    }
    else if (!strcmp(k, "battery.empty")) sprintf(reply, "> %u", bp.empty_mv);
    else if (!strcmp(k, "battery.full"))  sprintf(reply, "> %u", bp.full_mv);
    else if (!strcmp(k, "battery.forward")) {
        last_batt_mv = battery_mv();
        bf_update(last_batt_mv);
        char pc[8] = "unknown";
        if (bf_pct != 0xFF) sprintf(pc, "%u%%", bf_pct);
        sprintf(reply, "> battery=%s mv=%lu repeat=%s flood=%s", pc, (unsigned long)last_batt_mv,
                bf_rep_paused ? "blocked" : "allowed", bf_rep_paused || bf_fl_paused ? "blocked" : "allowed");
    }
    else if (!strcmp(k, "guest")) sprintf(reply, "> %s", bp.guest_on ? "on" : "off");
    else if (!strncmp(k, "guests", 6) && (!k[6] || k[6] == ' ')) xl_guests_get(k + 6, reply);
    else if (!strncmp(k, "logins", 6) && (!k[6] || k[6] == ' ')) xl_logins_get(k + 6, reply);
#endif
    else if (!strcmp(k, "reset.reason")) sprintf(reply, "> %s (watchdog resets since power-on: %u)", reset_why, wdt_resets);
    else if (!strcmp(k, "public.key")) { strcpy(reply, "> "); to_hex(reply + 2, own_pubkey, 32); }
    else if (!strcmp(k, "prv.key"))    { strcpy(reply, "> "); to_hex(reply + 2, cfg.privkey, 32); }
    else if (!strcmp(k, "role"))       strcpy(reply, "> repeater");
    else strcpy(reply, "??: unknown config");
}

static void handle_set(const char* cmd, char* reply) {
    char k[24];
    const char* v = cmd;
    int n = 0;
    while (*v && *v != ' ' && n < (int)sizeof(k) - 1) k[n++] = *v++;
    k[n] = 0;
    v = skip_ws(v);
    int32_t x; bool ok;
    int iv = atoi_u(v, &ok);
    const char* done = "OK";
    const ExtKey* e = ext_find(k);

    if (e) {
        if (!ext_set(e, v, reply)) return;
    } else if (!strcmp(k, "battery.pin")) {
        if (!strcmp(v, "off")) ext.bat_pin = 0; else if (!strcmp(v, "pb0")) ext.bat_pin = 1;
        else if (!strcmp(v, "pb1")) ext.bat_pin = 2; else { strcpy(reply, "Error, use off, pb0 or pb1"); return; }
        if (ext.bat_pin) pinMode(ext.bat_pin == 1 ? PB0 : PB1, INPUT_ANALOG);
    } else if (!strcmp(k, "battery.divider")) {
        if (!parse_fixed(v, 2, &x) || x < 100 || x > 1000) { strcpy(reply, "Error, range 1.00-10.00"); return; }
        ext.bat_div_x100 = x;
    } else if (!strcmp(k, "battery.cutoff") || !strcmp(k, "battery.resume")) {
        uint16_t mv = 0;
        if (strcmp(v, "off")) {
            if (!ok || iv < 2000 || iv > 4500) { strcpy(reply, "Error, 2000-4500 mV or off"); return; }
            mv = iv;
        }
        if (k[8] == 'c') ext.cut_mv = mv; else ext.resume_mv = mv;
        if (ext.cut_mv && resume_mv() <= ext.cut_mv) { strcpy(reply, "Warning: resume must be above cutoff"); cfg_save(); return; }
    } else if (!strcmp(k, "retry.preset")) {
        int pr = 0;
        while (pr < 3 && strcmp(v, preset_names[pr]) && !(v[0] == '0' + pr && !v[1])) pr++;
        if (pr == 3) { strcpy(reply, "Error, use infra, rooftop or mobile"); return; }
        ext_apply_preset(pr);
    } else if (!strcmp(k, "name")) {
        if (!valid_name(v) || strlen(v) >= sizeof(cfg.name)) { strcpy(reply, "Error, bad chars"); return; }
        strcpy(cfg.name, v);
    } else if (!strcmp(k, "lat") || !strcmp(k, "lon")) {
        if (!parse_fixed(v, 6, &x) || x < -180000000 || x > 180000000) { strcpy(reply, "Error, bad value"); return; }
        if (k[1] == 'a') cfg.lat_e6 = x; else cfg.lon_e6 = x;
    } else if (!strcmp(k, "radio")) {
#ifdef SPECTER_XL
        if (tr_active || tr_apply_at) {                   // a real change cancels tempradio
            if (tr_active) { tr_swap(); radio_init(); rx_start(); }
            tr_active = false; tr_apply_at = 0;
        }
#endif
        int32_t f, bw; int sf = 0, cr = 0;
        const char* c1 = strchr(v, ','); const char* c2 = c1 ? strchr(c1 + 1, ',') : NULL;
        const char* c3 = c2 ? strchr(c2 + 1, ',') : NULL;
        if (!c3 || !parse_fixed(v, 3, &f) || !parse_fixed(c1 + 1, 3, &bw)) { strcpy(reply, "Error, invalid radio params"); return; }
        sf = atoi_s(c2 + 1); cr = atoi_s(c3 + 1);
        if (f < 150000 || f > 960000 || sf < 5 || sf > 12 || cr < 5 || cr > 8 || bw < 7000 || bw > 500000) {
            strcpy(reply, "Error, invalid radio params"); return;
        }
        cfg.freq_khz = f; cfg.bw_hz = bw; cfg.sf = sf; cfg.cr = cr;
        done = "OK - reboot to apply";
    } else if (!strcmp(k, "freq")) {
        if (!parse_fixed(v, 3, &x) || x < 150000 || x > 960000) { strcpy(reply, "Error, bad value"); return; }
        cfg.freq_khz = x;
        done = "OK - reboot to apply";
    } else if (!strcmp(k, "tx")) {
        int t = atoi_s(v);
        if (t < -9 || t > 22) { strcpy(reply, "Error, must be -9..22"); return; }
        cfg.tx_dbm = t;
        radio.setOutputPower(t);
    } else if (!strcmp(k, "repeat")) {
        cfg.repeat = !strncmp(v, "on", 2);
        done = cfg.repeat ? "OK - repeat is now ON" : "OK - repeat is now OFF";
    } else if (!strcmp(k, "advert.interval")) {
        if (!ok || (iv > 0 && iv < 2) || iv > 240) { strcpy(reply, "Error: interval range is 2-240 minutes"); return; }
        cfg.advert_interval_min = iv;
        timers_dirty = true;
    } else if (!strcmp(k, "flood.advert.interval")) {
        if (!ok || (iv > 0 && iv < 3) || iv > 168) { strcpy(reply, "Error: interval range is 3-168 hours"); return; }
        cfg.flood_advert_h = iv;
        timers_dirty = true;
    } else if (!strcmp(k, "flood.max") || !strcmp(k, "flood.max.unscoped") || !strcmp(k, "flood.max.advert")) {
        if (!ok || iv > 64) { strcpy(reply, "Error, max 64"); return; }
        if (k[9] == 0) cfg.flood_max = iv; else if (k[10] == 'u') cfg.flood_max_unscoped = iv; else cfg.flood_max_advert = iv;
    } else if (!strcmp(k, "txdelay") || !strcmp(k, "direct.txdelay")) {
        if (!parse_fixed(v, 2, &x) || x < 0 || x > 200) { strcpy(reply, "Error, must be 0-2"); return; }
        if (k[0] == 't') cfg.txdelay_x100 = x; else cfg.direct_txdelay_x100 = x;
    } else if (!strcmp(k, "af")) {
        if (!parse_fixed(v, 2, &x) || x < 0 || x > 900) { strcpy(reply, "ERROR: af must be 0-9"); return; }
        cfg.af_x100 = x;
    } else if (!strcmp(k, "path.hash.mode")) {
        if (!ok || iv > 2) { strcpy(reply, "Error, must be 0,1, or 2"); return; }
        cfg.path_hash_mode = iv;
    } else if (!strcmp(k, "loop.detect")) {
        static const char* const ld[] = { "off", "minimal", "moderate", "strict" };
        int i = 0;
        while (i < 4 && strcmp(v, ld[i])) i++;
        if (i == 4) { strcpy(reply, "Error, must be off, minimal, moderate or strict"); return; }
        cfg.loop_detect = i;
    } else if (!strcmp(k, "prv.key")) {
        uint8_t key[32];
        if (strlen(v) != 64) { strcpy(reply, "Error, bad key"); return; }
        for (int i = 0; i < 32; i++) {
            int hi = hexval(v[2*i]), lo = hexval(v[2*i+1]);
            if (hi < 0 || lo < 0) { strcpy(reply, "Error, bad key"); return; }
            key[i] = (uint8_t)(hi << 4 | lo);
        }
        memcpy(cfg.privkey, key, 32);
        done = "OK, reboot to apply!";
    } else if (!strcmp(k, "dutycycle")) {
        if (!parse_fixed(v, 1, &x) || x < 10 || x > 1000) { strcpy(reply, "ERROR: dutycycle must be 1-100"); return; }
        cfg.af_x100 = (uint16_t)(100000L / x - 100);
        cfg_save();
        uint32_t d = (100000UL + (100UL + cfg.af_x100) / 2) / (100UL + cfg.af_x100);
        sprintf(reply, "OK - %lu.%lu%%", (unsigned long)(d / 10), (unsigned long)(d % 10));
        return;
#ifdef SPECTER_XL
    } else if (!strcmp(k, "allow.read.only")) {
        app.allow_ro = !strncmp(v, "on", 2);
    } else if (!strcmp(k, "multi.acks")) {
        if (!ok || iv > 1) { strcpy(reply, "Error, must be 0 or 1"); return; }
        app.multi_acks = iv;
    } else if (!strcmp(k, "radio.rxgain")) {
        app.rxgain = !strncmp(v, "on", 2);
        radio.setRxBoostedGainMode(app.rxgain);
        rx_start();
    } else if (!strcmp(k, "int.thresh")) {
        if (!ok || iv > 60) { strcpy(reply, "Error, range 0-60 dB (0 = off)"); return; }
        app.int_thresh = iv;
    } else if (!strcmp(k, "agc.reset.interval")) {
        if (!ok) { strcpy(reply, "Error, range 0-1020 seconds"); return; }
        if (iv > 1020) iv = 1020;                    // CommonRadioPrefs: constrain(secs, 0, 255 * 4)
        app.agc_s = iv / 4 * 4;
        cfg_save();
        sprintf(reply, "OK - interval rounded to %u", app.agc_s);
        return;
    } else if (!strcmp(k, "alert.channel")) {
        if (!xl_set_alert_channel(v)) { strcpy(reply, "Error: use #name, public, a 32/64-hex key, or off"); return; }
    } else if (!strcmp(k, "alerts")) {
        if (strcmp(v, "on") && strcmp(v, "off")) { strcpy(reply, "Error: on or off"); return; }
        more.alerts = v[1] == 'n';
    } else if (!strcmp(k, "alert.battery")) {
        if (!strcmp(v, "auto")) more.alert_mv = 0;
        else if (!strcmp(v, "off")) more.alert_mv = 1;
        else if (ok && iv >= 2000 && iv <= 4500) more.alert_mv = iv;
        else { strcpy(reply, "Error: 2000-4500 mV, auto or off"); return; }
    } else if (!strcmp(k, "cad")) {
        if (strcmp(v, "on") && strcmp(v, "off")) { strcpy(reply, "Error: on or off"); return; }
        more.cad = v[1] == 'n';
    } else if (!strcmp(k, "rxdelay")) {
        if (!parse_fixed(v, 1, &x) || x < 0 || x > 200) { strcpy(reply, "Error, must be 0-20"); return; }
        more.rxdelay_x10 = x;
    } else if (!strcmp(k, "radio.watchdog")) {
        if (!strcmp(v, "off")) app.radio_wd_h = 0xFFFF;
        else if (ok && iv >= 1 && iv <= 48) app.radio_wd_h = iv;
        else { strcpy(reply, "Error: 1-48 hours, or off"); return; }
    } else if (!strcmp(k, "flood.ratelimit")) {
        if (!strcmp(v, "off")) more.flood_rl = 0;
        else if (ok && iv >= 1 && iv <= 60) more.flood_rl = iv;
        else { strcpy(reply, "Error: 1-60 per minute, or off"); return; }
        memset(rl, 0, sizeof(rl));
    } else if (!strcmp(k, "owner.info")) {
        char* d = app.owner_info;
        for (; *v && d - app.owner_info < (int)sizeof(app.owner_info) - 1; v++) *d++ = (*v == '|') ? '\n' : *v;
        *d = 0;
    } else if (!strcmp(k, "repeat.battery") || !strcmp(k, "flood.battery")) {
        bool r = k[0] == 'r';
        uint8_t& on = r ? bp.rep_on : bp.fl_on;
        if (!strcmp(v, "off")) on = 0;
        else if (!strcmp(v, "on")) on = 1;
        else if (ok && iv >= 1 && iv <= 100) { on = 1; (r ? bp.rep_pct : bp.fl_pct) = iv; }
        else { sprintf(reply, "Error: use set %s off|on|1-100", k); return; }
        cfg_save();
        bf_update(battery_mv());
        strcpy(reply, "OK - saved");
        return;
    } else if (!strcmp(k, "battery.empty") || !strcmp(k, "battery.full")) {
        if (!ok || iv < 2000 || iv > 20000) { sprintf(reply, "Error: use set %s 2000-20000 (mV)", k); return; }
        uint16_t e = k[8] == 'e' ? iv : bp.empty_mv, f = k[8] == 'f' ? iv : bp.full_mv;
        if (f < e + 100) { strcpy(reply, "Error: battery.full must exceed battery.empty by at least 100 mV"); return; }
        bp.empty_mv = e; bp.full_mv = f;
        cfg_save();
        bf_update(battery_mv());
        strcpy(reply, "OK - saved");
        return;
    } else if (!strcmp(k, "guest")) {
        if (strcmp(v, "on") && strcmp(v, "off")) { strcpy(reply, "Err - use get guest or set guest on|off"); return; }
        bp.guest_on = v[1] == 'n';
        if (!bp.guest_on) xl_drop_guests();
        cfg_save();
        sprintf(reply, "OK - guest %s", bp.guest_on ? "on" : "off");
        return;
#endif
    } else if (!strcmp(k, "password") || !strcmp(k, "guest.password")) {
#ifdef SPECTER_XL
        if (strlen(v) > 15) { strcpy(reply, "Error, max 15 characters"); return; }
        strcpy(k[0] == 'p' ? auth.admin_pw : auth.guest_pw, v);
        if (k[0] == 'g' && !bp.guest_on) done = "OK - guest logins are off (set guest on)";
#else
        strcpy(reply, "Error: remote admin needs the XL (128 KB) build"); return;
#endif
    } else {
        sprintf(reply, "unknown config: %s", k); return;
    }
    cfg_save();
    strcpy(reply, done);
}

static void handle_command(char* cmd, char* reply) {
#ifdef SPECTER_XL
    if (rl_active) { region_load_line(cmd, reply); return; }
#endif
    while (*cmd == ' ') cmd++;
    reply[0] = 0;
    if (!strcmp(cmd, "reboot")) {
        reboot_pending = true;
    } else if (!strcmp(cmd, "advert")) {
        send_advert(true);
        strcpy(reply, "OK - Advert sent");
    } else if (!strcmp(cmd, "advert.zerohop")) {
        send_advert(false);
        strcpy(reply, "OK - zerohop advert sent");
    } else if (!strncmp(cmd, "time ", 5)) {
        bool ok;
        uint32_t t = 0; const char* s = skip_ws(cmd + 5);
        while (*s >= '0' && *s <= '9') t = t * 10 + (*s++ - '0');
        ok = t > 1600000000UL;
        if (ok && t >= clock_now()) {
            clock_set(t);
            cs_manual = true;                  // manual time wins over mesh sync until reboot
            strcpy(reply, "OK - clock set: "); fmt_clock(reply + 16, clock_now());
        }
        else strcpy(reply, "(ERR: clock cannot go backwards)");
    } else if (!strncmp(cmd, "powersaving", 11)) {
        const char* v = skip_ws(cmd + 11);
        if (!strcmp(v, "on") || !strcmp(v, "off")) {
            ext.power = v[1] == 'n';
            cfg_save();
            strcpy(reply, ext.power ? "on - reboot to apply (16 MHz core)" : "off - reboot to apply");
        } else strcpy(reply, ext.power ? "on" : "off");
    } else if (!strcmp(cmd, "stats-core")) {
        int q = 0; for (int i = 0; i < TXQ_SIZE; i++) q += txq[i].used;
        sprintf(reply, "{\"battery_mv\":%lu,\"uptime_secs\":%lu,\"errors\":0,\"queue_len\":%d}",
                (unsigned long)battery_mv(), (unsigned long)uptime_s(), q);
    } else if (!strcmp(cmd, "stats-radio")) {
        char sn[12];
        sprintf(reply, "{\"noise_floor\":%d,\"last_rssi\":%d,\"last_snr\":%s,\"tx_air_secs\":%lu,\"rx_air_secs\":%lu}",
                noise_floor, last_rssi, fmt_fixed(sn, last_snr4 * 25, 2),
                (unsigned long)(stat_tx_air_ms / 1000), (unsigned long)(stat_rx_air_ms / 1000));
    } else if (!strcmp(cmd, "stats-packets")) {
        sprintf(reply, "{\"recv\":%lu,\"sent\":%lu,\"flood_tx\":%lu,\"direct_tx\":%lu,\"flood_rx\":%lu,\"direct_rx\":%lu,\"recv_errors\":%lu}",
                (unsigned long)stat_rx, (unsigned long)stat_tx, (unsigned long)stat_flood_tx, (unsigned long)stat_direct_tx,
                (unsigned long)stat_flood_rx, (unsigned long)stat_direct_rx, (unsigned long)stat_rx_err);
    } else if (!strcmp(cmd, "clock.sync.mesh now")) {
        if (!ext.clk_on) strcpy(reply, "Error: clock.sync.mesh is off");
        else { cs_next_up = 0; cs_manual = false; clock_status(reply); }
#ifdef SPECTER_XL
    } else if (!strncmp(cmd, "tempradio ", 10)) {         // tempradio freq,bw,sf,cr,minutes (upstream)
        const char* v = skip_ws(cmd + 10);
        int32_t f, bw; int sf, cr, mins;
        const char* c1 = strchr(v, ','); const char* c2 = c1 ? strchr(c1 + 1, ',') : NULL;
        const char* c3 = c2 ? strchr(c2 + 1, ',') : NULL; const char* c4 = c3 ? strchr(c3 + 1, ',') : NULL;
        if (!c4 || !parse_fixed(v, 3, &f) || !parse_fixed(c1 + 1, 3, &bw)) { strcpy(reply, "Error, invalid params"); return; }
        sf = atoi_s(c2 + 1); cr = atoi_s(c3 + 1); mins = atoi_s(c4 + 1);
        if (f < 150000 || f > 960000 || sf < 5 || sf > 12 || cr < 5 || cr > 8 || bw < 7000 || bw > 500000 || mins <= 0) {
            strcpy(reply, "Error, invalid params"); return;
        }
        if (tr_active) tr_swap();                         // back to the real set first
        tr_active = false;
        tr_freq = f; tr_bw = bw; tr_sf = sf; tr_cr = cr;   // pending
        tr_apply_at = (millis() + 2000) | 1;              // let the reply go out first
        tr_revert_at = millis() + 2000 + (uint32_t)mins * 60000UL;
        sprintf(reply, "OK - temp params for %d mins", mins);
    } else if (!strcmp(cmd, "normalradio")) {            // cancel tempradio (after this reply goes out)
        if (!tr_active && !tr_apply_at) { strcpy(reply, "OK - normal radio"); return; }
        tr_apply_at = 0;
        if (tr_active) tr_revert_at = millis() + 2000;   // the loop reverts once the reply is on air
        strcpy(reply, "OK - restoring normal radio");
    } else if (!strcmp(cmd, "alert test")) {
        if (!more.key_len) strcpy(reply, "Error: no alert.channel set");
        else if (!more.alerts) strcpy(reply, "Error: alerts are off");
        else { xl_alert("test alert", true); strcpy(reply, "OK - alert sent"); }
    } else if (!strncmp(cmd, "discover.neighbors", 18)) {
        if (*skip_ws(cmd + 18)) { strcpy(reply, "Err - discover.neighbors has no options"); return; }
        uint8_t d[10];
        d[0] = CTL_DISCOVER_REQ;
        d[1] = 1 << ADV_TYPE_REPEATER;
        disc_tag = rnd() | 1; memcpy(d + 2, &disc_tag, 4);
        memset(d + 6, 0, 4);                              // since = 0
        disc_until = millis() + 60000;
        int n = build(out_buf, (PT_CONTROL << 2) | ROUTE_DIRECT, NULL, 0, NULL, 0, d, 10);
        if (n > 0) txq_push(out_buf, n, 0, 0);
        strcpy(reply, "OK - Discover sent");
    } else if (!strncmp(cmd, "neighbor.remove ", 16)) {
        uint8_t k[XL_NB_PFX]; int n = 0;
        const char* h = skip_ws(cmd + 16);
        while (n < XL_NB_PFX && hexval(h[0]) >= 0 && hexval(h[1]) >= 0) { k[n++] = hexval(h[0]) << 4 | hexval(h[1]); h += 2; }
        if (!n) { strcpy(reply, "ERR: bad pubkey"); return; }
        xl_remove_neighbour(k, n);
        strcpy(reply, "OK");
    } else if (!strncmp(cmd, "setperm ", 8)) {          // setperm <pubkey hex> <perms>
        uint8_t k[32]; int n = 0;
        const char* h = skip_ws(cmd + 8);
        while (n < 32 && hexval(h[0]) >= 0 && hexval(h[1]) >= 0) { k[n++] = hexval(h[0]) << 4 | hexval(h[1]); h += 2; }
        if (*h != ' ') { strcpy(reply, n ? "Err - bad params" : "Err - bad pubkey"); return; }
        if (!n) { strcpy(reply, "Err - bad pubkey"); return; }
        uint8_t role = atoi_s(h) & 3;
        XlClient* c = NULL;
        for (int i = 0; i < XL_MAX_CLIENTS && !c; i++)
            if (xl_clients[i].perms != 0xFF && !memcmp(xl_clients[i].pub, k, n)) c = &xl_clients[i];
        if (role == PERM_ACL_GUEST) {                    // guest = remove from the list
            if (!c) { strcpy(reply, "Err - invalid params"); return; }
            c->perms = 0xFF;
        } else {
            if (n < 32) { strcpy(reply, "Err - invalid params"); return; }
            c = xl_put(k);
            c->perms = role;
            ecdh(c->secret, k);
        }
        xl_acl_save();
        strcpy(reply, "OK");
    } else if (!strcmp(cmd, "get acl")) {                // USB only
        Serial1.println("ACL:");
        for (int i = 0; i < XL_MAX_CLIENTS; i++) {
            if (xl_clients[i].perms == 0xFF || xl_clients[i].perms == PERM_ACL_GUEST) continue;
            char hx[65]; to_hex(hx, xl_clients[i].pub, 32);
            Serial1.print("0"); Serial1.print(xl_clients[i].perms); Serial1.print(" "); Serial1.println(hx);
        }
    } else if (!strncmp(cmd, "neighbors.detail", 16)) {  // key4:secs_ago:snr:rssi:times_heard, 5 per page
        uint8_t idx[XL_MAX_NEIGHB];
        int n = xl_nb_sorted(idx, 0), page = atoi_s(cmd + 16), pages = (n + 4) / 5;
        if (page < 1) page = 1;
        if (!n) { strcpy(reply, "-none-"); return; }
        if (page > pages) { strcpy(reply, "Error, no such page"); return; }
        char* p = reply + sprintf(reply, "p%d/%d", page, pages);
        uint32_t up = uptime_s();
        for (int k = (page - 1) * 5; k < n && k < page * 5; k++) {
            const XlNeighbour& nb = xl_nb[idx[k]];
            *p++ = '\n'; to_hex(p, nb.pfx, 4); p += 8;
            p += sprintf(p, ":%lu:%d:%d:%u", (unsigned long)(up - nb.heard_up), nb.snr4, nb.rssi, nb.count);
        }
    } else if (!strcmp(cmd, "neighbors")) {          // upstream format: key4hex:secs_ago:snr×4, newest first
        uint8_t idx[XL_MAX_NEIGHB];
        int n = xl_nb_sorted(idx, 0);
        char* p = reply;
        uint32_t up = uptime_s();
        for (int k = 0; k < n && p - reply < 134; k++) {
            if (p != reply) *p++ = '\n';
            to_hex(p, xl_nb[idx[k]].pfx, 4); p += 8;
            p += sprintf(p, ":%lu:%d", (unsigned long)(up - xl_nb[idx[k]].heard_up), xl_nb[idx[k]].snr4);
        }
        if (p == reply) strcpy(reply, "-none-");
#endif
    } else if (!strcmp(cmd, "clock")) {
        fmt_clock(reply, clock_now());
    } else if (!strcmp(cmd, "ver")) {
        strcpy(reply, FW_NAME " " FW_VERSION " (Build: " __DATE__ ")");
    } else if (!strcmp(cmd, "board")) {
        strcpy(reply, "DX-LR30 (STM32F103+SX1262)");
#ifdef SPECTER_XL
    } else if (!strcmp(cmd, "power")) {              // CommonCLI 1.18; this board has no USB/solar/charger sensing
        sprintf(reply, "batt:%u mV usb:n/a solar_chg:n/a ext:no charger:no", (unsigned)battery_mv());
#endif
    } else if (!strcmp(cmd, "erase")) {
        HAL_FLASH_Unlock(); flash_erase(CONFIG_ADDR); HAL_FLASH_Lock();
        strcpy(reply, "File system erase: OK (defaults + new identity after reboot)");
    } else if (!strncmp(cmd, "get ", 4)) {
        handle_get(skip_ws(cmd + 4), reply);
    } else if (!strncmp(cmd, "set ", 4)) {
        handle_set(skip_ws(cmd + 4), reply);
    } else if (!strncmp(cmd, "region", 6) && (cmd[6] == 0 || cmd[6] == ' ')) {
        handle_region(cmd + 6, reply);
    } else if (!strcmp(cmd, "log start")) {
        log_on = true;  strcpy(reply, "   logging on");
    } else if (!strcmp(cmd, "log stop")) {
        log_on = false; strcpy(reply, "   logging off");
    } else if (!strcmp(cmd, "stats")) {
        sprintf(reply, "up=%lus rx=%lu fwd=%lu drop=%lu tx=%lu retry=%lu echo=%lu advguard=%lu lbt=%lu bat=%lumV",
                (unsigned long)uptime_s(), (unsigned long)stat_rx, (unsigned long)stat_fwd,
                (unsigned long)stat_drop, (unsigned long)stat_tx, (unsigned long)stat_retry,
                (unsigned long)stat_echo, (unsigned long)stat_adv_guard, (unsigned long)stat_lbt,
                (unsigned long)last_batt_mv);
    } else if (!strncmp(cmd, "password", 8) && (cmd[8] == 0 || cmd[8] == ' ')) {
#ifdef SPECTER_XL
        const char* v = skip_ws(cmd + 8);           // upstream: "password <new admin password>"
        if (!*v) strcpy(reply, auth.admin_pw[0] ? "Error: give a new password" : "remote login is off (no password set)");
        else if (strlen(v) > 15) strcpy(reply, "Error, max 15 characters");
        else { strcpy(auth.admin_pw, v); cfg_save(); sprintf(reply, "password now: %s", auth.admin_pw); }
#else
        strcpy(reply, "Error: remote admin needs the XL (128 KB) build");
#endif
    } else if (*cmd) {
        strcpy(reply, "Unknown command");
    }
}

#ifdef SPECTER_XL

// Over-the-air CLI (admin login): everything the USB console offers except the
// identity/erase commands, plus upstream's "clock sync" (sets time from the app).
static void handle_command_from(char* cmd, char* reply, uint32_t sender_ts) {
    if (rl_active) { region_load_line(cmd, reply); return; }   // lines are consumed before tag stripping (upstream)
    while (*cmd == ' ') cmd++;
    reply[0] = 0;
    if (strlen(cmd) > 4 && cmd[2] == '|') {     // app's "XX|" tag: reflect it on the reply (as upstream)
        memcpy(reply, cmd, 3);
        reply += 3; cmd += 3;
        reply[0] = 0;
    }
    if (strstr(cmd, "prv.key") || !strcmp(cmd, "erase") || !strncmp(cmd, "log ", 4) || !strcmp(cmd, "get acl")) {
        strcpy(reply, "Error: USB console only"); return;
    }
    if (!strcmp(cmd, "clock sync")) {
        if (sender_ts > clock_now()) {
            clock_set(sender_ts);
            cs_manual = true;
            strcpy(reply, "OK - clock set: "); fmt_clock(reply + 16, clock_now());
        } else strcpy(reply, "ERR: clock cannot go backwards");
        return;
    }
    handle_command(cmd, reply);
    if (reboot_pending) {                       // let the reply go out first
        reboot_pending = false;
        xl_reboot_at = (millis() + 4000) | 1;
        strcpy(reply, "OK - rebooting");
    }
}
#endif

static char    cli_buf[160];
static uint8_t cli_len = 0;
static bool    cli_last_cr = false;

static void cli_poll(void) {
    while (Serial1.available()) {
        char c = Serial1.read();
        bool lf_after_cr = (c == '\n' && cli_last_cr);   // accept CR, LF or CRLF line endings
        cli_last_cr = (c == '\r');
        if (lf_after_cr) continue;
        if (c == '\r' || c == '\n' || cli_len >= sizeof(cli_buf) - 1) {
            Serial1.print('\n');
            cli_buf[cli_len] = 0;
            char reply[176];
            handle_command(cli_buf, reply);
            if (reply[0]) { Serial1.print("  -> "); Serial1.println(reply); }
            cli_len = 0;
            if (reboot_pending) { Serial1.flush(); delay(50); reboot_now(); }
            continue;
        }
        if (c == 8 || c == 127) { if (cli_len) { cli_len--; Serial1.print("\b \b"); } continue; }
        cli_buf[cli_len++] = c;
        Serial1.print(c);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Arduino entry points
// ═════════════════════════════════════════════════════════════════════════════
static uint32_t next_local_advert_s = 0, next_flood_advert_s = 0, next_persist_s = 0, next_beat_s = 0;

void setup(void) {
    pinMode(PIN_LED, OUTPUT);
    led(true);
    pinMode(PIN_TXEN, OUTPUT); digitalWrite(PIN_TXEN, LOW);
    pinMode(PIN_RXEN, OUTPUT); digitalWrite(PIN_RXEN, LOW);

    Serial1.begin(115200);
#ifdef SPECTER_XL
    if (xl_magic_word != XL_MAGIC) {                 // nothing from the upper half has run yet
        Serial1.println(FW_NAME " XL: upper 64 KB of flash is blank or missing.");
        Serial1.println("Flash the complete .hex file (this build needs a 128 KB chip).");
        while (true) { led(true); delay(150); led(false); delay(850); }
    }
    radio_p = new Radio(new Module(PIN_NSS, PIN_DIO1, PIN_NRST, PIN_BUSY, SPI));
#endif
    IWatchdog.begin(8000000);

    bool have_cfg = false;
    memcpy(&cfg, (const void*)CONFIG_ADDR, sizeof(cfg));
    if (cfg.magic == CFG_MAGIC && cfg.check == cfg_checksum(cfg)) have_cfg = true;
    else cfg_defaults();
    memcpy(&ext, (const void*)(CONFIG_ADDR + sizeof(Config)), sizeof(ext));
    if (ext.magic != EXT_MAGIC || ext.check != ext_checksum(ext)) {
        ext_defaults();
        if (have_cfg) {                // upgrade from an older version: keep settings, add new defaults
            if (cfg.advert_interval_min == 2) cfg.advert_interval_min = ADVERT_INTERVAL_MIN;   // old defaults →
            if (cfg.flood_advert_h == 47) cfg.flood_advert_h = FLOOD_ADVERT_INTERVAL_H;        // new defaults
            cfg_save();
        }
    }
#ifdef SPECTER_XL
    memcpy(&auth, (const void*)AUTH_ADDR, sizeof(auth));
    if (auth.magic != AUTH_MAGIC || auth.check != auth_checksum(auth)) {
        memset(&auth, 0, sizeof(auth));
        auth.magic = AUTH_MAGIC;
    }
    auth.admin_pw[15] = auth.guest_pw[15] = 0;
    memcpy(&app, (const void*)APP_ADDR, sizeof(app));
    if (app.magic != APP_MAGIC || app.check != app_checksum(app)) {
        memset(&app, 0, sizeof(app));
        app.magic = APP_MAGIC;
    }
    app.owner_info[sizeof(app.owner_info) - 1] = 0;
    memcpy(&more, (const void*)MORE_ADDR, sizeof(more));
    if (more.magic != MORE_MAGIC || more.check != more_checksum(more)) {
        memset(&more, 0, sizeof(more));
        more.magic = MORE_MAGIC;
        more.alerts = 1;                              // on, but nothing is sent until a channel is set
    }
    more.label[sizeof(more.label) - 1] = 0;
    memcpy(&bp, (const void*)POW_ADDR, sizeof(bp));
    if (bp.magic != POW_MAGIC || bp.check != pow_checksum(bp)) {
        memset(&bp, 0, sizeof(bp));
        bp.magic = POW_MAGIC;
        bp.rep_pct = 10; bp.fl_pct = 20;              // thresholds used by "on" (both off)
        bp.empty_mv = 3000; bp.full_mv = 4200;
        bp.guest_on = auth.guest_pw[0] != 0;          // upgrade: a guest password already set keeps guests working
    }
    xl_init();
#endif
    regions_rekey();
    if (ext.bat_pin) pinMode(ext.bat_pin == 1 ? PB0 : PB1, INPUT_ANALOG);
#ifdef SPECTER_XL
    bf_rep_paused = bf_fl_paused = false;
    bf_update(battery_mv());
#endif

    bool woke = bkp_read() == CUTOFF_FLAG;          // woke from low-battery standby?
    reset_reason_capture(woke);
    if (woke) {
        uint32_t mv = battery_mv();
        if (ext.cut_mv && mv < resume_mv()) {        // keep this path short: it runs every ~26 s
            Serial1.print("Battery "); Serial1.print(mv); Serial1.println(" mV: still low, back to sleep");
            radio_cold_sleep();
            enter_standby();
        }
        bkp_write(0);
    }
    delay(200);
    Serial1.println();
    Serial1.println(FW_NAME " MeshCore Repeater " FW_VERSION);
    Serial1.print("Last reset: "); Serial1.println(reset_why);
    if (woke) Serial1.println("Battery recovered: resuming");
    if (!radio_init()) {
        while (true) { led(true); delay(100); led(false); delay(100); }   // IWDG resets & retries
    }
    for (int i = 0; i < 4; i++) rng_state ^= (uint32_t)radio.randomByte() << (i * 8);
    if (rng_state == 0) rng_state = 0x9E3779B9;

    if (!have_cfg) {
        // First boot: draw the identity from the (now running) radio's noise.
        SHA256 sha;
        sha.reset();
        sha.update(cfg.privkey, 32);
        for (int i = 0; i < 64; i++) { uint8_t b = radio.randomByte(); uint32_t t = micros(); sha.update(&b, 1); sha.update(&t, 4); }
        sha.finalize(cfg.privkey, 32);
        cfg_save();
        Serial1.println("First boot: new identity and default settings saved");
    }
    Ed25519::derivePublicKey(own_pubkey, cfg.privkey);
    clock_init();

    char a[16], b[16];
    Serial1.print("Name: "); Serial1.println(cfg.name);
    Serial1.print("Radio: "); Serial1.print(fmt_fixed(a, cfg.freq_khz, 3)); Serial1.print(",");
    Serial1.print(fmt_fixed(b, cfg.bw_hz, 3)); Serial1.print(","); Serial1.print(cfg.sf); Serial1.print(",");
    Serial1.print(cfg.cr); Serial1.print(" "); Serial1.print(cfg.tx_dbm); Serial1.print(" dBm ");
    Serial1.println(radio_has_tcxo ? "(tcxo)" : "(xtal)");
    Serial1.print("Power: "); Serial1.print(SystemCoreClock / 1000000UL); Serial1.print(" MHz, battery ");
    Serial1.print(battery_mv()); Serial1.println(" mV");
#ifdef SPECTER_XL
    Serial1.println(auth.admin_pw[0] ? "App login: on" : "App login: off (set one with 'password <x>')");
#endif
    Serial1.println("Type 'get name', 'set name <x>', 'region', 'log start' ...");

    budget_ms = budget_max() / 2;
    budget_updated = millis();
    rx_start();

    uint32_t up = uptime_s();
    next_local_advert_s = up + 16;
    uint32_t since_flood = clock_now() - j_last_flood_ts;
    uint32_t flood_iv = cfg.flood_advert_h * 3600UL;
    next_flood_advert_s = (!cfg.flood_advert_h) ? 0xFFFFFFFFUL
                        : (j_last_flood_ts == 0 || since_flood >= flood_iv) ? up + rnd_range(20, 60)
                        : up + (flood_iv - since_flood);
    next_persist_s = up + PERSIST_INTERVAL_MIN * 60UL;
    next_beat_s = up + 60;
    led(false);
}

void loop(void) {
    IWatchdog.reload();
    uint32_t up = uptime_s();
    cli_poll();

    uint32_t irq = radio.getIrqFlags();
    if (irq & RADIOLIB_SX126X_IRQ_RX_DONE) {
        uint8_t rxbuf[MAX_PKT];
        int len = (int)radio.getPacketLength();
        int state = (len > 0 && len < MAX_PKT) ? radio.readData(rxbuf, len) : RADIOLIB_ERR_PACKET_TOO_LONG;
        uint32_t ps = radio.packetStatus();
        int snr4 = (int8_t)((ps >> 8) & 0xFF);
        int rssi = -(int)(ps & 0xFF) / 2;
        activity_at = 0; header_seen = false;
        rx_start();
        if (state != RADIOLIB_ERR_NONE) stat_rx_err++;
        if (state == RADIOLIB_ERR_NONE) {
            stat_rx++;
            last_rssi = rssi; last_snr4 = snr4;
#ifdef SPECTER_XL
            last_rx_ms = millis();
#endif
            stat_rx_air_ms += airtime_ms(len);
            if (log_on) {
                Serial1.print("RX rssi="); Serial1.print(rssi);
                Serial1.print(" snr="); Serial1.print(snr4 / 4);
                Serial1.print(" len="); Serial1.println(len);
            }
            on_receive(rxbuf, len, (int8_t)snr4);
        }
        return;
    }

    if (cfg.flood_advert_h && (int32_t)(up - next_flood_advert_s) >= 0) {
        send_advert(true);
        next_flood_advert_s = up + cfg.flood_advert_h * 3600UL;
        next_local_advert_s = up + cfg.advert_interval_min * 60UL;
    } else if (cfg.advert_interval_min && (int32_t)(up - next_local_advert_s) >= 0) {
        send_advert(false);
        next_local_advert_s = up + cfg.advert_interval_min * 60UL;
    }

    rt_service();
    txq_service(irq);
    noise_floor_sample(irq);
#ifdef SPECTER_XL
    // agc.reset.interval: warm-sleep the radio to reset its front end (RadioLibWrapper::resetAGC)
    static uint32_t agc_next_ms = 0;
    if (app.agc_s && (int32_t)(millis() - agc_next_ms) >= 0) {
        agc_next_ms = millis() + app.agc_s * 1000UL;
        if (!header_seen && !activity_at && !(irq & (RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX126X_IRQ_HEADER_VALID))) {
            radio.sleep(true);
            rx_start();
            noise_floor = 0; nf_n = 0; nf_sum = 0;
        }
    }
#endif
#ifdef SPECTER_XL
    // radio.watchdog: nothing received for N hours → the SX1262 may be wedged; re-init it
    if (app.radio_wd_h != 0xFFFF) {
        uint32_t wd_ms = (app.radio_wd_h ? app.radio_wd_h : 6) * 3600000UL;
        if (millis() - last_rx_ms > wd_ms) {
            last_rx_ms = millis();
            stat_radio_wd++;
            LOGLN("radio watchdog: re-initialising the radio");
            if (!radio_init()) NVIC_SystemReset();
            rx_start();
            xl_alert("radio watchdog: nothing heard for hours, radio re-initialised", false);
        }
    }
#endif
    battery_monitor(up);
    if ((int32_t)(up - next_tele_s) >= 0) { next_tele_s = up + TELE_IV_S; tele_sample(); }

    if ((int32_t)(up - next_persist_s) >= 0) {
        journal_write(clock_now(), j_last_flood_ts);
        next_persist_s = up + PERSIST_INTERVAL_MIN * 60UL;
    }
    if (log_on && (int32_t)(up - next_beat_s) >= 0) {
        next_beat_s = up + 60;
        char r[160];
        handle_command((char*)"stats", r);
        Serial1.println(r);
    }
#ifdef SPECTER_XL
    if (tr_apply_at && (int32_t)(millis() - tr_apply_at) >= 0) {
        tr_apply_at = 0; tr_swap(); tr_active = true;     // cfg now holds the temporary params
        if (!radio_init()) NVIC_SystemReset();
        rx_start();
    }
    if (tr_active && (int32_t)(millis() - tr_revert_at) >= 0) {
        tr_swap(); tr_active = false;                     // back to the saved params
        if (!radio_init()) NVIC_SystemReset();
        rx_start();
    }
    if (!xl_boot_alert_done && up >= 60) xl_alert_boot();
    if (xl_acl_dirty_at && (int32_t)(millis() - xl_acl_dirty_at) >= 0) xl_acl_save();
    if (xl_reboot_at && (int32_t)(millis() - xl_reboot_at) >= 0) {
        int q = 0; for (int i = 0; i < TXQ_SIZE; i++) q += txq[i].used;
        if (!q || (int32_t)(millis() - xl_reboot_at) > 15000) {
            journal_write(clock_now(), j_last_flood_ts);
            reboot_now();
        }
    }
#endif
    if (timers_dirty) {
        timers_dirty = false;
        next_local_advert_s = up + cfg.advert_interval_min * 60UL;
        next_flood_advert_s = cfg.flood_advert_h ? up + cfg.flood_advert_h * 3600UL : 0xFFFFFFFFUL;
    }

    __WFI();
}
