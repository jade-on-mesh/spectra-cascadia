// Host-side tests for SPECTER forwarding rules and serial CLI.
// Build/run with ./run.sh (needs rweather Crypto sources).
#include <stdint.h>
#include <assert.h>
#include <string>

static uint32_t fake_config[256];
static uint32_t fake_journal[256];
static uint32_t fake_uid[3] = { 0x11223344, 0x55667788, 0x99AABBCC };
#define CONFIG_ADDR  ((uintptr_t)fake_config)
#define JOURNAL_ADDR ((uintptr_t)fake_journal)
#define UID_BASE     ((uintptr_t)fake_uid)
#define REGIONS "se-wa, #seattle"

#include "Arduino.h"
uint32_t fake_ms = 0;
FakeSerial Serial1;

static uint32_t* page_for(uint32_t addr, uint32_t* idx) {
    uint32_t c = (uint32_t)(uintptr_t)fake_config, j = (uint32_t)(uintptr_t)fake_journal;
    if (addr - c < 1024) { *idx = (addr - c) / 4; return fake_config; }
    if (addr - j < 1024) { *idx = (addr - j) / 4; return fake_journal; }
    assert(!"flash address outside the two pages");
    return nullptr;
}
int HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef* e, uint32_t*) {
    uint32_t i; uint32_t* p = page_for(e->PageAddress, &i);
    memset(p, 0xFF, 1024); return 0;
}
int HAL_FLASH_Program(uint32_t, uint32_t addr, uint64_t v) {
    uint32_t i; uint32_t* p = page_for(addr, &i);
    assert(p[i] == 0xFFFFFFFF);          // flash programs once per erase
    p[i] = (uint32_t)v; return 0;
}

#include "SPI.h"
#include "IWatchdog.h"
FakeSPI SPI; FakeWD IWatchdog;
#include "../../src/main.cpp"

// ── host versions of the STM32-only power helpers
static uint16_t fake_adc[18];
static uint16_t fake_bkp = 0;
struct StandbyEntered {};
uint16_t adc_read(uint8_t ch) { return fake_adc[ch]; }
uint16_t bkp_read(void) { return fake_bkp; }
void bkp_write(uint16_t v) { fake_bkp = v; }
void enter_standby(void) { throw StandbyEntered(); }
static uint16_t fake_bkp_dr[8];
static uint32_t fake_csr = (1UL << 27) | (1UL << 26);     // power-on
uint16_t bkp_get(int n) { return fake_bkp_dr[n]; }
void bkp_set(int n, uint16_t v) { fake_bkp_dr[n] = v; }
uint32_t reset_csr(void) { uint32_t c = fake_csr; fake_csr = 0; return c; }
static void set_vdd(uint32_t mv) { fake_adc[17] = (uint16_t)(1200UL * 4095UL / mv); }
static void set_pin_mv(uint8_t ch, uint32_t pin_mv, uint32_t vdd) { fake_adc[ch] = (uint16_t)(pin_mv * 4095UL / vdd); }

static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("PASS  %s\n", msg); else { printf("FAIL  %s\n", msg); fails++; } } while (0)

static int queued() { int n = 0; for (int i = 0; i < TXQ_SIZE; i++) n += txq[i].used; return n; }
static TxItem* last_q() { TxItem* b = nullptr; for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used) b = &txq[i]; return b; }
static void clearq() { for (int i = 0; i < TXQ_SIZE; i++) txq[i].used = false; }

static std::string cli(const char* line) {
    Serial1.out.clear();
    Serial1.in = std::string(line) + "\r";
    cli_poll();
    size_t p = Serial1.out.find("  -> ");
    if (p == std::string::npos) return "";
    std::string r = Serial1.out.substr(p + 5);
    if (!r.empty() && r.back() == '\n') r.pop_back();
    return r;
}

int main() {
    set_vdd(3300); fake_adc[16] = (uint16_t)(1430UL * 4095UL / 3300UL);
    memset(fake_config, 0xFF, sizeof(fake_config));
    memset(fake_journal, 0xFF, sizeof(fake_journal));
    setup();
    printf("own hash %02x\n", own_pubkey[0]);
    CHECK(Serial1.out.find("First boot") != std::string::npos, "first boot creates and saves config");
    CHECK(cfg.num_regions == 2 && !strcmp(cfg.regions[0], "se-wa") && !strcmp(cfg.regions[1], "seattle"),
          "REGIONS build flag seeds the region list");
    CHECK(cfg.advert_interval_min == 0 && cfg.flood_advert_h == 83, "defaults: no periodic zero-hop adverts, flood every 83 h");

    // ── transport code vs independent reference (Python HMAC: 0x1403) ──────
    uint8_t pl[] = { 0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    CHECK(transport_code(region_keys[0], PT_TXT_MSG, pl, sizeof(pl)) == 0x1403, "transport code matches HMAC reference");

    uint8_t other = own_pubkey[0] ^ 0xFF;

    // ── floods ────────────────────────────────────────────────────────────
    { uint8_t pk[] = { (PT_TXT_MSG<<2)|ROUTE_FLOOD, 0x01, other, 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05 };
      on_receive(pk, sizeof(pk), 0);
      TxItem* t = last_q();
      CHECK(t && t->len == sizeof(pk)+1 && t->buf[1] == 0x02 && t->buf[2] == other && t->buf[3] == own_pubkey[0]
            && !memcmp(t->buf+4, pk+3, sizeof(pk)-3), "flood: hash appended, hop count 2");
      clearq(); on_receive(pk, sizeof(pk), 0);
      CHECK(queued() == 0, "flood: duplicate dropped"); clearq(); }

    { uint8_t payload[] = { 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
      uint16_t tc = transport_code(region_keys[1], PT_TXT_MSG, payload, sizeof(payload));
      uint8_t pk[32]; int n = 0; pk[n++] = (PT_TXT_MSG<<2)|ROUTE_TRANSPORT_FLOOD; memcpy(pk+n, &tc, 2); n += 2;
      pk[n++] = 0x34; pk[n++] = 0x12; pk[n++] = 0x00; memcpy(pk+n, payload, sizeof(payload)); n += sizeof(payload);
      on_receive(pk, n, 0);
      TxItem* t = last_q();
      CHECK(t && t->buf[0] == pk[0] && !memcmp(t->buf+1, pk+1, 4) && t->buf[5] == 0x01 && t->buf[6] == own_pubkey[0]
            && !memcmp(t->buf+7, payload, sizeof(payload)), "scoped flood (#seattle): codes kept, hash appended");
      clearq();
      pk[1] ^= 0x55; pk[6] ^= 1;
      on_receive(pk, n, 0);
      CHECK(queued() == 0, "scoped flood for unknown region dropped"); clearq(); }

    // ── direct ────────────────────────────────────────────────────────────
    { uint8_t pk[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x02, own_pubkey[0], 0x77, 0xAA,0xBB,0x01,0x02,0x03,0x09 };
      on_receive(pk, sizeof(pk), 0);
      TxItem* t = last_q();
      CHECK(t && t->len == sizeof(pk)-1 && t->buf[1] == 0x01 && t->buf[2] == 0x77 && t->pri == 0, "direct: self removed from path");
      clearq(); on_receive(pk, sizeof(pk), 0);
      CHECK(queued() == 0, "direct: duplicate dropped (no ping-pong)"); clearq();
      uint8_t pk2[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x02, 0x77, own_pubkey[0], 0xAA,0xBB,0x01,0x02,0x03,0x0A };
      on_receive(pk2, sizeof(pk2), 0);
      CHECK(queued() == 0, "direct: not next hop -> dropped"); clearq(); }

    { uint8_t pk[] = { (PT_ACK<<2)|ROUTE_TRANSPORT_DIRECT, 1,2,3,4, 0x02, own_pubkey[0], 0x66, 0xDE,0xAD,0xBE,0xEF };
      on_receive(pk, sizeof(pk), 0);
      TxItem* t = last_q();
      CHECK(t && t->buf[0] == ((PT_ACK<<2)|ROUTE_DIRECT) && t->buf[1] == 0x01 && t->buf[2] == 0x66
            && !memcmp(t->buf+3, pk+8, 4) && t->len == 7, "direct ACK re-sent as DIRECT ACK"); clearq(); }

    { uint8_t pk[] = { (PT_MULTIPART<<2)|ROUTE_DIRECT, 0x01, own_pubkey[0], (2<<4)|PT_ACK, 0xCA,0xFE,0xBA,0xBE };
      on_receive(pk, sizeof(pk), 0);
      TxItem* t = last_q();
      CHECK(t && t->buf[0] == ((PT_ACK<<2)|ROUTE_DIRECT) && t->buf[1] == 0x00 && !memcmp(t->buf+2, pk+4, 4),
            "multipart ACK forwarded as plain ACK"); clearq(); }

    { uint8_t pk[] = { (PT_TRACE<<2)|ROUTE_DIRECT, 0x01, 0x28, 1,2,3,4, 5,6,7,8, 0x00, 0x99, own_pubkey[0], 0x55 };
      on_receive(pk, sizeof(pk), -20);
      TxItem* t = last_q();
      CHECK(t && t->buf[1] == 0x02 && t->buf[2] == 0x28 && (int8_t)t->buf[3] == -20 && t->pri == 5,
            "trace: SNR appended when we are listed next"); clearq(); }

    // ── adverts ───────────────────────────────────────────────────────────
    { send_advert(false);
      TxItem* t = last_q();
      CHECK(t && t->buf[0] == ((PT_ADVERT<<2)|ROUTE_DIRECT) && t->buf[1] == 0, "zero-hop advert is DIRECT with empty path");
      const uint8_t* p = t->buf + 2; int plen = t->len - 2;
      uint8_t msg[80]; memcpy(msg, p, 36); memcpy(msg+36, p+100, plen-100);
      CHECK(Ed25519::verify(p+36, p, msg, 36+plen-100), "own advert signature verifies");
      CHECK(p[100] == (ADV_TYPE_REPEATER|ADV_NAME_MASK), "advert flags = repeater+name (no location set)");
      clearq();
      send_advert(true);
      t = last_q();
      CHECK(t && t->buf[0] == ((PT_ADVERT<<2)|ROUTE_FLOOD) && t->buf[1] == 0, "flood advert, un-scoped by default");
      clearq(); }

    { uint8_t sk[32], pkey[32]; for (int i = 0; i < 32; i++) sk[i] = i*7+3; Ed25519::derivePublicKey(pkey, sk);
      auto mk = [&](uint8_t* out, uint8_t hops, uint32_t ts, bool forge) {
          int n = 0; out[n++] = (PT_ADVERT<<2)|ROUTE_FLOOD; out[n++] = hops; for (int i = 0; i < hops; i++) out[n++] = 0x40+i;
          uint8_t* pl = out+n; memcpy(pl, pkey, 32); memcpy(pl+32, &ts, 4); uint8_t app[] = {0x81,'N','o','d','e'};
          memcpy(pl+100, app, 5); uint8_t m[41]; memcpy(m, pl, 36); memcpy(m+36, app, 5);
          Ed25519::sign(pl+36, sk, pkey, m, 41); if (forge) pl[40] ^= 1; return n+105; };
      uint8_t buf[200]; uint32_t base = clock_now() + 100000;
      int n = mk(buf, 2, base, false); on_receive(buf, n, 0);
      CHECK(queued() == 1, "valid foreign advert forwarded"); clearq();
      n = mk(buf, 2, base+1, true); on_receive(buf, n, 0);
      CHECK(queued() == 0, "forged advert dropped"); clearq();
      n = mk(buf, 8, base+2, false); on_receive(buf, n, 0);
      CHECK(queued() == 0, "advert at flood.max.advert (8) dropped"); clearq(); }

    // ── mesh clock sync (consensus of signed advert timestamps) ──────────
    { auto zh = [&](int k, uint32_t ts) {
          uint8_t sk[32], pkey[32]; for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 3 + k * 37 + 11); Ed25519::derivePublicKey(pkey, sk);
          uint8_t pl[105]; memcpy(pl, pkey, 32); memcpy(pl+32, &ts, 4); uint8_t app[] = {0x82,'R','p','t','r'};
          memcpy(pl+100, app, 5); uint8_t m[41]; memcpy(m, pl, 36); memcpy(m+36, app, 5); Ed25519::sign(pl+36, sk, pkey, m, 41);
          uint8_t pk[200]; pk[0] = (PT_ADVERT<<2)|ROUTE_DIRECT; pk[1] = 0; memcpy(pk+2, pl, 105); on_receive(pk, 107, 40); };
      cs_count = 0;
      uint32_t t0 = clock_now();
      for (int k = 0; k < 8; k++) zh(k, t0 + 5000);
      CHECK(clock_now() < t0 + 100 && cli("get clock.sync.status").find("waiting samples=8/9") != std::string::npos,
            "clock sync waits for 9 samples");
      zh(8, t0 + 5000);
      CHECK(clock_now() >= t0 + 4995 && clock_now() <= t0 + 5010, "9 agreeing adverts set the clock forward");
      CHECK(cli("get clock.sync.status").find("> set") == 0, "status reports set");
      uint32_t t1 = clock_now();
      for (int k = 0; k < 9; k++) zh(20 + k, t1 + 99999);
      CHECK(clock_now() < t1 + 100, "after a successful sync, mesh sync sleeps 7 days");
      CHECK(cli("clock.sync.mesh now").find(">") == 0, "clock.sync.mesh now wakes sync");
      uint32_t t2 = clock_now();
      for (int k = 0; k < 9; k++) zh(40 + k, t2 - 3000);
      CHECK(clock_now() <= t2 - 2990 && clock_now() >= t2 - 3010, "consensus can move the clock backwards");
      cli("clock.sync.mesh now");
      uint32_t t3 = clock_now();
      for (int k = 0; k < 5; k++) zh(60 + k, t3 + 20000);
      for (int k = 0; k < 4; k++) zh(70 + k, t3 + 40000);
      CHECK(clock_now() < t3 + 100 && cli("get clock.sync.status").find("no-consensus") != std::string::npos,
            "split evidence: no consensus, clock unchanged");
      cli("clock.sync.mesh now"); cs_count = 0;
      uint32_t t4 = clock_now();
      for (int k = 0; k < 9; k++) zh(80 + k, t4 + 300);
      CHECK(clock_now() < t4 + 100 && cli("get clock.sync.status").find("in-sync") != std::string::npos,
            "offset under clock.sync.drift (600 s): left alone");
      cli("clock.sync.mesh now"); cs_count = 0;
      cli("time 4000000000");
      uint32_t t5 = clock_now();
      for (int k = 0; k < 9; k++) zh(90 + k, t5 + 9000);
      CHECK(clock_now() < t5 + 100 && cli("get clock.sync.status").find("manual") != std::string::npos,
            "manual time suppresses mesh sync");
      cs_manual = false; clk_base -= (4000000000UL - t4);         // undo the manual set for later tests
      clearq(); }

    // ── automatic retries ───────────────────────────────────────────────
    { auto tx_all = [&]() { for (int i = 0; i < 8; i++) { fake_ms += 10000; txq_service(0); } };
      auto fire = [&]() { fake_ms += 60000; rt_service(); };
      for (int i = 0; i < RT_SLOTS; i++) rt[i].used = false;
      clearq();
      // flood retry, no echo → resent
      uint8_t f1[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x00, 0x11,0x22,0x33,0x44,0x55,0x66,0x01 };
      on_receive(f1, sizeof(f1), 0);
      CHECK(rt_any(), "flood forward creates a retry slot");
      std::string first((char*)last_q()->buf, last_q()->len);
      tx_all(); fire();
      TxItem* t = last_q();
      CHECK(t && std::string((char*)t->buf, t->len) == first && stat_retry == 1, "no echo heard: flood packet resent");
      tx_all();
      // echo from a downstream repeater cancels remaining retries
      uint8_t f1e[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x02, own_pubkey[0], 0x99, 0x11,0x22,0x33,0x44,0x55,0x66,0x01 };
      on_receive(f1e, sizeof(f1e), 0);
      CHECK(!rt_any() && stat_echo == 1, "downstream echo cancels flood retry");
      fire(); CHECK(queued() == 0, "no resend after echo");
      // parallel repeater at the same hop count does not count as an echo
      uint8_t f2[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x00, 0x11,0x22,0x33,0x44,0x55,0x66,0x02 };
      on_receive(f2, sizeof(f2), 0); tx_all();
      uint8_t f2p[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x01, 0x98, 0x11,0x22,0x33,0x44,0x55,0x66,0x02 };
      on_receive(f2p, sizeof(f2p), 0);
      CHECK(rt_any(), "same-hop duplicate is not an echo");
      for (int i = 0; i < RT_SLOTS; i++) rt[i].used = false; clearq();
      // path gate (rooftop: flood.retry.path 2) and REQ never retried
      uint8_t f3[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x03, 0x91,0x92,0x93, 0x11,0x22,0x33,0x44,0x55,0x66,0x03 };
      on_receive(f3, sizeof(f3), 0);
      CHECK(queued() == 1 && !rt_any(), "flood beyond flood.retry.path: forwarded, no retry");
      clearq();
      uint8_t f4[] = { (PT_REQ<<2)|ROUTE_FLOOD, 0x00, 0xAB,0xCD,0x01,0x02,0x03,0x04 };
      on_receive(f4, sizeof(f4), 0);
      CHECK(queued() == 1 && !rt_any(), "REQ floods are never retried");
      clearq();

      // direct retry: next hop unknown → no retry (direct.retry.heard)
      uint8_t d1[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x03, own_pubkey[0], 0x5A, 0x6B, 0xAA,0xBB,0x01,0x02,0x03,0x21 };
      on_receive(d1, sizeof(d1), 0);
      CHECK(queued() == 1 && !rt_any(), "direct to an unheard next hop: no retry");
      clearq();
      // hear 0x5A relay a flood at +3 dB SNR → recent table; then retry is allowed
      uint8_t hz[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x01, 0x5A, 0x77,0x77,0x77,0x77,0x77,0x77,0x77 };
      on_receive(hz, sizeof(hz), 12); clearq(); for (int i = 0; i < RT_SLOTS; i++) rt[i].used = false;
      CHECK(cli("get recent.repeater").find("5A:3") != std::string::npos, "recent.repeater learns last hop + SNR");
      uint8_t d2[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x03, own_pubkey[0], 0x5A, 0x6B, 0xAA,0xBB,0x01,0x02,0x03,0x22 };
      on_receive(d2, sizeof(d2), 0);
      CHECK(rt_any(), "direct to a recently heard next hop: retry armed");
      tx_all(); fire();
      t = last_q();
      CHECK(t && t->cr == 7, "direct retry at 3 dB starts at CR 4/7");
      tx_all(); fire(); tx_all(); fire();
      t = last_q();
      CHECK(t && t->cr == 8, "later direct retries escalate to CR 4/8");
      uint8_t d2e[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x01, 0x6B, 0xAA,0xBB,0x01,0x02,0x03,0x22 };
      on_receive(d2e, sizeof(d2e), 0);
      CHECK(!rt_any(), "next hop forwarding (shorter path) cancels direct retry");
      clearq();
      // last hop before destination: no echo possible → no retry
      uint8_t d3[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x01, own_pubkey[0], 0xAA,0xBB,0x01,0x02,0x03,0x23 };
      on_receive(d3, sizeof(d3), 0);
      CHECK(queued() == 1 && !rt_any(), "final hop to destination: no retry");
      clearq(); for (int i = 0; i < RT_SLOTS; i++) rt[i].used = false; }

    // ── advert echo guard ───────────────────────────────────────────────
    { uint8_t sk[32], pkey[32]; for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 5 + 200); Ed25519::derivePublicKey(pkey, sk);
      auto adv = [&](uint8_t* out, uint8_t hops, uint32_t ts) {
          int n = 0; out[n++] = (PT_ADVERT<<2)|ROUTE_FLOOD; out[n++] = hops; for (int i = 0; i < hops; i++) out[n++] = 0x30 + i;
          uint8_t* pl = out + n; memcpy(pl, pkey, 32); memcpy(pl+32, &ts, 4); uint8_t app[] = {0x81,'G','u','a','r','d'};
          memcpy(pl+100, app, 6); uint8_t m[42]; memcpy(m, pl, 36); memcpy(m+36, app, 6);
          Ed25519::sign(pl+36, sk, pkey, m, 42); return n + 106; };
      clearq(); for (int i = 0; i < RT_SLOTS; i++) rt[i].used = false;
      uint8_t buf[220]; uint32_t now = clock_now();
      int n = adv(buf, 1, now - 60); on_receive(buf, n, 0);
      CHECK(queued() == 1, "fresh advert forwarded"); clearq();
      uint8_t echo[220]; int ne = adv(echo, 3, now - 60);
      on_receive(echo, ne, 0);
      memset(dedup_buf, 0, sizeof(dedup_buf));                        // dedup table forgets it
      on_receive(buf, n, 0);
      CHECK(queued() == 0 && stat_adv_guard == 1, "echoed advert is not forwarded again (advert guard)");
      int n2 = adv(buf, 1, now - 7 * 3600); on_receive(buf, n2, 0); clearq();
      on_receive(echo, adv(echo, 3, now - 7 * 3600), 0);
      memset(dedup_buf, 0, sizeof(dedup_buf));
      on_receive(buf, n2, 0);
      CHECK(queued() == 1, "adverts older than 6 h are not guarded"); clearq(); }

    // ── battery, telemetry, cutoff ──────────────────────────────────────
    { set_vdd(3300);
      std::string b = cli("get battery");
      CHECK(b.find("> 32") == 0 || b.find("> 33") == 0, "get battery reads VDD with no divider");
      CHECK(b.find("(VDD)") != std::string::npos, "battery source shown as VDD");
      CHECK(cli("set battery.pin pb0") == "OK" && cli("set battery.divider 2.00") == "OK", "set battery.pin / divider");
      set_pin_mv(8, 2000, 3300);
      b = cli("get battery");
      CHECK(b.find("> 39") == 0 || b.find("> 40") == 0, "battery via PB0 divider ≈ 4.0 V");
      CHECK(cli("set battery.divider 0.5") == "Error, range 1.00-10.00", "divider range");
      tele_count = 0; tele_head = 0;
      tele_sample(); set_pin_mv(8, 1900, 3300); tele_sample();
      std::string tv = cli("get telemetry.volt");
      CHECK(tv.find("> p1/1 30min newest-first: 3.79 3.99") == 0 || tv.find("> p1/1 30min newest-first: 3.8 4") == 0
            || tv.find("p1/1") != std::string::npos, "telemetry.volt history newest first");
      printf("      %s\n", tv.c_str());
      std::string tt = cli("get telemetry.temp");
      CHECK(tt.find(" 25 25") != std::string::npos || tt.find(" 24 24") != std::string::npos, "telemetry.temp ≈ 25 °C");
      CHECK(cli("get telemetry.volt 9") == "Error, no such page", "telemetry page range");

      CHECK(cli("set battery.cutoff 3300") == "OK" && cli("get battery.resume") == "> 3500", "cutoff with auto resume (+200 mV)");
      set_pin_mv(8, 1600, 3300);                                   // 3.2 V battery
      bool slept = false;
      try {
          for (int i = 0; i < 4; i++) { fake_ms += 31000; battery_monitor(uptime_s()); }
      } catch (StandbyEntered&) { slept = true; }
      CHECK(slept && fake_bkp == CUTOFF_FLAG, "3 low readings → standby with cutoff flag");
      // reboot while still low: straight back to standby before the radio starts
      slept = false; memset(&cfg, 0, sizeof(cfg));
      try { setup(); } catch (StandbyEntered&) { slept = true; }
      CHECK(slept, "boot while still low → back to standby");
      // recovered above resume threshold
      set_pin_mv(8, 1800, 3300);                                   // 3.6 V
      memset(&cfg, 0, sizeof(cfg)); Serial1.out.clear();
      slept = false;
      try { setup(); } catch (StandbyEntered&) { slept = true; }
      CHECK(!slept && fake_bkp == 0 && Serial1.out.find("Battery recovered") != std::string::npos, "battery recovered → normal boot");
      CHECK(cli("set battery.cutoff off") == "OK" && cli("get battery.cutoff") == "> off", "cutoff off");
      cli("set battery.pin off"); }

    // ── radio stats / powersaving ───────────────────────────────────────
    { noise_floor = 0; nf_n = 0; nf_sum = 0;
      for (int i = 0; i < 64; i++) { fake_ms += 300; noise_floor_sample(0); }
      CHECK(noise_floor == -110, "noise floor from 64 idle RSSI samples");
      last_rssi = -87; last_snr4 = 29;
      std::string r = cli("stats-radio");
      printf("      %s\n", r.c_str());
      CHECK(r.find("{\"noise_floor\":-110,\"last_rssi\":-87,\"last_snr\":7.25,\"tx_air_secs\":") == 0, "stats-radio (upstream JSON)");
      last_snr4 = -3;
      CHECK(cli("stats-radio").find("\"last_snr\":-0.75") != std::string::npos, "negative fractional SNR formatted");
      CHECK(cli("stats-packets").find("{\"recv\":") == 0 && cli("stats-packets").find("\"recv_errors\":") != std::string::npos, "stats-packets");
      CHECK(cli("stats-core").find("{\"battery_mv\":") == 0, "stats-core");
      CHECK(cli("powersaving") == "off", "powersaving default off");
      CHECK(cli("powersaving on").find("on - reboot to apply") == 0 && ext.power == 1, "powersaving on saved");
      cli("powersaving off"); }

    // ── formatter ──────────────────────────────────────────────────────
    { char b[64];
      fmtx(b, "%s|%d|%u|%ld|%lu|%02d|%c", "x", -42, 7u, -100000L, 4000000000UL, 5, 'Z');
      CHECK(!strcmp(b, "x|-42|7|-100000|4000000000|05|Z"), "fmtx formats like sprintf"); }

    // retry / clock CLI
    CHECK(cli("get retry.preset") == "> rooftop", "default preset rooftop");
    CHECK(cli("set retry.preset infra") == "OK" && cli("get direct.retry.count") == "> 4" && cli("get flood.retry.count") == "> 1", "preset infra");
    CHECK(cli("set flood.retry.path off") == "OK" && cli("get flood.retry.path") == "> off" && cli("get retry.preset") == "> custom", "flood.retry.path off → custom");
    CHECK(cli("set direct.retry.base 9") == "Error, range 10-5000", "range check");
    CHECK(cli("set clock.sync.drift 900") == "OK" && cli("get clock.sync.drift") == "> 900", "clock.sync.drift");
    CHECK(cli("set clock.sync.samples 2") == "Error, range 3-16", "clock.sync.samples range");
    CHECK(cli("set retry.preset rooftop") == "OK" && cli("set clock.sync.drift 600") == "OK", "restore defaults");

    { uint8_t pk[] = { (PT_RAW_CUSTOM<<2)|ROUTE_FLOOD, 0x00, 1,2,3,4,5,6 };
      on_receive(pk, sizeof(pk), 0); CHECK(queued() == 0, "RAW_CUSTOM never flooded"); clearq();
      uint8_t pk2[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x02, own_pubkey[0], own_pubkey[0], 1,2,3,4,5,6 };
      on_receive(pk2, sizeof(pk2), 0); CHECK(queued() == 0, "flood loop (own hash twice) dropped"); clearq();
      uint8_t pk3[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x41, 0x10, 0x20, 9,8,7,6,5,4 };
      on_receive(pk3, sizeof(pk3), 0); TxItem* t = last_q();
      CHECK(t && t->buf[1] == 0x42 && t->buf[4] == own_pubkey[0] && t->buf[5] == own_pubkey[1], "2-byte hash mode appends 2 bytes");
      clearq(); }

    // ── CLI (upstream syntax and reply style) ─────────────────────────────
    CHECK(cli("set name CM-Woodway-1") == "OK", "set name");
    CHECK(cli("get name") == "> CM-Woodway-1", "get name");
    CHECK(cli("set name bad,name") == "Error, bad chars", "set name rejects bad chars");
    CHECK(cli("get radio") == "> 910.525,62.5,7,5", "get radio (US default)");
    CHECK(cli("set radio 869.618,62.5,8,8") == "OK - reboot to apply", "set radio");
    CHECK(cli("get radio") == "> 869.618,62.5,8,8", "get radio after set");
    CHECK(cli("set radio 9999,62.5,8,8") == "Error, invalid radio params", "set radio rejects bad freq");
    CHECK(cli("set radio 910.525,62.5,7,5") == "OK - reboot to apply", "set radio back");
    CHECK(cli("set tx 22") == "OK" && cli("get tx") == "> 22", "set/get tx");
    CHECK(cli("set lat 47.793") == "OK" && cli("set lon -122.383") == "OK", "set lat/lon");
    CHECK(cli("get lat") == "> 47.793" && cli("get lon") == "> -122.383", "get lat/lon");
    CHECK(cli("set advert.interval 1") == "Error: interval range is 2-240 minutes", "advert.interval range");
    CHECK(cli("set flood.advert.interval 24") == "OK" && cli("get flood.advert.interval") == "> 24", "flood.advert.interval");
    CHECK(cli("set flood.max.advert 6") == "OK" && cfg.flood_max_advert == 6 && cfg.flood_max == 64, "set flood.max.advert");
    CHECK(cli("set txdelay 0.75") == "OK" && cli("get txdelay") == "> 0.75", "txdelay");
    CHECK(cli("set loop.detect strict") == "OK" && cli("get loop.detect") == "> strict", "loop.detect");
    CHECK(cli("set repeat off") == "OK - repeat is now OFF", "repeat off");
    { uint8_t pk[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x00, 7,7,7,7,7,7 };
      on_receive(pk, sizeof(pk), 0); CHECK(queued() == 0, "repeat off: nothing forwarded"); clearq(); }
    CHECK(cli("set repeat on") == "OK - repeat is now ON", "repeat on");
    CHECK(cli("get role") == "> repeater", "get role");
    CHECK(cli("get public.key").size() == 2 + 64, "get public.key");
    CHECK(cli("ver").find("Spectra-Cascadia v2.6.0") == 0, "ver");
    CHECK(cli("clock").find("UTC") != std::string::npos, "clock");
    CHECK(cli("time 1000") == "(ERR: clock cannot go backwards)", "time cannot go backwards");
    CHECK(cli("password abc").find("XL") != std::string::npos, "password needs the XL build");
    CHECK(cli("frobnicate") == "Unknown command", "unknown command");
    { Serial1.out.clear(); Serial1.in = "get tx\n"; cli_poll();
      CHECK(Serial1.out.find("  -> > 22") != std::string::npos, "LF-only line ending accepted");
      Serial1.out.clear(); Serial1.in = "get tx\r\nget role\r\n"; cli_poll();
      CHECK(Serial1.out.find("> 22") != std::string::npos && Serial1.out.find("> repeater") != std::string::npos
            && Serial1.out.find("Unknown") == std::string::npos, "CRLF handled as one line ending"); }

    CHECK(cli("region put tacoma") == "OK - (flood allowed)", "region put");
    CHECK(cli("region denyf seattle") == "OK", "region denyf");
    CHECK(cli("region list allowed") == "*,se-wa,tacoma", "region list allowed (wildcard first, as upstream)");
    CHECK(cli("region list denied") == "seattle", "region list denied");
    CHECK(cli("region default se-wa") == " default scope is now se-wa", "region default");
    CHECK(cli("region remove tacoma") == "OK", "region remove");
    CHECK(cli("region save") == "OK", "region save");
    { send_advert(true); TxItem* t = last_q();
      uint16_t tc; memcpy(&tc, t->buf+1, 2);
      CHECK(t->buf[0] == ((PT_ADVERT<<2)|ROUTE_TRANSPORT_FLOOD) && tc == transport_code(region_keys[0], PT_ADVERT, t->buf+6, t->len-6),
            "flood advert scoped to default region"); clearq(); }
    { uint8_t payload[] = { 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05,0x06,0x08 };
      uint16_t tc = transport_code(region_keys[1], PT_TXT_MSG, payload, sizeof(payload));
      uint8_t pk[32]; int n = 0; pk[n++] = (PT_TXT_MSG<<2)|ROUTE_TRANSPORT_FLOOD; memcpy(pk+n, &tc, 2); n += 2;
      pk[n++] = 0; pk[n++] = 0; pk[n++] = 0; memcpy(pk+n, payload, sizeof(payload)); n += sizeof(payload);
      on_receive(pk, n, 0); CHECK(queued() == 0, "denied region (#seattle) not forwarded"); clearq(); }
    CHECK(cli("region denyf *") == "OK", "region denyf * (wildcard)");
    { uint8_t pk[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x00, 8,8,8,8,8,8 };
      on_receive(pk, sizeof(pk), 0); CHECK(queued() == 0, "wildcard denied: un-scoped flood dropped"); clearq(); }
    CHECK(cli("region allowf *") == "OK", "region allowf *");

    cli("region save");

    // ── persistence across reboot ─────────────────────────────────────────
    { uint8_t pub_before[32]; memcpy(pub_before, own_pubkey, 32);
      uint32_t t_before = clock_now();
      memset(&cfg, 0, sizeof(cfg));
      fake_ms += 3000; clk_uptime_s = 0; clk_ms_accum = 0; j_last_flood_ts = 0;
      Serial1.out.clear();
      setup();
      CHECK(Serial1.out.find("First boot") == std::string::npos, "reboot loads saved config");
      CHECK(!memcmp(pub_before, own_pubkey, 32), "identity survives reboot");
      CHECK(!strcmp(cfg.name, "CM-Woodway-1") && cfg.tx_dbm == 22 && cfg.lat_e6 == 47793000, "settings survive reboot");
      CHECK(cfg.num_regions == 2 && cfg.default_region == 0 && (cfg.region_flags[1] & REGION_DENY_FLOOD), "regions survive reboot");
      CHECK(clock_now() > t_before, "clock resumes ahead of last advert");
      for (int i = 0; i < 200; i++) journal_write(clock_now() + i, j_last_flood_ts);
      uint32_t ts = 0, fl = 0; journal_read(&ts, &fl);
      CHECK(ts >= clock_now() + 199, "journal wraps and keeps newest record");
      cfg.advert_interval_min = 2; cfg.flood_advert_h = 47; cfg_save();   // old v2.1 defaults
      fake_config[sizeof(Config) / 4] = 0;               // simulate v2.1 flash: no extended settings
      memset(&cfg, 0, sizeof(cfg)); Serial1.out.clear(); setup();
      CHECK(Serial1.out.find("First boot") == std::string::npos && !strcmp(cfg.name, "CM-Woodway-1")
            && !memcmp(pub_before, own_pubkey, 32) && ext.magic == EXT_MAGIC && ext.preset == 1,
            "upgrade from v2.1 keeps name/identity, adds retry/clock defaults");
      CHECK(cfg.advert_interval_min == 0 && cfg.flood_advert_h == 83, "upgrade migrates old advert defaults (2 min / 47 h → off / 83 h)"); }

    CHECK(cli("erase").find("OK") != std::string::npos, "erase");
    { memset(&cfg, 0, sizeof(cfg)); Serial1.out.clear(); setup();
      CHECK(Serial1.out.find("First boot") != std::string::npos && !strncmp(cfg.name, "Spectra-", 8), "erase -> defaults on next boot"); }

    // ── region hierarchy, home, def, load, private names (upstream RegionMap/CommonCLI)
    { cli("region default <null>");
      while (cfg.num_regions) { char b[40]; sprintf(b, "region remove %s", cfg.regions[cfg.num_regions - 1]); cli(b); }
      CHECK(cli("region put wa") == "OK - (flood allowed)" && cli("region put se-wa wa") == "OK - (flood allowed)"
            && cli("region put seattle se-wa") == "OK - (flood allowed)", "region put with parents");
      CHECK(cli("region put $club") == "OK - (flood allowed)", "region put $private name accepted");
      cli("region denyf seattle");
      std::string t = cli("region");
      CHECK(t == "*^ F\n wa F\n  se-wa F\n   seattle\n $club F", "region tree export (indent per level, ^ home, F allowed)");
      CHECK(cli("region get seattle") == " seattle (se-wa) ", "region get shows parent");
      CHECK(cli("region remove se-wa") == "Err - not empty", "can't remove a region with children");
      CHECK(cli("region home sea") == " home is now seattle" && cli("region home") == " home is seattle", "region home (prefix match)");
      CHECK(cli("region").find("seattle^") != std::string::npos, "home marked ^");
      CHECK(cli("region default $club") == "Err - private region has no key", "private region can't be the default scope");
      { uint8_t pl[] = { 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x09 };
        uint8_t key[16]; region_key_for("$club", key);
        uint16_t tc = transport_code(key, PT_TXT_MSG, pl, sizeof(pl));
        CHECK(region_match(tc, PT_TXT_MSG, pl, sizeof(pl)) < 0, "private $ region never matches (no key, as upstream)"); }
      CHECK(cli("region remove $club") == "OK" && cli("region remove seattle") == "OK" && cli("region home") == " home is *",
            "removing the home region resets home to *");
      CHECK(cli("region load") == "Err - ??" && cli("region def a b") == "Err - ??", "region load/def are XL-only");
      cli("region put pnw"); cli("region put wa pnw"); cli("region save");
      setup();
      CHECK(cli("region get wa") == " wa (pnw) F", "hierarchy survives reboot"); }
    printf("\n%d failure(s)\n", fails);
    return fails != 0;
}
