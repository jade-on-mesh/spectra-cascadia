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
    memset(fake_config, 0xFF, sizeof(fake_config));
    memset(fake_journal, 0xFF, sizeof(fake_journal));
    setup();
    printf("own hash %02x\n", own_pubkey[0]);
    CHECK(Serial1.out.find("First boot") != std::string::npos, "first boot creates and saves config");
    CHECK(cfg.num_regions == 2 && !strcmp(cfg.regions[0], "se-wa") && !strcmp(cfg.regions[1], "seattle"),
          "REGIONS build flag seeds the region list");

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

    { uint32_t future = clock_now() + 50000;
      for (int k = 0; k < 3; k++) {
          uint8_t sk[32], pkey[32]; for (int i = 0; i < 32; i++) sk[i] = i+k*31+1; Ed25519::derivePublicKey(pkey, sk);
          uint8_t pl[105]; memcpy(pl, pkey, 32); uint32_t ts = future+k; memcpy(pl+32, &ts, 4); uint8_t app[] = {0x81,'A','B','C','D'};
          memcpy(pl+100, app, 5); uint8_t m[41]; memcpy(m, pl, 36); memcpy(m+36, app, 5); Ed25519::sign(pl+36, sk, pkey, m, 41);
          uint8_t pk[200]; pk[0] = (PT_ADVERT<<2)|ROUTE_DIRECT; pk[1] = 0; memcpy(pk+2, pl, 105); on_receive(pk, 107, 0); }
      CHECK(clock_now() >= future, "clock learned forward from verified zero-hop adverts"); clearq(); }

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
    CHECK(cli("ver").find("2.1.0-cascadia") == 0, "ver");
    CHECK(cli("clock").find("UTC") != std::string::npos, "clock");
    CHECK(cli("time 1000") == "(ERR: clock cannot go backwards)", "time cannot go backwards");
    CHECK(cli("password abc") == "Error: remote admin not supported", "password not supported");
    CHECK(cli("frobnicate") == "Unknown command", "unknown command");
    { Serial1.out.clear(); Serial1.in = "get tx\n"; cli_poll();
      CHECK(Serial1.out.find("  -> > 22") != std::string::npos, "LF-only line ending accepted");
      Serial1.out.clear(); Serial1.in = "get tx\r\nget role\r\n"; cli_poll();
      CHECK(Serial1.out.find("> 22") != std::string::npos && Serial1.out.find("> repeater") != std::string::npos
            && Serial1.out.find("Unknown") == std::string::npos, "CRLF handled as one line ending"); }

    CHECK(cli("region put tacoma") == "OK - (flood allowed)", "region put");
    CHECK(cli("region denyf seattle") == "OK", "region denyf");
    CHECK(cli("region list allowed") == "se-wa,tacoma", "region list allowed");
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
      CHECK(ts >= clock_now() + 199, "journal wraps and keeps newest record"); }

    CHECK(cli("erase").find("OK") != std::string::npos, "erase");
    { memset(&cfg, 0, sizeof(cfg)); Serial1.out.clear(); setup();
      CHECK(Serial1.out.find("First boot") != std::string::npos && !strncmp(cfg.name, "SPECTER-", 8), "erase -> defaults on next boot"); }

    printf("\n%d failure(s)\n", fails);
    return fails != 0;
}
