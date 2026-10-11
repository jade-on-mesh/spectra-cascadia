// Host-side tests for the XL build: app login, requests and remote CLI,
// checked against upstream MeshCore's own ed25519 (orlp) key exchange.
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
#define SPECTER_XL 1
extern "C" {
#include "ed_25519.h"
}

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

// ── a minimal MeshCore *client* (the app/companion side), written from
//    upstream's Utils::encryptThenMAC / MACThenDecrypt
static int c_enc(const uint8_t* ss, uint8_t* dest, const uint8_t* src, int len) {
    AES128 aes; aes.setKey(ss, 16);
    int n = 0;
    for (; len > 0; len -= 16, src += 16, n += 16) {
        uint8_t b[16] = {0}; memcpy(b, src, len < 16 ? len : 16); aes.encryptBlock(dest + 2 + n, b);
    }
    SHA256 h; h.resetHMAC(ss, 32); h.update(dest + 2, n); h.finalizeHMAC(ss, 32, dest, 2);
    return n + 2;
}
static int c_dec(const uint8_t* ss, uint8_t* dest, const uint8_t* src, int len) {
    uint8_t mac[2]; SHA256 h; h.resetHMAC(ss, 32); h.update(src + 2, len - 2); h.finalizeHMAC(ss, 32, mac, 2);
    if (memcmp(mac, src, 2)) return -1;
    AES128 aes; aes.setKey(ss, 16);
    int n = 0; for (; n + 16 <= len - 2; n += 16) aes.decryptBlock(dest + n, src + 2 + n);
    return n;
}

struct Client { uint8_t seed[32], pub[32], prv[64], ss[32]; };
static void mk_client(Client& c, uint8_t k) {
    for (int i = 0; i < 32; i++) c.seed[i] = (uint8_t)(k * 31 + i * 5 + 1);
    ed25519_create_keypair(c.pub, c.prv, c.seed);
    ed25519_key_exchange(c.ss, own_pubkey, c.prv);           // the app's side of the shared secret
}

// Build a packet: hdr, path (hash_count 1-byte hashes), payload
static int mk_pkt(uint8_t* out, uint8_t hdr, const uint8_t* path, int hops, const uint8_t* pl, int plen) {
    int n = 0; out[n++] = hdr; out[n++] = (uint8_t)hops;
    memcpy(out + n, path, hops); n += hops; memcpy(out + n, pl, plen); return n + plen;
}
// Datagram payload (REQ / TXT_MSG / PATH) from client to repeater
static int mk_dgram(uint8_t* pl, const Client& c, const uint8_t* data, int len) {
    pl[0] = own_pubkey[0]; pl[1] = c.pub[0]; return 2 + c_enc(c.ss, pl + 2, data, len);
}
// Decrypt a queued reply addressed to client c; returns plaintext length or -1
static int open_reply(const TxItem* t, const Client& c, Pkt& p, uint8_t* out) {
    if (!t || !parse(t->buf, t->len, p)) return -1;
    if (p.payload[0] != c.pub[0] || p.payload[1] != own_pubkey[0]) return -1;
    return c_dec(c.ss, out, p.payload + 2, p.payload_len - 2);
}

static uint32_t ts_now = 1800000000UL;

int main() {
    set_vdd(3300); fake_adc[16] = (uint16_t)(1430UL * 4095UL / 3300UL);
    memset(fake_config, 0xFF, sizeof(fake_config));
    memset(fake_journal, 0xFF, sizeof(fake_journal));
    setup();
    printf("own hash %02x\n", own_pubkey[0]);
    CHECK(Serial1.out.find("App login: off") != std::string::npos, "fresh XL boot: app login off until a password is set");

    // ── key agreement must match upstream's orlp ed25519_key_exchange, both ways
    { uint8_t opub[32], oprv[64]; ed25519_create_keypair(opub, oprv, cfg.privkey);
      CHECK(!memcmp(opub, own_pubkey, 32), "orlp and rweather derive the same public key from our seed");
      int ok = 0;
      for (int k = 0; k < 20; k++) {
          Client c; mk_client(c, (uint8_t)k);
          uint8_t mine[32], theirs[32]; ecdh(mine, c.pub);
          ed25519_key_exchange(theirs, c.pub, oprv);
          ok += !memcmp(mine, c.ss, 32) && !memcmp(theirs, c.ss, 32);
      }
      CHECK(ok == 20, "ECDH secret matches the app side for 20 random clients"); }

    Client a; mk_client(a, 1);
    uint8_t hop = 0x77;
    auto login = [&](const Client& c, const char* pw, uint32_t ts, bool flood) {
        uint8_t data[32]; memcpy(data, &ts, 4); strcpy((char*)data + 4, pw);
        uint8_t pl[120]; pl[0] = own_pubkey[0]; memcpy(pl + 1, c.pub, 32);
        int pn = 33 + c_enc(c.ss, pl + 33, data, 4 + strlen(pw));
        uint8_t pk[200]; int n = mk_pkt(pk, (PT_ANON_REQ << 2) | (flood ? ROUTE_FLOOD : ROUTE_DIRECT), &hop, flood ? 1 : 0, pl, pn);
        clearq(); on_receive(pk, n, 20);
    };

    login(a, "", ts_now++, true);
    CHECK(queued() == 0, "no password configured: login refused (even blank)");
    login(a, "password", ts_now++, true);
    CHECK(queued() == 0, "no password configured: upstream's default 'password' refused");

    CHECK(cli("password hunter2") == "password now: hunter2", "password <x> over USB");
    CHECK(cli("set guest.password visitor") == "OK" && cli("get guest.password") == "> visitor", "guest.password set/get");
    CHECK(cli("password 0123456789abcdefg").find("max 15") != std::string::npos, "password length limit");

    // persists across reboot
    setup();
    CHECK(Serial1.out.find("App login: on") != std::string::npos && !strcmp(auth.admin_pw, "hunter2")
          && !strcmp(auth.guest_pw, "visitor"), "passwords survive reboot");

    // ── wrong password / wrong key
    login(a, "nope", ts_now++, true);
    CHECK(queued() == 0, "wrong password: no reply, not forwarded");
    { Client imp = a; for (int i = 0; i < 32; i++) imp.ss[i] ^= 0x5A;     // can't derive the secret
      login(imp, "hunter2", ts_now++, true);
      TxItem* t = last_q();
      CHECK(queued() == 1 && t->buf[1] == 2, "undecryptable ANON_REQ is just forwarded like any flood"); }

    // ── admin login by flood → PATH return carrying the login response
    { login(a, "hunter2", ts_now++, true);
      Pkt p; uint8_t d[200]; int n = open_reply(last_q(), a, p, d);
      CHECK(queued() == 1 && p.ptype == PT_PATH && (p.route == ROUTE_FLOOD || p.route == ROUTE_TRANSPORT_FLOOD) && p.hash_count == 0,
            "flood login answered with a flooded PATH packet");
      CHECK(n >= 16 && d[0] == 1 && d[1] == hop && d[2] == PT_RESPONSE, "PATH carries our route back (1 hop via 0x77) + RESPONSE");
      const uint8_t* r = d + 3;
      uint32_t now; memcpy(&now, r, 4);
      CHECK(r[4] == 0 && r[6] == 1 && r[7] == 3 && r[12] == 2 && now >= 1600000000UL - 1 + 1 - 1,
            "login OK: admin flag, perms=3, firmware level 2");
      clearq(); }

    // replayed login (same timestamp, new path) is rejected
    { uint32_t ts = ts_now - 1; uint8_t data[32]; memcpy(data, &ts, 4); strcpy((char*)data + 4, "hunter2");
      uint8_t pl[120]; pl[0] = own_pubkey[0]; memcpy(pl + 1, a.pub, 32);
      int pn = 33 + c_enc(a.ss, pl + 33, data, 11);
      uint8_t path2[2] = { 0x31, 0x32 };
      uint8_t pk[200]; int n = mk_pkt(pk, (PT_ANON_REQ << 2) | ROUTE_FLOOD, path2, 2, pl, pn);
      clearq(); on_receive(pk, n, 20);
      CHECK(queued() == 0, "replayed login rejected"); }

    // ── client tells us its route (PATH) → replies go direct
    { uint8_t data[8] = { 1, hop, 0xFF, 0, 0, 0, 0, 0 };
      uint8_t pl[64]; int pn = mk_dgram(pl, a, data, 3);
      uint8_t pk[100]; int n = mk_pkt(pk, (PT_PATH << 2) | ROUTE_DIRECT, NULL, 0, pl, pn);
      clearq(); on_receive(pk, n, 20);
      XlClient* c = xl_find(a.pub);
      CHECK(queued() == 0 && c && c->out_len == 1 && c->out_path[0] == hop, "PATH from the app: route to client learned"); }

    auto req = [&](const Client& c, uint32_t ts, const uint8_t* body, int blen, uint8_t ptype) {
        uint8_t data[200]; memcpy(data, &ts, 4); memcpy(data + 4, body, blen);
        uint8_t pl[220]; int pn = mk_dgram(pl, c, data, 4 + blen);
        uint8_t pk[255]; int n = mk_pkt(pk, (ptype << 2) | ROUTE_DIRECT, NULL, 0, pl, pn);
        clearq(); on_receive(pk, n, 20);
    };

    // ── status request
    { uint8_t b[] = { REQ_TYPE_GET_STATUS, 0, 0, 0, 0 };
      uint32_t ts = ts_now++; req(a, ts, b, sizeof(b), PT_REQ);
      Pkt p; uint8_t d[200]; int n = open_reply(last_q(), a, p, d);
      uint32_t tag, up; memcpy(&tag, d, 4); memcpy(&up, d + 4 + 16, 4);
      uint16_t bat; memcpy(&bat, d + 4, 2);
      CHECK(n >= 4 + 52 && p.ptype == PT_RESPONSE && p.route == ROUTE_DIRECT && p.hash_count == 1 && p.path[0] == hop,
            "status: RESPONSE sent direct along the learned path");
      CHECK(tag == ts && up == uptime_s() && bat > 3000 && bat < 3600, "status: tag, uptime and battery fields in place");
      req(a, ts, b, sizeof(b), PT_REQ);
      CHECK(queued() == 0, "status: replayed request ignored"); }

    // ── telemetry (Cayenne LPP voltage + temperature)
    { uint8_t b[] = { REQ_TYPE_GET_TELEMETRY_DATA, 0, 0, 0, 0 };
      req(a, ts_now++, b, sizeof(b), PT_REQ);
      Pkt p; uint8_t d[200]; open_reply(last_q(), a, p, d);
      CHECK(d[4] == 1 && d[5] == 116 && d[8] == 1 && d[9] == 103, "telemetry: LPP voltage + temperature on channel 1"); }

    // ── neighbours: a zero-hop repeater advert gets listed
    { uint8_t sk[32], pkey[32]; for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 9 + 4); Ed25519::derivePublicKey(pkey, sk);
      uint32_t ts = clock_now(); uint8_t pl[105]; memcpy(pl, pkey, 32); memcpy(pl + 32, &ts, 4);
      uint8_t app[] = { 0x82, 'N', 'b', 'r', '1' }; memcpy(pl + 100, app, 5);
      uint8_t m[41]; memcpy(m, pl, 36); memcpy(m + 36, app, 5); Ed25519::sign(pl + 36, sk, pkey, m, 41);
      uint8_t pk[200]; pk[0] = (PT_ADVERT << 2) | ROUTE_DIRECT; pk[1] = 0; memcpy(pk + 2, pl, 105); on_receive(pk, 107, -22);
      fake_ms += 5000;
      uint8_t b[] = { REQ_TYPE_GET_NEIGHBOURS, 0, 10, 0, 0, 0, 6, 1, 2, 3, 4 };
      req(a, ts_now++, b, sizeof(b), PT_REQ);
      Pkt p; uint8_t d[200]; int n = open_reply(last_q(), a, p, d);
      int16_t total, res; memcpy(&total, d + 4, 2); memcpy(&res, d + 6, 2);
      uint32_t ago; memcpy(&ago, d + 8 + 6, 4);
      CHECK(n > 0 && total == 1 && res == 1 && !memcmp(d + 8, pkey, 6) && ago >= 4 && ago <= 6 && (int8_t)d[18] == -22,
            "neighbours: key prefix, heard-ago and SNR"); }

    // ── remote CLI (TXT_MSG, CLI_DATA)
    auto rcli = [&](const Client& c, const char* cmd, uint8_t txt_type) -> std::string {
        uint8_t b[160]; b[0] = txt_type << 2; strcpy((char*)b + 1, cmd);
        req(c, ts_now++, b, 1 + strlen(cmd), PT_TXT_MSG);
        for (int i = 0; i < TXQ_SIZE; i++) {
            if (!txq[i].used) continue;
            Pkt p; uint8_t d[220]; int n = open_reply(&txq[i], c, p, d);
            if (n > 5 && p.ptype == PT_TXT_MSG && (d[4] >> 2) == TXT_TYPE_CLI_DATA) { d[n] = 0; return std::string((char*)d + 5); }
        }
        return "<none>";
    };
    CHECK(rcli(a, "get name", 1) == std::string("> ") + cfg.name, "remote CLI: get name");
    CHECK(rcli(a, "set name Hilltop", 1) == "OK" && !strcmp(cfg.name, "Hilltop"), "remote CLI: set name (saved)");
    CHECK(rcli(a, "ver", 1).find("Spectra-Cascadia v2.4.1") == 0, "remote CLI: ver");
    CHECK(rcli(a, "get prv.key", 1) == "Error: USB console only", "remote CLI: private key can't be read over the air");
    CHECK(rcli(a, "set prv.key 00", 1) == "Error: USB console only", "remote CLI: private key can't be set over the air");
    CHECK(rcli(a, "erase", 1) == "Error: USB console only", "remote CLI: erase refused");
    { uint32_t before = clock_now();
      std::string r = rcli(a, "clock sync", 1);
      CHECK(r.find("OK - clock set") == 0 && clock_now() >= ts_now - 2 && clock_now() > before, "remote CLI: clock sync takes the app's time"); }
    CHECK(rcli(a, "password swordfish", 1) == "password now: swordfish", "remote CLI: change admin password");
    { std::string r = rcli(a, "reboot", 1);
      CHECK(r == "OK - rebooting" && xl_reboot_at && !reboot_pending, "remote CLI: reboot is deferred so the reply goes out");
      xl_reboot_at = 0; }

    // legacy plain-text CLI gets an ACK = sha256(ts+flags+text, client pub)[0:4]
    { uint32_t ts = ts_now; uint8_t b[32]; b[0] = 0; strcpy((char*)b + 1, "clock");
      rcli(a, "clock", 0);
      uint8_t raw[40]; memcpy(raw, &ts, 4); memcpy(raw + 4, b, 6);
      uint8_t ack[4]; SHA256 h; h.reset(); h.update(raw, 4 + 1 + 5); h.update(a.pub, 32); h.finalize(ack, 4);
      bool found = false;
      for (int i = 0; i < TXQ_SIZE; i++) {
          Pkt p; if (txq[i].used && parse(txq[i].buf, txq[i].len, p) && p.ptype == PT_ACK && !memcmp(p.payload, ack, 4)) found = true;
      }
      CHECK(found, "legacy plain CLI: ACK with upstream's hash"); }

    // ── guest
    { Client g; mk_client(g, 9);
      login(g, "visitor", ts_now++, false);
      Pkt p; uint8_t d[200]; int n = open_reply(last_q(), g, p, d);
      CHECK(n >= 13 && p.ptype == PT_RESPONSE && d[6] == 0 && d[7] == 0, "guest login (direct): RESPONSE, not admin");
      CHECK(rcli(g, "get name", 1) == "<none>", "guest: CLI ignored");
      uint8_t b[] = { REQ_TYPE_GET_ACCESS_LIST, 0, 0 };
      req(g, ts_now++, b, sizeof(b), PT_REQ);
      CHECK(queued() == 0, "guest: access list refused");
      req(a, ts_now++, b, sizeof(b), PT_REQ);
      uint8_t d2[200]; int n2 = open_reply(last_q(), a, p, d2);
      CHECK(n2 >= 4 + 14 && !memcmp(d2 + 4, a.pub, 6) && d2[10] == 3 && !memcmp(d2 + 11, g.pub, 6) && d2[17] == 0,
            "admin: access list shows admin + guest"); }

    // ── anonymous clock query (BASIC), answered along the supplied reply path
    { Client s; mk_client(s, 22);
      uint32_t ts = ts_now++; uint8_t data[16]; memcpy(data, &ts, 4); data[4] = ANON_REQ_TYPE_BASIC; data[5] = 1; data[6] = 0x42;
      uint8_t pl[120]; pl[0] = own_pubkey[0]; memcpy(pl + 1, s.pub, 32);
      int pn = 33 + c_enc(s.ss, pl + 33, data, 7);
      uint8_t pk[200]; int n = mk_pkt(pk, (PT_ANON_REQ << 2) | ROUTE_DIRECT, NULL, 0, pl, pn);
      clearq(); on_receive(pk, n, 20);
      Pkt p; uint8_t d[64]; int m = open_reply(last_q(), s, p, d);
      uint32_t tag, now; memcpy(&tag, d, 4); memcpy(&now, d + 4, 4);
      CHECK(m >= 9 && p.route == ROUTE_DIRECT && p.path[0] == 0x42 && tag == ts && now == clock_now(), "anonymous clock query"); }


    // ── the app's settings screen: "XX|" tags reflected, every key it reads answers
    { auto app_cmd = [&](const char* c) { std::string t = std::string("3F|") + c; std::string r = rcli(a, t.c_str(), 1);
                                          return r.compare(0, 3, "3F|") == 0 ? r.substr(3) : std::string("<no tag> ") + r; };
      CHECK(app_cmd("get name") == "> Hilltop", "app tag: '3F|get name' -> '3F|> Hilltop'");
      CHECK(app_cmd("erase") == "Error: USB console only", "app tag can't smuggle erase past the USB-only check");
      CHECK(app_cmd("get prv.key") == "Error: USB console only", "app tag can't read the private key");
      const char* keys[] = { "name", "radio", "tx", "repeat", "allow.read.only", "radio.rxgain", "multi.acks", "owner.info",
                             "lat", "lon", "loop.detect", "dutycycle", "advert.interval", "flood.advert.interval", "flood.max",
                             "path.hash.mode", "txdelay", "direct.txdelay", "int.thresh", "agc.reset.interval" };
      int good = 0;
      for (const char* k : keys) { std::string r = app_cmd((std::string("get ") + k).c_str()); if (r.compare(0, 1, ">") == 0) good++; else printf("      get %s -> %s\n", k, r.c_str()); }
      CHECK(good == 20, "all 20 settings-screen keys answer '> value'");
      CHECK(app_cmd("get dutycycle") == "> 50.0%", "dutycycle derived from af (af 1.0 = 50%)");
      CHECK(app_cmd("set dutycycle 25").find("OK - 25.0%") == 0 && cli("get af") == "> 3", "set dutycycle 25 -> af 3");
      CHECK(app_cmd("set owner.info Jade|CascadiaMesh") == "OK" && app_cmd("get owner.info") == "> Jade|CascadiaMesh",
            "owner.info round trip ('|' = newline)");
      CHECK(!strcmp(app.owner_info, "Jade\nCascadiaMesh"), "owner.info stored with a newline");
      CHECK(app_cmd("set radio.rxgain on") == "OK" && radio.boosted && app_cmd("get radio.rxgain") == "> on", "radio.rxgain on applies boosted gain");
      CHECK(app_cmd("set int.thresh 14") == "OK" && app.int_thresh == 14, "int.thresh");
      CHECK(app_cmd("set agc.reset.interval 30") == "OK - interval rounded to 28", "agc.reset.interval rounds to 4 s like upstream");
      CHECK(app_cmd("set allow.read.only on") == "OK" && app_cmd("set multi.acks 1") == "OK", "allow.read.only / multi.acks stored");
      CHECK(app_cmd("set lat 47.6062") == "OK" && app_cmd("get lat") == "> 47.6062", "lat round trip");
      CHECK(app_cmd("set radio 910.525,62.5,7,5").find("OK") == 0, "set radio in the app's format");
      CHECK(app_cmd("neighbors").find(":") == 8, "neighbors CLI: key:secs:snr");
      setup();
      CHECK(!strcmp(app.owner_info, "Jade\nCascadiaMesh") && app.rxgain && radio.boosted && app.agc_s == 28 && app.int_thresh == 14,
            "app settings survive reboot (rx gain re-applied)");
      xl_init();
      login(a, "swordfish", ts_now++, false); clearq(); }

    // AGC reset fires on schedule
    { int s0 = radio.sleeps; fake_ms += 29000; loop(); CHECK(radio.sleeps == s0 + 1, "agc.reset.interval: radio warm-reset on schedule"); clearq(); }

    // owner info in the anonymous owner query
    { Client s; mk_client(s, 23);
      uint32_t ts = ts_now++; uint8_t data[16]; memcpy(data, &ts, 4); data[4] = ANON_REQ_TYPE_OWNER; data[5] = 0;
      uint8_t pl[120]; pl[0] = own_pubkey[0]; memcpy(pl + 1, s.pub, 32);
      int pn = 33 + c_enc(s.ss, pl + 33, data, 6);
      uint8_t pk[200]; int n = mk_pkt(pk, (PT_ANON_REQ << 2) | ROUTE_DIRECT, NULL, 0, pl, pn);
      clearq(); on_receive(pk, n, 20);
      Pkt p; uint8_t d[200]; int m = open_reply(last_q(), s, p, d);
      d[m > 0 ? m : 0] = 0;
      CHECK(m > 8 && !strncmp((char*)d + 8, "Hilltop\nJade\nCascadiaMesh", 25), "anonymous owner query: name + owner info"); clearq(); }

    // ── packets for other nodes are untouched
    { uint8_t pl[40]; pl[0] = own_pubkey[0] ^ 1; pl[1] = 5; memset(pl + 2, 0xAB, 18);
      uint8_t pk[64]; int n = mk_pkt(pk, (PT_REQ << 2) | ROUTE_FLOOD, &hop, 1, pl, 20);
      clearq(); on_receive(pk, n, 20);
      CHECK(queued() == 1, "REQ for another node still forwarded"); clearq(); }

    // ── half-flashed guard
    { CHECK(xl_magic_word == XL_MAGIC, "upper-half marker present"); }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
