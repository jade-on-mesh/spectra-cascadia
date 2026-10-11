// Host-side tests for the XL build: app login, requests and remote CLI,
// checked against upstream MeshCore's own ed25519 (orlp) key exchange.
// Build/run with ./run.sh (needs rweather Crypto sources).
#include <stdint.h>
#include <assert.h>
#include <string>

static uint32_t fake_config[256];
static uint32_t fake_journal[256];
static uint32_t fake_acl[256];
static uint32_t fake_uid[3] = { 0x11223344, 0x55667788, 0x99AABBCC };
#define CONFIG_ADDR  ((uintptr_t)fake_config)
#define JOURNAL_ADDR ((uintptr_t)fake_journal)
#define ACL_ADDR     ((uintptr_t)fake_acl)
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
    uint32_t q = (uint32_t)(uintptr_t)fake_acl;
    if (addr - q < 1024) { *idx = (addr - q) / 4; return fake_acl; }
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
    memset(fake_acl, 0xFF, sizeof(fake_acl));
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
    CHECK(rcli(a, "ver", 1).find("Spectra-Cascadia v1.17.1.1") == 0, "remote CLI: ver");
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


    // multi.acks 1: a forwarded direct ACK goes out as a multipart ACK, then the plain ACK 300 ms later
    { clearq();
      uint8_t pk[] = { (PT_ACK<<2)|ROUTE_DIRECT, 0x02, own_pubkey[0], 0x66, 0x11,0x22,0x33,0x44 };
      on_receive(pk, sizeof(pk), 0);
      TxItem *mp = nullptr, *ack = nullptr;
      for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used) { if ((txq[i].buf[0] >> 2) == PT_MULTIPART) mp = &txq[i]; else ack = &txq[i]; }
      CHECK(queued() == 2 && mp && ack && mp->buf[1] == 1 && mp->buf[2] == 0x66 && mp->buf[3] == ((1 << 4) | PT_ACK)
            && !memcmp(mp->buf + 4, pk + 4, 4) && ack->buf[0] == ((PT_ACK<<2)|ROUTE_DIRECT) && !memcmp(ack->buf + 3, pk + 4, 4)
            && (int32_t)(ack->due - mp->due) >= 0,
            "multi.acks 1: multipart ACK (remaining=1) then the plain ACK");
      app.multi_acks = 0; clearq();
      uint8_t pk2[] = { (PT_ACK<<2)|ROUTE_DIRECT, 0x02, own_pubkey[0], 0x66, 0x55,0x66,0x77,0x88 };
      on_receive(pk2, sizeof(pk2), 0);
      CHECK(queued() == 1, "multi.acks 0: just the plain ACK"); clearq(); }

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


    // ── v2.5: admin list survives reboot (admins only, as upstream ClientACL)
    { CHECK(xl_acl_dirty_at != 0 || xl_find(a.pub), "admin login marks the list for saving");
      fake_ms += 6000; loop(); clearq();
      CHECK(xl_acl_dirty_at == 0 && fake_acl[0] == ACL_MAGIC, "admin list written to its flash page after 5 s");
      setup();
      XlClient* c = xl_find(a.pub);
      CHECK(c && c->perms == PERM_ACL_ADMIN, "admin still known after reboot");
      Client g2; mk_client(g2, 9);
      CHECK(!xl_find(g2.pub), "guests are not kept across reboot");
      CHECK(rcli(a, "get name", 1) == "> Hilltop", "admin's CLI works after reboot without logging in again");
      Client b; mk_client(b, 40);
      char cmd[120]; char hx[65]; to_hex(hx, b.pub, 32); sprintf(cmd, "setperm %s 3", hx);
      CHECK(cli(cmd) == "OK" && xl_find(b.pub) && xl_find(b.pub)->perms == PERM_ACL_ADMIN, "setperm adds an admin by key");
      CHECK(rcli(b, "get name", 1) == "> Hilltop", "setperm admin can use the CLI without a password");
      hx[8] = 0; sprintf(cmd, "setperm %s 0", hx);
      CHECK(cli(cmd) == "OK" && !xl_find(b.pub), "setperm ... 0 removes (prefix ok)");
      CHECK(rcli(a, "get acl", 1) == "Error: USB console only", "get acl is USB only");
      Serial1.out.clear(); cli("get acl");
      to_hex(hx, a.pub, 32);
      CHECK(Serial1.out.find(std::string("03 ") + hx) != std::string::npos, "get acl lists the admin"); clearq(); }

    // ── v2.5: 128 neighbours (8-byte prefixes)
    { memset(xl_nb, 0, sizeof(xl_nb));
      uint8_t pk[32];
      for (int i = 0; i < 130; i++) { memset(pk, 0, 32); pk[0] = 0x10; pk[1] = (uint8_t)i; pk[2] = (uint8_t)(i >> 8); fake_ms += 1000; xl_note_neighbour(pk, (int8_t)(i & 63)); }
      int n = 0; for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up) n++;
      CHECK(n == 128 && sizeof(XlNeighbour) == 16, "128 neighbours, 16 bytes each");
      bool oldest_gone = true; for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up && xl_nb[i].pfx[1] < 2 && !xl_nb[i].pfx[2]) oldest_gone = false;
      CHECK(oldest_gone, "full table replaces the least recently heard");
      uint8_t b[] = { REQ_TYPE_GET_NEIGHBOURS, 0, 26, 100, 0, 0, 4, 9, 9, 9, 9 };
      req(a, ts_now++, b, sizeof(b), PT_REQ);
      Pkt p; uint8_t d[200]; int m = open_reply(last_q(), a, p, d);
      int16_t total, res; memcpy(&total, d + 4, 2); memcpy(&res, d + 6, 2);
      CHECK(m > 0 && total == 128 && res == 14, "neighbours REQ pages past 100 (offset 100 of 128)");
      std::string nl = rcli(a, "neighbors", 1);
      CHECK(nl.compare(0, 9, "10810000:") == 0, "neighbors CLI newest first");
      CHECK(rcli(a, "neighbor.remove 108100", 1) == "OK" && rcli(a, "neighbors", 1).compare(0, 9, "10800000:") == 0, "neighbor.remove by prefix");
      clearq(); }

    // ── v2.5: discover.neighbors (zero-hop CONTROL, upstream format)
    { std::string r = rcli(a, "discover.neighbors", 1);
      TxItem* t = nullptr; for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used && (txq[i].buf[0] >> 2) == PT_CONTROL) t = &txq[i];
      CHECK(r == "OK - Discover sent" && t && t->buf[0] == ((PT_CONTROL << 2) | ROUTE_DIRECT) && t->buf[1] == 0
            && t->buf[2] == 0x80 && t->buf[3] == 4 && t->len == 12, "discover request: zero-hop CONTROL 0x80, repeaters filter");
      uint32_t tag; memcpy(&tag, t->buf + 4, 4);
      clearq();
      uint8_t other[32]; for (int i = 0; i < 32; i++) other[i] = 0xC0 + i;
      uint8_t pk[50]; pk[0] = (PT_CONTROL << 2) | ROUTE_DIRECT; pk[1] = 0; pk[2] = 0x92; pk[3] = 12; memcpy(pk + 4, &tag, 4); memcpy(pk + 8, other, 32);
      on_receive(pk, 40, -9);
      bool found = false; for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up && !memcmp(xl_nb[i].pfx, other, 8) && xl_nb[i].snr4 == -9) found = true;
      CHECK(found, "discover response adds the neighbour");
      memset(xl_nb, 0, sizeof(xl_nb)); pk[4] ^= 1; on_receive(pk, 40, -9);
      found = false; for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up) found = true;
      CHECK(!found, "response with a wrong tag ignored");
      // answering someone else's discover
      uint8_t rq[14] = { (PT_CONTROL << 2) | ROUTE_DIRECT, 0, 0x80, 4, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0 };
      clearq(); on_receive(rq, 12, 22);
      TxItem* rs = last_q();
      CHECK(rs && rs->buf[2] == (0x90 | 2) && (int8_t)rs->buf[3] == 22 && !memcmp(rs->buf + 4, rq + 4, 4)
            && !memcmp(rs->buf + 8, own_pubkey, 32) && rs->len == 40, "answers a discover request with our key and the SNR");
      rq[2] = 0x81; clearq(); on_receive(rq, 12, 22); rs = last_q();
      CHECK(rs && rs->len == 2 + 14, "prefix_only request gets an 8-byte key");
      for (int i = 0; i < 4; i++) { clearq(); on_receive(rq, 12, 22); }
      CHECK(queued() == 0, "discover answers rate-limited (4 per 2 min)");
      fake_ms += 121000; clearq(); rq[3] = 0x02; on_receive(rq, 12, 22);
      CHECK(queued() == 0, "discover for other node types ignored"); clearq(); }

    // ── v2.5: reset reason
    { fake_csr = (1UL << 29); Serial1.out.clear(); setup();
      bool shown = Serial1.out.find("Last reset: watchdog") != std::string::npos;
      CHECK(cli("get reset.reason") == "> watchdog (watchdog resets since power-on: 1)" && shown, "watchdog reset reported");
      fake_csr = (1UL << 29); setup();
      CHECK(cli("get reset.reason").find("watchdog resets since power-on: 2") != std::string::npos, "watchdog resets counted");
      cli("reboot"); fake_csr = (1UL << 28); setup();
      CHECK(cli("get reset.reason") == "> reboot command (watchdog resets since power-on: 2)", "reboot command recognised");
      fake_csr = (1UL << 27) | (1UL << 26); setup();
      CHECK(cli("get reset.reason") == "> power-on / brownout (watchdog resets since power-on: 0)", "power-on resets the count");
      xl_init(); login(a, "swordfish", ts_now++, false); clearq(); }

    // ── region def / load (XL)
    { while (cfg.num_regions) { char b[40]; sprintf(b, "region remove %s", cfg.regions[cfg.num_regions - 1]); cli(b); }
      std::string d = cli("region def pnw or|pnw wa");
      CHECK(cli("region get or") == " or (pnw) F" && cli("region get wa") == " wa (pnw) F", "region def: chain with |jump");
      Serial1.out.clear();
      cli("region load");
      Serial1.in = std::string(" cascadia F\r  wa\r   tacoma F\r  or F\r\r"); cli_poll();
      CHECK(Serial1.out.find("OK - loaded 4 regions") != std::string::npos, "region load: indented lines, blank line ends");
      CHECK(cli("region get tacoma") == " tacoma (wa) F" && cli("region get wa") == " wa (cascadia) F"
            && region_find("se-wa") < 0, "region load replaced the map (existing flags kept)");
      cli("region allowf *"); cli("region save");
      setup();
      CHECK(cli("region get tacoma") == " tacoma (wa) F", "hierarchy survives reboot"); }


    // ── v2.6: alerts to a channel
    { auto chan_key = [](const char* name, uint8_t key[32]) {        // as the app derives a hashtag channel
          uint8_t h[32]; SHA256 sha; sha.reset(); sha.update(name, strlen(name)); sha.finalize(h, 32);
          memset(key, 0, 32); memcpy(key, h, 16); };
      auto read_alert = [&](const uint8_t* buf, int len, const uint8_t key[32], std::string& text) -> bool {
          Pkt p; if (!parse(buf, len, p) || p.ptype != PT_GRP_TXT) return false;
          uint8_t h[32]; SHA256 sha; sha.reset(); sha.update(key, 16); sha.finalize(h, 32);
          if (p.payload[0] != h[0]) return false;
          uint8_t d[200]; int n = c_dec(key, d, p.payload + 1, p.payload_len - 1);
          if (n < 6 || d[4] != 0) return false;
          d[n] = 0; text = (char*)d + 5; return true; };
      auto find_alert = [&](const uint8_t key[32], std::string& text) -> bool {
          for (int i = 0; i < TXQ_SIZE; i++) if (txq[i].used && read_alert(txq[i].buf, txq[i].len, key, text)) return true;
          return false; };
      uint8_t key[32]; chan_key("#cascadia-ops", key);
      std::string txt;
      clearq();
      CHECK(cli("get alert.channel") == "> off" && cli("get alerts") == "> on (no alert.channel set)", "defaults: alerts on, no channel");
      CHECK(cli("alert test") == "Error: no alert.channel set" && queued() == 0, "no channel: nothing sent");
      CHECK(cli("set alert.channel #cascadia-ops") == "OK" && cli("get alert.channel") == "> #cascadia-ops", "set alert.channel #name");
      CHECK(cli("alert test") == "OK - alert sent" && find_alert(key, txt) && txt == "Hilltop: test alert",
            "test alert decrypts with the app's #channel key, 'name: text'");
      clearq();
      CHECK(cli("set alerts off") == "OK" && cli("alert test") == "Error: alerts are off" && queued() == 0, "alerts off: nothing sent");
      cli("set alerts on");
      CHECK(cli("set alert.channel nope") != "OK" && cli("get alert.channel") == "> off", "bad channel rejected (and cleared)");
      CHECK(cli("set alert.channel public") == "OK" && cli("get alert.channel") == "> Public", "public channel");
      { uint8_t pk[32] = { 0x8b,0x33,0x87,0xe9,0xc5,0xcd,0xea,0x6a,0xc9,0xe5,0xed,0xba,0xa1,0x15,0xcd,0x72 };
        clearq(); cli("alert test"); CHECK(find_alert(pk, txt), "public channel uses the standard Public key"); }
      CHECK(cli("set alert.channel 00112233445566778899aabbccddeeff") == "OK" && cli("get alert.channel") == "> private 00112233...", "private channel by hex key");
      cli("set alert.channel #cascadia-ops"); clearq();
      // battery warning: auto threshold = cutoff + 150
      cli("set battery.pin pb0"); cli("set battery.divider 2.00"); cli("set battery.cutoff 3300");
      CHECK(cli("get alert.battery") == "> auto (3450)", "alert.battery auto = cutoff + 150 mV");
      set_pin_mv(8, 1700, 3300);                                  // 3.40 V
      fake_ms += 400000; next_batt_s = 0; battery_monitor(uptime_s());
      CHECK(find_alert(key, txt) && txt.find("Hilltop: battery low: 3") == 0, "low-battery warning");
      clearq(); next_batt_s = 0; fake_ms += 400000; battery_monitor(uptime_s());
      CHECK(queued() == 0, "warned once (until it recovers)");
      // cutoff: alert goes out before standby
      set_pin_mv(8, 1600, 3300);
      int tx0 = radio.tx_count; bool slept = false;
      try { for (int i = 0; i < 4; i++) { fake_ms += 31000; battery_monitor(uptime_s()); } } catch (StandbyEntered&) { slept = true; }
      std::string last;
      CHECK(slept && radio.tx_count > tx0 && read_alert(radio.last_tx, radio.last_tx_len, key, last)
            && last.find("shutting down until 3500 mV") != std::string::npos, "cutoff alert transmitted before standby");
      fake_bkp = 0; cli("set battery.cutoff off"); set_pin_mv(8, 1950, 3300);
      // boot alert a minute after an unplanned restart
      fake_csr = (1UL << 29); setup(); clearq();
      fake_ms += 61000; loop();
      CHECK(find_alert(key, txt) && txt.find("restarted (watchdog") != std::string::npos, "boot alert after a watchdog reset");
      clearq(); cli("reboot"); fake_csr = (1UL << 28); setup(); fake_ms += 61000; loop();
      CHECK(!find_alert(key, txt), "no boot alert after a reboot command");
      cli("set alert.channel off"); xl_init(); login(a, "swordfish", ts_now++, false); clearq(); }

    // ── v2.6: flood.ratelimit
    { CHECK(cli("get flood.ratelimit") == "> off", "flood.ratelimit off by default");
      CHECK(cli("set flood.ratelimit 2") == "OK", "set flood.ratelimit 2");
      auto grp = [&](uint8_t first_hop, uint8_t seq) {
          uint8_t pk[40]; int n = 0; pk[n++] = (PT_GRP_TXT << 2) | ROUTE_FLOOD; pk[n++] = 1; pk[n++] = first_hop;
          pk[n++] = 0x33; for (int i = 0; i < 18; i++) pk[n++] = (uint8_t)(seq * 7 + i);
          clearq(); on_receive(pk, n, 0); return queued(); };
      int a1 = grp(0x41, 1), a2 = grp(0x41, 2), a3 = grp(0x41, 3);
      CHECK(a1 == 1 && a2 == 1 && a3 == 0, "third channel flood from the same entry point in a minute is dropped");
      CHECK(grp(0x42, 4) == 1, "another entry point is not affected");
      fake_ms += 31000;
      CHECK(grp(0x41, 5) == 1 && grp(0x41, 6) == 0, "refills at 2 per minute");
      CHECK(cli("get flood.ratelimit") == "> 2 (dropped 2)", "dropped count shown");
      uint8_t ack[] = { (PT_ACK << 2) | ROUTE_FLOOD, 0, 1, 2, 3, 4 };
      int ok = 0; for (int i = 0; i < 5; i++) { ack[2] = i; clearq(); on_receive(ack, sizeof(ack), 0); ok += queued(); }
      CHECK(ok == 5, "ACKs are never rate limited");
      cli("set flood.ratelimit off"); clearq(); }

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
