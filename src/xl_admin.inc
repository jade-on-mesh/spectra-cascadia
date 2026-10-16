// ═════════════════════════════════════════════════════════════════════════════
//  SPECTER XL — remote administration from the normal MeshCore app
//  (128 KB builds only; included from main.cpp when SPECTER_XL is defined)
//
//  Implements the repeater-server side of upstream MeshCore's
//  examples/simple_repeater: password login (ANON_REQ), REQ status / telemetry /
//  neighbours / access list / owner info, CLI over TXT_MSG, PATH learning, and
//  the anonymous clock / owner / regions queries. Wire formats, crypto and
//  timings follow upstream so the stock app and companion firmware work as-is.
// ═════════════════════════════════════════════════════════════════════════════

#define XL_MAX_CLIENTS   12
#define XL_MAX_NEIGHB    128      // upstream: 50 full keys; we keep 8-byte prefixes (the app asks for 4)
#define XL_NB_PFX        8
#define PERM_ACL_GUEST   0
#define PERM_ACL_ADMIN   3
#define RESP_SERVER_LOGIN_OK 0
#define REQ_TYPE_GET_STATUS         0x01
#define REQ_TYPE_KEEP_ALIVE         0x02
#define REQ_TYPE_GET_TELEMETRY_DATA 0x03
#define REQ_TYPE_GET_ACCESS_LIST    0x05
#define REQ_TYPE_GET_NEIGHBOURS     0x06
#define REQ_TYPE_GET_OWNER_INFO     0x07
#define ANON_REQ_TYPE_REGIONS 0x01
#define ANON_REQ_TYPE_OWNER   0x02
#define ANON_REQ_TYPE_BASIC   0x03
#define TXT_TYPE_PLAIN    0
#define TXT_TYPE_CLI_DATA 1
#define TXT_TYPE_CLI_COMMAND 3
#define SERVER_RESPONSE_DELAY 300
#define TXT_ACK_DELAY         200
#define CLI_REPLY_DELAY       600
#define FIRMWARE_VER_LEVEL    2
#define OUT_PATH_UNKNOWN      0xFF

struct XlClient {
    uint8_t  pub[32];
    uint8_t  secret[32];
    uint32_t last_ts;
    uint8_t  perms;            // PERM_ACL_* (0xFF = empty slot)
    uint8_t  out_len;          // packed path_len byte, or OUT_PATH_UNKNOWN
    uint8_t  out_path[MAX_PATH_SIZE];
    uint32_t last_active_up;
};
static XlClient xl_clients[XL_MAX_CLIENTS];

struct XlNeighbour { uint8_t pfx[XL_NB_PFX]; uint32_t heard_up; int8_t snr4, rssi; uint16_t count; };   // 16 bytes
static XlNeighbour xl_nb[XL_MAX_NEIGHB];

// ── admin list persistence (ClientACL::save): admins / non-guest roles only,
//    in the last 1 KB page of the upper half (kept out of the image by specter_xl.ld)
#ifndef ACL_ADDR
#define ACL_ADDR 0x0801FC00UL
#endif
#define ACL_MAGIC 0x324C4341UL    // "ACL2"
#define ACL_REC_WORDS 18          // pub 32 + secret 32 + last_ts 4 + perms 4
static uint32_t xl_acl_dirty_at = 0;
static uint32_t xl_disc_ts = 0;   // discovery "modified" time (region save), kept in the same page

static uint32_t fnv_step(uint32_t h, uint32_t w) { h ^= w; return h * 16777619UL; }
static void xl_acl_save(void) {
    uint32_t words[ACL_REC_WORDS];
    uint32_t n = 0;
    for (int i = 0; i < XL_MAX_CLIENTS; i++) if (xl_clients[i].perms != 0xFF && xl_clients[i].perms != PERM_ACL_GUEST) n++;
    HAL_FLASH_Unlock();
    flash_erase(ACL_ADDR);
    uint32_t a = ACL_ADDR, h = 0x811C9DC5UL;
    uint32_t hdr[3] = { ACL_MAGIC, xl_disc_ts, n };
    for (int k = 0; k < 3; k++) { HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, a, hdr[k]); a += 4; h = fnv_step(h, hdr[k]); }
    for (int i = 0; i < XL_MAX_CLIENTS; i++) {
        const XlClient& c = xl_clients[i];
        if (c.perms == 0xFF || c.perms == PERM_ACL_GUEST) continue;
        memcpy(words, c.pub, 32); memcpy(words + 8, c.secret, 32);
        words[16] = c.last_ts; words[17] = c.perms;
        for (int k = 0; k < ACL_REC_WORDS; k++) { HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, a, words[k]); a += 4; h = fnv_step(h, words[k]); }
    }
    HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, a, h);
    HAL_FLASH_Lock();
    xl_acl_dirty_at = 0;
}
static void xl_acl_dirty(void) { xl_acl_dirty_at = (millis() + 5000) | 1; }   // LAZY_CONTACTS_WRITE_DELAY
static void xl_acl_touch_regions(void) { xl_disc_ts = clock_now(); xl_acl_save(); }
static uint32_t xl_disc_mod(void) { return xl_disc_ts; }

static uint8_t  xl_reply[180];
static uint32_t xl_last_unique = 0;
static uint32_t xl_reboot_at = 0;
static uint32_t stat_logins = 0;

static void xl_init(void) {
    for (int i = 0; i < XL_MAX_CLIENTS; i++) xl_clients[i].perms = 0xFF;
    const volatile uint32_t* w = (const volatile uint32_t*)ACL_ADDR;
    uint32_t n = w[2];
    if (w[0] != ACL_MAGIC || n > XL_MAX_CLIENTS) return;
    uint32_t h = 0x811C9DC5UL;
    for (uint32_t k = 0; k < 3 + n * ACL_REC_WORDS; k++) h = fnv_step(h, w[k]);
    if (h != w[3 + n * ACL_REC_WORDS]) return;
    xl_disc_ts = w[1];
    for (uint32_t i = 0; i < n; i++) {
        const volatile uint32_t* r = w + 3 + i * ACL_REC_WORDS;
        XlClient& c = xl_clients[i];
        memset(&c, 0, sizeof(c));
        for (int k = 0; k < 8; k++) { uint32_t v = r[k]; memcpy(c.pub + 4 * k, &v, 4); v = r[8 + k]; memcpy(c.secret + 4 * k, &v, 4); }
        c.last_ts = r[16];
        c.perms = (uint8_t)r[17];
        c.out_len = OUT_PATH_UNKNOWN;
    }
}

static uint32_t now_unique(void) {
    uint32_t t = clock_now();
    if (t <= xl_last_unique) t = xl_last_unique + 1;
    return xl_last_unique = t;
}

// ── crypto (Utils::encryptThenMAC / MACThenDecrypt, Identity::calcSharedSecret) ──

static int aes_encrypt(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int len) {
    AES128 aes;
    aes.setKey(secret, 16);
    uint8_t* d = dest;
    while (len > 0) {
        uint8_t blk[16];
        memset(blk, 0, 16);
        memcpy(blk, src, len < 16 ? len : 16);
        aes.encryptBlock(d, blk);
        d += 16; src += 16; len -= 16;
    }
    return d - dest;
}

static int encrypt_then_mac(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int len) {
    int n = aes_encrypt(secret, dest + CIPHER_MAC_SIZE, src, len);
    SHA256 sha;
    sha.resetHMAC(secret, 32);
    sha.update(dest + CIPHER_MAC_SIZE, n);
    sha.finalizeHMAC(secret, 32, dest, CIPHER_MAC_SIZE);
    return n + CIPHER_MAC_SIZE;
}

// Returns decrypted length (multiple of 16), or 0 if the MAC doesn't match or the
// ciphertext isn't a whole number of AES blocks (checked first, as upstream 1.18).
static int mac_then_decrypt(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int len) {
    if (len <= CIPHER_MAC_SIZE || (len - CIPHER_MAC_SIZE) % 16) return 0;
    uint8_t mac[CIPHER_MAC_SIZE];
    SHA256 sha;
    sha.resetHMAC(secret, 32);
    sha.update(src + CIPHER_MAC_SIZE, len - CIPHER_MAC_SIZE);
    sha.finalizeHMAC(secret, 32, mac, CIPHER_MAC_SIZE);
    if (memcmp(mac, src, CIPHER_MAC_SIZE)) return 0;
    AES128 aes;
    aes.setKey(secret, 16);
    int n = 0;
    for (const uint8_t* s = src + CIPHER_MAC_SIZE; s + 16 <= src + len; s += 16, n += 16) aes.decryptBlock(dest + n, s);
    return n;
}

// MeshCore's ed25519_key_exchange: X25519 between our expanded private scalar
// and the peer's Ed25519 key mapped to Montgomery form, u = (1 + y) / (1 - y).
static void ecdh(uint8_t secret[32], const uint8_t peer_pub[32]) {
    limb_t y[NUM_LIMBS_256BIT], one[NUM_LIMBS_256BIT], num[NUM_LIMBS_256BIT], den[NUM_LIMBS_256BIT], inv[NUM_LIMBS_256BIT];
    BigNumberUtil::unpackLE(y, NUM_LIMBS_256BIT, peer_pub, 32);
    y[NUM_LIMBS_256BIT - 1] &= ((((limb_t)1) << (LIMB_BITS - 1)) - 1);
    Curve25519::reduceQuick(y);
    memset(one, 0, sizeof(one)); one[0] = 1;
    Curve25519::add(num, one, y);
    Curve25519::sub(den, one, y);
    Curve25519::recip(inv, den);                     // (recip must not work in place)
    Curve25519::mul(num, num, inv);
    Curve25519::reduceQuick(num);
    uint8_t u[32], s[64];
    BigNumberUtil::packLE(u, 32, num, NUM_LIMBS_256BIT);
    SHA512 sha;
    sha.reset();
    sha.update(cfg.privkey, 32);
    sha.finalize(s, 64);
    s[0] &= 248; s[31] &= 127; s[31] |= 64;
    IWatchdog.reload();
    Curve25519::eval(secret, s, u);
    memset(s, 0, sizeof(s));
}

// ── sending ─────────────────────────────────────────────────────────────────

// Flood reply, scoped like the request (sendFloodReply): region idx, or -1 un-scoped.
static void xl_send_flood(uint8_t ptype, const uint8_t* payload, int plen, uint8_t hash_size, int scope, uint32_t delay) {
    uint8_t hdr = (ptype << 2);
    uint16_t tc[2] = { 0, 0 };
    if (scope < 0 && cfg.default_region < cfg.num_regions) scope = cfg.default_region;
    if (scope >= 0) { hdr |= ROUTE_TRANSPORT_FLOOD; tc[0] = transport_code(region_keys[scope], ptype, payload, plen); }
    else hdr |= ROUTE_FLOOD;
    int n = build(out_buf, hdr, tc, (uint8_t)((hash_size - 1) << 6), NULL, 0, payload, plen);
    uint8_t h[8];
    packet_hash(h, ptype, 0, payload, plen);
    mark_seen(h);
    txq_push(out_buf, n, 1, delay);
}

static void xl_send_direct(uint8_t ptype, const uint8_t* payload, int plen, uint8_t path_len, const uint8_t* path, uint32_t delay) {
    int pbytes = (path_len & 63) * ((path_len >> 6) + 1);
    int n = build(out_buf, (ptype << 2) | ROUTE_DIRECT, NULL, path_len, path, pbytes, payload, plen);
    uint8_t h[8];
    packet_hash(h, ptype, path_len, payload, plen);
    mark_seen(h);
    txq_push(out_buf, n, 0, delay);
}

// Datagram (REQ/RESPONSE/TXT_MSG) to a client: direct via its out_path, else flood.
static void xl_send_datagram(XlClient* c, uint8_t ptype, const uint8_t* data, int len, uint8_t hash_size, int scope, uint32_t delay) {
    uint8_t pl[MAX_PKT];
    pl[0] = c->pub[0];
    pl[1] = own_pubkey[0];
    int n = 2 + encrypt_then_mac(c->secret, pl + 2, data, len);
    if (c->out_len != OUT_PATH_UNKNOWN) xl_send_direct(ptype, pl, n, c->out_len, c->out_path, delay);
    else xl_send_flood(ptype, pl, n, hash_size, scope, delay);
}

// createPathReturn(): tell the client the path to us, carrying the response as 'extra'.
static void xl_send_path_return(const uint8_t* dest_pub, const uint8_t* secret, const Pkt& p,
                                const uint8_t* extra, int extra_len, int scope) {
    int pbytes = p.hash_count * p.hash_size;
    if (pbytes + extra_len + 5 > 184 - 2 - 16) return;           // MAX_COMBINED_PATH
    uint8_t data[184];
    int d = 0;
    data[d++] = p.path_len;
    memcpy(data + d, p.path, pbytes); d += pbytes;
    data[d++] = PT_RESPONSE;
    memcpy(data + d, extra, extra_len); d += extra_len;
    uint8_t pl[MAX_PKT];
    pl[0] = dest_pub[0];
    pl[1] = own_pubkey[0];
    int n = 2 + encrypt_then_mac(secret, pl + 2, data, d);
    xl_send_flood(PT_PATH, pl, n, p.hash_size, scope, SERVER_RESPONSE_DELAY);
}

static void xl_reply_route(XlClient* c, const uint8_t* secret, const Pkt& p, int len, int scope) {
    bool flood = p.route == ROUTE_FLOOD || p.route == ROUTE_TRANSPORT_FLOOD;
    if (flood) xl_send_path_return(c->pub, secret, p, xl_reply, len, scope);
    else xl_send_datagram(c, PT_RESPONSE, xl_reply, len, p.hash_size, scope, SERVER_RESPONSE_DELAY);
}

// ── clients ─────────────────────────────────────────────────────────────────

static XlClient* xl_find(const uint8_t* pub) {
    for (int i = 0; i < XL_MAX_CLIENTS; i++)
        if (xl_clients[i].perms != 0xFF && !memcmp(xl_clients[i].pub, pub, 32)) return &xl_clients[i];
    return NULL;
}

static XlClient* xl_put(const uint8_t* pub) {
    XlClient* c = xl_find(pub);
    if (c) return c;
    int s = 0;                                       // empty slot, else least recently active guest, else oldest
    for (int i = 0; i < XL_MAX_CLIENTS; i++) {
        if (xl_clients[i].perms == 0xFF) { s = i; break; }
        bool ig = xl_clients[i].perms != PERM_ACL_ADMIN, sg = xl_clients[s].perms != PERM_ACL_ADMIN;
        if ((ig && !sg) || (ig == sg && xl_clients[i].last_active_up < xl_clients[s].last_active_up)) s = i;
    }
    c = &xl_clients[s];
    memset(c, 0, sizeof(*c));
    memcpy(c->pub, pub, 32);
    c->out_len = OUT_PATH_UNKNOWN;
    c->perms = PERM_ACL_GUEST;
    return c;
}

// ── neighbours (zero-hop repeater adverts) ──────────────────────────────────

static void xl_note_neighbour(const uint8_t* pub, int8_t snr4) {
    int s = 0;
    for (int i = 0; i < XL_MAX_NEIGHB; i++) {
        if (xl_nb[i].heard_up && !memcmp(xl_nb[i].pfx, pub, XL_NB_PFX)) { s = i; break; }
        if (xl_nb[i].heard_up < xl_nb[s].heard_up) s = i;
    }
    if (!xl_nb[s].heard_up || memcmp(xl_nb[s].pfx, pub, XL_NB_PFX)) xl_nb[s].count = 0;   // new entry
    memcpy(xl_nb[s].pfx, pub, XL_NB_PFX);
    xl_nb[s].heard_up = uptime_s() | 1;
    xl_nb[s].snr4 = snr4;
    xl_nb[s].rssi = (int8_t)(last_rssi < -128 ? -128 : last_rssi);
    if (xl_nb[s].count < 0xFFFF) xl_nb[s].count++;
}


// Indexes of known neighbours, sorted: order 0 newest, 1 oldest, 2 strongest, 3 weakest.
static int xl_nb_sorted(uint8_t* idx, uint8_t order) {
    int n = 0;
    for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up) idx[n++] = i;
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0; j--) {
            const XlNeighbour &a = xl_nb[idx[j-1]], &b = xl_nb[idx[j]];
            bool swap = order == 1 ? a.heard_up > b.heard_up : order == 2 ? a.snr4 < b.snr4
                      : order == 3 ? a.snr4 > b.snr4 : a.heard_up < b.heard_up;
            if (!swap) break;
            uint8_t t = idx[j]; idx[j] = idx[j-1]; idx[j-1] = t;
        }
    return n;
}

static void xl_remove_neighbour(const uint8_t* pfx, int len) {
    if (len > XL_NB_PFX) len = XL_NB_PFX;
    for (int i = 0; i < XL_MAX_NEIGHB; i++)
        if (xl_nb[i].heard_up && !memcmp(xl_nb[i].pfx, pfx, len)) xl_nb[i].heard_up = 0;
}

// ── request handlers ────────────────────────────────────────────────────────

// Login attempt limit: 5 per minute (each costs a key exchange), and after 3 wrong
// passwords in a row a lockout of 1 min that doubles each time, up to 16 min.
static uint32_t xl_lg_win = 0, xl_lock_until = 0;
static uint8_t  xl_lg_n = 0, xl_bad = 0, xl_lock_level = 0;
static uint32_t stat_login_limited = 0;
static bool xl_login_allowed(void) {
    uint32_t now = millis();
    if (xl_lock_until && (int32_t)(now - xl_lock_until) < 0) { stat_login_limited++; return false; }
    if (now - xl_lg_win > 60000UL) { xl_lg_win = now; xl_lg_n = 0; }
    if (xl_lg_n >= 5) { stat_login_limited++; return false; }
    xl_lg_n++;
    return true;
}
static void xl_login_result(bool ok) {
    if (ok) { xl_bad = 0; xl_lock_level = 0; return; }
    if (++xl_bad >= 3) {
        xl_bad = 0;
        xl_lock_until = (millis() + (60000UL << xl_lock_level)) | 1;
        if (xl_lock_level < 4) xl_lock_level++;
        LOGLN("  login: locked out");
    }
}

static int xl_login(XlClient** out, const uint8_t* sender_pub, const uint8_t* secret, uint32_t ts, const char* pw, bool flood) {
    XlClient* c = NULL;
    if (!pw[0]) c = xl_find(sender_pub);             // blank password: already known?
    if (!c) {
        uint8_t perms;
        if (auth.admin_pw[0] && !strcmp(pw, auth.admin_pw)) perms = PERM_ACL_ADMIN;
        else if (auth.guest_pw[0] && !strcmp(pw, auth.guest_pw)) perms = PERM_ACL_GUEST;
        else { LOGLN("  login: bad password"); xl_login_result(false); return 0; }
        c = xl_put(sender_pub);
        if (ts <= c->last_ts) { LOGLN("  login: replay"); return 0; }
        bool changed = c->perms != perms;
        c->last_ts = ts;
        c->perms = perms;
        memcpy(c->secret, secret, 32);
        if (changed && perms != PERM_ACL_GUEST) xl_acl_dirty();
    }
    c->last_active_up = uptime_s();
    xl_login_result(true);
    if (flood) c->out_len = OUT_PATH_UNKNOWN;        // rediscover the route
    *out = c;
    stat_logins++;
    LOGLN(c->perms == PERM_ACL_ADMIN ? "  login: admin" : "  login: guest");
    uint32_t now = now_unique();
    memcpy(xl_reply, &now, 4);
    xl_reply[4] = RESP_SERVER_LOGIN_OK;
    xl_reply[5] = 0;
    xl_reply[6] = c->perms == PERM_ACL_ADMIN;
    xl_reply[7] = c->perms;
    uint32_t r = rnd(); memcpy(xl_reply + 8, &r, 4);
    xl_reply[12] = FIRMWARE_VER_LEVEL;
    return 13;
}

static void put16(uint8_t*& p, uint16_t v) { memcpy(p, &v, 2); p += 2; }
static void put32(uint8_t*& p, uint32_t v) { memcpy(p, &v, 4); p += 4; }

static int xl_request(XlClient* c, uint32_t ts, const uint8_t* req, int len) {
    memcpy(xl_reply, &ts, 4);                         // reflect the sender's timestamp as a tag
    uint8_t* p = xl_reply + 4;
    switch (req[0]) {
        case REQ_TYPE_GET_STATUS: {                   // struct RepeaterStats
            int q = 0; for (int i = 0; i < TXQ_SIZE; i++) q += txq[i].used;
            put16(p, (uint16_t)battery_mv()); put16(p, q);
            put16(p, (uint16_t)(int16_t)noise_floor); put16(p, (uint16_t)(int16_t)last_rssi);
            put32(p, stat_rx); put32(p, stat_tx);
            put32(p, stat_tx_air_ms / 1000); put32(p, uptime_s());
            put32(p, stat_flood_tx); put32(p, stat_direct_tx);
            put32(p, stat_flood_rx); put32(p, stat_direct_rx);
            put16(p, 0); put16(p, (uint16_t)(int16_t)last_snr4);
            put16(p, 0); put16(p, 0);
            put32(p, stat_rx_air_ms / 1000); put32(p, stat_rx_err);
            return p - xl_reply;
        }
        case REQ_TYPE_GET_TELEMETRY_DATA: {           // Cayenne LPP: voltage + temperature, channel 1
            uint16_t v = (uint16_t)(battery_mv() / 10);
            int16_t t = (int16_t)(temp_c() * 10);
            *p++ = 1; *p++ = 116; *p++ = v >> 8; *p++ = v & 0xFF;
            *p++ = 1; *p++ = 103; *p++ = (uint16_t)t >> 8; *p++ = t & 0xFF;
            return p - xl_reply;
        }
        case REQ_TYPE_GET_ACCESS_LIST:
            if (c->perms != PERM_ACL_ADMIN || len < 3 || req[1] || req[2]) return 0;
            for (int i = 0; i < XL_MAX_CLIENTS; i++) {
                if (xl_clients[i].perms == 0xFF) continue;
                memcpy(p, xl_clients[i].pub, 6); p += 6; *p++ = xl_clients[i].perms;
            }
            return p - xl_reply;
        case REQ_TYPE_GET_NEIGHBOURS: {
            if (len < 7 || req[1] != 0) return 0;
            uint8_t count = req[2]; uint16_t offset; memcpy(&offset, req + 3, 2);
            uint8_t order = req[5], plen = req[6] > 32 ? 32 : req[6];
            uint8_t idx[XL_MAX_NEIGHB];
            int n = xl_nb_sorted(idx, order);
            uint8_t* hdr = p; p += 4;
            int16_t total = n, results = 0;
            for (int k = 0; k < count && k + offset < n && (p - hdr) + plen + 5 <= 4 + 130; k++) {
                const XlNeighbour& nb = xl_nb[idx[k + offset]];
                memset(p, 0, plen);                    // we keep 8 bytes of each key
                memcpy(p, nb.pfx, plen < XL_NB_PFX ? plen : XL_NB_PFX); p += plen;
                put32(p, uptime_s() - nb.heard_up); *p++ = (uint8_t)nb.snr4;
                results++;
            }
            memcpy(hdr, &total, 2); memcpy(hdr + 2, &results, 2);
            return p - xl_reply;
        }
        case REQ_TYPE_GET_OWNER_INFO:
            return 4 + sprintf((char*)p, "%s\n%s\n%s", FW_VERSION, cfg.name, app.owner_info);
        case REQ_TYPE_KEEP_ALIVE:
        default:
            return 0;
    }
}

static int xl_anon_query(uint8_t type, uint32_t ts, const uint8_t* data) {
    memcpy(xl_reply, &ts, 4);
    uint32_t now = clock_now();
    memcpy(xl_reply + 4, &now, 4);
    char* t = (char*)xl_reply + 8;
    if (type == ANON_REQ_TYPE_BASIC) { xl_reply[8] = cfg.repeat ? 0 : 0x80; return 9; }
    if (type == ANON_REQ_TYPE_OWNER) return 8 + sprintf(t, "%s\n%s", cfg.name, app.owner_info);
    if (type == ANON_REQ_TYPE_REGIONS) {
        region_list(t, 1, false);
        if (!strcmp(t, "-none-")) *t = 0;
        return 8 + strlen(t);
    }
    (void)data;
    return 0;
}

// ── entry point: a packet whose dest hash is ours ───────────────────────────
// Returns true if it was for us (decrypted), so the caller must not forward it.
static bool xl_handle_for_us(const Pkt& p, int8_t snr4, int scope) {
    (void)snr4;
    if (p.payload_len < 4 || p.payload[0] != own_pubkey[0]) return false;
    bool flood = p.route == ROUTE_FLOOD || p.route == ROUTE_TRANSPORT_FLOOD;
    uint8_t data[MAX_PKT];

    if (p.ptype == PT_ANON_REQ) {
        if (p.payload_len < 1 + 32 + 3) return false;
        if (!xl_login_allowed()) return false;           // too many attempts: don't even do the key exchange
        const uint8_t* sender = p.payload + 1;
        uint8_t secret[32];
        ecdh(secret, sender);
        int n = mac_then_decrypt(secret, data, p.payload + 33, p.payload_len - 33);
        if (n < 5) return false;
        data[n] = 0;
        uint32_t ts; memcpy(&ts, data, 4);
        int rl = 0;
        XlClient* c = NULL;
        if (data[4] == 0 || data[4] >= ' ') {
            rl = xl_login(&c, sender, secret, ts, (const char*)data + 4, flood);
        } else if (!flood) {
            // {type}{reply path len}{reply path}: answer along the supplied path
            uint8_t rpl = data[5];
            int pb = (rpl & 63) * ((rpl >> 6) + 1);
            if ((rpl >> 6) == 3 || pb > MAX_PATH_SIZE || 6 + pb > n) return true;
            rl = xl_anon_query(data[4], ts, data + 6);
            if (rl) {
                uint8_t pl[MAX_PKT];
                pl[0] = sender[0]; pl[1] = own_pubkey[0];
                int pn = 2 + encrypt_then_mac(secret, pl + 2, xl_reply, rl);
                xl_send_direct(PT_RESPONSE, pl, pn, rpl, data + 6, SERVER_RESPONSE_DELAY);
            }
            return true;
        }
        if (!rl) return true;
        if (flood) xl_send_path_return(sender, secret, p, xl_reply, rl, scope);
        else {
            uint8_t pl[MAX_PKT];
            pl[0] = sender[0]; pl[1] = own_pubkey[0];
            int pn = 2 + encrypt_then_mac(secret, pl + 2, xl_reply, rl);
            if (c && c->out_len != OUT_PATH_UNKNOWN) xl_send_direct(PT_RESPONSE, pl, pn, c->out_len, c->out_path, SERVER_RESPONSE_DELAY);
            else xl_send_flood(PT_RESPONSE, pl, pn, p.hash_size, scope, SERVER_RESPONSE_DELAY);
        }
        return true;
    }

    if (p.ptype != PT_REQ && p.ptype != PT_TXT_MSG && p.ptype != PT_PATH) return false;
    // dest(1) src(1) MAC+cipher: try every known client with that source hash
    for (int i = 0; i < XL_MAX_CLIENTS; i++) {
        XlClient* c = &xl_clients[i];
        if (c->perms == 0xFF || c->pub[0] != p.payload[1]) continue;
        int n = mac_then_decrypt(c->secret, data, p.payload + 2, p.payload_len - 2);
        if (n <= 0) continue;
        data[n] = 0;
        c->last_active_up = uptime_s();

        if (p.ptype == PT_PATH) {                      // the client's route back to us → our out_path
            uint8_t pl = data[0];
            int pb = (pl & 63) * ((pl >> 6) + 1);
            if ((pl >> 6) != 3 && pb <= MAX_PATH_SIZE && 1 + pb <= n) {
                c->out_len = pl;
                memcpy(c->out_path, data + 1, pb);
                LOGLN("  path to client learned");
            }
            return true;
        }

        uint32_t ts; memcpy(&ts, data, 4);
        if (p.ptype == PT_REQ) {
            if (ts <= c->last_ts) { LOGLN("  req: replay"); return true; }
            int rl = xl_request(c, ts, data + 4, n - 4);
            if (!rl) return true;
            c->last_ts = ts;
            xl_reply_route(c, c->secret, p, rl, scope);
            return true;
        }

        // TXT_MSG: CLI command (admins only)
        if (c->perms != PERM_ACL_ADMIN || n <= 5) return true;
        uint8_t flags = data[4] >> 2;
        if (flags != TXT_TYPE_PLAIN && flags != TXT_TYPE_CLI_DATA && flags != TXT_TYPE_CLI_COMMAND) return true;
        if (ts < c->last_ts) { LOGLN("  cli: replay"); return true; }
        bool retry = ts == c->last_ts;
        c->last_ts = ts;
        if (flags == TXT_TYPE_PLAIN) {                 // legacy CLI clients expect an ACK
            uint8_t ack[4];
            SHA256 sha;
            sha.reset();
            sha.update(data, 5 + strlen((char*)data + 5));
            sha.update(c->pub, 32);
            sha.finalize(ack, 4);
            if (c->out_len != OUT_PATH_UNKNOWN) xl_send_direct(PT_ACK, ack, 4, c->out_len, c->out_path, TXT_ACK_DELAY);
            else xl_send_flood(PT_ACK, ack, 4, p.hash_size, scope, TXT_ACK_DELAY);
        }
        if (retry) return true;
        uint8_t temp[5 + 176];
        char* reply = (char*)temp + 5;
        reply[0] = 0;
        handle_command_from((char*)data + 5, reply, ts);
        int tl = strlen(reply);
        if (tl > 160) tl = 160;
        if (tl > 0) {
            uint32_t t = now_unique();
            if (t == ts) t++;
            memcpy(temp, &t, 4);
            temp[4] = TXT_TYPE_CLI_DATA << 2;
            xl_send_datagram(c, PT_TXT_MSG, temp, 5 + tl, p.hash_size, scope, CLI_REPLY_DELAY);
        }
        return true;
    }
    return false;
}

// ── alerts to a channel (upstream BaseChatMesh::sendGroupMessage format) ────
// Nothing is sent until "set alert.channel" names a channel; "set alerts off" mutes.
static uint32_t xl_alert_last_ms = 0;
static bool xl_alert_any = false, xl_batt_warned = false, xl_boot_alert_done = false;

static bool xl_alert(const char* text, bool urgent) {
    if (!more.alerts || !more.key_len) return false;
    if (!urgent && xl_alert_any && millis() - xl_alert_last_ms < 300000UL) return false;   // ≤ 1 per 5 min
    xl_alert_last_ms = millis(); xl_alert_any = true;
    uint8_t data[5 + 160];
    uint32_t t = now_unique();
    memcpy(data, &t, 4);
    data[4] = TXT_TYPE_PLAIN << 2;
    char* m = (char*)data + 5;
    strcpy(m, cfg.name); strcat(m, ": ");
    strncat(m, text, 150 - strlen(m));
    uint8_t h[32];
    SHA256 sha; sha.reset(); sha.update(more.secret, more.key_len); sha.finalize(h, 32);
    uint8_t pl[MAX_PKT];
    pl[0] = h[0];                                    // channel hash
    int n = 1 + encrypt_then_mac(more.secret, pl + 1, data, 5 + strlen(m));
    xl_send_flood(PT_GRP_TXT, pl, n, (uint8_t)(cfg.path_hash_mode + 1), -1, 0);
    LOG("  alert: "); LOGLN(m);
    return true;
}

static uint16_t xl_alert_threshold(void) {          // alert.battery: 0 auto (cutoff + 150), 1 off
    if (more.alert_mv == 1) return 0;
    return more.alert_mv ? more.alert_mv : (ext.cut_mv ? ext.cut_mv + 150 : 0);
}
static void xl_alert_battery(uint32_t mv) {
    uint16_t th = xl_alert_threshold();
    if (!th || !mv) return;
    if (!xl_batt_warned && mv < th) {
        char t[48]; sprintf(t, "battery low: %lu mV", (unsigned long)mv);
        if (xl_alert(t, false)) xl_batt_warned = true;
    } else if (xl_batt_warned && mv > th + 100UL) xl_batt_warned = false;
}
static void xl_alert_boot(void) {                   // once, a minute after start-up
    xl_boot_alert_done = true;
    if (!strcmp(reset_why, "reboot command")) return;
    char t[96];
    if (!strcmp(reset_why, "low-battery standby"))
        sprintf(t, "back on after low-battery shutdown, battery %lu mV", (unsigned long)battery_mv());
    else
        sprintf(t, "restarted (%s, %u watchdog resets since power-on), battery %lu mV", reset_why, wdt_resets, (unsigned long)battery_mv());
    xl_alert(t, true);
}

// "set alert.channel": #hashtag, public, a 32/64-hex key, or off
static bool xl_set_alert_channel(const char* v) {
    static const uint8_t pub_psk[16] = { 0x8b,0x33,0x87,0xe9,0xc5,0xcd,0xea,0x6a,0xc9,0xe5,0xed,0xba,0xa1,0x15,0xcd,0x72 };
    memset(more.secret, 0, 32);
    more.label[0] = 0;
    if (!strcmp(v, "off") || !strcmp(v, "none")) { more.key_len = 0; return true; }
    if (!strcmp(v, "public") || !strcmp(v, "Public")) {
        memcpy(more.secret, pub_psk, 16); more.key_len = 16; strcpy(more.label, "Public"); return true;
    }
    if (v[0] == '#' && v[1] && strlen(v) < sizeof(more.label)) {
        uint8_t h[32];
        SHA256 sha; sha.reset(); sha.update(v, strlen(v)); sha.finalize(h, 32);
        memcpy(more.secret, h, 16); more.key_len = 16; strcpy(more.label, v); return true;
    }
    int n = strlen(v);
    if (n == 32 || n == 64) {
        for (int i = 0; i < n / 2; i++) {
            int a = hexval(v[2 * i]), b = hexval(v[2 * i + 1]);
            if (a < 0 || b < 0) { more.key_len = 0; return false; }
            more.secret[i] = (uint8_t)(a << 4 | b);
        }
        more.key_len = n / 2;
        strcpy(more.label, "private "); memcpy(more.label + 8, v, 8); strcpy(more.label + 16, "...");
        return true;
    }
    more.key_len = 0;
    return false;
}

