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

#define XL_MAX_CLIENTS   6
#define XL_MAX_NEIGHB    8
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

struct XlNeighbour { uint8_t pub[32]; uint32_t heard_up; int8_t snr4; };
static XlNeighbour xl_nb[XL_MAX_NEIGHB];

static uint8_t  xl_reply[180];
static uint32_t xl_last_unique = 0;
static uint32_t xl_reboot_at = 0;
static uint32_t stat_logins = 0;

static void xl_init(void) {
    for (int i = 0; i < XL_MAX_CLIENTS; i++) xl_clients[i].perms = 0xFF;
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

// Returns decrypted length (multiple of 16), or 0 if the MAC doesn't match.
static int mac_then_decrypt(const uint8_t* secret, uint8_t* dest, const uint8_t* src, int len) {
    if (len <= CIPHER_MAC_SIZE) return 0;
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
        if (!memcmp(xl_nb[i].pub, pub, 32)) { s = i; break; }
        if (xl_nb[i].heard_up < xl_nb[s].heard_up) s = i;
    }
    memcpy(xl_nb[s].pub, pub, 32);
    xl_nb[s].heard_up = uptime_s() | 1;
    xl_nb[s].snr4 = snr4;
}

// ── request handlers ────────────────────────────────────────────────────────

static int xl_login(XlClient** out, const uint8_t* sender_pub, const uint8_t* secret, uint32_t ts, const char* pw, bool flood) {
    XlClient* c = NULL;
    if (!pw[0]) c = xl_find(sender_pub);             // blank password: already known?
    if (!c) {
        uint8_t perms;
        if (auth.admin_pw[0] && !strcmp(pw, auth.admin_pw)) perms = PERM_ACL_ADMIN;
        else if (auth.guest_pw[0] && !strcmp(pw, auth.guest_pw)) perms = PERM_ACL_GUEST;
        else { LOGLN("  login: bad password"); return 0; }
        c = xl_put(sender_pub);
        if (ts <= c->last_ts) { LOGLN("  login: replay"); return 0; }
        c->last_ts = ts;
        c->perms = perms;
        memcpy(c->secret, secret, 32);
    }
    c->last_active_up = uptime_s();
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
            int idx[XL_MAX_NEIGHB], n = 0;
            for (int i = 0; i < XL_MAX_NEIGHB; i++) if (xl_nb[i].heard_up) idx[n++] = i;
            for (int i = 1; i < n; i++)                // order: 0 newest, 1 oldest, 2 strongest, 3 weakest
                for (int j = i; j > 0; j--) {
                    const XlNeighbour &a = xl_nb[idx[j-1]], &b = xl_nb[idx[j]];
                    bool swap = order == 1 ? a.heard_up > b.heard_up : order == 2 ? a.snr4 < b.snr4
                              : order == 3 ? a.snr4 > b.snr4 : a.heard_up < b.heard_up;
                    if (!swap) break;
                    int t = idx[j]; idx[j] = idx[j-1]; idx[j-1] = t;
                }
            uint8_t* hdr = p; p += 4;
            int16_t total = n, results = 0;
            for (int k = 0; k < count && k + offset < n && (p - hdr) + plen + 5 <= 4 + 130; k++) {
                const XlNeighbour& nb = xl_nb[idx[k + offset]];
                memcpy(p, nb.pub, plen); p += plen;
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
        if (flags != TXT_TYPE_PLAIN && flags != TXT_TYPE_CLI_DATA) return true;
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
