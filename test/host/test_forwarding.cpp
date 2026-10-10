#include <stdint.h>
#include <assert.h>
static uint32_t fake_flash[256];
static uint32_t fake_uid[3] = { 0x11223344, 0x55667788, 0x99AABBCC };
#define JOURNAL_ADDR ((uintptr_t)fake_flash)
#define UID_BASE ((uintptr_t)fake_uid)
#define REGIONS "se-wa, #seattle"
#include "Arduino.h"
uint32_t fake_ms = 0;
FakeSerial Serial1;
int HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef*, uint32_t*) { memset(fake_flash, 0xFF, sizeof(fake_flash)); return 0; }
int HAL_FLASH_Program(uint32_t, uint32_t addr, uint64_t v) {
  uint32_t idx = (addr - (uint32_t)(uintptr_t)fake_flash) / 4;
  assert(idx < 256);
  assert(fake_flash[idx] == 0xFFFFFFFF);   // flash can only be programmed once per erase
  fake_flash[idx] = (uint32_t)v; return 0;
}
#include "SPI.h"
#include "IWatchdog.h"
FakeSPI SPI; FakeWD IWatchdog;
#include "../../src/main.cpp"

static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("PASS  %s\n", msg); else { printf("FAIL  %s\n", msg); fails++; } } while(0)

static int queued() { int n=0; for (int i=0;i<TXQ_SIZE;i++) n += txq[i].used; return n; }
static TxItem* last_q() { TxItem* b=nullptr; for (int i=0;i<TXQ_SIZE;i++) if (txq[i].used) b=&txq[i]; return b; }
static void clearq() { for (int i=0;i<TXQ_SIZE;i++) txq[i].used=false; }
static void hexdump(const char* t, const uint8_t* b, int n){ printf("%s", t); for(int i=0;i<n;i++) printf("%02x", b[i]); printf("\n"); }

int main() {
  memset(fake_flash, 0xFF, sizeof(fake_flash));
  identity_init(); regions_init(); clock_init();
  printf("own hash %02x, regions=%d\n", own_pubkey[0], num_regions);
  CHECK(num_regions == 2 && !strcmp(region_names[0], "se-wa") && !strcmp(region_names[1], "seattle"), "REGIONS list parsed");

  // transport code reference print (checked against Python)
  uint8_t pl[] = { 0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
  printf("TC se-wa TXT = %04x\n", transport_code(region_keys[0], PT_TXT_MSG, pl, sizeof(pl)));
  hexdump("KEY se-wa = ", region_keys[0], 16);

  uint8_t other = own_pubkey[0] ^ 0xFF;

  // 1. unscoped flood TXT_MSG, path [other]
  { uint8_t pk[] = { (PT_TXT_MSG<<2)|ROUTE_FLOOD, 0x01, other, 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05 };
    on_receive(pk, sizeof(pk), 0);
    TxItem* t = last_q();
    CHECK(t && t->len == sizeof(pk)+1 && t->buf[1] == 0x02 && t->buf[2] == other && t->buf[3] == own_pubkey[0]
          && !memcmp(t->buf+4, pk+3, sizeof(pk)-3), "flood: hash appended, hop count 2");
    clearq(); on_receive(pk, sizeof(pk), 0);
    CHECK(queued() == 0, "flood: duplicate dropped");
    clearq(); }

  // 2. scoped flood for configured region
  { uint8_t payload[] = { 0xAA,0xBB,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
    uint16_t tc = transport_code(region_keys[1], PT_TXT_MSG, payload, sizeof(payload));
    uint8_t pk[32]; int n=0; pk[n++]=(PT_TXT_MSG<<2)|ROUTE_TRANSPORT_FLOOD; memcpy(pk+n,&tc,2); n+=2; pk[n++]=0x34; pk[n++]=0x12;
    pk[n++]=0x00; memcpy(pk+n,payload,sizeof(payload)); n+=sizeof(payload);
    on_receive(pk, n, 0);
    TxItem* t = last_q();
    CHECK(t && t->buf[0]==pk[0] && !memcmp(t->buf+1, pk+1, 4) && t->buf[5]==0x01 && t->buf[6]==own_pubkey[0]
          && !memcmp(t->buf+7, payload, sizeof(payload)), "scoped flood (#seattle): codes kept, hash appended after them");
    clearq();
    pk[1]^=0x55; payload[0]^=1; pk[6]^=1;   // different payload, wrong code
    on_receive(pk, n, 0);
    CHECK(queued()==0, "scoped flood for unknown region dropped"); clearq(); }

  // 3. direct: we are next hop
  { uint8_t pk[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x02, own_pubkey[0], 0x77, 0xAA,0xBB,0x01,0x02,0x03,0x09 };
    on_receive(pk, sizeof(pk), 0);
    TxItem* t = last_q();
    CHECK(t && t->len==sizeof(pk)-1 && t->buf[0]==pk[0] && t->buf[1]==0x01 && t->buf[2]==0x77 && t->pri==0, "direct: self removed from path");
    clearq(); on_receive(pk, sizeof(pk), 0);
    CHECK(queued()==0, "direct: duplicate dropped (no ping-pong)"); clearq();
    uint8_t pk2[] = { (PT_TXT_MSG<<2)|ROUTE_DIRECT, 0x02, 0x77, own_pubkey[0], 0xAA,0xBB,0x01,0x02,0x03,0x0A };
    on_receive(pk2, sizeof(pk2), 0);
    CHECK(queued()==0, "direct: not next hop -> dropped"); clearq(); }

  // 4. transport-direct ACK -> plain DIRECT ACK
  { uint8_t pk[] = { (PT_ACK<<2)|ROUTE_TRANSPORT_DIRECT, 1,2,3,4, 0x02, own_pubkey[0], 0x66, 0xDE,0xAD,0xBE,0xEF };
    on_receive(pk, sizeof(pk), 0);
    TxItem* t = last_q();
    CHECK(t && t->buf[0]==((PT_ACK<<2)|ROUTE_DIRECT) && t->buf[1]==0x01 && t->buf[2]==0x66 && !memcmp(t->buf+3,pk+8,4) && t->len==7, "direct ACK re-sent as DIRECT ACK");
    clearq(); }

  // 5. TRACE: path holds SNRs, payload lists hashes
  { uint8_t pk[] = { (PT_TRACE<<2)|ROUTE_DIRECT, 0x01, 0x28, 1,2,3,4, 5,6,7,8, 0x00, 0x99, own_pubkey[0], 0x55 };
    on_receive(pk, sizeof(pk), -20);
    TxItem* t = last_q();
    CHECK(t && t->buf[1]==0x02 && t->buf[2]==0x28 && (int8_t)t->buf[3]==-20 && t->pri==5, "trace: SNR appended when we are listed next");
    clearq(); }

  // 6. adverts
  { send_advert(false);
    TxItem* t = last_q();
    CHECK(t && t->buf[0]==((PT_ADVERT<<2)|ROUTE_DIRECT) && t->buf[1]==0, "zero-hop advert is DIRECT with empty path");
    const uint8_t* p = t->buf+2; int plen = t->len-2;
    uint8_t msg[80]; memcpy(msg,p,36); memcpy(msg+36,p+100,plen-100);
    CHECK(Ed25519::verify(p+36, p, msg, 36+plen-100), "own advert signature verifies");
    CHECK(p[100] == (ADV_TYPE_REPEATER|ADV_NAME_MASK), "advert flags = repeater+name");
    clearq();
    send_advert(true);
    t = last_q();
    CHECK(t && t->buf[0]==((PT_ADVERT<<2)|ROUTE_FLOOD) && t->buf[1]==0, "flood advert");
    clearq(); }

  // 7. foreign flood advert: valid sig forwarded, forged dropped, too many hops dropped
  { uint8_t sk[32], pkey[32]; for (int i=0;i<32;i++) sk[i]=i*7+3; Ed25519::derivePublicKey(pkey, sk);
    auto mk = [&](uint8_t* out, uint8_t hops, uint32_t ts, bool forge) {
      int n=0; out[n++]=(PT_ADVERT<<2)|ROUTE_FLOOD; out[n++]=hops; for(int i=0;i<hops;i++) out[n++]=0x40+i;
      uint8_t* pl=out+n; memcpy(pl,pkey,32); memcpy(pl+32,&ts,4); uint8_t app[]={0x81,'N','o','d','e'};
      memcpy(pl+100,app,5); uint8_t m[41]; memcpy(m,pl,36); memcpy(m+36,app,5);
      Ed25519::sign(pl+36, sk, pkey, m, 41); if (forge) pl[40]^=1; return n+105; };
    uint8_t buf[200]; uint32_t base = clock_now() + 100000;
    int n = mk(buf, 2, base, false); on_receive(buf, n, 0);
    CHECK(queued()==1, "valid foreign advert forwarded"); clearq();
    n = mk(buf, 2, base+1, true); on_receive(buf, n, 0);
    CHECK(queued()==0, "forged advert dropped"); clearq();
    n = mk(buf, 8, base+2, false); on_receive(buf, n, 0);
    CHECK(queued()==0, "advert at flood.max.advert (8) dropped"); clearq();
  }

  // 8. clock learning: 3 distinct senders far ahead -> clock jumps forward
  { uint32_t before = clock_now(); uint32_t future = before + 50000;
    for (int k=0;k<3;k++){ uint8_t sk[32], pkey[32]; for(int i=0;i<32;i++) sk[i]=i+k*31+1; Ed25519::derivePublicKey(pkey,sk);
      uint8_t pl[105]; memcpy(pl,pkey,32); uint32_t ts=future+k; memcpy(pl+32,&ts,4); uint8_t app[]={0x81,'A','B','C','D'};
      memcpy(pl+100,app,5); uint8_t m[41]; memcpy(m,pl,36); memcpy(m+36,app,5); Ed25519::sign(pl+36,sk,pkey,m,41);
      uint8_t pk[200]; pk[0]=(PT_ADVERT<<2)|ROUTE_DIRECT; pk[1]=0; memcpy(pk+2,pl,105); on_receive(pk,107,0); }
    CHECK(clock_now() >= future, "clock learned forward from verified zero-hop adverts"); clearq(); }

  // 9. reboot: timestamp must not go backwards
  { uint32_t t_before = clock_now();
    fake_ms += 3000;  // a little later
    clk_uptime_s = 0; clk_ms_accum = 0; j_last_flood_ts = 0;
    clock_init();
    CHECK(clock_now() > t_before, "after reboot, clock resumes ahead of last advert");
    CHECK(j_last_flood_ts != 0, "last flood-advert time survives reboot");
    // fill the page to force an erase cycle
    for (int i=0;i<200;i++) journal_write(clock_now()+i, j_last_flood_ts);
    uint32_t ts=0, fl=0; journal_read(&ts,&fl);
    CHECK(ts >= clock_now()+199, "journal wraps and keeps newest record"); }

  // 10. loop / unknown types
  { uint8_t pk[] = { (PT_RAW_CUSTOM<<2)|ROUTE_FLOOD, 0x00, 1,2,3,4,5,6 };
    on_receive(pk, sizeof(pk), 0); CHECK(queued()==0, "RAW_CUSTOM never flooded"); clearq();
    uint8_t pk2[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x02, own_pubkey[0], own_pubkey[0], 1,2,3,4,5,6 };
    on_receive(pk2, sizeof(pk2), 0); CHECK(queued()==0, "flood loop (own hash twice) dropped"); clearq(); }

  // 11. 2-byte path hashes
  { uint8_t pk[] = { (PT_GRP_TXT<<2)|ROUTE_FLOOD, 0x41, 0x10, 0x20, 9,8,7,6,5,4 };
    on_receive(pk, sizeof(pk), 0); TxItem* t=last_q();
    CHECK(t && t->buf[1]==0x42 && t->buf[4]==own_pubkey[0] && t->buf[5]==own_pubkey[1], "2-byte hash mode appends 2 bytes"); clearq(); }

  printf("\n%d failure(s)\n", fails);
  return fails != 0;
}
