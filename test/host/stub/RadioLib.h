#pragma once
#include <Arduino.h>
#define RADIOLIB_NC 0xFFFFFFFF
#define RADIOLIB_ERR_NONE 0
#define RADIOLIB_CHANNEL_FREE (-15)
#define RADIOLIB_LORA_DETECTED (-702)
#define RADIOLIB_ERR_SPI_CMD_FAILED -707
#define RADIOLIB_ERR_SPI_CMD_INVALID -706
#define RADIOLIB_ERR_TX_TIMEOUT -5
#define RADIOLIB_ERR_PACKET_TOO_LONG -4
#define RADIOLIB_ERR_CRC_MISMATCH -7
#define RADIOLIB_SX126X_RX_TIMEOUT_INF 0xFFFFFF
#define RADIOLIB_IRQ_RX_DEFAULT_FLAGS 0
#define RADIOLIB_IRQ_RX_DEFAULT_MASK 0
#define RADIOLIB_IRQ_PREAMBLE_DETECTED 3
#define RADIOLIB_SX126X_IRQ_TIMEOUT 0x200
#define RADIOLIB_SX126X_IRQ_CRC_ERR 0x40
#define RADIOLIB_SX126X_IRQ_HEADER_ERR 0x20
#define RADIOLIB_SX126X_IRQ_HEADER_VALID 0x10
#define RADIOLIB_SX126X_IRQ_SYNC_WORD_VALID 0x8
#define RADIOLIB_SX126X_IRQ_PREAMBLE_DETECTED 0x4
#define RADIOLIB_SX126X_IRQ_RX_DONE 0x2
#define RADIOLIB_SX126X_IRQ_TX_DONE 0x1
#define RADIOLIB_SX126X_CMD_GET_RSSI_INST 0x15
struct Module { Module(uint32_t,uint32_t,uint32_t,uint32_t,FakeSPI&) {} int16_t SPIreadStream(uint16_t, uint8_t* d, size_t) { *d = 220; return 0; } };
struct SX1262 {
  Module* m;
  SX1262(Module* mm) : m(mm) {}
  int begin(float f,float b,int s,int,int,int,int p,float,bool) { f_khz = (uint32_t)(f * 1000.0f + 0.5f); bw_hz = (uint32_t)(b * 1000.0f + 0.5f); sf = s; pre = p; return 0; }
  void setRfSwitchPins(int,int) {}
  void setCRC(int) {}
  uint64_t getTimeOnAir(size_t len) { return (uint64_t)(len * 2000 + 40000); } // ~2ms/byte fake
  int startReceive(uint32_t,uint32_t,uint32_t,size_t) { return 0; }
  uint32_t irq = 0;
  uint32_t getIrqFlags() { return irq | RADIOLIB_SX126X_IRQ_TX_DONE; }
  int clearIrqFlags(uint32_t f) { irq &= ~f; return 0; }
  int standby() { return 0; }
  uint8_t last_tx[256]; size_t last_tx_len = 0; int tx_count = 0;
  int startTransmit(const uint8_t* b, size_t n) { memcpy(last_tx, b, n); last_tx_len = n; tx_count++; return 0; }
  int finishTransmit() { return 0; }
  uint8_t randomByte() { return 0x5A; }
  size_t getPacketLength() { return 0; }
  int readData(uint8_t*, size_t) { return 0; }
  float getSNR() { return 0; }
  float getRSSI() { return 0; }
  int16_t setOutputPower(int) { return 0; }
  bool boosted = false; int sleeps = 0; int scans = 0; int16_t scan_result = RADIOLIB_CHANNEL_FREE;
  int16_t scanChannel() { scans++; return scan_result; }
  int16_t setRxBoostedGainMode(bool b, bool = true) { boosted = b; return 0; }
  int16_t sleep(bool = true) { sleeps++; return 0; }
  int last_cr = 5; int16_t setCodingRate(int c) { last_cr = c; return 0; }
  // radio2: what the radio is tuned to (kHz / Hz as integers for easy checks)
  uint32_t f_khz = 0, bw_hz = 0; int sf = 0; int pre = 0; int tunes = 0; int16_t tune_err = 0;
  int16_t setFrequency(float f, bool) { if (tune_err) return tune_err; f_khz = (uint32_t)(f * 1000.0f + 0.5f); tunes++; return 0; }
  int16_t setBandwidth(float b) { bw_hz = (uint32_t)(b * 1000.0f + 0.5f); return 0; }
  int16_t setSpreadingFactor(int s) { sf = s; return 0; }
  int16_t setPreambleLength(size_t p) { pre = (int)p; return 0; }
protected:
  uint32_t getPacketStatus() { return 0; }
  Module* getMod() { return m; }
public:
};
