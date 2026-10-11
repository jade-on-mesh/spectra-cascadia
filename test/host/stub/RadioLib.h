#pragma once
#include <Arduino.h>
#define RADIOLIB_NC 0xFFFFFFFF
#define RADIOLIB_ERR_NONE 0
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
struct Module { Module(uint32_t,uint32_t,uint32_t,uint32_t,FakeSPI&) {} };
struct SX1262 {
  SX1262(Module*) {}
  int begin(float,float,int,int,int,int,int,float,bool) { return 0; }
  void setRfSwitchPins(int,int) {}
  void setCRC(int) {}
  uint64_t getTimeOnAir(size_t len) { return (uint64_t)(len * 2000 + 40000); } // ~2ms/byte fake
  int startReceive(uint32_t,uint32_t,uint32_t,size_t) { return 0; }
  uint32_t irq = 0;
  uint32_t getIrqFlags() { return irq | RADIOLIB_SX126X_IRQ_TX_DONE; }
  int clearIrqFlags(uint32_t f) { irq &= ~f; return 0; }
  int standby() { return 0; }
  int startTransmit(const uint8_t*, size_t) { return 0; }
  int finishTransmit() { return 0; }
  uint8_t randomByte() { return 0x5A; }
  size_t getPacketLength() { return 0; }
  int readData(uint8_t*, size_t) { return 0; }
  float getSNR() { return 0; }
  float getRSSI() { return 0; }
  int16_t setOutputPower(int) { return 0; }
  int last_cr = 5; int16_t setCodingRate(int c) { last_cr = c; return 0; }
protected:
  uint32_t getPacketStatus() { return 0; }
public:
};
