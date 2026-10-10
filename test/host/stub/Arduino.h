#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define HIGH 1
#define LOW 0
#define OUTPUT 1
#define PA0 0
#define PA1 1
#define PA2 2
#define PA3 3
#define PA4 4
#define PB11 27
#define HEX 16
extern uint32_t fake_ms;
inline uint32_t millis() { return fake_ms; }
inline uint32_t micros() { return fake_ms * 1000; }
inline void delay(uint32_t ms) { fake_ms += ms; }
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
inline int analogRead(int) { return 0; }
inline void __WFI() {}
struct FakeSerial {
  void begin(int) {}
  template<class T> void print(T v) { (void)v; }
  template<class T> void print(T v, int) { (void)v; }
  template<class T> void println(T v) { (void)v; }
  template<class T> void println(T v, int) { (void)v; }
  void println() {}
};
extern FakeSerial Serial1;
// Fake flash
#define FLASH_TYPEERASE_PAGES 0
#define FLASH_TYPEPROGRAM_WORD 2
struct FLASH_EraseInitTypeDef { uint32_t TypeErase, Banks, PageAddress, NbPages; };
inline void HAL_FLASH_Unlock() {}
inline void HAL_FLASH_Lock() {}
int HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef*, uint32_t*);
int HAL_FLASH_Program(uint32_t, uint32_t, uint64_t);
