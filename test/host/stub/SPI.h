#pragma once
struct FakeSPI { void begin() {} uint8_t transfer(uint8_t) { return 0; } };
extern FakeSPI SPI;
