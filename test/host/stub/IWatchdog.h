#pragma once
struct FakeWD { void begin(uint32_t) {} void reload() {} };
extern FakeWD IWatchdog;
