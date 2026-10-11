# 128 KB flash self-test

Many STM32F103C8 chips report 64 KB but have 128 KB of working flash (same die as the
F103CB). It's untested by ST and not guaranteed, so check each board before using a
128 KB build on it.

1. Flash `flash128_test.bin` at `0x08000000` with the ST-Link (CubeProgrammer). Don't use
   Full chip erase: the test never touches the first 64 KB, so SPECTER's saved settings survive.
2. Plug the board's USB-C in and open a serial monitor on its COM port at 115200. Press RST.
3. Wait ~10 s. It prints `PASS` or `FAIL` (repeated every 5 s). LED: slow blink = PASS, fast = FAIL.
4. Reflash SPECTER as usual.

The test erases and writes all 64 upper pages with three patterns (address-unique,
inverted, checkerboard), then verifies them. A pass shows the memory works now; it
can't prove long-term data retention, which ST doesn't specify for the upper half.
