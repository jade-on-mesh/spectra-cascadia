/*
 * flash128_test — does this STM32F103C8 really have 128 KB of usable flash?
 *
 * Flash this at 0x08000000 with the ST-Link, open the serial monitor at 115200,
 * and press RST. It erases, writes and verifies every 1 KB page from
 * 0x08010000 to 0x0801FFFF with three patterns, then prints PASS or FAIL
 * (repeated every 5 s). LED: slow blink = PASS, fast blink = FAIL.
 *
 * It never touches the first 64 KB, so SPECTER's saved settings in
 * 0x0800F800-0x0800FFFF survive; reflash SPECTER (without Full chip erase) after.
 */
#include <Arduino.h>

#define BASE   0x08010000UL
#define PAGES  64
#define PAGE   1024UL
#define LED    PB11

static uint32_t bad_pages = 0, bad_words = 0, first_bad = 0;
static bool done = false, pass = false;

static uint32_t pattern(uint8_t pass_no, uint32_t addr) {
    switch (pass_no) {
        case 0:  return addr ^ 0xA5A55A5AUL;          // address-unique
        case 1:  return ~(addr ^ 0xA5A55A5AUL);       // every bit flipped
        default: return (addr & 4) ? 0x55555555UL : 0xAAAAAAAAUL;   // checkerboard
    }
}

static bool erase_page(uint32_t addr) {
    FLASH_EraseInitTypeDef er = {};
    er.TypeErase = FLASH_TYPEERASE_PAGES;
    er.PageAddress = addr;
    er.NbPages = 1;
    uint32_t err = 0;
    return HAL_FLASHEx_Erase(&er, &err) == HAL_OK && err == 0xFFFFFFFFUL;
}

static void run_test(void) {
    HAL_FLASH_Unlock();
    for (uint32_t p = 0; p < PAGES; p++) {
        uint32_t a0 = BASE + p * PAGE;
        bool page_bad = false;
        for (uint8_t n = 0; n < 3 && !page_bad; n++) {
            if (!erase_page(a0)) { page_bad = true; break; }
            for (uint32_t a = a0; a < a0 + PAGE; a += 4)
                if (*(volatile uint32_t*)a != 0xFFFFFFFFUL) { page_bad = true; bad_words++; }
            for (uint32_t a = a0; a < a0 + PAGE && !page_bad; a += 4)
                if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, a, pattern(n, a)) != HAL_OK) page_bad = true;
            for (uint32_t a = a0; a < a0 + PAGE; a += 4)
                if (*(volatile uint32_t*)a != pattern(n, a)) { page_bad = true; bad_words++; }
        }
        erase_page(a0);                                 // leave the page blank
        if (page_bad) { if (!bad_pages) first_bad = a0; bad_pages++; }
        digitalWrite(LED, p & 1);
        Serial1.print('.');
    }
    HAL_FLASH_Lock();
    pass = bad_pages == 0;
    done = true;
}

static void report(void) {
    uint16_t size_kb = *(volatile uint16_t*)0x1FFFF7E0UL;
    uint32_t devid = DBGMCU->IDCODE & 0xFFF;
    Serial1.println();
    Serial1.print("Flash size register: "); Serial1.print(size_kb); Serial1.print(" KB, device ID 0x");
    Serial1.println(devid, HEX);
    Serial1.print("Upper 64 KB (0x08010000-0x0801FFFF), 64 pages x 3 patterns: ");
    if (pass) Serial1.println("PASS - all pages erased, written and verified");
    else {
        Serial1.print("FAIL - "); Serial1.print(bad_pages); Serial1.print(" bad page(s), first at 0x");
        Serial1.print(first_bad, HEX); Serial1.print(", "); Serial1.print(bad_words); Serial1.println(" bad words");
    }
}

void setup() {
    pinMode(LED, OUTPUT);
    Serial1.begin(115200);
    delay(1500);
    Serial1.println();
    Serial1.println("=== STM32F103 128 KB flash test ===");
    Serial1.print("Testing");
    run_test();
    report();
}

void loop() {
    static uint32_t last = 0;
    digitalWrite(LED, (millis() / (pass ? 500 : 80)) & 1);
    if (millis() - last > 5000) { last = millis(); report(); }
}
