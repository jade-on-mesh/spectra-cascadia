/*
 * Spectra-Cascadia XL linker script — STM32F103C8T6/CBT6 using all 128 KB of flash.
 * Based on the stm32duino F103C8T_F103CB(T-U) script (ST, BSD-3-Clause).
 *
 *   0x08000000  62 KB  vectors, firmware core, settings code
 *   0x0800F800   1 KB  settings page (name, identity, regions, passwords) — not in the image
 *   0x0800FC00   1 KB  clock journal                                     — not in the image
 *   0x08010000  63 KB  RadioLib + Crypto, then the XL marker word
 *   0x0801FC00   1 KB  saved admin list + discovery time         — not in the image
 *
 * Ship the .hex (not .bin) so flashing never touches the two settings pages.
 */

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = ORIGIN(RAM) + LENGTH(RAM);	/* end of "RAM" Ram type memory */

_Min_Heap_Size = 0x200;	/* required amount of heap  */
_Min_Stack_Size = 0x400;	/* required amount of stack */

/* Memories definition */
MEMORY
{
  RAM    (xrw)    : ORIGIN = 0x20000000,   LENGTH = LD_MAX_DATA_SIZE
  FLASH    (rx)    : ORIGIN = 0x08000000, LENGTH = 0xF800   /* 62 KB, then settings + clock journal pages */
  FLASH_HI (rx)    : ORIGIN = 0x08010000, LENGTH = 0xFC00   /* the "hidden" upper 64 KB, minus the admin-list page */
}

/* Sections */
SECTIONS
{
  /* XL: the radio driver and crypto libraries live in the upper 64 KB.
     Listed first so these input sections are claimed before .text/.rodata. */
  .text_hi :
  {
    . = ALIGN(4);
    *libRadioLib.a:*(.text .text* .rodata .rodata*)
    /* RNG.cpp has a global constructor, which runs before setup() can check
       the upper half, so it stays low. (tools/xl_hex.py checks all of them.) */
    EXCLUDE_FILE(*libCrypto.a:RNG.cpp.o) *libCrypto.a:*(.text .text* .rodata .rodata*)
    /* libm (powf for rxdelay) is only used after setup(); libgcc and libc stay
       low because startup code needs them before the upper half is checked. */
    *libm.a:*(.text .text* .rodata .rodata*)
    . = ALIGN(4);
    KEEP(*(.xl_magic))   /* last word: present only if the whole upper half was written */
    . = ALIGN(4);
  } >FLASH_HI

  /* The startup code into "FLASH" Rom type memory */
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(4);
  } >FLASH

  /* The program code and other data into "FLASH" Rom type memory */
  .text :
  {
    . = ALIGN(4);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >FLASH

  /* Constant data into "FLASH" Rom type memory */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >FLASH

  .ARM.extab (READONLY) : {
    . = ALIGN(4);
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    . = ALIGN(4);
  } >FLASH

  .ARM (READONLY) : {
    . = ALIGN(4);
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
    . = ALIGN(4);
  } >FLASH

  .preinit_array (READONLY) :
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
    . = ALIGN(4);
  } >FLASH

  .init_array (READONLY) :
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
    . = ALIGN(4);
  } >FLASH

  .fini_array (READONLY) :
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
    . = ALIGN(4);
  } >FLASH

  /* Used by the startup to initialize data */
  _sidata = LOADADDR(.data);

  /* Initialized data sections into "RAM" Ram type memory */
  .data :
  {
    . = ALIGN(4);
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    *(.RamFunc)        /* .RamFunc sections */
    *(.RamFunc*)       /* .RamFunc* sections */

    . = ALIGN(4);
    _edata = .;        /* define a global symbol at data end */

  } >RAM AT> FLASH

  /* Uninitialized data section into "RAM" Ram type memory */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss section */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >RAM

  /* User_heap_stack section, used to check that there is enough "RAM" Ram  type memory left */
  ._user_heap_stack :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >RAM

  /* Remove information from the compiler libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}
