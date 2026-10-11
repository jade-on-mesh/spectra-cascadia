# PlatformIO extra script for the XL (128 KB) build:
#  1. refuse an image whose startup code (vectors, global constructors) reaches
#     into the upper 64 KB — that code runs before setup() can check the upper
#     half was actually flashed;
#  2. emit firmware.hex. The image has a gap at 0x0800F800-0x0800FFFF (settings +
#     clock journal); a .hex skips it, a .bin would overwrite it with zeros.
import struct, subprocess
Import("env")

HI = 0x08010000

def check_startup(target, source, env):
    elf = str(target[0])
    objdump = env.subst("$OBJCOPY").replace("objcopy", "objdump")
    out = subprocess.check_output([objdump, "-s", "-j", ".init_array", "-j", ".preinit_array", elf], text=True)
    bad = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].startswith("80"):
            continue
        for w in parts[1:5]:
            if len(w) == 8:
                (addr,) = struct.unpack("<I", bytes.fromhex(w))
                if addr >= HI:
                    bad.append(hex(addr))
    if bad:
        print("XL: global constructor(s) placed in the upper 64 KB: %s" % ", ".join(bad))
        print("    Exclude their object file from .text_hi in specter_xl.ld")
        env.Exit(1)

env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", check_startup)
env.AddPostAction(
    "$BUILD_DIR/${PROGNAME}.elf",
    env.VerboseAction("$OBJCOPY -O ihex $BUILD_DIR/${PROGNAME}.elf $BUILD_DIR/${PROGNAME}.hex",
                      "Building $BUILD_DIR/${PROGNAME}.hex"))
