#!/usr/bin/env python3
"""Write the executable PROGBITS sections of a 32-bit little-endian ELF as one raw image.
  elf_exec_image.py <elf> <out.bin>   -> prints the base address (hex)"""
import struct
import sys

d = open(sys.argv[1], "rb").read()
assert d[:4] == b"\x7fELF" and d[4] == 1 and d[5] == 1, "ELF32 LE only"
shoff, = struct.unpack_from("<I", d, 0x20)
shentsize, shnum = struct.unpack_from("<HH", d, 0x2e)
secs = []
for i in range(shnum):
    name, typ, flags, addr, off, size = struct.unpack_from("<IIIIII", d, shoff + i * shentsize)
    if typ == 1 and flags & 0x2 and flags & 0x4 and size:
        secs.append((addr, off, size))
lo = min(a for a, _, _ in secs)
hi = max(a + s for a, _, s in secs)
img = bytearray(hi - lo)
for a, o, s in secs:
    img[a - lo:a - lo + s] = d[o:o + s]
open(sys.argv[2], "wb").write(img)
print("%x" % lo)
