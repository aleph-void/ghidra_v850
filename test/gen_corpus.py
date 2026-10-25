#!/usr/bin/env python3
"""V850/RH850 decode corpora, 8-byte slots (longest instruction: prepare with imm32, 8 bytes).

  gen_corpus.py <binutils-src>/opcodes/v850-opc.c <outdir>
     -> table.bin (+ table.txt: slot -> opcode-table entry), first.bin, fuzz.bin

table.bin: 48 encodings of every v850_opcodes[] entry, opcode bits fixed, other bits random
           (every encoding the reference disassembler's table can produce)
first.bin: every first halfword with three random second/third halfwords
fuzz.bin:  100,000 random slots
Fixed seeds; output is deterministic.
"""
import os
import random
import re
import struct
import sys

src, out = sys.argv[1], sys.argv[2]
OP = lambda x: (x & 0x3f) << 5
BOP = lambda x: (0x58 << 4) | (x & 0x0f)
two = lambda x, y: (x & 0xffff) | ((y & 0xffff) << 16)
one = lambda x: x
env = {"OP": OP, "BOP": BOP, "two": two, "one": one, "OP_MASK": OP(0x3f),
       "BOP_MASK": (0x78 << 4) | 0x0f, "BOP7": lambda x: 0x107e0 | (x & 0xf), "BOP7_MASK": 0x1ffe0 | 0xf}
text = open(src).read()
text = text[text.index("const struct v850_opcode v850_opcodes[]"):]
entries = []


def split_top(sx):
    parts, depth, cur = [], 0, ""
    for ch in sx:
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [x.strip() for x in parts]


for m in re.finditer(r'^\{\s*"([^"]+)",(.*)$', text, re.M):
    name = m.group(1)
    f = split_top(m.group(2))
    try:
        entries.append((name, eval(f[0], env), eval(f[1], env)))
    except Exception as e:  # noqa: BLE001
        print("skip", name, f[:2], e, file=sys.stderr)
rnd = random.Random(7)
tb = bytearray()
lines = []
for name, opc, mask in entries:
    for _ in range(48):
        w = (opc & mask) | (rnd.getrandbits(32) & ~mask & 0xffffffff)
        slot = struct.pack("<I", w) + bytes(rnd.getrandbits(8) for _ in range(4))
        lines.append("%08x %s %08x %08x" % (len(tb), name, opc, mask))
        tb += slot
open(os.path.join(out, "table.bin"), "wb").write(tb)
open(os.path.join(out, "table.txt"), "w").write("\n".join(lines) + "\n")
fb = bytearray()
for h in range(0x10000):
    for _ in range(3):
        fb += struct.pack("<H", h) + bytes(rnd.getrandbits(8) for _ in range(6))
open(os.path.join(out, "first.bin"), "wb").write(fb)
rz = random.Random(1)
zb = bytearray()
for _ in range(100000):
    zb += bytes(rz.getrandbits(8) for _ in range(8))
open(os.path.join(out, "fuzz.bin"), "wb").write(zb)
print("%d opcode-table entries; table.bin %d, first.bin %d, fuzz.bin %d slots"
      % (len(entries), len(tb) // 8, len(fb) // 8, len(zb) // 8))
