#!/usr/bin/env python3
"""P-code semantic tests for the RH850 module, run in Ghidra's emulator by EmuCheck.java.

  emu_tests.py <outdir> [--break NAME]  -> emu.s, emu.bin (v850-elf-as -mv850e3v5 / ld), emu.txt
  emu_tests.py <outdir> --arch v850e1   -> emu_v850e1.*: the tests that assemble for V850E1, for
                                           the RH850:LE:32:V850E1 language

Each test is a short instruction sequence at its own label. emu.txt has one line per test:
  <name> <start-hex> <stop-hex> <init: key=val,...|-> <expect: key=val,...>
Keys are register names (r1, sp, r10, PSW, ...), the PSW flags Z S OV CY SAT, or m1:/m2:/m4:/m8:
<addr> for memory. Values are hex. Before every test r1-r31 and PSW are 0 and sp is 0x8000.
Expected values were worked out by hand from the RH850G3KH software manual (R01US0165).
--break NAME makes that test's first expectation wrong, to show the harness can fail.
"""
import os
import struct
import subprocess
import sys

F1 = struct.unpack("<I", struct.pack("<f", 1.5))[0]
F2 = struct.unpack("<I", struct.pack("<f", 2.25))[0]
F3 = struct.unpack("<I", struct.pack("<f", 3.75))[0]
D1 = struct.unpack("<Q", struct.pack("<d", 2.5))[0]
D2 = struct.unpack("<Q", struct.pack("<d", 4.0))[0]
D3 = struct.unpack("<Q", struct.pack("<d", 10.0))[0]

TESTS = [
    ("mov_imm", ["mov 5, r6", "movea -2, r6, r7", "movhi 0x1234, r0, r8", "mov 0x12345678, r9"], {},
     {"r6": 5, "r7": 3, "r8": 0x12340000, "r9": 0x12345678}),
    ("add_carry", ["add r7, r6"], {"r6": 0xffffffff, "r7": 1}, {"r6": 0, "CY": 1, "Z": 1, "OV": 0, "S": 0}),
    ("add_overflow", ["add r7, r6"], {"r6": 0x7fffffff, "r7": 1}, {"r6": 0x80000000, "OV": 1, "S": 1, "CY": 0}),
    ("sub_borrow", ["sub r7, r6"], {"r6": 1, "r7": 2}, {"r6": 0xffffffff, "CY": 1, "S": 1, "Z": 0}),
    ("subr", ["subr r7, r6"], {"r6": 1, "r7": 5}, {"r6": 4, "CY": 0}),
    ("cmp_eq", ["cmp r7, r6"], {"r6": 9, "r7": 9}, {"Z": 1, "CY": 0}),
    ("cmp_imm", ["cmp -1, r6"], {"r6": 0}, {"Z": 0, "CY": 1}),
    ("addi", ["addi 100, r6, r7"], {"r6": 0xfffffff0}, {"r7": 0x54, "CY": 1}),
    ("satadd", ["satadd r7, r6"], {"r6": 0x7fffffff, "r7": 5}, {"r6": 0x7fffffff, "SAT": 1, "OV": 1}),
    ("satsub", ["satsub r7, r6"], {"r6": 0x80000000, "r7": 1}, {"r6": 0x80000000, "SAT": 1}),
    ("logic", ["and r7, r6", "or r8, r6", "xor r9, r6", "andi 0xff, r6, r10", "not r10, r11"],
     {"r6": 0xf0f0f0f0, "r7": 0x0ff00ff0, "r8": 0x1, "r9": 0x10}, {"r6": 0x00f000e1, "r10": 0xe1, "r11": 0xffffff1e}),
    ("tst", ["tst r7, r6"], {"r6": 0xf0, "r7": 0x0f}, {"Z": 1, "r6": 0xf0}),
    ("shifts_imm", ["shl 4, r6", "shr 8, r7", "sar 8, r8"], {"r6": 0x10000001, "r7": 0x80000180, "r8": 0x80000180},
     {"r6": 0x00000010, "r7": 0x00800001, "r8": 0xff800001, "CY": 1}),
    ("shl_carry", ["shl 1, r6"], {"r6": 0x80000000}, {"r6": 0, "CY": 1, "Z": 1}),
    ("shift_reg_mask", ["shl r7, r6"], {"r6": 1, "r7": 0x21}, {"r6": 2}),
    ("shift3", ["shr r7, r6, r8"], {"r6": 0xf0, "r7": 4}, {"r8": 0xf, "r6": 0xf0}),
    ("ext", ["sxb r6", "zxh r7", "sxh r8", "zxb r9"], {"r6": 0x80, "r7": 0xffff1234, "r8": 0x8000, "r9": 0x1ff},
     {"r6": 0xffffff80, "r7": 0x1234, "r8": 0xffff8000, "r9": 0xff}),
    ("bsw_bsh_hsw", ["bsw r6, r7", "bsh r6, r8", "hsw r6, r9"], {"r6": 0x11223344},
     {"r7": 0x44332211, "r8": 0x22114433, "r9": 0x33441122}),
    ("mul", ["mul r7, r6, r8", "mulu r10, r9, r11"], {"r6": 0xfffffffe, "r7": 3, "r9": 0x80000000, "r10": 4},
     {"r6": 0xfffffffa, "r8": 0xffffffff, "r9": 0, "r11": 2}),
    ("mulh", ["mulh r7, r6"], {"r6": 0xffff, "r7": 3}, {"r6": 0xfffffffd}),
    ("div", ["div r7, r6, r8"], {"r6": 0xfffffff9, "r7": 2}, {"r6": 0xfffffffd, "r8": 0xffffffff}),
    ("divu", ["divu r7, r6, r8"], {"r6": 100, "r7": 7}, {"r6": 14, "r8": 2}),
    ("divh", ["divh r7, r6"], {"r6": 100, "r7": 0x10007}, {"r6": 14}),
    ("setf_cmov", ["cmp r7, r6", "setf lt, r8", "cmov z, r9, r10, r11"], {"r6": 1, "r7": 2, "r9": 7, "r10": 8},
     {"r8": 1, "r11": 8}),
    ("sasf", ["cmp r6, r6", "sasf z, r8"], {"r6": 1, "r8": 1}, {"r8": 3}),
    ("adf_sbf", ["cmp r6, r6", "adf z, r7, r8, r9", "sbf nz, r7, r8, r10"], {"r7": 2, "r8": 10},
     {"r9": 13, "r10": 7}),
    ("sch", ["sch1l r6, r7", "sch0r r6, r8"], {"r6": 0x00f00000}, {"r7": 9, "r8": 1}),
    ("bins", ["bins r6, 8, 4, r7"], {"r6": 0xabc, "r7": 0xffffffff}, {"r7": 0xfffffcff}),
    ("rotl", ["rotl 4, r6, r7"], {"r6": 0x80000001}, {"r7": 0x18}),
    ("bit_ops", ["set1 3, 0[r6]", "clr1 0, 1[r6]", "not1 7, 2[r6]", "tst1 3, 0[r6]"],
     {"r6": 0x4000, "m1:4000": 0, "m1:4001": 0xff, "m1:4002": 0x80},
     {"m1:4000": 8, "m1:4001": 0xfe, "m1:4002": 0, "Z": 0}),
    ("load_sign", ["ld.b 0[r6], r7", "ld.bu 0[r6], r8", "ld.h 0[r6], r9", "ld.hu 0[r6], r10", "ld.w 0[r6], r11"],
     {"r6": 0x4000, "m4:4000": 0x8180ff80}, {"r7": 0xffffff80, "r8": 0x80, "r9": 0xffffff80, "r10": 0xff80,
                                              "r11": 0x8180ff80}),
    ("store", ["st.b r7, 1[r6]", "st.h r7, 2[r6]", "st.w r7, 4[r6]"], {"r6": 0x4000, "r7": 0x11223344},
     {"m1:4001": 0x44, "m2:4002": 0x3344, "m4:4004": 0x11223344}),
    ("sld_sign", ["sld.b 0[ep], r7", "sld.h 2[ep], r8", "sld.bu 0[ep], r9", "sst.w r8, 4[ep]"],
     {"ep": 0x4000, "m4:4000": 0x80010080}, {"r7": 0xffffff80, "r8": 0xffff8001, "r9": 0x80,
                                              "m4:4004": 0xffff8001}),
    ("ld23_dw", ["ld.w 0x10000[r6], r7", "ld.dw 8[r6], r8", "st.dw r8, 16[r6]"],
     {"r6": 0x4000, "m4:14000": 0xcafe, "m8:4008": 0x1122334455667788},
     {"r7": 0xcafe, "r8": 0x55667788, "r9": 0x11223344, "m8:4010": 0x1122334455667788}),
    # RH850G4MH post-increment/decrement forms (not in binutils): ld.w [r6]+, r7; st.b r7, [r8]-
    ("ldpostinc", [".hword 0x17e6, 0x3b78", ".hword 0x27e8, 0x3b72"], {"r6": 0x4000, "r8": 0x4100, "m4:4000": 0x99},
     {"r7": 0x99, "r6": 0x4004, "r8": 0x40ff, "m1:4100": 0x99}),
    ("branches", ["cmp r7, r6", "blt 1f", "mov 1, r10", "1: cmp r6, r7", "bgt 2f", "mov 1, r11", "2: nop"],
     {"r6": 0xffffffff, "r7": 1}, {"r10": 0, "r11": 0}),
    ("bcond_unsigned", ["cmp r7, r6", "bh 1f", "mov 1, r10", "1: nop"], {"r6": 0xffffffff, "r7": 1}, {"r10": 0}),
    # bz with a 17-bit displacement (format VII, raw: binutils' gas has no explicit 17-bit mnemonic)
    ("bcond17", ["cmp r6, r6", "8: .hword 0x07e2", ".hword ((1f - 8b) & 0xfffe) | 1", "mov 1, r10",
                 ".fill 300, 2, 0", "1: nop"], {}, {"r10": 0}),
    ("jarl_jmp", ["jarl sub_add, lp", "mov 7, r11"], {"r6": 2, "r7": 3}, {"r10": 5, "r11": 7}),
    ("jarl_reg", ["movea lo(sub_add), r0, r12", "jarl [r12], lp"], {"r6": 4, "r7": 4}, {"r10": 8}),
    # GCC's V850E2 indirect call: jarl .+4, lp; add 4, lp; jmp [reg]
    ("icall_e2", ["movea lo(sub_add), r0, r12", "jarl 1f, lp", "1: add 4, lp", "jmp [r12]", "mov 7, r11"],
     {"r6": 2, "r7": 3}, {"r10": 5, "r11": 7}),
    ("prepare_dispose", ["mov 0x111, r20", "mov 0x222, r29", "jarl sub_frame, lp"], {},
     {"r20": 0x111, "r29": 0x222, "r10": 0x333, "sp": 0x8000}),
    ("pushsp_popsp", ["mov 5, r6", "mov 6, r7", "pushsp r6-r7", "mov 0, r6", "mov 0, r7", "popsp r6-r7"], {},
     {"r6": 5, "r7": 6, "sp": 0x8000, "m4:7ffc": 5, "m4:7ff8": 6}),
    ("switch", ["mov 1, r6", "switch r6", "3: .hword (2f - 3b) / 2", ".hword (4f - 3b) / 2",
                "2: mov 1, r10", "br 5f", "4: mov 2, r10", "5: nop"], {}, {"r10": 2}),
    # loop r6, 1b (raw: gas parses LOOP's operands differently)
    ("loop", ["mov 3, r6", "1: add 1, r7", "9: .hword 0x06e6", ".hword ((9b - 1b) & 0xfffe) | 1"], {},
     {"r6": 0, "r7": 3}),
    # LDL.W/STC.W: the first STC.W succeeds, the second (link consumed) fails
    ("ldl_stc", ["ldl.w [r6], r7", "stc.w r8, [r6]", "stc.w r9, [r6]"], {"r6": 0x4000, "r8": 0x55, "r9": 0x66,
     "m4:4000": 0x11}, {"r7": 0x11, "r8": 1, "r9": 0, "m4:4000": 0x55}),
    ("caxi", ["caxi [r6], r7, r8"], {"r6": 0x4000, "r7": 5, "r8": 9, "m4:4000": 5}, {"m4:4000": 9, "r8": 5}),
    ("fpu_single", ["addf.s r7, r6, r8", "mulf.s r7, r6, r9", "cmpf.s lt, r6, r7, 1", "trfsr 1"],
     {"r6": F1, "r7": F2}, {"r8": F3, "r9": struct.unpack("<I", struct.pack("<f", 3.375))[0], "Z": 1}),
    ("fpu_double", ["addf.d r6, r8, r10", "mulf.d r6, r8, r12"],
     {"r6": D1 & 0xffffffff, "r7": D1 >> 32, "r8": D2 & 0xffffffff, "r9": D2 >> 32},
     {"r10": struct.unpack("<Q", struct.pack("<d", 6.5))[0] & 0xffffffff,
      "r11": struct.unpack("<Q", struct.pack("<d", 6.5))[0] >> 32,
      "r12": D3 & 0xffffffff, "r13": D3 >> 32}),
    ("fpu_convert", ["cvtf.ws r6, r7", "trncf.sw r8, r9", "ceilf.sw r8, r10"], {"r6": 0xfffffffd, "r8": F3},
     {"r7": struct.unpack("<I", struct.pack("<f", -3.0))[0], "r9": 3, "r10": 4}),
    ("fpu_cmov", ["cmpf.s eq, r6, r6, 2", "cmovf.s 2, r7, r8, r9"], {"r6": F1, "r7": 0x11, "r8": 0x22},
     {"r9": 0x11}),
    # FPSR.RM (bits 18-19) rounds inexact conversions: 0 nearest even, 1 toward zero, 2 toward
    # +inf, 3 toward -inf. 2.5f = 0x40200000, 3.5f = 0x40600000, -2.5f = 0xc0200000.
    ("fpu_rm_nearest", ["cvtf.sw r6, r7", "cvtf.sw r8, r9", "cvtf.sw r10, r11"],
     {"FPSR": 0, "r6": 0x40200000, "r8": 0x40600000, "r10": 0xc0200000}, {"r7": 2, "r9": 4, "r11": 0xfffffffe}),
    ("fpu_rm_zero", ["cvtf.sw r6, r7", "cvtf.sw r8, r9", "cvtf.sw r10, r11"],
     {"FPSR": 0x40000, "r6": 0x40200000, "r8": 0x40600000, "r10": 0xc0200000}, {"r7": 2, "r9": 3, "r11": 0xfffffffe}),
    ("fpu_rm_up", ["cvtf.sw r6, r7", "cvtf.sw r8, r9", "cvtf.sw r10, r11"],
     {"FPSR": 0x80000, "r6": 0x40200000, "r8": 0x40600000, "r10": 0xc0200000}, {"r7": 3, "r9": 4, "r11": 0xfffffffe}),
    ("fpu_rm_down", ["cvtf.sw r6, r7", "cvtf.sw r8, r9", "cvtf.sw r10, r11"],
     {"FPSR": 0xc0000, "r6": 0x40200000, "r8": 0x40600000, "r10": 0xc0200000}, {"r7": 2, "r9": 3, "r11": 0xfffffffd}),
    # 2^24 + 1 is not a single: nearest even 2^24 (0x4b800000), up 2^24 + 2 (0x4b800001)
    ("fpu_rm_i2f_up", ["cvtf.ws r6, r7", "cvtf.ws r8, r9"], {"FPSR": 0x80000, "r6": 0x01000001, "r8": 0xfeffffff},
     {"r7": 0x4b800001, "r9": 0xcb800000}),
    ("fpu_rm_i2f_down", ["cvtf.ws r6, r7", "cvtf.ws r8, r9"], {"FPSR": 0xc0000, "r6": 0x01000001, "r8": 0xfeffffff},
     {"r7": 0x4b800000, "r9": 0xcb800001}),
    # double 1 + 2^-30 (0x3ff00000_04000000) to single: up 1 + 2^-23, its negation up -1.0
    ("fpu_rm_ds_up", ["cvtf.ds r6, r8", "cvtf.ds r10, r9"],
     {"FPSR": 0x80000, "r6": 0x04000000, "r7": 0x3ff00000, "r10": 0x04000000, "r11": 0xbff00000},
     {"r8": 0x3f800001, "r9": 0xbf800000}),
    # 1e300 (0x7e37e43c_8800759c) to single: nearest overflows to +inf, toward zero gives FLT_MAX
    ("fpu_rm_ds_overflow", ["cvtf.ds r6, r8", "ldsr r12, fpsr", "cvtf.ds r6, r9"],
     {"FPSR": 0, "r12": 0x40000, "r6": 0x8800759c, "r7": 0x7e37e43c}, {"r8": 0x7f800000, "r9": 0x7f7fffff}),
    # 2^64 - 1 (unsigned) and 2^63 - 1 (signed) to single: nearest rounds up to 2^64 / 2^63,
    # toward zero gives the largest singles below them
    ("fpu_rm_l2f_nearest", ["cvtf.uls r6, r8", "cvtf.ls r10, r9"],
     {"FPSR": 0, "r6": 0xffffffff, "r7": 0xffffffff, "r10": 0xffffffff, "r11": 0x7fffffff},
     {"r8": 0x5f800000, "r9": 0x5f000000}),
    ("fpu_rm_l2f_zero", ["cvtf.uls r6, r8", "cvtf.ls r10, r9"],
     {"FPSR": 0x40000, "r6": 0xffffffff, "r7": 0xffffffff, "r10": 0xffffffff, "r11": 0x7fffffff},
     {"r8": 0x5f7fffff, "r9": 0x5effffff}),
    # 2^64 - 2048 (0x43efffff_ffffffff) to unsigned 64-bit: above 2^63
    ("fpu_dul_big", ["cvtf.dul r6, r8"], {"FPSR": 0, "r6": 0xffffffff, "r7": 0x43efffff},
     {"r8": 0xfffff800, "r9": 0xffffffff}),
    # single 1 + 2^-12 (0x3f800800) to half: nearest 1.0 (0x3c00), up 1 + 2^-10 (0x3c01)
    ("fpu_rm_sh", ["cvtf.sh r6, r7", "ldsr r12, fpsr", "cvtf.sh r6, r8"],
     {"FPSR": 0, "r12": 0x80000, "r6": 0x3f800800}, {"r7": 0x3c00, "r8": 0x3c01}),
]

SUBS = """
sub_add:
	add r6, r7
	mov r7, r10
	jmp [lp]
sub_frame:
	prepare {r20, r29, lp}, 2
	mov 0, r20
	mov 0x333, r10
	mov 0, r29
	dispose 2, {r20, r29, lp}, [lp]
"""


def lines(asm):
    out = []
    for a in asm:
        if a[:1].isdigit() and a[1:3] == ": ":
            out += [a[:2], "\t" + a[3:]]
        else:
            out.append("\t" + a)
    return out


# tests that spell RH850-only instructions as raw .hword encodings (gas has no mnemonic for
# them), so assembling for another architecture does not reject them
RAW_RH850 = {"ldpostinc", "bcond17", "loop"}


def assembles(asm, arch, out):
    """does the test's code (with the shared subroutines) assemble for arch?"""
    src = os.path.join(out, "probe.s")
    open(src, "w").write("\n".join(["\t.text"] + lines(asm) + [SUBS]) + "\n")
    return subprocess.call(["v850-elf-as", "-m" + arch, src, "-o", os.path.join(out, "probe.o")],
                           stderr=subprocess.DEVNULL) == 0


def main():
    out = sys.argv[1]
    brk = sys.argv[sys.argv.index("--break") + 1] if "--break" in sys.argv else None
    arch = sys.argv[sys.argv.index("--arch") + 1] if "--arch" in sys.argv else "v850e3v5"
    base = "emu" if arch == "v850e3v5" else "emu_" + arch
    tests = [t for t in TESTS
             if arch == "v850e3v5" or (t[0] not in RAW_RH850 and assembles(t[1], arch, out))]
    s = ["\t.text", "\t.org 0x100"]
    for i, (name, asm, init, exp) in enumerate(tests):
        s.append("t%d:" % i)
        for a in asm:
            if a[:1].isdigit() and a[1:3] == ": ":
                s.append(a[:2])
                s.append("\t" + a[3:])
            else:
                s.append("\t" + a)
        s.append("t%d_end:" % i)
        s.append("\tbr t%d_end" % i)
    s.append(SUBS)
    src = os.path.join(out, base + ".s")
    open(src, "w").write("\n".join(s) + "\n")
    obj, elf, binf = (os.path.join(out, base + e) for e in (".o", ".elf", ".bin"))
    subprocess.check_call(["v850-elf-as", "-m" + arch, src, "-o", obj])
    subprocess.check_call(["v850-elf-ld", "-Ttext=0", "-e", "0", obj, "-o", elf])
    subprocess.check_call(["v850-elf-objcopy", "-O", "binary", "-j", ".text", elf, binf])
    syms = {}
    for line in subprocess.check_output(["v850-elf-nm", elf], text=True).splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    with open(os.path.join(out, base + ".txt"), "w") as f:
        for i, (name, asm, init, exp) in enumerate(tests):
            exp = dict(exp)
            if name == brk:
                k = next(iter(exp))
                exp[k] = exp[k] ^ 1
            kv = lambda d: ",".join("%s=%x" % (k, v) for k, v in d.items()) or "-"
            f.write("%s %x %x %s %s\n" % (name, syms["t%d" % i], syms["t%d_end" % i], kv(init), kv(exp)))
    print("%d emulator tests (%s) -> %s" % (len(tests), arch, out))


if __name__ == "__main__":
    main()
