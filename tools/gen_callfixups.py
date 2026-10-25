#!/usr/bin/env python3
# Generates the call fixups for GCC's out-of-line prologue/epilogue helpers (libgcc
# config/v850/lib1funcs.S, used with -mprolog-function, the default at -Os) into
# data/languages/v850.cspec, between the "generated call fixups" markers.
#
#   python3 tools/gen_callfixups.py        (from the repository root)
#
# __save_<regs> is called with "jarl __save_<regs>, r10": it allocates 4 bytes per register,
# stores the registers from 0[sp] upwards (r29 first, down to the lowest of r20..r29, then r2,
# then r31) and returns with "jmp [r10]". __return_<regs> is reached with "jr" from the
# function's epilogue: it reloads the same slots, frees them and returns to the caller with
# "jmp [r31]". The fixups replace the call (or the tail jump) with that effect, so the
# decompiler sees the stack frame and the saved registers instead of calls.
import os
import re

CSPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "languages", "v850.cspec")


def variants():
    for top in ("r29", "r31"):
        for low in [2] + list(range(20, 30)) + ([] if top == "r29" else [31]):
            if top == "r29" and low == 29:
                name = "r29"
                regs = ["r29"]
            elif low == 31:
                name = "r31"
                regs = []
            else:
                name = "r%d_%s" % (low, top)
                regs = ["r%d" % r for r in range(29, max(low, 20) - 1, -1)]
                if low == 2:
                    regs.append("r2")
            if top == "r31":
                regs.append("lp")
            yield name, regs


def fixup(kind, name, regs):
    n = 4 * len(regs)
    lines = []
    if kind == "save":
        lines.append("sp = sp - %d;" % n)
        for i, r in enumerate(regs):
            lines.append("a%d:4 = sp + %d; *[ram]:4 a%d = %s;" % (i, 4 * i, i, r))
    else:
        for i, r in enumerate(regs):
            lines.append("a%d:4 = sp + %d; %s = *[ram]:4 a%d;" % (i, 4 * i, r, i))
        lines.append("sp = sp + %d;" % n)
    f = "__%s_%s" % (kind, name)
    return ('  <callfixup name="%s">\n    <target name="%s"/>\n    <pcode>\n      <body><![CDATA[\n'
            '        %s\n      ]]></body>\n    </pcode>\n  </callfixup>') % (f, f, "\n        ".join(lines))


out = []
for name, regs in variants():
    out.append(fixup("save", name, regs))
    out.append(fixup("return", name, regs))
BEGIN = "  <!-- generated call fixups (tools/gen_callfixups.py): begin -->"
END = "  <!-- generated call fixups: end -->"
s = open(CSPEC, newline="").read()
nl = "\r\n" if "\r\n" in s else "\n"
s = s.replace("\r\n", "\n")
block = BEGIN + "\n" + "\n".join(out) + "\n" + END
if BEGIN in s:
    s = re.sub(re.escape(BEGIN) + ".*?" + re.escape(END), lambda m: block, s, flags=re.S)
else:
    s = s.replace("</compiler_spec>", block + "\n</compiler_spec>")
open(CSPEC, "w", newline="").write(s.replace("\n", nl))
print("wrote", CSPEC, len(out), "call fixups")
