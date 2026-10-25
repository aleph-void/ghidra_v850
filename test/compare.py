#!/usr/bin/env python3
"""Compare Ghidra slot disassembly (DumpSlots.java) with GNU objdump slot disassembly (slotdis)
for V850/RH850.

  compare.py <ghidra.txt> <objdump.txt> [examples-per-class]

exact:    same length and text after lower-casing, removing blanks in the operands and writing
          every number as (signed) hex
semantic: additionally register aliases (r3=sp, r4=gp, r5=tp, r30=ep, r31=lp) and
          addresses modulo 2^32
"""
import re
import sys
from collections import Counter, defaultdict

NUM = re.compile(r"(?<![\w.])(-?)(0x[0-9a-f]+|\d+)(?![\w])")
ALIAS = {"sp": "r3", "gp": "r4", "tp": "r5", "ep": "r30", "lp": "r31", "zero": "r0", "hp": "r2"}
ALIASRE = re.compile(r"(?<![\w])(%s)(?![\w])" % "|".join(ALIAS))


def load(path):
    d = {}
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) < 2:
            continue
        d[int(p[0], 16)] = (int(p[1]), p[2] if len(p) > 2 else "")
    return d


def canon(m):
    v = int(m.group(2), 0)
    return ("-" if m.group(1) else "") + hex(v)


def exact_norm(t):
    t = t.lower().replace("\t", " ").strip()
    t = re.sub(r"\s*<(?!invalid)[^>]*>", "", t)
    m, _, ops = t.partition(" ")
    t = m + " " + ops.replace(" ", "")
    return NUM.sub(canon, t).strip()


BRALIAS = {"bc": "bl", "bnc": "bnl", "bz": "be", "bnz": "bne", "bt": "be", "bf": "bne"}
PAIR = re.compile(r"(?<![\w])r(\d+)r(\d+)(?![\w])")


def expand_list(m):
    out = []
    for item in m.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            a, b = (int(ALIAS.get(x, x)[1:]) for x in item.split("-"))
            out += ["r%d" % i for i in range(a, b + 1)]
        else:
            out.append(ALIAS.get(item, item))
    return "{" + ",".join(out) + "}"


def sem_norm(t):
    t = exact_norm(t)
    m, _, ops = t.partition(" ")
    m = BRALIAS.get(m, m)
    ops = ALIASRE.sub(lambda x: ALIAS[x.group(1)], ops)
    # register pairs (Ghidra names the 64-bit pair, objdump its first register)
    ops = re.sub(r"(?<![\w])(r0r1|r2sp|gptp|eplp)(?![\w])", lambda x: {"r0r1": "r0", "r2sp": "r2", "gptp": "r4", "eplp": "r30"}[x.group(1)], ops)
    ops = PAIR.sub(lambda x: "r" + x.group(1) if int(x.group(2)) == int(x.group(1)) + 1 else x.group(0), ops)
    # objdump prints the jump register of DISPOSE even when it is r0 (no jump)
    if m == "dispose":
        ops = re.sub(r",r0$", "", ops)
    # register lists: objdump writes ranges
    ops = re.sub(r"\{([^}]*)\}", expand_list, ops)
    # addresses and negative numbers modulo 2^32
    ops = NUM.sub(lambda x: hex((-int(x.group(2), 0) if x.group(1) else int(x.group(2), 0)) & 0xffffffff), ops)
    return (m + " " + ops).strip()


def split_ops(t):
    m, _, ops = t.partition(" ")
    parts, depth, cur = [], 0, ""
    for ch in ops:
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        parts.append(cur)
    return m, parts


def sem_equal(g, o):
    """semantic equality; objdump names system registers "a/b/c" (all names of that regID at
    selID 0) or "<invalid s-reg number>" (other selIDs), so a Ghidra name in that list, or any
    name for an invalid one, matches."""
    g, o = sem_norm(g), sem_norm(o)
    if g == o:
        return True
    gm, gp = split_ops(g)
    om, op = split_ops(o)
    if gm != om or len(gp) != len(op):
        return False
    for a, b in zip(gp, op):
        if a == b:
            continue
        if b.startswith("<invalid") and re.match(r"^[a-z_][\w]*$", a):
            continue
        if "/" in b and a in b.split("/"):
            continue
        # system register names: objdump merges the names several cores use for one regID
        if gm.split(".")[0] in ("ldsr", "stsr", "ldtc", "ldvc", "sttc", "stvc") and "/" in b \
                and re.match(r"^[a-z_][\w]*$", a):
            continue
        return False
    return True


def mnem(t):
    return t.split(" ")[0].lower() if t else "-"


def main():
    g = load(sys.argv[1])
    o = load(sys.argv[2])
    nex = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    cnt = Counter()
    classes = defaultdict(list)
    for off in sorted(o):
        gl, gt = g.get(off, (0, "BAD"))
        ol, ot = o[off]
        gbad = gl == 0
        obad = ol == 0 or ot.startswith("(bad)") or ot.startswith(".") or "unknown" in ot
        cnt["total"] += 1
        if gbad and obad:
            cnt["both_reject"] += 1
            continue
        if gbad:
            cnt["ref_only"] += 1
            classes["ref only: " + mnem(ot)].append((off, gt, ot, ol))
            continue
        if obad:
            cnt["ghidra_only"] += 1
            classes["ghidra only: " + mnem(gt)].append((off, gt, ot, gl))
            continue
        cnt["both_decode"] += 1
        if gl == ol and exact_norm(gt) == exact_norm(ot):
            cnt["exact"] += 1
            cnt["semantic"] += 1
        elif gl == ol and sem_equal(gt, ot):
            cnt["semantic"] += 1
            classes["~ " + mnem(ot)].append((off, gt, ot, gl))
        else:
            key = ("LEN " if gl != ol else "DIFF ") + mnem(ot) + " / " + mnem(gt)
            classes[key].append((off, gt, ot, "%d/%d" % (gl, ol)))
    bd = cnt["both_decode"] or 1
    print("compared %d slots: both decode %d, exact %d (%.2f%%), semantic %d (%.2f%%), "
          "ghidra-only %d, ref-only %d, both reject %d"
          % (cnt["total"], cnt["both_decode"], cnt["exact"], 100.0 * cnt["exact"] / bd,
             cnt["semantic"], 100.0 * cnt["semantic"] / bd, cnt["ghidra_only"], cnt["ref_only"],
             cnt["both_reject"]))
    for k in sorted(classes, key=lambda k: (k.startswith("~"), -len(classes[k]))):
        v = classes[k]
        print("  [%d] %s" % (len(v), k))
        for off, gt, ot, ln in v[:nex]:
            print("      %08x len %s  ghidra: %-36s objdump: %s" % (off, ln, gt, ot))


if __name__ == "__main__":
    main()
