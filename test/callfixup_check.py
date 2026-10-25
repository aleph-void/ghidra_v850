#!/usr/bin/env python3
"""Check the cspec's save/return call fixups against the helpers linked into real binaries.

  callfixup_check.py <v850.cspec> <objdump> <elf>...

For every __save_*/__return_* helper in each ELF (objdump -d), the stack adjustment and the
register stored to / loaded from each sp (or ep = sp) offset must equal what the fixup of the
same name does.
"""
import re
import subprocess
import sys

cspec, od, elfs = sys.argv[1], sys.argv[2], sys.argv[3:]
text = open(cspec).read()
fix = {}
for name, body in re.findall(r'<callfixup name="([^"]+)">.*?<!\[CDATA\[(.*?)\]\]>', text, re.S):
    adj = int(re.search(r"sp = sp [-+] (\d+)", body).group(1))
    slots = {int(o): r for o, r in re.findall(r"a\d+:4 = sp \+ (\d+); (?:\*\[ram\]:4 a\d+ = (\w+)|)", body) if r}
    slots.update({int(o): r for o, r in re.findall(r"a\d+:4 = sp \+ (\d+); (\w+) = \*\[ram\]:4", body)})
    fix[name] = (adj, slots)
ok = bad = 0
for elf in elfs:
    dis = subprocess.check_output([od, "-d", elf], text=True)
    for name, body in re.findall(r"<(__(?:save|return)_[a-z0-9_]+)>:\n(.*?)\n\n", dis, re.S):
        adj, slots = None, {}
        for ins in body.splitlines():
            m = re.search(r"\taddi\t(-?\d+), sp, sp", ins)
            if m:
                adj = abs(int(m.group(1)))
            m = re.search(r"\ts?st\.w\t(\w+), (\d+)\[(?:sp|ep)\]", ins) or re.search(r"\ts?ld\.w\t(\d+)\[(?:sp|ep)\], (\w+)", ins)
            if m:
                a, b = m.groups()
                off, reg = (int(b), a) if a.startswith("r") or a in ("lp", "ep", "gp") else (int(a), b)
                slots[off] = {"r31": "lp"}.get(reg, reg)
        want = fix.get(name)
        if want == (adj, slots):
            ok += 1
        else:
            bad += 1
            print("MISMATCH %s in %s: binary %s, fixup %s" % (name, elf, (adj, slots), want))
print("call fixups vs linked helpers: %d agree, %d differ" % (ok, bad))
sys.exit(1 if bad else 0)
