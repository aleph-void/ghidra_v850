

# Ghidra processor module for Renesas v850

[![Sponsor Aleph Void](https://img.shields.io/badge/Sponsor-Aleph%20Void-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/aleph-void)

1. V850E2 version based on **User’s Manual: V850E2M Architecture** ([link](https://www.renesas.com/us/en/doc/products/mpumcu/doc/v850/r01us0001ej0100_v850e2m.pdf))

2. V850E3 version based on gcc `objdump` and `gdb` sources,
CubeSuite IDE [manual](https://www.renesas.com/sg/en/doc/products/tool/doc/003/r20ut2584ej0101_qscdrh850.pdf)
and **RH850G3KH User’s Manual: Software** [link](https://www.renesas.com/us/en/document/mas/rh850g3kh-users-manual-software) (R01US0165EJ0120)


## Installation

Prebuilt extension zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's Releases page:
install one with *File > Install Extensions* and restart Ghidra. To build from source, run
`gradle buildExtension` with `GHIDRA_INSTALL_DIR` set (see [GHIDRA-RARE.md](GHIDRA-RARE.md)).

The languages are `RH850:LE:32:default` (V850E3 / RH850, including G4MH),
`RH850:LE:32:V850E2M` and `RH850:LE:32:V850E1` (V850E/E1/ES core code). Select V850E1
explicitly for E1 ELFs: GCC gives E1 and E2V3 the same RH850 ABI flags. The processor is called RH850
so that it does not collide with the V850
module that ships with Ghidra (an older derivative of this one); both offer themselves for V850
ELF files.


## TODOs

Status in this fork (Ghidra-Rare; details, test results and the remaining gaps in
[GHIDRA-RARE.md](GHIDRA-RARE.md)):

* ~~fix a lot of bugs~~ fixed: decoding agrees with GNU objdump 2.45 on every encoding both
  decode (the whole binutils opcode table and random words, both languages; the encodings only
  objdump accepts are objdump quirks), and the semantics are checked by emulator tests
* ~~complete RH850 support~~ fixed for everything GNU binutils knows (FPU, G4MH virtualization,
  MMU, cache and debug instructions, system registers for every regID/selID); remaining: the
  RH850G4MH post-increment/decrement loads and stores are implemented from the manual but no
  reference disassembler decodes them

Open issues: #42 (`sar imm5, r0`) and #40 (SR11 selID 2, now `PMR_IMSR`) are fixed, #20 (CALLT
targets) is handled by `ghidra_scripts/RH850CallT.java`; #34 and #33 are not module defects
(see GHIDRA-RARE.md).
