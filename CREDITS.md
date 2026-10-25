# Credits: Renesas RH850 / V850E2M module

This module is a community SLEIGH module that Ghidra-Rare imported, tested and fixed. The
processor specification was written by its original authors; Ghidra-Rare added the changes
listed below.

## Upstream

| | |
|---|---|
| Selected source | [esaulenka/ghidra_v850](https://github.com/esaulenka/ghidra_v850), commit `14c1b5be32b8ec741ee626c8bca9885c58f7a473` (2025-08-14) |
| License | MIT (`LICENSE`, unchanged) |
| Original authors | Alexey Esaulenko ([@esaulenka](https://github.com/esaulenka)), with contributions by Willem Melching ([@pd0wm](https://github.com/pd0wm)), Egor Kin ([@EgorKin](https://github.com/EgorKin)), Roman ([@HexRoman](https://github.com/HexRoman)) and Moku Z ([@jbmokuz](https://github.com/jbmokuz)) |
| Relation to Ghidra's V850 module | Ghidra's own V850 module (Ghidra 9.2, PR #1430 by @Aleckaj) was built from an early (2019-2020) version of this repository; both have developed separately since |
| Compared, not borrowed | [kaikozlov/ghidra_rh850](https://github.com/kaikozlov/ghidra_rh850) and [ZEEKRZERO/Ghidra-RH850](https://github.com/ZEEKRZERO/Ghidra-RH850) (no license): not used |

No code was copied from the alternatives or from GNU binutils. Encodings were checked against
GNU binutils 2.45 (objdump); semantics follow the V850E2M and RH850G3KH/G4MH manuals, with the
GNU simulator consulted for SCH0R-family flags. Note: upstream's `v850e3.sinc` quotes lines of
binutils' GPL opcode table as comments; they were left as they are.

Ghidra-Rare's changes are separate commits on branch `ghidra-rare` of a fork of the upstream
repository, on top of the upstream history, so the original license and authorship are
preserved.

## Ghidra-Rare changes

Each item names the problem and how it was found.

1. **Processor renamed to RH850** (`RH850:LE:32:default` for V850E3/RH850, `RH850:LE:32:V850E2M`).
   Upstream's `v850`/`v850:LE:32:default` differed from Ghidra's built-in `V850:LE:32:default`
   only by case, and both modules' ELF opinions match the same `e_machine`. Found by review.
2. **Floating point regenerated** (`tools/gen_float.py`). cvtf.dw decoded as cvtf.sw, cvtf.ld and
   cvtf.uld as cvtf.ls/cvtf.uls, divf.d as divf.s, ceilf.suw as ceilf.sul, floorf.sw as
   floorf.suw; all roundf forms missing; cmovf operands reversed; cmpf condition 8 misnamed.
   Found by differential testing.
3. **Load/store.** SLD.B and SLD.H zero-extended (sign-extend per manual); SST operand order;
   LD.B/H/W disp16 with r0. Found by emulator tests and differential testing.
4. **System registers and RH850 G4MH instructions.** LDSR/STSR and the LDTC/STTC/LDVC/STVC
   family failed on every regID/selID without a name; LDTC.VR/PC and STTC.GR/VR/PC had r0 fixed
   in their patterns; CACHE, PREF, DB*, HVCALL/HVTRAP, TLB* were `unimpl` (decompiler halt) and
   are now user operations; JARL [reg1], r0 accepted; LOOP left reg1 unchanged at zero; RIE
   operands. Found by differential testing.
5. **Missing instructions**: BREAKPOINT, DBTRAP, RMTRAP, DBRET, the N-step division and the
   accumulator extensions (user operations). Found by differential testing.
6. **Shifts**: register shift counts use reg1 & 0x1f; SHL's carry came from the wrong bit;
   imm5 forms with r0. Found by emulator tests.
7. **Arithmetic/logic semantics**: SAT followed the carry instead of the overflow; TST tested
   reg2 alone; BSW/BSH/HSW dropped bytes; SCH0R/SCH1R/SCH0L/SCH1L returned wrong positions;
   NOP was a user operation that stopped the emulator; DIVQ shown as DIV; MULHI with reg2 = r0
   (the JMP disp32/LOOP encoding). Found by emulator tests.
8. **Display**: condition operands (`cmov nz, ...`, `setf lt, ...`) and branch mnemonics as in
   the manual and objdump; DISPOSE list without trailing comma; PREPARE's imm16-high value.
9. **Upstream limitations**: LDL.W/STC.W link semantics (source TODOs); SR11 selID 2 named
   PMR_IMSR (issue #40); `ghidra_scripts/RH850CallT.java` resolves CALLT through CTBP
   (issue #20); r0 shift/add destinations (issue #42).
10. **GCC's V850E2 indirect call** `jarl .+4, lp; add 4, lp; jmp [reg]` recognised (it made
   every call site a function and every jump an unrecoverable jump table). Found by real binaries.
11. **Spec files**: GCC cspec (r20-r29 callee-saved, ep/lp not; 64-bit results in r11:r10), DWARF
   register map, ELF opinion for EM_V800, EM_V850 by architecture and EM_CYGNUS_V850.
12. **V850E1 and follow-up fixes**: added the E1 language and architecture-specific ELF opinions,
    a dedicated RH850 ELF loader, CALLT and GCC prologue-helper analyzers, and call fixups for
    libgcc save/return helpers. Extended floating-point conversion p-code for FPSR rounding modes
    and unsigned 64-bit values. Rechecked decode, emulation and nine GCC-built ELFs.

Ghidra-Rare additions: `GHIDRA-RARE.md`, `CREDITS.md`, `build.gradle`, `test/`; the README's
installation and TODO sections were updated, and `extension.properties` was replaced (upstream's
named the extension `Renesas_v850`, version 9.1).
