# Ghidra-Rare notes: Renesas RH850 / V850E2M / V850E1

Ghidra processor module for Renesas RH850 (V850E3 cores: G3K, G3M, G3KH, G3MH, G4MH) and
V850E2M and V850E1 (including V850E/ES core code). It is a community module, [esaulenka/ghidra_v850](https://github.com/esaulenka/ghidra_v850)
(MIT), imported by Ghidra-Rare, tested against GNU binutils and fixed. See [CREDITS.md](CREDITS.md)
for provenance and the list of changes.

| Language ID | Cores |
|---|---|
| `RH850:LE:32:default` | RH850 / V850E3V5 (G3K ... G4MH): adds the RH850 FPU forms, LD.DW/ST.DW, 23-bit loads/stores, LOOP, PUSHSP/POPSP, BINS, ROTL, G4MH virtualization, MMU and cache instructions, system registers by regID/selID |
| `RH850:LE:32:V850E2M` | V850E2M / V850E2V3 |
| `RH850:LE:32:V850E1` | V850E1, V850E and V850ES core instructions; no V850E1F FPU |

## Ghidra already has a V850 module: why this one

Ghidra ships `V850:LE:32:default` (E1/E2/E2M) and `V850:LE:32:v850e3v5`. That module grew from
an early version of this repository. This module uses the processor name `RH850`, so its
language IDs cannot collide with Ghidra's. Its ELF loader offers the RH850 family first;
architecture flags select E3 or E2M where available. E1 and E2V3 GCC ELFs share the same flags,
so E1 needs explicit selection.

Measured against GNU objdump 2.45 on the same corpora (semantic agreement where both decode;
"objdump-only" = encodings objdump decodes and the module rejects, "Ghidra-only" = the reverse):

| Corpus | Ghidra 12.1.4 `V850:LE:32:v850e3v5` | upstream esaulenka (as imported) | this module `RH850:LE:32:default` |
|---|---|---|---|
| binutils opcode table, 48 samples per entry (19,344) | 73.14%; 205 Ghidra-only, 410 objdump-only | 92.04%; 202 / 2,083 | **100.00%; 0 / 151** |
| every first halfword x 3 (196,608) | 99.69%; 1,152 / 4 | 84.05%; 221 / 824 | **100.00%; 1 / 51** |
| random 8-byte words (100,000) | 99.67%; 586 / 1 | 83.90%; 89 / 424 | **100.00%; 0 / 25** |

The V850E2M language against objdump's v850e2v3 machine: 100.00% on all three corpora (Ghidra's
`V850:LE:32:default`: 90.02%, 99.78%, 99.80%).

What Ghidra's module gets wrong on RH850 code (from the opcode-table corpus): conditional branch
targets for a quarter of Bcond/Bcond17 encodings, BR printed as BT, BINS/BINSU/BINSL/BINSM and
TST1 operand order, LDL.W/STC.W, PUSHSP decoded over the DIVN/SDIVN family and over undefined
words, and no HVCALL/HVTRAP/LDTC/STTC/LDVC/STVC/TLB* (G4MH) instructions. Its cspec also lists
ep and lp as callee-saved, which GCC does not. On the GCC `-mv850e2v3` Lua build it found 2,278
"functions" with 738 unrecoverable jump tables and 117 KB of undisassembled code, because GCC's
V850E2 indirect call (`jarl .+4, lp; add 4, lp; jmp [reg]`) looks like a call to the next
instruction; this module recognises the sequence (1,054 functions, 138 undisassembled bytes).

## Results

| Test | Result |
|---|---|
| Decode vs objdump (table above) | 100.00% semantic where both decode, 85-95% exact, on all three languages and all three corpora. V850E1 has 0 Ghidra-only and 0 objdump-only encodings on all three corpora; the older cores' remaining objdump-only encodings are confirmed objdump quirks (below) |
| Every-entry decode test (`CoverageCheck.java`) | 556/556 constructors reached (RH850), 374/374 (V850E2M), 243/243 (V850E1) |
| p-code emulator (`EmuCheck.java`) | 63/63 RH850 sequences, including FPSR rounding modes and unsigned 64-bit conversions; 34/34 V850E1 sequences. Coverage includes arithmetic and flags, loads/stores, branches/calls, prologue/epilogue, atomic ops and FPU |
| Real binaries: 9 GCC 14 ELFs from public source | 5,005 functions, 472,196 instructions; every function decompiles, and every decoded instruction agrees semantically with objdump. V850E1: 1,715 functions, 172,262 instructions, 0 bad-instruction bookmarks, selected explicitly because GCC gives E1 and E2V3 the same RH850 ABI flags. V850E2V3: 17 bad-instruction bookmarks at executable-section words GNU objdump also rejects. RH850: 0 bad-instruction bookmarks. Other error bookmarks are Ghidra's DWARF line-table importer rejecting negative line numbers |
| Builds | `.sla` 50.9 KB (RH850) / 33.9 KB (V850E2M); compiles and builds with Ghidra 12.1.3, 12.1.4 and 12.2 |

Real-binary samples (`test/fetch-real-samples.sh`: pinned, SHA-256 checked, built with
`test/build-toolchain.sh`, GCC 14.3.0 + newlib 4.5.0; never committed): Lua 5.4.7 (MIT) and the
zlib 1.3.1 (zlib licence) example and minigzip programs, each for V850E1, V850E2V3 and RH850
(V850E3V5, hard float).

## Upstream's known limitations

| Source | Limitation | State |
|---|---|---|
| README TODO | "fix a lot of bugs" | Fixed: see CREDITS.md for the list; decode agreement and emulator results above |
| README TODO | "complete RH850 support" | Fixed for everything binutils knows; the G4MH post-increment/decrement forms are implemented from the manual but unverified (no reference decodes them) |
| README | Installation by copying into `Ghidra/Extensions` | Stale; replaced by release zips / `gradle buildExtension` |
| `v850e3.sinc` TODOs | LDL.W did not record the link, STC.W always succeeded | Fixed (link address and flag; emulator test `ldl_stc`) |
| Issue #42 (open) | `sar 0x18, r0` (`b8 02`) not decoded | Fixed: shifts and ADD imm5 with r0 decode, as in objdump |
| Issue #40 (open) | SR11 selID 2 shown as IMSR, PMR on other cores | Fixed: named `PMR_IMSR` (the name differs between RH850 generations) |
| Issue #20 (open) | CALLT targets unknown (CTBP) | The automatic `RH850CallTAnalyzer` finds CTBP when startup code loads it from a constant, or accepts it as an analysis option, then adds call overrides and functions. The script remains available for manual use |
| Issue #34 (open) | "ld.w off by one" | Not a defect: the upstream analysis in the issue is right (the compiler biased the table base by one element); the decoding agrees with objdump |
| Issue #33 (open) | "Better decompiler output" | Not reproducible as a module defect: the examples hinge on the user's memory map (peripheral blocks, volatile areas). This fork's GCC cspec, the semantic fixes and the V850E2 indirect-call handling improve the output generally |
| Issues #11, #17, #27, #36, #38, #39 (closed) | encodings that did not decode | Re-checked: all decode and agree with objdump (#17 and #36 are `ldsr r18, INTCFG, 2` and `ldsr rX, MPIDX/MPID0, 5`) |

## Confirmed reference-tool bugs

- objdump prints JR/JARL/JMP disp32 encodings whose displacement has bit 0 set (reserved) as
  2- or 4-byte instructions with a 32-bit target (its 6-byte special case only covers bit 0 =
  0). These are most of the objdump-only encodings.
- objdump accepts odd displacements for LD.H/ST.H/LD.W/ST.W disp23 (bit 20, which must be 0 for
  halfword and word accesses).
- objdump's TRNCF.SUL entry accepts an odd destination register for a 64-bit result (the
  other `.sul`/`.sl` conversions require an even register).
- objdump prints DISPOSE's jump register even when it is r0 (no jump), and names system
  registers by a merged list of several cores' names (`sr6/fpsr/vmadr/dcc`) or
  `<invalid s-reg number>` for selID > 0.

## Known gaps

- GCC gives `-mv850e1` and `-mv850e2v3` the same RH850 ABI flags; the ELF header cannot choose
  between those languages. Select V850E1 explicitly for E1 binaries. The module's ELF loader
  chooses the RH850 family ahead of Ghidra's built-in V850 module.
- V850E2V3 sample ELFs contain 17 executable-section words GNU objdump also rejects. Analysis
  records bad-instruction bookmarks at these locations; the decoded instructions still agree.
- System instructions without data semantics (CACHE, PREF, debug, hypervisor, TLB, accumulator
  and N-step-division extensions) are user operations; RIE stays unimplemented (trap).
- Floating-point conversions model FPSR.RM (nearest, toward zero, up and down), including
  unsigned 64-bit conversions; exception flags and traps are not modelled.
- RH850G4MH post-increment/decrement loads and stores (`ld.w [r1]+, r2`) are decoded from the
  G4MH manual and emulator-tested, but binutils 2.45 does not know them (unverified against a
  reference disassembler).
- The CC-RH (Renesas) calling convention is not described; only GCC's.

Unverified: CC-RH or GHS output and third-party RH850 firmware (no freely licensed samples found).

## Testing

```
test/build-toolchain.sh <workdir> <prefix>      # v850-elf binutils/gcc/newlib (once)
export PATH=<prefix>/bin:$PATH GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
test/fetch-real-samples.sh <samples>            # optional: build the real-binary samples
BU_SRC=<binutils-2.45 source> BU_BUILD=<binutils build --enable-targets=all> \
  REAL_SAMPLES=<samples> test/run-tests.sh <workdir>
```

`tools/gen_float.py` regenerates `data/languages/v850_float.sinc`;
`tools/gen_callfixups.py` regenerates the GCC save/return call fixups in `v850.cspec`.
`RH850CallTAnalyzer` resolves CALLT targets automatically when CTBP is known.
