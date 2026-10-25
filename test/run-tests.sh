#!/usr/bin/env bash
# RH850 (V850E3) / V850E2M processor module tests.
#
#   test/run-tests.sh [workdir]
#
# 1. compile both SLEIGH specs and link the module into $GHIDRA_INSTALL_DIR/Ghidra/Processors
# 2. decode corpora (gen_corpus.py): 48 encodings of every entry of binutils' V850 opcode table,
#    every first halfword with three tails, and 100,000 random 8-byte slots; Ghidra
#    (DumpSlots.java) vs GNU objdump's disassembler (slotdis, binutils 2.45 libopcodes) for
#    v850e3v5 (RH850:LE:32:default) and v850e2v3 (RH850:LE:32:V850E2M); compare.py scores
#    exact/semantic agreement and buckets every difference
# 3. every-entry decode test (CoverageCheck.java): every constructor of both languages is reached
# 4. p-code emulator tests (emu_tests.py, EmuCheck.java); needs v850-elf-as/ld (build-toolchain.sh)
# 5. if REAL_SAMPLES is set (fetch-real-samples.sh output): real-binaries.sh
#
# Environment: GHIDRA_INSTALL_DIR; BU_SRC (binutils 2.45 source: opcodes/v850-opc.c is read to
# build the opcode-table corpus); SLOTDIS, or BU_BUILD (build tree configured
# --enable-targets=all) to build it from slotdis.c.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}" "${BU_SRC:?set BU_SRC}"
W=$(mkdir -p "${1:-$PWD/rh850-test-work}" && cd "${1:-$PWD/rh850-test-work}" && pwd)
cd "$W"

echo "== compiling SLEIGH"
for s in "$MOD"/data/languages/*.slaspec; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "^ERROR|^Error" || true
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/RH850"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_BUILD:?set SLOTDIS, or BU_BUILD to build it}"
	SLOTDIS=$W/slotdis
	gcc -O2 -DPACKAGE=1 -DPACKAGE_VERSION=1 -include "$BU_BUILD/bfd/config.h" -o "$SLOTDIS" \
		"$HERE/slotdis.c" -I"$BU_BUILD/bfd" -I"$BU_SRC/include" -I"$BU_SRC/bfd" \
		"$BU_BUILD/opcodes/.libs/libopcodes.a" "$BU_BUILD/bfd/.libs/libbfd.a" \
		"$BU_BUILD/libiberty/libiberty.a" "$BU_BUILD/libsframe/.libs/libsframe.a" \
		"$BU_BUILD/zlib/libz.a" -lzstd 2>/dev/null
fi
export SLOTDIS

echo "== decode corpora vs GNU objdump"
python3 "$HERE/gen_corpus.py" "$BU_SRC/opcodes/v850-opc.c" .
for c in table first fuzz; do
	for v in "default v850e3v5" "V850E2M v850e2v3"; do
		set -- $v
		"$SLOTDIS" $2 8 $c.bin >o_${c}_$2.txt
		"$HERE/ghidra-slots.sh" RH850:LE:32:$1 $c.bin 8 g_${c}_$1.txt
		echo "-- $c: RH850:LE:32:$1 vs objdump $2"
		python3 "$HERE/compare.py" g_${c}_$1.txt o_${c}_$2.txt 3 | tee cmp_${c}_$1.txt | grep -v '^      ' | grep -v '\] ~' | head -20
	done
done

echo "== every-entry decode test"
head -c 64 /dev/zero >zero.bin
for l in default V850E2M; do
	"$HERE/ghidra-script.sh" raw RH850:LE:32:$l zero.bin CoverageCheck.java "$W/cov_$l.txt" 256
	echo "-- RH850:LE:32:$l: $(tail -1 cov_$l.txt)"
	grep '^unreached' cov_$l.txt | head -20 || true
done

echo "== p-code emulator tests"
python3 "$HERE/emu_tests.py" .
"$HERE/ghidra-script.sh" raw RH850:LE:32:default emu.bin EmuCheck.java "$W/emu.txt" "$W/emu_out.txt"
grep -v '^PASS' emu_out.txt

if [[ -n ${REAL_SAMPLES:-} ]]; then
	echo "== real binaries"
	"$HERE/real-binaries.sh" "$REAL_SAMPLES" "$W/real"
fi

echo "== summary"
grep -H "^compared" cmp_*.txt | sed 's/^cmp_//; s/\.txt:/: /'
grep -H "^coverage" cov_*.txt | sed 's/\.txt:/: /'
tail -1 emu_out.txt
