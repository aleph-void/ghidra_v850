#!/usr/bin/env bash
# Real-binary check: import each ELF built by fetch-real-samples.sh into headless Ghidra with NO
# -processor flag (the ELF opinion picks the language), auto-analyze, decompile every function
# (RealCheck.java) and disassemble every instruction Ghidra found with GNU libopcodes at the same
# address (slotdis -l, the machine matching the language Ghidra chose), scored by compare.py.
#
#   test/real-binaries.sh <samples-dir> [workdir]
# Environment: GHIDRA_INSTALL_DIR (Ghidra with this module installed or symlinked into
# Ghidra/Processors), SLOTDIS (slotdis built from slotdis.c, see run-tests.sh),
# DECOMP_TIMEOUT (default 60).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
: "${SLOTDIS:?set SLOTDIS}"
TMO=${DECOMP_TIMEOUT:-60}
SAMPLES=$(readlink -f "$1")
W=$(readlink -f "${2:-real-out}")
mkdir -p "$W"
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/rh850-real.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT

run_one() {
	local f=$1 n p
	n=$(basename "$f")
	p=$(mktemp -d "$PROJ/p.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$f" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "$TMO" \
		-deleteProject >"$W/$n.log" 2>&1 || tail -20 "$W/$n.log" >&2
	rm -rf "$p"
}

mapfile -t files < <(find "$SAMPLES" -maxdepth 1 -name '*.elf' | sort)
echo "== headless import + analysis + decompile (${#files[@]} files, 4 at a time)"
i=0
for f in "${files[@]}"; do
	run_one "$f" &
	i=$((i + 1))
	(( i % 4 == 0 )) && wait
done
wait

echo "== results"
for f in "${files[@]}"; do
	n=$(basename "$f")
	mach=v850e3v5
	grep -q 'language: RH850:LE:32:V850E2M' "$W/$n.sum" && mach=v850e2v3
	base=$(python3 "$HERE/elf_exec_image.py" "$f" "$W/$n.img")
	python3 "$HERE/lst2slots.py" "$W/$n.lst" >"$W/$n.slots"
	"$SLOTDIS" "$mach" 8 "$W/$n.img" -l "$W/$n.slots" -b "$base" >"$W/$n.ref"
	echo "-- $n"
	grep -E "^(language|functions|instructions|bad-instruction|error bookmarks|decompile|functions whose)" "$W/$n.sum" | sed 's/^/   /'
	echo "   vs objdump ($mach): $(python3 "$HERE/compare.py" "$W/$n.slots" "$W/$n.ref" 10 | tee "$W/$n.cmp" | head -1 | sed 's/^compared //')"
done
echo "(full outputs: $W/<file>.{sum,lst,c,cmp})"
