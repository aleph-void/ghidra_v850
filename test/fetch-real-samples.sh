#!/usr/bin/env bash
# Fetch public C sources (pinned, SHA-256 checked) and build them with v850-elf-gcc
# (build-toolchain.sh) for V850E2V3 and RH850 (V850E3V5, hard float) into <outdir>/*.elf.
# Nothing fetched or built here is committed.
#   test/fetch-real-samples.sh <outdir>
# Sources and licences: Lua 5.4.7 (MIT), zlib 1.3.1 (zlib licence); newlib (BSD-style) and
# libgcc (GPL with the runtime exception) come from the toolchain.
set -euo pipefail
O=$(mkdir -p "$1" && cd "$1" && pwd)
S=$O/src
mkdir -p "$S"
fetch() { # url sha256 file
	[[ -f $S/$3 ]] || curl -fsSL -o "$S/$3" "$1"
	echo "$2  $S/$3" | sha256sum -c --quiet
}
fetch https://www.lua.org/ftp/lua-5.4.7.tar.gz 9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30 lua-5.4.7.tar.gz
fetch https://zlib.net/fossils/zlib-1.3.1.tar.gz 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz
(cd "$S" && rm -rf lua-5.4.7 zlib-1.3.1 && tar xzf lua-5.4.7.tar.gz && tar xzf zlib-1.3.1.tar.gz)
v850-elf-gcc --version | head -1
Z="adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c"
for cpu in v850e2v3 v850e3v5; do
	F="-O2 -g -m$cpu"
	[[ $cpu == v850e3v5 ]] && F="$F -mhard-float"
	(cd "$S/lua-5.4.7/src" && v850-elf-gcc $F -std=gnu99 -DLUA_USE_C89 -o "$O/${cpu}_lua.elf" \
		$(ls ./*.c | grep -v luac.c) -lm)
	for p in example minigzip; do
		(cd "$S/zlib-1.3.1" && v850-elf-gcc $F -include unistd.h -I. -o "$O/${cpu}_zlib_$p.elf" test/$p.c $Z)
	done
done
ls -l "$O"/*.elf
