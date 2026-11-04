#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Stand-in for the native hubcheck in local dry runs and CI of this repository. It is NOT a checker:
# it reads the first word of the file and answers FLAG, BLOCK, or pass. Same command line as the real one
# (see check-release.mjs). The real binary is HUB-wasm's wonderlandos/hub wasm/bin/hubcheck.
# TODO(ADR 0047): replace by the pinned build named in tools/hubcheck.rev once HUB-wasm ships it.
set -eu
file=
for a in "$@"; do file=$a; done
[ -f "$file" ] || exit 2
case $(head -c 5 "$file") in
BLOCK) printf '{"verdict":"block","findings":[{"rule":"stub/block","sentence":"The stub blocks files that start with BLOCK.","evidence":""}]}\n' ;;
FLAG\ ) printf '{"verdict":"flag","findings":[{"rule":"permissions/more","sentence":"Asks for more than the last version: it can now read the files you choose.","evidence":"files.read added"}]}\n' ;;
*) printf '{"verdict":"pass","findings":[]}\n' ;;
esac
