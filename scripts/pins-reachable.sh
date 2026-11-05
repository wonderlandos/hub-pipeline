#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Every commit tools/*.rev pins must be reachable from a branch or tag of its public repository: scripts/tool.sh builds
# from a plain clone, which only has reachable commits, so a pin on a rewritten or unpushed branch breaks sign.yml and
# ca.yml (they always build afresh) while ci.yml, with the tool cache, stays green. GitHub still serves such a commit
# when asked by its id, so "it can be fetched" is not enough: the id is looked up in the history of every ref.
# What the pinned trees pin in turn (the crates/shell submodule of woltrust, the git dependencies in hubcheck's
# wasm/Cargo.lock) is checked the same way and reported as WARN: tool.sh and cargo fetch those by id, which works only
# as long as GitHub keeps the commit.
#
#   pins-reachable.sh [<tools dir>]     (default: tools/ of this repository; ci.yml runs it on every push and PR)
#
# Exit 0 when every direct pin is reachable, 1 when one is not, 2 when a repository cannot be read.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tools=${1:-$here/../tools}
work=$(mktemp -d "${TMPDIR:-/tmp}/hub-pins.XXXXXX")
trap 'rm -rf "$work"' EXIT
fails=0 warns=0

# The history (commits only, no trees or blobs) of every branch and tag of <url>, cloned once into $work.
history() { # <url> -> prints the path of a bare clone
    local url=${1%.git} dir
    dir=$work/$(printf '%s' "$url" | tr -c 'A-Za-z0-9' _)
    if [ ! -d "$dir" ]; then
        git clone -q --bare --filter=tree:0 "$url" "$dir" >&2 || { echo "pins: $url cannot be cloned" >&2; exit 2; }
        git -C "$dir" fetch -q --tags origin >&2 || true
        git -C "$dir" log --all --format=%H >"$dir/reachable"
    fi
    echo "$dir"
}
# reachable <url> <sha> <what> <level FAIL|WARN>
reachable() {
    local url=$1 sha=$2 what=$3 level=$4 dir full
    dir=$(history "$url") || exit 2
    full=$(grep -m 1 "^$sha" "$dir/reachable" || true)
    if [ -n "$full" ]; then echo "ok   $what: ${full:0:12} is reachable from a ref of $url"; return 0; fi
    # Not in any ref's history: say whether GitHub still has it at all (a rewritten or unpushed branch) or not.
    local why="no such commit"
    git -C "$dir" -c protocol.version=2 fetch -q --depth 1 --filter=tree:0 origin "$sha" 2>/dev/null &&
        why="the commit exists but no branch or tag of the repository contains it (rewritten or unpushed branch)"
    echo "$level $what: $sha is not reachable from any ref of $url: $why" >&2
    if [ "$level" = FAIL ]; then fails=$((fails + 1)); else warns=$((warns + 1)); fi
}

for name in woltrust hubcheck; do
    case $name in   # the same repositories as scripts/tool.sh
    hubcheck) repo=https://github.com/wonderlandos/hub ;;
    woltrust) repo=https://github.com/wonderlandos/wolos ;;
    esac
    rev=$(tr -d ' \n' <"$tools/$name.rev")
    [ "$rev" = unpinned ] && { echo "ok   $name: unpinned"; continue; }
    [[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL $name: tools/$name.rev is not a 40-digit commit id" >&2; fails=$((fails + 1)); continue; }
    reachable "$repo" "$rev" "$name (tools/$name.rev)" FAIL || true
    dir=$(history "$repo") || exit 2
    grep -q "^$rev" "$dir/reachable" || continue
    case $name in
    woltrust)
        sub=$(git -C "$dir" ls-tree "$rev" crates/shell | awk '$2 == "commit" { print $3 }')
        [ -z "$sub" ] || reachable https://github.com/wonderlandos/wolos-shell "$sub" "woltrust's crates/shell submodule" WARN || true ;;
    hubcheck)
        while read -r url sha; do
            reachable "$url" "$sha" "hubcheck's git dependency ${url##*/} (wasm/Cargo.lock)" WARN || true
        done < <(git -C "$dir" show "$rev:wasm/Cargo.lock" | sed -n 's/^source = "git+\([^?#"]*\)[^#"]*#\([0-9a-f]\{40\}\)"$/\1 \2/p' | sort -u) ;;
    esac
done
[ "$warns" = 0 ] || echo "pins: $warns indirect pin(s) only fetchable by id (WARN above)" >&2
[ "$fails" = 0 ] || { echo "pins: $fails pinned commit(s) not reachable: move tools/<name>.rev to a commit on a branch (tools/README.md)" >&2; exit 1; }
echo "ok   every pinned commit is reachable"
