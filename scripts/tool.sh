#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Builds a pinned tool of the pipeline from its exact commit (cached) and prints the path of its binary on the last line.
#
#   tool.sh hubcheck|woltrust
#
# tools/<name>.rev holds one 40-digit commit id (or "unpinned": exit 3, nothing is built, the workflow stops).
# tools/<name>.sha256 (optional) is the sha256 of the binary built from that commit on the pipeline's own machine
# (rustc of tools/README.md): a differing hash is printed as a warning (a rustc of another version builds other bytes);
# TOOL_SHA256_STRICT=1 makes it a refusal.
#   hubcheck   wonderlandos/hub    wasm/          cargo build --release --locked --bin hubcheck   (HUB-wasm, ADR 0047)
#   woltrust   wonderlandos/wolos  crates/woltrust cargo build --release --locked -p woltrust --bin woltrust (ADR 0046)
#
# The source is a fresh clone checked out at exactly that commit, never a working tree: what is built is what the
# commit id names. The binary is kept in $TOOL_CACHE/<name>-<rev>/bin (default ~/.cache/hub-pipeline-tools; ci.yml and the
# scan job of check.yml keep it in actions/cache under a key with the commit id; sign.yml and ca.yml, which hold
# secrets, always build afresh), so a second call builds nothing.
#
# HUBCHECK_SRC / WOLTRUST_SRC (optional): a local git repository to clone from instead of GitHub (offline work). It
# must contain the pinned commit; its working tree and uncommitted changes are never used (only commits are cloned).
# WOLTRUST_SRC also serves the crates/shell submodule to hubcheck's woltrust dependency.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
name=${1:?usage: tool.sh hubcheck|woltrust}
case $name in
hubcheck) repo=https://github.com/wonderlandos/hub;   src=${HUBCHECK_SRC:-} ;;
woltrust) repo=https://github.com/wonderlandos/wolos; src=${WOLTRUST_SRC:-} ;;
*) echo "tool: unknown tool $name" >&2; exit 2 ;;
esac
rev=$(tr -d ' \n' <"$here/../tools/$name.rev")
if [ "$rev" = unpinned ]; then
    echo "tool: $name is not pinned (tools/$name.rev says unpinned); nothing was built" >&2
    exit 3
fi
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "tool: tools/$name.rev is neither a 40-digit commit id nor 'unpinned'" >&2; exit 2; }

cache=${TOOL_CACHE:-${HOME:?}/.cache/hub-pipeline-tools}/$name-$rev
bin=$cache/bin/$name
check_sha() { # the pinned sha256 of the binary, when tools/<name>.sha256 is there
    local want got
    [ -s "$here/../tools/$name.sha256" ] || return 0
    want=$(tr -d ' \n' <"$here/../tools/$name.sha256")
    got=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$want" = "$got" ]; then echo "tool: $name sha256 $got matches tools/$name.sha256" >&2; return 0; fi
    echo "tool: WARNING $name built from $rev has sha256 $got, tools/$name.sha256 says $want (another rustc?)" >&2
    [ "${TOOL_SHA256_STRICT:-0}" = 1 ] && return 1
    return 0
}
if [ -x "$bin" ] && [ "$(cat "$cache/rev" 2>/dev/null)" = "$rev" ]; then
    echo "tool: $name $rev from the cache" >&2
    check_sha "$bin" || exit 1
    echo "$bin"
    exit 0
fi

mkdir -p "$cache"
checkout=$cache/src
rm -rf "$checkout"
from=${src:-$repo}
echo "tool: building $name at $rev from $from" >&2
git clone -q --no-checkout ${src:+--no-local} "$from" "$checkout" >&2
git -C "$checkout" -c advice.detachedHead=false checkout -q "$rev" >&2
[ "$(git -C "$checkout" rev-parse HEAD)" = "$rev" ] || { echo "tool: $from has no commit $rev" >&2; exit 1; }
# The wolos workspace lists crates/shell, a submodule: cargo reads its manifest to load the workspace. Only that one,
# at the commit the pinned tree records (woltrust does not depend on it). With WOLTRUST_SRC it comes from that
# checkout's crates/shell; else from wonderlandos/wolos-shell, which must hold that commit.
if [ "$name" = woltrust ]; then
    shell_from=https://github.com/wonderlandos/wolos-shell.git local=()
    if [ -n "$src" ] && [ -e "$src/crates/shell/.git" ]; then shell_from=$(cd "$src/crates/shell" && pwd); local=(-c protocol.file.allow=always); fi
    git -C "$checkout" submodule set-url crates/shell "$shell_from" >&2
    git "${local[@]}" -C "$checkout" submodule update -q --init crates/shell >&2
fi
export CARGO_TARGET_DIR=$cache/target
# hubcheck depends on woltrust by git (wonderlandos/wolos), whose workspace needs the crates/shell submodule too. With
# WOLTRUST_SRC set, cargo fetches that submodule from the local checkout instead (offline work; same commit ids).
if [ "$name" = hubcheck ] && [ -n "${WOLTRUST_SRC:-}" ] && [ -e "$WOLTRUST_SRC/crates/shell/.git" ]; then
    shell_dir=$(cd "$WOLTRUST_SRC/crates/shell" && pwd)
    export CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_CONFIG_COUNT=2
    export GIT_CONFIG_KEY_0=url.$shell_dir.insteadOf GIT_CONFIG_VALUE_0=https://github.com/wonderlandos/wolos-shell.git
    export GIT_CONFIG_KEY_1=protocol.file.allow GIT_CONFIG_VALUE_1=always
fi
case $name in
hubcheck) (cd "$checkout/wasm" && cargo build -q --release --locked --bin hubcheck) >&2 ;;
woltrust) (cd "$checkout" && cargo build -q --release --locked -p woltrust --bin woltrust) >&2 ;;
esac
mkdir -p "$cache/bin"
cp "$CARGO_TARGET_DIR/release/$name" "$bin.tmp"
mv "$bin.tmp" "$bin"
echo "$rev" >"$cache/rev"
rm -rf "$checkout" "$CARGO_TARGET_DIR"   # only bin/ and rev stay: that is what actions/cache keeps
check_sha "$bin" || exit 1
echo "$bin"
