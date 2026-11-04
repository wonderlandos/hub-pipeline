#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Rewrites the binary fixtures of this repository (fixtures/assets/*, fixtures/trust/, fixtures/request-issue.json) from
# the TEST authority of woltrust, at the commit of tools/woltrust.rev. Not part of any workflow; run it when a fixture
# has to change, then `SAMPLE_OUT=fixtures/sample-signed scripts/test.sh`.
#
#   fixtures/gen/run.sh            WOLTRUST_SRC=<local wolos repository> to clone from it instead of GitHub
#
# hub_index_fixtures.rs is copied into crates/woltrust/examples/ of a fresh clone and run there with --locked: it uses
# only woltrust and that crate's own dependencies.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
rev=$(tr -d ' \n' <"$root/tools/woltrust.rev")
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "gen: tools/woltrust.rev is not a commit id" >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/hub-index-gen.XXXXXX")
trap 'rm -rf "$work"' EXIT
src=${WOLTRUST_SRC:-}
git clone -q --no-checkout ${src:+--no-local} "${src:-https://github.com/wonderlandos/wolos}" "$work/wolos"
git -C "$work/wolos" -c advice.detachedHead=false checkout -q "$rev"
shell_from=https://github.com/wonderlandos/wolos-shell.git local=()
if [ -n "$src" ] && [ -e "$src/crates/shell/.git" ]; then shell_from=$(cd "$src/crates/shell" && pwd); local=(-c protocol.file.allow=always); fi
git -C "$work/wolos" submodule set-url crates/shell "$shell_from"
git "${local[@]}" -C "$work/wolos" submodule update -q --init crates/shell
mkdir -p "$work/wolos/crates/woltrust/examples"
cp "$here/hub_index_fixtures.rs" "$work/wolos/crates/woltrust/examples/"
(cd "$work/wolos" && cargo run -q --release --locked -p woltrust --example hub_index_fixtures -- "$root/fixtures")
