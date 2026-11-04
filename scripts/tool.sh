#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Builds a pinned tool of the pipeline and prints the path of its binary on the last line.
#
#   tool.sh hubcheck|woltrust        reads tools/<name>.rev (a 40-digit commit id, or "unpinned")
#
# unpinned = the tool does not exist yet: exit 3, nothing is built, the workflow stops (a dry run uses the
# stand-ins in scripts/ instead). The source is built with --locked at exactly that commit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
name=${1:?usage: tool.sh hubcheck|woltrust}
rev=$(tr -d ' \n' <"$here/../tools/$name.rev")
case $name in
hubcheck) repo=https://github.com/wonderlandos/hub ;;      # TODO(ADR 0047): wasm/bin/hubcheck, HUB-wasm
woltrust) repo=https://github.com/wonderlandos/wolos ;;    # TODO(ADR 0046): crates/woltrust gets its CLI
*) echo "tool: unknown tool $name" >&2; exit 2 ;;
esac
if [ "$rev" = unpinned ]; then
    echo "tool: $name is not pinned yet (tools/$name.rev says unpinned); nothing was built" >&2
    exit 3
fi
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "tool: tools/$name.rev is neither a commit id nor 'unpinned'" >&2; exit 2; }
root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tool-$name
cargo install --git "$repo" --rev "$rev" --locked --root "$root" "$name" >&2
echo "$root/bin/$name"
