#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# The schema here (schema/) must be byte for byte the one the public log publishes (wonderlandos/hub-log schema/):
# sign.yml stops on any difference before it builds anything, so a schema change has to land in both repositories.
# This is the same comparison, run by ci.yml on every push and pull request, so the drift shows when the schema is
# changed and not at the next signing.
#
#   schema-sync.sh [<hub-log checkout>]
#
# Without an argument the public log's main is cloned read-only (https, no credential) into a scratch folder.
# Exit 0 when both are the same, 1 with the diff when they differ, 2 when the log cannot be read.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
log=${1:-}
tmp=
trap '[ -z "$tmp" ] || rm -rf "$tmp"' EXIT
if [ -z "$log" ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/hub-log-schema.XXXXXX")
    git clone --quiet --depth 1 --branch main https://github.com/wonderlandos/hub-log "$tmp/log" ||
        { echo "schema-sync: wonderlandos/hub-log could not be cloned" >&2; exit 2; }
    log=$tmp/log
fi
[ -d "$log/schema" ] || { echo "schema-sync: $log/schema is not there" >&2; exit 2; }
log=$(cd "$log" && pwd)
if (cd "$root" && diff -r schema "$log/schema"); then
    echo "ok   schema/ is the one hub-log publishes ($(find "$root/schema" -type f | wc -l) files)"
else
    echo "FAIL schema/ differs from hub-log schema/ (above): push the same files to wonderlandos/hub-log schema/," \
        "or sign.yml stops at 'The schema here is the one hub-log publishes'" >&2
    exit 1
fi
