#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Uploads a signed publication to the CDN under plugins/ and reads it back.
#
#   publish.sh <dir>        <dir>: index.json index.json.sig index.json.wsig revoked.json revoked.json.wsig
#                           [statements/<id>/<version>.wsig]
#
# WOLOS_CDN_UPLOAD_TOKEN   the token (secret of the sign environment), handed to cdn-put as UPLOAD_TOKEN
# CDN_BASE                 the upload server, default what cdn-put knows (its own default)
# CDN_PUBLIC               where clients read, default https://cdn.wolos.org
# DRY_RUN=1                prints the plan and uploads nothing
#
# Order: the revocation list first (the index points at it), then the signatures, and index.json last: it is the file
# a client reads first, so a client never sees an index whose revocation list is not there yet. A client that
# lands between two uploads gets a signature mismatch and tries again later; it never gets a wrong index
# accepted, because every file is checked against its signature.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: publish.sh <dir>}
public=${CDN_PUBLIC:-https://cdn.wolos.org}
files=(revoked.json revoked.json.wsig index.json.wsig index.json.sig index.json)
for f in "${files[@]}"; do [ -s "$dir/$f" ] || { echo "publish: $dir/$f is missing" >&2; exit 1; }; done
# Release statements go first of all: the index points at them.
if [ -d "$dir/statements" ]; then
    mapfile -t statements < <(cd "$dir" && find statements -name '*.wsig' | LC_ALL=C sort)
    files=("${statements[@]}" "${files[@]}")
fi

if [ "${DRY_RUN:-0}" = 1 ]; then
    for f in "${files[@]}"; do echo "dry run: would upload $dir/$f to plugins/$f ($(wc -c <"$dir/$f") bytes)"; done
    exit 0
fi

: "${WOLOS_CDN_UPLOAD_TOKEN:?WOLOS_CDN_UPLOAD_TOKEN is not set}"
export UPLOAD_TOKEN=$WOLOS_CDN_UPLOAD_TOKEN
extra=()
[ -z "${CDN_BASE:-}" ] || extra=(--base "$CDN_BASE")
for f in "${files[@]}"; do
    "$here/../tools/cdn-put" "$dir/$f" "plugins/$f" "${extra[@]}"
done

# Read back what clients will read. The CDN may need a moment; the files must match byte for byte.
for f in "${files[@]}"; do
    want=$(sha256sum "$dir/$f" | cut -d' ' -f1)
    ok=0
    for try in 1 2 3 4 5 6; do
        got=$(curl -fsS --max-time 30 -H 'Cache-Control: no-cache' "$public/plugins/$f" | sha256sum | cut -d' ' -f1 || true)
        if [ "$got" = "$want" ]; then ok=1; break; fi
        sleep $((try * 5))
    done
    [ "$ok" = 1 ] || { echo "publish: $public/plugins/$f does not serve the file that was uploaded" >&2; exit 1; }
    echo "published: $public/plugins/$f ($want)"
done
