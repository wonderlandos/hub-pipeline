#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Uploads a signed publication to the CDN under plugins/ and reads it back.
#
#   publish.sh <dir>        <dir>: index.json index.json.sig index.json.wsig revoked.json revoked.json.wsig
#                           revoked.rkdb revoked.checkpoint.json intermediates.json [emergency.rkdr] [release.json.wsig]
#                           [statements/<id>/<version>.wsig] [pictures/<sha256>.<png|webp>]
#                           pictures/ (scripts/pictures.mjs stage: the listings' icons and screenshots, read from the
#                           packages by hubcheck extract) go to plugins/pictures/<sha256>.<png|webp>, first of all.
#                           Everything goes to plugins/<name> (crates/core/src/trust.rs: RKDB_PATH, EMERGENCY_PATH,
#                           INTERMEDIATES_PATH; cdn.rs RKDB_CHECKPOINTS), except release.json.wsig, which goes to
#                           latest/release.json.wsig, beside the release manifest it signs (cdn.rs LATEST).
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
# Intermediates and the emergency section first (a client needs them to check the rest), then the database and its
# checkpoint, then the list, the signatures, and index.json last.
files=(intermediates.json revoked.rkdb revoked.checkpoint.json revoked.json revoked.json.wsig index.json.wsig index.json.sig index.json)
for f in "${files[@]}"; do [ -s "$dir/$f" ] || { echo "publish: $dir/$f is missing" >&2; exit 1; }; done
[ ! -s "$dir/emergency.rkdr" ] || files=(emergency.rkdr "${files[@]}")
# The release manifest's signature is the one file outside plugins/: it lives beside release.json under latest/.
[ ! -s "$dir/release.json.wsig" ] || files+=(release.json.wsig)
target() { case $1 in release.json.wsig) echo "latest/$1" ;; *) echo "plugins/$1" ;; esac; }
# Release statements go first of all: the index points at them.
if [ -d "$dir/statements" ]; then
    mapfile -t statements < <(cd "$dir" && find statements -name '*.wsig' | LC_ALL=C sort)
    files=("${statements[@]}" "${files[@]}")
fi
# The pictures the listings name, before everything: a page that shows the new index finds them there. Only names
# of the form <64 hex>.png|webp (what pictures.mjs stages); anything else in the folder is refused.
if [ -d "$dir/pictures" ]; then
    mapfile -t pictures < <(cd "$dir" && find pictures -type f | LC_ALL=C sort)
    for f in "${pictures[@]}"; do
        [[ $f =~ ^pictures/[0-9a-f]{64}\.(png|webp)$ ]] || { echo "publish: $dir/$f is not a picture name (<sha256>.png|webp)" >&2; exit 1; }
    done
    files=("${pictures[@]}" "${files[@]}")
fi

if [ "${DRY_RUN:-0}" = 1 ]; then
    for f in "${files[@]}"; do echo "dry run: would upload $dir/$f to $(target "$f") ($(wc -c <"$dir/$f") bytes)"; done
    exit 0
fi

: "${WOLOS_CDN_UPLOAD_TOKEN:?WOLOS_CDN_UPLOAD_TOKEN is not set}"
export UPLOAD_TOKEN=$WOLOS_CDN_UPLOAD_TOKEN
extra=()
[ -z "${CDN_BASE:-}" ] || extra=(--base "$CDN_BASE")
for f in "${files[@]}"; do
    "$here/../tools/cdn-put" "$dir/$f" "$(target "$f")" "${extra[@]}"
done

# Read back what clients will read. The CDN may need a moment; the files must match byte for byte.
# A picture must also come with its own type: the CDN (wolos-cdn bucket.rs serve, tower-http ServeFile) types a file by
# its name's extension (.png image/png, .webp image/webp) and every answer says nosniff, so a page would not show a
# picture served as anything else. cdn-put has no type to give (its parts are application/octet-stream); the name is it.
headers=$(mktemp "${TMPDIR:-/tmp}/publish-headers.XXXXXX")
trap 'rm -f "$headers"' EXIT
for f in "${files[@]}"; do
    want=$(sha256sum "$dir/$f" | cut -d' ' -f1)
    ok=0
    for try in 1 2 3 4 5 6; do
        got=$(curl -fsS --max-time 30 -H 'Cache-Control: no-cache' -D "$headers" "$public/$(target "$f")" | sha256sum | cut -d' ' -f1 || true)
        if [ "$got" = "$want" ]; then ok=1; break; fi
        sleep $((try * 5))
    done
    [ "$ok" = 1 ] || { echo "publish: $public/$(target "$f") does not serve the file that was uploaded" >&2; exit 1; }
    case $f in
    pictures/*.png | pictures/*.webp)
        type_want=image/${f##*.}
        type_got=$(tr -d '\r' <"$headers" | awk 'tolower($1) == "content-type:" { print tolower($2) }' | tail -n 1)
        type_got=${type_got%%;*}
        [ "$type_got" = "$type_want" ] || { echo "publish: $public/$(target "$f") is served as '${type_got:-no type}', not $type_want" >&2; exit 1; } ;;
    esac
    echo "published: $public/$(target "$f") ($want${type_want:+, $type_want})"
    type_want=
done
