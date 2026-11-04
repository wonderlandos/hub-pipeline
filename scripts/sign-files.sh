#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Signs what build-index.mjs and build-revoked.mjs made.
#
#   sign-files.sh <dir> <index-cert-serial>
#
# <dir> holds index.json and revoked.json; it gets
#   index.json.sig      legacy Ed25519 over the exact bytes of index.json (64 raw bytes; the 0.12 reader)
#   index.json.wsig     hybrid signature, label wolos/index/1, by the Index intermediate (serial given)
#   revoked.json.wsig   hybrid signature, label wolos/revocation/1, by the Index intermediate
#
# Keys come from the environment of the step only, never from a file in git, never printed:
#   WOLOS_INDEX_SIGNING_KEY   the Index intermediate's key material, read by `woltrust sign --key-env`
#   WOLOS_LEGACY_INDEX_KEY    PEM (PKCS#8) of the legacy Ed25519 index key
#   WOLTRUST_BIN              the real woltrust (tools/woltrust.rev)
# DRY_RUN=1 uses the test keys and scripts/woltrust-stub.mjs; its output must never be published.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: sign-files.sh <dir> <index-cert-serial>}
serial=${2:?usage: sign-files.sh <dir> <index-cert-serial>}
[[ $serial =~ ^[0-9a-f]{16}$ ]] || { echo "sign-files: the certificate serial is 16 lowercase hex characters" >&2; exit 2; }
for f in index.json revoked.json; do [ -s "$dir/$f" ] || { echo "sign-files: $dir/$f is missing" >&2; exit 1; }; done

scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sign.XXXXXX")
chmod 700 "$scratch"
trap 'rm -rf "$scratch"' EXIT

if [ "${DRY_RUN:-0}" = 1 ]; then
    node "$here/test-keys.mjs" "$scratch/keys"
    woltrust=(node "$here/woltrust-stub.mjs")
    legacy_key=$scratch/keys/legacy.pem
    keyargs=(--key-file "$scratch/keys/index.pem")
else
    : "${WOLTRUST_BIN:?WOLTRUST_BIN is not set: the real woltrust is required outside a dry run}"
    : "${WOLOS_INDEX_SIGNING_KEY:?WOLOS_INDEX_SIGNING_KEY is not set}"
    : "${WOLOS_LEGACY_INDEX_KEY:?WOLOS_LEGACY_INDEX_KEY is not set}"
    [ -x "$WOLTRUST_BIN" ] || { echo "sign-files: $WOLTRUST_BIN is not executable" >&2; exit 1; }
    woltrust=("$WOLTRUST_BIN")
    legacy_key=$scratch/legacy.pem
    (umask 077 && printf '%s\n' "$WOLOS_LEGACY_INDEX_KEY" >"$legacy_key")
    keyargs=(--key-env WOLOS_INDEX_SIGNING_KEY)
fi

# Legacy Ed25519, raw 64 bytes, over the bytes as they are.
openssl pkeyutl -sign -inkey "$legacy_key" -rawin -in "$dir/index.json" -out "$dir/index.json.sig"
[ "$(wc -c <"$dir/index.json.sig")" -eq 64 ] || { echo "sign-files: the legacy signature is not 64 bytes" >&2; exit 1; }
openssl pkey -in "$legacy_key" -pubout -out "$scratch/legacy.pub"
openssl pkeyutl -verify -pubin -inkey "$scratch/legacy.pub" -rawin -in "$dir/index.json" -sigfile "$dir/index.json.sig" >/dev/null

# Hybrid, both halves, by the Index intermediate.
"${woltrust[@]}" sign --purpose index --cert "$serial" "${keyargs[@]}" "$dir/index.json" >"$dir/index.json.wsig"
"${woltrust[@]}" sign --purpose revocation --cert "$serial" "${keyargs[@]}" "$dir/revoked.json" >"$dir/revoked.json.wsig"
node "$here/validate.mjs" wsig "$dir/index.json.wsig"
node "$here/validate.mjs" wsig "$dir/revoked.json.wsig"
echo "signed: $dir/index.json{.sig,.wsig} $dir/revoked.json.wsig (certificate $serial)"
