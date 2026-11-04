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
#   WOLTRUST_BIN              the pinned woltrust (scripts/tool.sh woltrust), always: dry runs sign for real, with TEST keys
#   WOLOS_INDEX_SIGNING_KEY   the Index intermediate's key material (plain, or a locked .wolkey), read by `woltrust sign --key-env`
#   WOLOS_KEY_PASSPHRASE      the passphrase of a locked .wolkey (woltrust --passphrase-env; not read for a plain key)
#   WOLOS_LEGACY_INDEX_KEY    PEM (PKCS#8) of the legacy Ed25519 index key
#   SIGN_ROOTS, SIGN_INTERMEDIATES  where the self-check finds the certificates (default certs/roots, certs/intermediates;
#                             in a dry run fixtures/trust/): the signed files must verify in woltrust before they leave
# DRY_RUN=1 signs with the TEST keys of scripts/test-keys.mjs (the TEST Index intermediate of woltrust, whose serial
# must then be the one given); its output verifies only against the TEST root and must never be published.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: sign-files.sh <dir> <index-cert-serial>}
serial=${2:?usage: sign-files.sh <dir> <index-cert-serial>}
[[ $serial =~ ^[0-9a-f]{16}$ ]] || { echo "sign-files: the certificate serial is 16 lowercase hex characters" >&2; exit 2; }
for f in index.json revoked.json; do [ -s "$dir/$f" ] || { echo "sign-files: $dir/$f is missing" >&2; exit 1; }; done
: "${WOLTRUST_BIN:?WOLTRUST_BIN is not set: run scripts/tool.sh woltrust}"
[ -x "$WOLTRUST_BIN" ] || { echo "sign-files: $WOLTRUST_BIN is not executable" >&2; exit 1; }

scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sign.XXXXXX")
chmod 700 "$scratch"
trap 'rm -rf "$scratch"' EXIT

if [ "${DRY_RUN:-0}" = 1 ]; then
    node "$here/test-keys.mjs" "$scratch/keys"
    [ "$serial" = "$(cat "$scratch/keys/index.serial")" ] || { echo "sign-files: a dry run signs as the TEST Index intermediate $(cat "$scratch/keys/index.serial"), not $serial" >&2; exit 2; }
    legacy_key=$scratch/keys/legacy.pem
    keyargs=(--key-file "$scratch/keys/index.key")
    roots=${SIGN_ROOTS:-$here/../fixtures/trust/roots} intermediates=${SIGN_INTERMEDIATES:-$here/../fixtures/trust/intermediates}
    verify_test=(--allow-test)
else
    : "${WOLOS_INDEX_SIGNING_KEY:?WOLOS_INDEX_SIGNING_KEY is not set}"
    : "${WOLOS_LEGACY_INDEX_KEY:?WOLOS_LEGACY_INDEX_KEY is not set}"
    legacy_key=$scratch/legacy.pem
    (umask 077 && printf '%s\n' "$WOLOS_LEGACY_INDEX_KEY" >"$legacy_key")
    keyargs=(--key-env WOLOS_INDEX_SIGNING_KEY --passphrase-env WOLOS_KEY_PASSPHRASE)
    roots=${SIGN_ROOTS:-$here/../certs/roots} intermediates=${SIGN_INTERMEDIATES:-$here/../certs/intermediates}
    verify_test=()
fi

# Legacy Ed25519, raw 64 bytes, over the bytes as they are.
openssl pkeyutl -sign -inkey "$legacy_key" -rawin -in "$dir/index.json" -out "$dir/index.json.sig"
[ "$(wc -c <"$dir/index.json.sig")" -eq 64 ] || { echo "sign-files: the legacy signature is not 64 bytes" >&2; exit 1; }
openssl pkey -in "$legacy_key" -pubout -out "$scratch/legacy.pub"
openssl pkeyutl -verify -pubin -inkey "$scratch/legacy.pub" -rawin -in "$dir/index.json" -sigfile "$dir/index.json.sig" >/dev/null

# Hybrid, both halves, by the Index intermediate.
"$WOLTRUST_BIN" sign --purpose index --cert "$serial" "${keyargs[@]}" "$dir/index.json" >"$dir/index.json.wsig"
"$WOLTRUST_BIN" sign --purpose revocation --cert "$serial" "${keyargs[@]}" "$dir/revoked.json" >"$dir/revoked.json.wsig"
node "$here/validate.mjs" wsig "$dir/index.json.wsig"
node "$here/validate.mjs" wsig "$dir/revoked.json.wsig"
# What a client does before it trusts the files: both signatures through the roots, the list fresh.
for f in revoked:revocation index:index; do
    "$WOLTRUST_BIN" verify --purpose "${f#*:}" --wsig "$dir/${f%%:*}.json.wsig" --roots "$roots" --intermediates "$intermediates" \
        --list "$dir/revoked.json" "${verify_test[@]}" ${HUB_NOW:+--now "$HUB_NOW"} "$dir/${f%%:*}.json" >"$scratch/verify.json" ||
        { echo "sign-files: $dir/${f%%:*}.json.wsig does not verify: $(cat "$scratch/verify.json")" >&2; exit 1; }
done
echo "signed: $dir/index.json{.sig,.wsig} $dir/revoked.json.wsig (certificate $serial)"
