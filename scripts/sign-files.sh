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
#   revoked.rkdb        the revocation database (ADR 0046 "RKDB", woltrust rkdb make): every entry of revoked.json, chained to
#                       the previous database (SIGN_PREVIOUS_RKDB, default none: serial 1), signed by the Index intermediate;
#                       with <dir>/emergency.rkdr present (a root-signed section made offline by `woltrust emergency`), that
#                       section is carried inside it (--root-section)
#   revoked.checkpoint.json   {format:1, serial, sha512_256} of revoked.rkdb (woltrust rkdb checkpoint): published on the CDN and
#                       in the log; WolOS reads both and keeps the higher serial as its floor
#   intermediates.json  a JSON array of the .wolcert objects of SIGN_INTERMEDIATES (what the image may be missing: a rotated
#                       Index or Authors CA), the file WolOS reads at /plugins/intermediates.json
#   release.json.wsig   when <dir>/release.json is there (the WolOS release manifest the sign run was given): the Index's
#                       hybrid signature over it, label wolos/index/1 (wol_core update/check.rs reads `base.wsig` with it)
#   statements/<id>/<version>.wsig   when <dir>/statements holds bodies: the release statements, label wolos/release/1
#
# Keys come from the environment of the step only, never from a file in git, never printed:
#   WOLTRUST_BIN              the pinned woltrust (scripts/tool.sh woltrust), always: dry runs sign for real, with TEST keys
#   WOLOS_INDEX_SIGNING_KEY   the Index intermediate's key material (plain, or a locked .wolkey), read by `woltrust sign --key-env`
#   WOLOS_KEY_PASSPHRASE      the passphrase of a locked .wolkey (woltrust --passphrase-env; not read for a plain key)
#   WOLOS_LEGACY_INDEX_KEY    PEM (PKCS#8) of the legacy Ed25519 index key
#   SIGN_ROOTS, SIGN_INTERMEDIATES  where the self-check finds the certificates (default certs/roots, certs/intermediates;
#                             in a dry run fixtures/trust/): the signed files must verify in woltrust before they leave
#   SIGN_PREVIOUS_RKDB        the last published revoked.rkdb (log/signed/revoked.rkdb); the new one follows it (serial + 1,
#                             every old entry kept). Unset or missing: a first database, serial 1
# DRY_RUN=1 signs with the TEST keys of scripts/test-keys.mjs (the TEST Index intermediate of woltrust, whose serial
# must then be the one given); its output verifies only against the TEST root and must never be published.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: sign-files.sh <dir> <index-cert-serial>}
serial=${2:?usage: sign-files.sh <dir> <index-cert-serial>}
[[ $serial =~ ^([0-9a-f]{16}|[0-9a-f]{128})$ ]] || { echo "sign-files: the certificate id is 128 lowercase hex characters (16 for the TEST authority)" >&2; exit 2; }
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

# Release statements (statements.mjs), when build-index.mjs wrote their bodies: signed first: an index that points at
# statements is not signed at all when they cannot be.
if [ -d "$dir/statements" ]; then
    node "$here/statements.mjs" sign --dir "$dir/statements" --cert "$serial" "${keyargs[@]}"
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

# The revocation database and its checkpoint (lead decision "RKDB"): the same entries as revoked.json, chained to the
# database published before, with the emergency section inside it when one is in force.
rkdb_args=()
[ -z "${SIGN_PREVIOUS_RKDB:-}" ] || [ ! -s "$SIGN_PREVIOUS_RKDB" ] || rkdb_args+=(--previous "$SIGN_PREVIOUS_RKDB")
[ ! -s "$dir/emergency.rkdr" ] || rkdb_args+=(--root-section "$dir/emergency.rkdr")
"$WOLTRUST_BIN" rkdb make --source "$dir/revoked.json" "${rkdb_args[@]}" ${HUB_NOW:+--now "$HUB_NOW"} --cert "$serial" "${keyargs[@]}" >"$dir/revoked.rkdb"
"$WOLTRUST_BIN" rkdb checkpoint "$dir/revoked.rkdb" >"$dir/revoked.checkpoint.json"
"$WOLTRUST_BIN" rkdb verify --roots "$roots" --intermediates "$intermediates" "${verify_test[@]}" ${HUB_NOW:+--now "$HUB_NOW"} "$dir/revoked.rkdb" >"$scratch/rkdb.txt" ||
    { echo "sign-files: $dir/revoked.rkdb does not verify: $(cat "$scratch/rkdb.txt")" >&2; exit 1; }
if [ -n "${SIGN_PREVIOUS_RKDB:-}" ] && [ -s "$SIGN_PREVIOUS_RKDB" ]; then
    # The chain a client checks: the new database follows the held one (serial + 1, prev hash, no entry lost).
    "$WOLTRUST_BIN" rkdb delta "$SIGN_PREVIOUS_RKDB" "$dir/revoked.rkdb" >/dev/null ||
        { echo "sign-files: $dir/revoked.rkdb does not follow $SIGN_PREVIOUS_RKDB" >&2; exit 1; }
fi
node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(c.format!==1||!Number.isInteger(c.serial)||!/^[0-9a-f]{64}$/.test(c.sha512_256))process.exit(1)' "$dir/revoked.checkpoint.json" ||
    { echo "sign-files: $dir/revoked.checkpoint.json is not {format:1, serial, sha512_256}" >&2; exit 1; }

# The intermediates WolOS may fetch: every certificate of the store's intermediates folder, as a JSON array (sorted by file name).
node -e 'const fs=require("fs"),p=require("path"),d=process.argv[1];const a=fs.existsSync(d)?fs.readdirSync(d).filter(f=>f.endsWith(".wolcert")).sort().map(f=>JSON.parse(fs.readFileSync(p.join(d,f),"utf8"))):[];fs.writeFileSync(process.argv[2],JSON.stringify(a)+"\n")' "$intermediates" "$dir/intermediates.json"

# The WolOS release manifest, when this run was given one: signed as an index (label wolos/index/1, the label update/check.rs reads).
if [ -s "$dir/release.json" ]; then
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$dir/release.json" || { echo "sign-files: $dir/release.json is not JSON" >&2; exit 1; }
    "$WOLTRUST_BIN" sign --purpose index --cert "$serial" "${keyargs[@]}" "$dir/release.json" >"$dir/release.json.wsig"
    node "$here/validate.mjs" wsig "$dir/release.json.wsig"
fi
# What a client does before it trusts the files: both signatures through the roots, the list fresh.
release=; [ ! -s "$dir/release.json.wsig" ] || release=release:index
for f in revoked:revocation index:index $release; do
    "$WOLTRUST_BIN" verify --purpose "${f#*:}" --wsig "$dir/${f%%:*}.json.wsig" --roots "$roots" --intermediates "$intermediates" \
        --list "$dir/revoked.json" "${verify_test[@]}" ${HUB_NOW:+--now "$HUB_NOW"} "$dir/${f%%:*}.json" >"$scratch/verify.json" ||
        { echo "sign-files: $dir/${f%%:*}.json.wsig does not verify: $(cat "$scratch/verify.json")" >&2; exit 1; }
done
echo "signed: $dir/index.json{.sig,.wsig} $dir/revoked.json.wsig $dir/revoked.rkdb (serial $(node -p 'require(process.argv[1]).serial' "$dir/revoked.checkpoint.json"))${release:+ $dir/release.json.wsig} (certificate $serial)"
