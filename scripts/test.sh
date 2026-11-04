#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Every script of this repository against fixtures/, with no secret and no network (a mock Worker on 127.0.0.1,
# the stand-in hubcheck, the stand-in woltrust, test keys derived from fixed seeds). Nothing in the repository is
# written; the results are in a scratch folder, or in $SAMPLE_OUT when it is set (that is how
# fixtures/sample-signed/ was made).
#
#   scripts/test.sh
# shellcheck disable=SC2015  # ok() never fails, so "A && ok || bad" is the if-then-else it reads as
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
fx=$root/fixtures
work=$(mktemp -d "${TMPDIR:-/tmp}/hub-index-test.XXXXXX")
mock_pid=
cleanup() { [ -z "$mock_pid" ] || kill "$mock_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
export HUB_NOW=1793750400   # 2026-11-04 in Unix seconds: fixed, so every output is the same every time
export HUB_TEST=1
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*" >&2; fails=$((fails + 1)); }
expect_fail() { # <what> <command...>: the command must exit non-zero
    local what=$1; shift
    if "$@" >/dev/null 2>&1; then bad "$what: was accepted"; else ok "$what: refused"; fi
}

# 0. The vendored upload tool is the pinned one.
(cd "$root/tools" && sha256sum --check --quiet cdn-put.sha256) && ok "tools/cdn-put matches its pin" || bad "tools/cdn-put changed"

# 1. The fixtures are valid, and the schema refuses what it should.
node "$here/validate.mjs" request "$fx/request-issue.json" >/dev/null && ok "issue request valid" || bad "issue request"
node "$here/validate.mjs" request "$fx/request-revoke.json" >/dev/null && ok "revoke request valid" || bad "revoke request"
node --input-type=module - "$here" "$fx" "$work" <<'JS' || fails=$((fails + 1))
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { checkIndex, checkRevoked, checkRequest } = await import(pathToFileURL(`${process.argv[2]}/validate.mjs`).href);
const [, , , fx] = process.argv;
const exp = JSON.parse(readFileSync(`${fx}/export.json`, "utf8"));
const base = () => ({ format: 1, serial: 2, issued: 1793750400, expires: 1794355200, apps: structuredClone(exp.apps), plugins: structuredClone(exp.plugins), extensions: structuredClone(exp.extensions), intermediates: [], revoked: { url: "https://cdn.wolos.org/plugins/revoked.json", sha256: "a".repeat(64), serial: 2 } });
let n = 0, failed = 0;
const must = (name, idx, text) => {
  const r = checkIndex(idx, { bytes: 1000 });
  const hit = r.errors.some((e) => e.includes(text));
  console.log(`${hit ? "ok  " : "FAIL"} index refused: ${name}`);
  n++; if (!hit) failed++;
};
if (checkIndex(base(), { bytes: 1000 }).errors.length) { console.log("FAIL the base index is not valid"); failed++; }
let i;
i = base(); i.apps[0].url = "https://evil.example/a.wol"; must("asset not on GitHub", i, "url");
i = base(); i.apps[0].url = "https://github.com/alice/notes/releases/download/v1.0/a.zip"; must("app without .wol", i, "url");
i = base(); i.plugins[0].url = i.apps[0].url; must("plugin without .wolplug", i, "url");
i = base(); i.apps[0].sha256 = "XYZ"; must("bad sha256", i, "sha256");
i = base(); i.apps[0].verdict = "block"; must("a blocked entry", i, "verdict");
i = base(); i.apps[0].trust = "trusted"; must("unknown trust", i, "trust");
i = base(); i.apps[0].id = "bob.notes"; must("id outside the owner's namespace", i, "must start with the owner");
i = base(); i.apps[0].id = "org.wolos.notes"; must("org.wolos. for a person", i, "org.wolos");
i = base(); i.apps[0].source.repo = "mallory/notes"; must("url not in source.repo", i, "source.repo");
i = base(); i.apps[0].source.tag = "v9"; must("url not at source.tag", i, "source.tag");
i = base(); i.extensions[0].host = undefined; delete i.extensions[0].host; must("extension without host", i, "host");
i = base(); i.apps[0].host = "x.y"; must("app with host", i, "host");
i = base(); i.apps.push(structuredClone(i.apps[0])); must("id twice", i, "listed twice");
i = base(); i.plugins[0].trust = "community"; i.plugins[0].cert = "a11ce00000000001"; must("community with a certificate", i, "community");
i = base(); i.extensions[0].findings = []; must("flag without findings", i, "findings");
i = base(); i.apps[0].surprise = 1; must("unknown field", i, "not a known field");
i = base(); i.expires = i.issued + 30 * 86400; must("expiry far away", i, "7 days");
i = base(); delete i.serial; must("no serial", i, "serial");
const rl = { format: 1, serial: 1, issued: 1, expires: 2, entries: [{ serial: "b0b00000000000ad", at: 1, reason: "key-compromise" }] };
for (const [name, mut, text] of [["bad reason", (l) => { l.entries[0].reason = "oops"; }, "reason"], ["bad serial", (l) => { l.entries[0].serial = "123"; }, "serial"], ["extra key", (l) => { l.entries[0].note = "x"; }, "not a known field"], ["twice", (l) => { l.entries.push({ ...l.entries[0] }); }, "twice"]]) {
  const l = structuredClone(rl); mut(l); const hit = checkRevoked(l).some((e) => e.includes(text));
  console.log(`${hit ? "ok  " : "FAIL"} revocation list refused: ${name}`); n++; if (!hit) failed++;
}
const issue = JSON.parse(readFileSync(`${fx}/request-issue.json`, "utf8"));
const rq = (name, mut, text) => { const r = structuredClone(issue); mut(r); const hit = checkRequest(r).some((e) => e.includes(text)); console.log(`${hit ? "ok  " : "FAIL"} request refused: ${name}`); n++; if (!hit) failed++; };
rq("org.wolos. namespace", (r) => { r.namespaces = ["alice.", "org.wolos."]; }, "org.wolos");
rq("namespace missing the login", (r) => { r.namespaces = ["other."]; }, "namespaces include");
rq("no proof", (r) => { delete r.proof; }, "proof");
console.log(`${n - failed}/${n} negative checks`);
process.exit(failed ? 1 : 0);
JS

# 2. The mock Worker, the check job's three scripts, and the token separation of I9.
export HUB_API=http://127.0.0.1:18787
node "$here/mock-hub.mjs" --port 18787 --pending "$fx/pending.json" --export "$fx/export.json" --received "$work/received.jsonl" >"$work/mock.log" &
mock_pid=$!
for _ in $(seq 1 50); do curl -fs -o /dev/null -H 'Authorization: Bearer check-token' "$HUB_API/api/pipeline/pending" 2>/dev/null && break; sleep 0.1; done
HUB_TOKEN=check-token node "$here/api.mjs" pending --out "$work/pending.json" >/dev/null && ok "check token reads pending" || bad "pending"
expect_fail "check token cannot export" env HUB_TOKEN=check-token node "$here/api.mjs" export --out "$work/x.json"
expect_fail "sign token cannot post verdicts" env HUB_TOKEN=sign-token node "$here/api.mjs" verdicts --in "$fx/../fixtures/pending.json"
expect_fail "no token, no answer" env HUB_TOKEN=nonsense node "$here/api.mjs" pending --out "$work/x.json"
expect_fail "plain http to a real host" env HUB_API=http://example.org HUB_TOKEN=x node "$here/api.mjs" pending --out "$work/x.json"
HUBCHECK_BIN="$here/hubcheck-stub.sh" node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/verdicts.json" --work "$work/scan" >"$work/scan.log"
node "$here/verdicts.mjs" clean --pending "$work/pending.json" --verdicts "$work/verdicts.json" --out "$work/clean.json" >/dev/null
HUB_TOKEN=check-token node "$here/api.mjs" verdicts --in "$work/clean.json" >/dev/null
got=$(node -e 'for (const l of require("fs").readFileSync(process.argv[1],"utf8").trim().split("\n")) { const v = JSON.parse(l); console.log(v.listing_id + " " + v.verdict + (v.findings[0] ? " " + v.findings[0].rule : "")); }' "$work/received.jsonl" | sort)
want=$'alice.notes pass\nalice.weather pass\ncarol.gone not-checked fetch/failed\ndave.swapped block asset/size-mismatch\nexamplelabs.notes-sync flag permissions/more\nmallory.tool block stub/block'
[ "$got" = "$want" ] && ok "six releases, six verdicts (pass, pass, flag, block, block, not-checked)" || { bad "verdicts differ"; diff <(echo "$want") <(echo "$got") >&2 || true; }
# a verdict for a release that was not pending, and a repeated one, never get through
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));v.verdicts.push({listing_id:"zed.other",version:"1",verdict:"pass",sha256:"a".repeat(64),findings:[]},v.verdicts[0],{...v.verdicts[1],findings:[{rule:"x",sentence:"\u0007"}]});require("fs").writeFileSync(process.argv[2],JSON.stringify(v))' "$work/verdicts.json" "$work/verdicts-extra.json"
n=$(node "$here/verdicts.mjs" clean --pending "$work/pending.json" --verdicts "$work/verdicts-extra.json" --out "$work/clean2.json" 2>/dev/null | cut -d' ' -f1)
[ "$n" = 6 ] && ok "unknown, repeated and malformed verdicts are dropped" || bad "verdict gate kept $n"
# no checker installed: nothing is decided, never a pass
HUBCHECK_BIN=/nonexistent node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/none.json" --work "$work/scan2" >/dev/null
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts.filter(x=>x.verdict==="pass");process.exit(v.length?1:0)' "$work/none.json" && ok "no hubcheck: no pass" || bad "pass without hubcheck"

# 3. The sign job: owners, revocations, index, signatures, decision, upload plan.
export DRY_RUN=1
node "$here/verify-owners.mjs" --export "$fx/export.json" --previous "$fx/previous-index.json" --fixture "$fx/github.json" --out "$work/export.checked.json" >/dev/null && ok "owners checked against the GitHub fixture" || bad "owners"
node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1]));f.repos[5001].owner.id=999;require("fs").writeFileSync(process.argv[2],JSON.stringify(f))' "$fx/github.json" "$work/github-bad.json"
node "$here/verify-owners.mjs" --export "$fx/export.json" --fixture "$work/github-bad.json" --out "$work/export.bad.json" >/dev/null 2>&1
[ "$(node -p 'require(process.argv[1]).apps.length' "$work/export.bad.json")" = 0 ] && ok "a taken-over owner is left out" || bad "owner takeover accepted"
out=$work/out; mkdir -p "$out"
node "$here/build-revoked.mjs" --source "$fx/revocations.json" --previous "$fx/previous-index.json" --out "$out/revoked.json" >/dev/null
node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --previous "$fx/previous-index.json" --out "$out/index.json" >/dev/null
node "$here/validate.mjs" index "$out/index.json" --revoked "$out/revoked.json" --now "$HUB_NOW" >/dev/null && ok "index.json valid (schema and rules)" || bad "index.json"
node "$here/validate.mjs" revoked "$out/revoked.json" >/dev/null && ok "revoked.json valid" || bad "revoked.json"
"$here/sign-files.sh" "$out" 7e57000000000001 >/dev/null && ok "signed: .sig (legacy), .wsig (hybrid), revoked.json.wsig" || bad "signing"
cp "$out/index.json" "$work/index2.json"; node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --previous "$fx/previous-index.json" --out "$work/index2.json" >/dev/null
cmp -s "$out/index.json" "$work/index2.json" && ok "the same export gives the same bytes" || bad "index not reproducible"
node "$here/legacy-check.mjs" "$out/index.json" "$out/index.json.sig" "$(node -e 'import("'"$here"'/test-keys.mjs").then(m=>console.log(m.publicHex(m.testKey("legacy"))))')" && ok "a 0.12 reader would verify and keep the entries" || bad "0.12 compatibility"
mkdir -p "$work/prev"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == yes* ]] && ok "first publication: $r" || bad "needs-publish first: $r"
cp "$out"/* "$work/prev/"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == no* ]] && ok "unchanged and recent: $r" || bad "needs-publish unchanged: $r"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev" --now $((HUB_NOW + 86400))); [[ $r == yes* ]] && ok "a day later: $r" || bad "needs-publish day: $r"
cp "$out/revoked.json" "$work/prev/revoked.json"; node -e 'const f=require("fs"),p=process.argv[1];const l=JSON.parse(f.readFileSync(p));l.entries.push({serial:"c0c0000000000001",at:1,reason:"abuse"});f.writeFileSync(p,JSON.stringify(l))' "$work/prev/revoked.json"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == yes* ]] && ok "revocations changed: $r" || bad "needs-publish revoked: $r"
"$here/publish.sh" "$out" >/dev/null && ok "upload plan (dry run)" || bad "publish dry run"
# a tampered file or a missing signature must not pass the 0.12 check
sed 's/"serial": 42/"serial": 43/' "$out/index.json" >"$work/tampered.json"
expect_fail "a changed index does not verify" node "$here/legacy-check.mjs" "$work/tampered.json" "$out/index.json.sig" "$(node -e 'import("'"$here"'/test-keys.mjs").then(m=>console.log(m.publicHex(m.testKey("legacy"))))')"
# a half-empty export must not empty the index
node -e 'const f=require("fs");const e=JSON.parse(f.readFileSync(process.argv[1]));const p={format:1,serial:41,issued:1,expires:2,apps:[],plugins:[],extensions:[]};for(let i=0;i<8;i++){const x=structuredClone(e.apps[0]);x.id="alice.a"+i;p.apps.push(x)}f.writeFileSync(process.argv[2],JSON.stringify(p))' "$fx/export.json" "$work/big-prev.json"
expect_fail "an index that lost most of its entries" node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --previous "$work/big-prev.json" --out "$work/x.json"

# 4. The ca workflow's script, with the test CA, in a scratch copy.
ca=$work/ca; mkdir -p "$ca/requests" "$ca/certs"; cp "$fx"/request-*.json "$ca/requests/"
export WOLTRUST="node $here/woltrust-stub.mjs"
node "$here/ca.mjs" issue --request "$ca/requests/request-issue.json" --certs "$ca/certs" --issuer-serial 7e57ca0000000001 --source "$ca/revocations.json" --archive >"$work/issue.log" && ok "certificate issued: $(cut -d' ' -f2 "$work/issue.log")" || bad "issue"
serial=$(cut -d' ' -f2 "$work/issue.log")
[ -f "$ca/certs/$serial.wolcert" ] && [ -f "$ca/requests/done/request-issue.json" ] && ok "certificate written, request archived" || bad "issue files"
expect_fail "a second certificate for the same account" node "$here/ca.mjs" issue --request "$ca/requests/done/request-issue.json" --certs "$ca/certs" --issuer-serial 7e57ca0000000001 --source "$ca/revocations.json"
expect_fail "revoking a serial that was never issued" node "$here/ca.mjs" revoke --request "$ca/requests/request-revoke.json" --certs "$ca/certs" --source "$ca/revocations.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.serial=process.argv[2];r.reason="superseded";f.writeFileSync(process.argv[3],JSON.stringify(r))' "$fx/request-revoke.json" "$serial" "$ca/requests/revoke-issued.json"
node "$here/ca.mjs" revoke --request "$ca/requests/revoke-issued.json" --certs "$ca/certs" --source "$ca/revocations.json" >/dev/null && ok "revocation appended to revocations.json" || bad "revoke"
node "$here/build-revoked.mjs" --source "$ca/revocations.json" --out "$work/rev2.json" >/dev/null && grep -q "$serial" "$work/rev2.json" && ok "...and it is in the next revoked.json" || bad "revocation not propagated"
node "$here/ca.mjs" issue --request "$ca/requests/done/request-issue.json" --certs "$ca/certs" --issuer-serial 7e57ca0000000001 --source "$ca/revocations.json" >/dev/null 2>&1 && ok "after the revocation the account may get a new certificate" || bad "re-issue after revocation"

# 5. Optional: keep what was made as the sample (SAMPLE_OUT=fixtures/sample-signed scripts/test.sh).
if [ -n "${SAMPLE_OUT:-}" ]; then
    mkdir -p "$SAMPLE_OUT"
    cp "$out"/* "$SAMPLE_OUT/"
    node "$here/test-keys.mjs" "$work/keys"
    cp "$work/keys/legacy.pub.hex" "$SAMPLE_OUT/legacy-test-key.pub.hex"
    echo "sample written to $SAMPLE_OUT"
fi

if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed" >&2; exit 1; fi
echo "all checks passed"
