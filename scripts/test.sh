#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Every script of this repository against fixtures/, with the REAL pinned tools (tools/*.rev, built and cached by
# scripts/tool.sh; or WOLTRUST_BIN / HUBCHECK_BIN), no secret and no network but that build (a mock Worker on
# 127.0.0.1, the TEST authority of woltrust, keys derived from public names). Nothing in the repository is written;
# the results are in a scratch folder, or in $SAMPLE_OUT when it is set (that is how fixtures/sample-signed/ was made).
#
#   scripts/test.sh
# shellcheck disable=SC2015  # ok() never fails, so "A && ok || bad" is the if-then-else it reads as
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
fx=$root/fixtures
work=$(mktemp -d "${TMPDIR:-/tmp}/hub-pipeline-test.XXXXXX")
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

# 0. The vendored upload tool is the pinned one; the two pinned tools are built (or taken from the cache).
(cd "$root/tools" && sha256sum --check --quiet cdn-put.sha256) && ok "tools/cdn-put matches its pin" || bad "tools/cdn-put changed"
WOLTRUST_BIN=${WOLTRUST_BIN:-$("$here/tool.sh" woltrust | tail -n 1)}
HUBCHECK_BIN=${HUBCHECK_BIN:-$("$here/tool.sh" hubcheck | tail -n 1)}
export WOLTRUST_BIN HUBCHECK_BIN
[ -x "$WOLTRUST_BIN" ] && [ -x "$HUBCHECK_BIN" ] || { echo "FAIL the pinned tools are not there: $WOLTRUST_BIN $HUBCHECK_BIN" >&2; exit 1; }
ok "tools: woltrust $(cut -c1-7 "$root/tools/woltrust.rev") ($WOLTRUST_BIN), hubcheck $(cut -c1-7 "$root/tools/hubcheck.rev") $("$HUBCHECK_BIN" version)"
keys=$work/keys
node "$here/test-keys.mjs" "$keys"
INDEX_SERIAL=$(cat "$keys/index.serial") AUTHORS_SERIAL=$(cat "$keys/authors.serial")
trust=$fx/trust

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
i = base(); i.extensions[0].url = "https://github.com/examplelabs/notes-sync/releases/download/v0.3/x.wolplug"; must("extension without .wolext", i, "url");
i = base(); i.extensions[0].permissions = ["http"]; must("extension with permissions", i, "permissions");
i = base(); i.plugins[0].url = i.apps[0].url; must("plugin without .wolplug", i, "url");
i = base(); i.apps[0].sha256 = "XYZ"; must("bad sha256", i, "sha256");
i = base(); i.apps[0].verdict = "block"; must("a blocked entry", i, "verdict");
i = base(); i.apps[0].trust = "verified"; must("unknown trust (verified is now trusted)", i, "trust");
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
rq("namespace missing the login", (r) => { r.namespaces = ["other."]; }, "exactly");
rq("no proof", (r) => { delete r.proof; }, "proof");
rq("not approved", (r) => { delete r.approved_by; }, "approved_by");
rq("no tier", (r) => { delete r.tier; }, "tier");
rq("an unknown tier", (r) => { r.tier = "gold"; }, "tier");
rq("origin without the CLA", (r) => { r.tier = "origin"; }, "cla_accepted_at");
rq("approved by the subject", (r) => { r.approved_by = ["Alice"]; }, "own certificate");
rq("one encryption key alone", (r) => { delete r.keys["ml-kem-768"]; }, "both or not at all");
rq("an organisation inside an organisation", (r) => { r.kind = "org"; r.requested_by = { github_id: 1003, login: "bob" }; }, "only a person");
// audit-1 H2 (repro-namespace.mjs): extra prefixes for a person, any prefix for an organisation, reserved and look-alike names
rq("a person asking for more prefixes than their own", (r) => { r.namespaces = ["alice.", "mozilla.", "signal.", "github."]; }, "exactly");
rq("a person asking for a sub-prefix only", (r) => { r.namespaces = ["alice.tools."]; }, "exactly");
rq("an organisation asking for another prefix", (r) => { r.kind = "org"; delete r.subject.org; r.requested_by = { github_id: 1003, login: "bob" }; r.namespaces = ["anything."]; }, "exactly");
rq("an organisation request with nobody asking", (r) => { r.kind = "org"; delete r.subject.org; r.namespaces = ["alice."]; }, "requested_by");
rq("a reserved login", (r) => { r.subject.login = "wolos"; r.namespaces = ["wolos."]; }, "reserved");
rq("a login that looks like a reserved one", (r) => { r.subject.login = "w0los"; r.namespaces = ["w0los."]; }, "reserved");
rq("a person requesting for someone else", (r) => { r.requested_by = { github_id: 1003, login: "bob" }; }, "for themselves");
rq("approved before it was asked", (r) => { r.approved_at = r.requested_at - 1; }, "approved_at");
rq("a short ml-kem-768 key", (r) => { r.keys["ml-kem-768"] = r.keys["ml-kem-768"].slice(1); }, "ml-kem-768");
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
# The store hubcheck checks signatures with: the TEST root, the intermediates, a revocation list the Index signed an hour ago.
mkdir -p "$work/last"
node "$here/build-revoked.mjs" --source "$fx/revocations.json" --out "$work/last/revoked.json" --now $((HUB_NOW - 3600)) >/dev/null
"$WOLTRUST_BIN" sign --purpose revocation --cert "$INDEX_SERIAL" --key-file "$keys/index.key" "$work/last/revoked.json" >"$work/last/revoked.json.wsig"
node "$here/store.mjs" --roots "$trust/roots" --intermediates "$trust/intermediates" --list "$work/last/revoked.json" --allow-test --out "$work/store.json" >/dev/null && ok "trust store for hubcheck (TEST root, 2 intermediates, a fresh list)" || bad "store"
expect_fail "a store with the TEST root outside a test" env HUB_TEST=0 DRY_RUN=0 node "$here/store.mjs" --roots "$trust/roots" --allow-test --out "$work/x.json"
HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/verdicts.json" --work "$work/scan" >"$work/scan.log"
node "$here/verdicts.mjs" clean --pending "$work/pending.json" --verdicts "$work/verdicts.json" --out "$work/clean.json" >/dev/null
HUB_TOKEN=check-token node "$here/api.mjs" verdicts --in "$work/clean.json" >/dev/null
got=$(node -e 'for (const l of require("fs").readFileSync(process.argv[1],"utf8").trim().split("\n")) { const v = JSON.parse(l); console.log(v.listing_id + " " + v.verdict + (v.findings[0] ? " " + v.findings[0].rule : "") + (v.trust ? " " + v.trust : "") + (v.cert ? " " + v.cert : "")); }' "$work/received.jsonl" | sort)
want=$'alice.notes pass listing/icon origin fd51eec17572cf6c\nalice.weather flag file/not-compressed origin fd51eec17572cf6c\ncarol.gone not-checked fetch/failed\ndave.swapped block asset/size-mismatch\nexamplelabs.notes-sync flag file/not-compressed origin 36a3609eff7d96b1\nmallory.tool block file/hash community'
[ "$got" = "$want" ] && ok "six releases, six verdicts from the real hubcheck (pass, flag, flag, block, block, not-checked; trust and cert passed on)" || { bad "verdicts differ"; diff <(echo "$want") <(echo "$got") >&2 || true; }
# a verdict for a release that was not pending, and a repeated one, never get through
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));v.verdicts.push({listing_id:"zed.other",version:"1",verdict:"pass",sha256:"a".repeat(64),findings:[]},v.verdicts[0],{...v.verdicts[1],findings:[{rule:"x",sentence:"\u0007"}]});require("fs").writeFileSync(process.argv[2],JSON.stringify(v))' "$work/verdicts.json" "$work/verdicts-extra.json"
n=$(node "$here/verdicts.mjs" clean --pending "$work/pending.json" --verdicts "$work/verdicts-extra.json" --out "$work/clean2.json" 2>/dev/null | cut -d' ' -f1)
[ "$n" = 6 ] && ok "unknown, repeated and malformed verdicts are dropped" || bad "verdict gate kept $n"
# nothing is ever decided without the real checker and its store
nopass() { node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts;process.exit(v.some(x=>x.verdict==="pass"||x.verdict==="flag")?1:0)' "$1"; }
HUBCHECK_BIN=/nonexistent HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/none.json" --work "$work/scan2" >/dev/null
nopass "$work/none.json" && ok "no hubcheck: nothing passes" || bad "pass without hubcheck"
node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/nostore.json" --work "$work/scan3" >/dev/null
nopass "$work/nostore.json" && ok "no trust store: nothing passes" || bad "pass without a store"
printf '#!/bin/sh\necho "{\\"verdict\\":\\"pass\\"}"\n' >"$work/junk-hubcheck"; printf '#!/bin/sh\nsleep 5\n' >"$work/slow-hubcheck"; printf '#!/bin/sh\necho "{\\"verdict\\":\\"pass\\",\\"findings\\":[]}"; exit 1\n' >"$work/fail-hubcheck"
chmod +x "$work"/*-hubcheck
for t in junk:check/tool-failed slow:check/timeout fail:check/tool-failed; do
    HUBCHECK_SECS=1 HUBCHECK_BIN="$work/${t%%:*}-hubcheck" HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/odd.json" --work "$work/scan4" >/dev/null
    nopass "$work/odd.json" && grep -q "${t#*:}" "$work/odd.json" && ok "a checker that ${t%%:*}s decides nothing (${t#*:})" || bad "${t%%:*} checker"
done
# the file must be the listing's: another id or another version than the release is blocked
node -e 'const f=require("fs");const p=JSON.parse(f.readFileSync(process.argv[1]));const a=p.releases.find(r=>r.listing_id==="alice.notes");const b=structuredClone(a);b.listing_id="alice.other";const c=structuredClone(a);c.version="2.0";p.releases=[b,c];f.writeFileSync(process.argv[2],JSON.stringify(p))' "$work/pending.json" "$work/pending-swap.json"
HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending-swap.json" --assets-dir "$fx/assets" --out "$work/swap.json" --work "$work/scan6" >/dev/null
[ "$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts.map(v=>v.verdict+" "+v.findings[0].rule).join(",")' "$work/swap.json")" = "block listing/id-mismatch,block listing/version-mismatch" ] && ok "a file listed under another id or version is blocked (hubcheck's file id and version)" || bad "id/version check: $(cat "$work/swap.json")"
# without a revocation list hubcheck f2bce73 keeps the rules' verdict and the signature's class, and says so in a finding
node "$here/store.mjs" --roots "$trust/roots" --intermediates "$trust/intermediates" --allow-test --out "$work/store-nolist.json" >/dev/null
HUBCHECK_STORE="$work/store-nolist.json" node "$here/check-release.mjs" --pending "$work/pending.json" --assets-dir "$fx/assets" --out "$work/nolist.json" --work "$work/scan5" >/dev/null
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts.find(x=>x.listing_id==="alice.notes");process.exit(v.verdict==="pass"&&v.findings.some(f=>f.rule==="trust/list-too-old")?0:1)' "$work/nolist.json" && ok "no revocation list: alice.notes passes the rules and the verdict says the list is too old (trust/list-too-old)" || bad "trust without a list: $(node -p 'JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts.find(x=>x.listing_id==="alice.notes"))' "$work/nolist.json")"

# 2b. The listing facts and pictures (hubcheck f2bce73: `facts` in the report, `extract` writes the pictures): the
# verdict carries the facts in the Worker's metaOf shape, the pictures go to hub-log pictures/ and from there to the CDN.
node -e 'const f=require("fs");const p=JSON.parse(f.readFileSync(process.argv[1]));const a=p.releases[0];f.writeFileSync(process.argv[2],JSON.stringify({releases:[{...a,listing_id:"bob.gallery",version:"1.0-1",tag:"v1.0-1",asset_name:"bob.gallery-1.0-1.wol",asset_url:"https://github.com/bob/gallery/releases/download/v1.0-1/bob.gallery-1.0-1.wol",size:f.statSync(process.argv[3]).size,repo:"bob/gallery",repo_id:5009,owner_id:1003}]}))' "$work/pending.json" "$work/pending-gallery.json" "$fx/assets/bob.gallery-1.0-1.wol"
HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending-gallery.json" --assets-dir "$fx/assets" --out "$work/gallery.json" --work "$work/scan7" --pictures "$work/pics" >/dev/null
gal=$(node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0];const f=v.facts||{};console.log([v.verdict,f.name,f.summary,(f.description||"").slice(0,5),f.icon&&f.icon.mime,f.icon&&f.icon.w,(f.screenshots||[]).length,f.screenshots&&f.screenshots[0].path,Object.keys(f).sort().join("+")].join("|"))' "$work/gallery.json")
[ "$gal" = "pass|Hello|A first look at your computer|Hello|image/png|512|1|screenshots/main.png|description+icon+name+screenshots+summary" ] && ok "a package with a listing: the verdict keeps hubcheck's facts (name, summary, description, icon, screenshots) in the Worker's shape" || bad "facts kept: $gal"
[ "$(ls "$work/pics" | sort | tr '\n' ' ')" = "3e0b5d9543783976039d0ab01171bb8b08c8fdc113b2891f467f6d0e7e0667f8.png 95d648d3d175b7df65af3f36caacaacc448897768f22945b5637685a8d5242f6.png " ] && ok "hubcheck extract: the icon and the screenshot are written as <sha256>.png, nothing else" || bad "pictures: $(ls "$work/pics")"
HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending-gallery.json" --assets-dir "$fx/assets" --out "$work/gallery-nopics.json" --work "$work/scan8" >/dev/null
node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0].facts;process.exit(f.name==="Hello"&&f.description&&!f.icon&&!f.screenshots?0:1)' "$work/gallery-nopics.json" && ok "without --pictures the facts keep the text and no picture reference (a listing never points at bytes the CDN lacks)" || bad "facts without pictures"
# a checker whose extract writes other bytes than the report names, and one whose extract fails: no picture reference survives
printf '#!/bin/sh\nif [ "$1" = extract ]; then "%s" "$@" >/dev/null || exit $?; for f in "$4"/*; do printf x >>"$f"; done; exit 0; fi\nexec "%s" "$@"\n' "$HUBCHECK_BIN" "$HUBCHECK_BIN" >"$work/liar-hubcheck"
printf '#!/bin/sh\nif [ "$1" = extract ]; then exit 1; fi\nexec "%s" "$@"\n' "$HUBCHECK_BIN" >"$work/noextract-hubcheck"
chmod +x "$work/liar-hubcheck" "$work/noextract-hubcheck"
for t in liar noextract; do
    rm -rf "$work/pics-$t"
    HUBCHECK_BIN="$work/$t-hubcheck" HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending-gallery.json" --assets-dir "$fx/assets" --out "$work/gallery-$t.json" --work "$work/scan9" --pictures "$work/pics-$t" >/dev/null
    node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0];process.exit(v.verdict==="pass"&&v.facts.name==="Hello"&&!v.facts.icon&&!v.facts.screenshots?0:1)' "$work/gallery-$t.json" && [ -z "$(ls "$work/pics-$t" 2>/dev/null)" ] && ok "extract with $t pictures: the verdict stays, no picture is kept or written" || bad "extract $t"
done
# a block verdict carries no facts at all
node -e 'const f=require("fs");const p=JSON.parse(f.readFileSync(process.argv[1]));p.releases[0].version="9.9";f.writeFileSync(process.argv[2],JSON.stringify(p))' "$work/pending-gallery.json" "$work/pending-gallery-ver.json"
HUBCHECK_STORE="$work/store.json" node "$here/check-release.mjs" --pending "$work/pending-gallery-ver.json" --assets-dir "$fx/assets" --out "$work/gallery-block.json" --work "$work/scan10" --pictures "$work/pics-block" >/dev/null
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0];process.exit(v.verdict==="block"&&!("facts" in v)?0:1)' "$work/gallery-block.json" && [ -z "$(ls "$work/pics-block" 2>/dev/null)" ] && ok "a blocked file (version mismatch) posts no facts and writes no picture" || bad "facts on a block"
# clean: a picture stays only when its exact bytes are in the extract folder; the bytes are copied for hub-log
node "$here/verdicts.mjs" clean --pending "$work/pending-gallery.json" --verdicts "$work/gallery.json" --out "$work/gallery-clean.json" --pictures "$work/pics" --pictures-out "$work/log-pics" | grep -q "2 picture(s)" \
    && [ "$(ls "$work/log-pics" | wc -l)" = 2 ] && node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0].facts;process.exit(f.icon&&f.screenshots.length===1?0:1)' "$work/gallery-clean.json" && ok "clean: facts and both pictures go on (2 files copied for hub-log pictures/)" || bad "clean with pictures"
cp -r "$work/pics" "$work/pics-bad"; printf x >>"$work/pics-bad/95d648d3d175b7df65af3f36caacaacc448897768f22945b5637685a8d5242f6.png"
node "$here/verdicts.mjs" clean --pending "$work/pending-gallery.json" --verdicts "$work/gallery.json" --out "$work/gallery-clean2.json" --pictures "$work/pics-bad" --pictures-out "$work/log-pics2" >/dev/null
node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0].facts;process.exit(!f.icon&&f.screenshots.length===1&&f.name==="Hello"?0:1)' "$work/gallery-clean2.json" && [ "$(ls "$work/log-pics2" | wc -l)" = 1 ] && ok "clean: a picture whose bytes changed on the way is dropped, the rest stays" || bad "clean with a changed picture"
node "$here/verdicts.mjs" clean --pending "$work/pending-gallery.json" --verdicts "$work/gallery.json" --out "$work/gallery-clean3.json" >/dev/null
node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0].facts;process.exit(!f.icon&&!f.screenshots&&f.name==="Hello"?0:1)' "$work/gallery-clean3.json" && ok "clean without a picture folder: text facts only" || bad "clean without pictures"
# a verdict with a hostile fact (a path with a control character, a 5 MiB picture, 9 screenshots, a huge description) loses only that fact
node -e 'const f=require("fs");const g=JSON.parse(f.readFileSync(process.argv[1]));const v=g.verdicts[0];const pic=v.facts.icon;v.facts.icon={...pic,path:"a\nb"};v.facts.screenshots=Array(9).fill(v.facts.screenshots[0]);v.facts.description="x".repeat(4001);v.facts.summary="one\ntwo";f.writeFileSync(process.argv[2],JSON.stringify(g))' "$work/gallery.json" "$work/gallery-hostile.json"
node "$here/verdicts.mjs" clean --pending "$work/pending-gallery.json" --verdicts "$work/gallery-hostile.json" --out "$work/gallery-clean4.json" --pictures "$work/pics" >/dev/null
node -e 'const f=JSON.parse(require("fs").readFileSync(process.argv[1])).verdicts[0].facts;process.exit(f.name==="Hello"&&!f.icon&&!f.description&&!f.summary&&f.screenshots.length===8?0:1)' "$work/gallery-clean4.json" && ok "clean: a malformed fact (control character, over a limit) is left out, nine screenshots are cut to the Worker's eight, the verdict and the other facts stay" || bad "hostile facts: $(cat "$work/gallery-clean4.json")"
# the mock Worker takes what the real one takes (its metaOf), so the whole chain is exercised
HUB_TOKEN=check-token node "$here/api.mjs" verdicts --in "$work/gallery-clean.json" >/dev/null && tail -n1 "$work/received.jsonl" | node -e 'const v=JSON.parse(require("fs").readFileSync(0,"utf8"));process.exit(v.listing_id==="bob.gallery"&&v.facts.icon.sha256.length===64?0:1)' && ok "the check token posts the verdict with its facts" || bad "post with facts"
node --input-type=module -e 'const {batches}=await import(process.argv[1]);const v=Array.from({length:250},(_,i)=>({listing_id:"a.b"+i,version:"1",verdict:"pass",facts:{description:"x".repeat(i<100?100:4000)}}));const b=batches(v);const sizes=b.map(x=>Buffer.byteLength(JSON.stringify({verdicts:x})));process.exit(b.flat().length===250&&b.every(x=>x.length<=100)&&sizes.every(n=>n<256*1024)&&b.length>=4?0:1)' "file://$here/api.mjs" && ok "api.mjs cuts verdicts into calls under the Worker's 100 entries and 256 KiB (facts make a verdict big)" || bad "verdict batches"
# the sign job: pictures named by the export are staged from hub-log pictures/ with their hash checked again
node -e 'const f=require("fs");const v=JSON.parse(f.readFileSync(process.argv[1])).verdicts[0].facts;const view=(p)=>({sha256:p.sha256,mime:p.mime,w:p.w,h:p.h,size:p.size,file:p.sha256+"."+(p.mime==="image/png"?"png":"webp")});f.writeFileSync(process.argv[2],JSON.stringify({apps:[{id:"bob.gallery",icon:view(v.icon),screenshots:v.screenshots.map(view)}],plugins:[{id:"zed.nopic"},{id:"zed.missing",icon:{sha256:"b".repeat(64),mime:"image/png",w:128,h:128,size:100,file:"b".repeat(64)+".png"}}],extensions:[]}))' "$work/gallery-clean.json" "$work/export-pics.json"
node "$here/pictures.mjs" stage --export "$work/export-pics.json" --from "$work/log-pics" --out "$work/stage" 2>"$work/stage.err" | grep -q "^2 picture(s) staged" && [ "$(ls "$work/stage" | wc -l)" = 2 ] && grep -q "zed.missing" "$work/stage.err" && ok "pictures.mjs stage: both pictures staged for the CDN, a missing one named and left out" || bad "stage: $(cat "$work/stage.err")"
cp -r "$work/log-pics" "$work/log-pics3"; printf x >>"$work/log-pics3/3e0b5d9543783976039d0ab01171bb8b08c8fdc113b2891f467f6d0e7e0667f8.png"
node "$here/pictures.mjs" stage --export "$work/export-pics.json" --from "$work/log-pics3" --out "$work/stage2" 2>/dev/null | grep -q "^1 picture(s) staged" && ok "pictures.mjs stage: a picture whose bytes differ from the reference is not staged" || bad "stage with a changed picture"

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
printf '{"version":"0.13.0","kernel":"7.0.0"}\n' >"$out/release.json"
"$here/sign-files.sh" "$out" "$INDEX_SERIAL" >/dev/null && ok "signed by the real woltrust: .sig (legacy), .wsig (hybrid), revoked.json.wsig, both verified" || bad "signing"
# trust phase 4 (woltrust 68b5a03): the revocation database, its checkpoint, the intermediates file, the release manifest signature
"$WOLTRUST_BIN" rkdb verify --roots "$trust/roots" --intermediates "$trust/intermediates" --allow-test --now "$HUB_NOW" "$out/revoked.rkdb" >"$work/rkdb.txt" && grep -q '^serial 1 ' "$work/rkdb.txt" && grep -q 'entries 1$' "$work/rkdb.txt" && ok "revoked.rkdb: serial 1, 1 entry, verifies through the TEST root ($(head -n1 "$work/rkdb.txt"))" || bad "revoked.rkdb: $(cat "$work/rkdb.txt")"
cp_want=$("$WOLTRUST_BIN" rkdb checkpoint "$out/revoked.rkdb")
[ "$(cat "$out/revoked.checkpoint.json")" = "$cp_want" ] && node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(c.format===1&&c.serial===1&&/^[0-9a-f]{64}$/.test(c.sha512_256)&&Object.keys(c).length===3?0:1)' "$out/revoked.checkpoint.json" && ok "revoked.checkpoint.json is {format:1, serial:1, sha512_256} of that database" || bad "checkpoint: $(cat "$out/revoked.checkpoint.json")"
[ "$(node -p 'const a=require(process.argv[1]);Array.isArray(a)&&a.length===2&&a.every(c=>c.format===1&&typeof c.body==="string")' "$out/intermediates.json")" = true ] && ok "intermediates.json: a JSON array of the 2 TEST intermediates (.wolcert objects)" || bad "intermediates.json"
# the next database follows this one: serial 2, every entry kept, a delta exists; a database that does not follow is refused
mkdir -p "$work/next"; cp "$out/revoked.json" "$work/next/"; node -e 'const f=require("fs"),p=process.argv[1];const l=JSON.parse(f.readFileSync(p));l.entries.push({serial:"c0c0000000000001",at:1793700000,reason:"abuse"});l.serial=2;f.writeFileSync(p,JSON.stringify(l))' "$work/next/revoked.json"
"$WOLTRUST_BIN" rkdb make --source "$work/next/revoked.json" --previous "$out/revoked.rkdb" --now "$HUB_NOW" --cert "$INDEX_SERIAL" --key-file "$keys/index.key" >"$work/next/revoked.rkdb"
"$WOLTRUST_BIN" rkdb verify --roots "$trust/roots" --intermediates "$trust/intermediates" --allow-test --now "$HUB_NOW" "$work/next/revoked.rkdb" | grep -q '^serial 2 .* entries 2$' && "$WOLTRUST_BIN" rkdb delta "$out/revoked.rkdb" "$work/next/revoked.rkdb" >/dev/null && ok "the next database follows (serial 2, 2 entries, delta from serial 1)" || bad "rkdb chain"
expect_fail "a database behind the floor" "$WOLTRUST_BIN" rkdb verify --roots "$trust/roots" --intermediates "$trust/intermediates" --allow-test --now "$HUB_NOW" --floor 5 "$out/revoked.rkdb"
# an emergency section is carried inside the database when it is beside the list
"$WOLTRUST_BIN" rkdb make --source "$out/revoked.json" --root-section "$out/revoked.json" --now "$HUB_NOW" --cert "$INDEX_SERIAL" --key-file "$keys/index.key" >/dev/null 2>&1 && bad "a file that is not a root section was taken as one" || ok "rkdb make refuses an emergency.rkdr that is not a root-signed section"
expect_fail "a dry run signing as another certificate" "$here/sign-files.sh" "$out" 7e57000000000001
verify() { "$WOLTRUST_BIN" verify --purpose "$1" --wsig "$2" --roots "$trust/roots" --intermediates "$trust/intermediates" --list "$3" --allow-test --now "$HUB_NOW" "$4" >"$work/verify.json"; }
verify index "$out/index.json.wsig" "$out/revoked.json" "$out/index.json" && grep -q '"trust":"wolos"' "$work/verify.json" && ok "woltrust verify: index.json is signed by the TEST Index intermediate ($INDEX_SERIAL)" || bad "index.json.wsig: $(cat "$work/verify.json")"
verify revocation "$out/revoked.json.wsig" "$out/revoked.json" "$out/revoked.json" && ok "woltrust verify: revoked.json too" || bad "revoked.json.wsig: $(cat "$work/verify.json")"
verify index "$out/release.json.wsig" "$out/revoked.json" "$out/release.json" && ok "release.json.wsig: the Index signed the release manifest (label wolos/index/1)" || bad "release.json.wsig: $(cat "$work/verify.json")"
expect_fail "woltrust verify without --allow-test (the TEST root never counts)" "$WOLTRUST_BIN" verify --purpose index --wsig "$out/index.json.wsig" --roots "$trust/roots" --intermediates "$trust/intermediates" --list "$out/revoked.json" --now "$HUB_NOW" "$out/index.json"
"$WOLTRUST_BIN" revoke --source "$fx/revocations.json" --now "$HUB_NOW" >"$work/rev-woltrust.json"
node "$here/build-revoked.mjs" --source "$fx/revocations.json" --now "$HUB_NOW" --out "$work/rev-node.json" >/dev/null
node -e 'const f=require("fs");const a=JSON.parse(f.readFileSync(process.argv[1])),b=JSON.parse(f.readFileSync(process.argv[2]));process.exit(JSON.stringify(a)===JSON.stringify(b)?0:1)' "$work/rev-woltrust.json" "$work/rev-node.json" && ok "build-revoked.mjs makes the list woltrust revoke makes" || bad "build-revoked differs from woltrust revoke"
cp "$out/index.json" "$work/index2.json"; node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --previous "$fx/previous-index.json" --out "$work/index2.json" >/dev/null
cmp -s "$out/index.json" "$work/index2.json" && ok "the same export gives the same bytes" || bad "index not reproducible"
node "$here/legacy-check.mjs" "$out/index.json" "$out/index.json.sig" "$(cat "$keys/legacy.pub.hex")" && ok "a 0.12 reader would verify and keep the entries" || bad "0.12 compatibility"
mkdir -p "$work/prev"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == yes* ]] && ok "first publication: $r" || bad "needs-publish first: $r"
cp "$out"/* "$work/prev/"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == no* ]] && ok "unchanged and recent: $r" || bad "needs-publish unchanged: $r"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev" --now $((HUB_NOW + 86400))); [[ $r == yes* ]] && ok "a day later: $r" || bad "needs-publish day: $r"
cp "$out/revoked.json" "$work/prev/revoked.json"; node -e 'const f=require("fs"),p=process.argv[1];const l=JSON.parse(f.readFileSync(p));l.entries.push({serial:"c0c0000000000001",at:1,reason:"abuse"});f.writeFileSync(p,JSON.stringify(l))' "$work/prev/revoked.json"
r=$(node "$here/needs-publish.mjs" --index "$out/index.json" --revoked "$out/revoked.json" --previous "$work/prev"); [[ $r == yes* ]] && ok "revocations changed: $r" || bad "needs-publish revoked: $r"
"$here/publish.sh" "$out" >"$work/publish.txt" && grep -q 'to plugins/revoked.rkdb ' "$work/publish.txt" && grep -q 'to plugins/revoked.checkpoint.json ' "$work/publish.txt" && grep -q 'to plugins/intermediates.json ' "$work/publish.txt" && grep -q 'to latest/release.json.wsig ' "$work/publish.txt" && [ "$(tail -n1 "$work/publish.txt" | grep -c 'release.json.wsig')" = 1 ] && [ "$(grep -c 'to plugins/index.json ' "$work/publish.txt")" = 1 ] && ok "upload plan (dry run): the database, checkpoint, intermediates, release signature (latest/) and the index" || bad "publish dry run: $(cat "$work/publish.txt")"
# the pictures go first, as <sha256>.png|webp under plugins/pictures/; any other name in that folder stops the upload
rm -rf "$work/out-pics"; cp -r "$out" "$work/out-pics"; cp -r "$work/stage" "$work/out-pics/pictures"
DRY_RUN=1 "$here/publish.sh" "$work/out-pics" >"$work/publish-pics.txt" && [ "$(grep -c 'to plugins/pictures/[0-9a-f]\{64\}\.png ' "$work/publish-pics.txt")" = 2 ] && [ "$(grep -n 'plugins/pictures/' "$work/publish-pics.txt" | tail -n1 | cut -d: -f1)" = 2 ] && ok "upload plan (dry run): the 2 pictures go to plugins/pictures/<sha256>.png before everything else" || bad "publish pictures: $(cat "$work/publish-pics.txt")"
echo x >"$work/out-pics/pictures/notes.txt"
expect_fail "publish.sh with a file in pictures/ that is not <sha256>.png|webp" env DRY_RUN=1 "$here/publish.sh" "$work/out-pics"
expect_fail "commit-log refuses a path outside the published ones" env HUB_LOG_DIR=/nonexistent "$here/commit-log.sh" "x" README.md
# the checkpoint is published at the root of the log too (cdn.rs RKDB_CHECKPOINTS); commit-log.sh lets it through
( cd "$work" && rm -rf logck && git init -q logck && cd logck && git remote add origin git@github.com:wonderlandos/hub-log.git && printf '{}' >revoked.checkpoint.json && GIT_SSH_COMMAND=false HUB_LOG_DIR=. "$here/commit-log.sh" "ck" revoked.checkpoint.json >/dev/null 2>&1; [ "$(git -C "$work/logck" log -1 --format=%s 2>/dev/null)" = ck ] ) && ok "commit-log.sh takes revoked.checkpoint.json at the root (committed; only the push to GitHub is missing here)" || bad "commit-log checkpoint path"
# a tampered file or a missing signature must not pass the 0.12 check, nor woltrust
sed 's/"serial": 42/"serial": 43/' "$out/index.json" >"$work/tampered.json"
expect_fail "a changed index does not verify (0.12 reader)" node "$here/legacy-check.mjs" "$work/tampered.json" "$out/index.json.sig" "$(cat "$keys/legacy.pub.hex")"
expect_fail "a changed index does not verify (woltrust)" verify index "$out/index.json.wsig" "$out/revoked.json" "$work/tampered.json"
# the committed sample is exactly what this run signed (deterministic signatures), and it verifies on its own
if [ -z "${SAMPLE_OUT:-}" ]; then
    same=1; for f in index.json index.json.sig index.json.wsig revoked.json revoked.json.wsig revoked.rkdb revoked.checkpoint.json; do cmp -s "$out/$f" "$fx/sample-signed/$f" || same=0; done
    [ $same = 1 ] && ok "fixtures/sample-signed is byte for byte what this run signed" || bad "fixtures/sample-signed is stale: SAMPLE_OUT=fixtures/sample-signed scripts/test.sh"
    verify index "$fx/sample-signed/index.json.wsig" "$fx/sample-signed/revoked.json" "$fx/sample-signed/index.json" && ok "the sample index verifies in woltrust" || bad "sample index: $(cat "$work/verify.json")"
fi
# Release statements (TRUST-core-4 shape, chat 7293): bodies and index references now; signing waits for the woltrust that has
# --purpose release (tools/woltrust.features), so the sign step refuses rather than publish an index pointing at nothing.
st=$work/st; mkdir -p "$st/out"
node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --statements "$st/out/statements" --statements-url https://cdn.wolos.org/plugins/statements --out "$st/out/index.json" >/dev/null && node "$here/validate.mjs" index "$st/out/index.json" >/dev/null && ok "index with release statement references is valid" || bad "statements index"
node --input-type=module - "$here" "$st/out" <<'JS' && ok "one statement body per listed version, the frozen shape, serials matching the index" || bad "statement bodies"
import { readFileSync } from "node:fs";
const [, , here, dir] = process.argv;
const { statementSerial, assemble } = await import(`${here}/statements.mjs`);
const idx = JSON.parse(readFileSync(`${dir}/index.json`, "utf8"));
const kinds = { apps: "package", plugins: "plugin", extensions: "extension" };
let n = 0;
for (const [list, kind] of Object.entries(kinds)) for (const e of idx[list]) {
  const raw = readFileSync(`${dir}/statements/${e.id}/${e.version}.body.json`);
  const b = JSON.parse(raw);
  const keys = Object.keys(b).join(",");
  const want = ["format", "serial", "sha256", "id", "version", "kind", ...(b.origin ? ["origin"] : []), "verdict", "findings", "checked_at", ...(b.cert ? ["cert"] : [])].join(",");
  if (keys !== want || b.format !== 1 || b.kind !== kind || b.sha256 !== e.sha256 || b.cert !== e.cert || b.findings !== e.findings.length) throw new Error(`${e.id}: ${keys}`);
  if (b.serial !== e.statement.serial || b.serial !== statementSerial(e.id, e.version, e.sha256) || e.statement.url !== `https://cdn.wolos.org/plugins/statements/${e.id}/${e.version}.wsig`) throw new Error(`${e.id}: serial or url`);
  const f = JSON.parse(assemble(raw, { cert: "0e972272c2e22af3", ed25519: "e", second: "s" }));
  if (Object.keys(f).join(",") !== "format,body,cert,sig" || !Buffer.from(f.body, "base64url").equals(raw)) throw new Error("file shape");
  n++;
}
if (n !== 3) throw new Error(`${n} statements`);
JS
cp "$out/revoked.json" "$st/out/"
expect_fail "statements are not signed while the pinned woltrust cannot (tools/woltrust.features)" "$here/sign-files.sh" "$st/out" "$INDEX_SERIAL"
expect_fail "...and woltrust 68b5a03 itself has no --purpose release" env WOLTRUST_FEATURES=statements "$here/sign-files.sh" "$st/out" "$INDEX_SERIAL"
[ ! -e "$st/out/index.json.wsig" ] && ok "so the index that points at statements was never signed" || bad "an index with unsigned statements was signed"

# a half-empty export must not empty the index
node -e 'const f=require("fs");const e=JSON.parse(f.readFileSync(process.argv[1]));const p={format:1,serial:41,issued:1,expires:2,apps:[],plugins:[],extensions:[]};for(let i=0;i<8;i++){const x=structuredClone(e.apps[0]);x.id="alice.a"+i;p.apps.push(x)}f.writeFileSync(process.argv[2],JSON.stringify(p))' "$fx/export.json" "$work/big-prev.json"
expect_fail "an index that lost most of its entries" node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --previous "$work/big-prev.json" --out "$work/x.json"

# 4. The ca workflow: an approved request fetched from the Worker by id, issued by the real woltrust with the TEST
#    Authors CA, the certificate reported back; then revocation.
ca=$work/ca; mkdir -p "$ca/requests" "$ca/certs" "$ca/approved"; cp "$fx/request-revoke.json" "$ca/requests/"
cp "$fx/request-issue.json" "$ca/approved/r-0001.json"; cp "$fx/request-origin.json" "$ca/approved/r-0002.json"
kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
node "$here/mock-hub.mjs" --port 18787 --pending "$fx/pending.json" --export "$fx/export.json" --received "$work/received-ca.jsonl" --requests "$ca/approved" >"$work/mock-ca.log" &
mock_pid=$!
for _ in $(seq 1 50); do curl -fs -o /dev/null -H 'Authorization: Bearer ca-token' "$HUB_API/api/pipeline/requests/r-0001" 2>/dev/null && break; sleep 0.1; done
expect_fail "the check token cannot read requests" env HUB_TOKEN=check-token node "$here/api.mjs" request --id r-0001 --out "$work/x.json"
expect_fail "an id that is not a request id" env HUB_TOKEN=ca-token node "$here/api.mjs" request --id ../pending --out "$work/x.json"
expect_fail "a request the Worker does not have" env HUB_TOKEN=ca-token node "$here/api.mjs" request --id r-9999 --out "$work/x.json"
HUB_TOKEN=ca-token node "$here/api.mjs" request --id r-0001 --out "$ca/requests/r-0001.json" >/dev/null && node "$here/validate.mjs" request "$ca/requests/r-0001.json" >/dev/null && ok "approved request r-0001 fetched from the Worker and valid" || bad "fetch request"
export WOLTRUST=$WOLTRUST_BIN
issue() { node "$here/ca.mjs" issue --github-fixture "$fx/github.json" --certs "$ca/certs" --issuer-serial "$AUTHORS_SERIAL" --key-file "$keys/authors.key" --intermediates "$trust/intermediates" --source "$ca/revocations.json" "$@"; }
cp "$ca/requests/r-0001.json" "$work/r-0001.json"
expect_fail "an approver who is not a CA approver" issue --request "$work/r-0001.json" --approvers dave
expect_fail "nobody may approve (CA_APPROVERS empty)" issue --request "$work/r-0001.json" --approvers ""
expect_fail "a trusted certificate without the approver list" issue --request "$work/r-0001.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.proof.second=r.proof.second.replace(/^./,c=>c==="A"?"B":"A");f.writeFileSync(process.argv[2],JSON.stringify(r))' "$work/r-0001.json" "$work/bad-proof.json"
expect_fail "a proof of possession that does not verify (woltrust issue --proof)" issue --request "$work/bad-proof.json" --approvers carol-ca
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.subject.github_id=1002;f.writeFileSync(process.argv[2],JSON.stringify(r))' "$work/r-0001.json" "$work/other-id.json"
expect_fail "a proof made for another GitHub account" issue --request "$work/other-id.json" --approvers carol-ca
expect_fail "the wrong CA key" node "$here/ca.mjs" issue --github-fixture "$fx/github.json" --request "$work/r-0001.json" --certs "$ca/certs" --issuer-serial "$AUTHORS_SERIAL" --key-file "$keys/index.key" --intermediates "$trust/intermediates" --approvers carol-ca
# audit-1 H2: what is signed comes from the signed request and from GitHub, never from the Worker's record
squat() { node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));Object.assign(r.subject,JSON.parse(process.argv[2]));if(process.argv[3])r.namespaces=JSON.parse(process.argv[3]);f.writeFileSync(process.argv[4],JSON.stringify(r))' "$work/r-0001.json" "$1" "$2" "$3"; }
squat '{"login":"mozilla"}' '["mozilla."]' "$work/squat.json"
issue --request "$work/squat.json" --approvers carol-ca >"$work/h2.log" 2>&1 || true; grep -q "GitHub id 1001 is alice" "$work/h2.log" && ok "a login the Worker put in that GitHub does not give for the signed id is refused (squatting)" || bad "login squat: $(cat "$work/h2.log")"
squat '{"github_id":4321}' '' "$work/squat2.json"
issue --request "$work/squat2.json" --approvers carol-ca >"$work/h2.log" 2>&1 || true; grep -q "GitHub knows no user with id 4321" "$work/h2.log" && ok "a GitHub id GitHub does not know is refused" || bad "unknown id: $(cat "$work/h2.log")"
squat '{"github_id":1004,"login":"a1ice"}' '["a1ice."]' "$work/confusable.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.requested_by={github_id:1001,login:"alice"};f.writeFileSync(process.argv[2],JSON.stringify(r))' "$fx/request-org.json" "$work/org-by-member.json"
expect_fail "an organisation certificate asked by a member who is not an owner" issue --request "$work/org-by-member.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.requested_by={github_id:1006,login:"bob"};f.writeFileSync(process.argv[2],JSON.stringify(r))' "$fx/request-org.json" "$work/org-by-liar.json"
expect_fail "an organisation certificate whose asker is not the GitHub id given" issue --request "$work/org-by-liar.json"
CA_MJS="$here/ca.mjs" GH_MJS="$here/github-identity.mjs" GH="$fx/github.json" REQ="$work/r-0001.json" node --input-type=module -e '
const { resolveIdentity } = await import(process.env.CA_MJS);
const { githubIdentity } = await import(process.env.GH_MJS);
const gh = githubIdentity(process.env.GH);
const r = JSON.parse((await import("node:fs")).readFileSync(process.env.REQ));
const a = await resolveIdentity({ ...r, subject: { ...r.subject, name: "Microsoft Corporation" } }, gh);
const c = await resolveIdentity({ ...r, subject: { github_id: 1005, login: "carol", name: "x" }, namespaces: ["carol."] }, gh);
const d = await resolveIdentity({ ...r, subject: { github_id: 1006, login: "dave", name: "x", org: { github_id: 2002, login: "examplelabs" } }, namespaces: ["dave."] }, gh);
process.exit(a.subject.name === "Alice Example" && c.subject.name === "carol" && !d.subject.org && a.subject.org?.login === "examplelabs" ? 0 : 1);' && ok "name from GitHub (not the request), a bidi-spoofed GitHub name falls back to the login, an organisation only when GitHub shows the membership" || bad "identity from GitHub"
[ -z "$(ls "$ca/certs")" ] && ok "nothing was written by the refused requests" || bad "a refused request left a certificate"
# class (woltrust 68b5a03 reads it): a trusted certificate stands on the subject's origin certificate, so origin comes first.
expect_fail "a trusted certificate before the subject's origin certificate" issue --request "$ca/requests/r-0001.json" --approvers carol-ca
# The origin tier: issued on the CLA alone, no approver; one active origin certificate per account.
HUB_TOKEN=ca-token node "$here/api.mjs" request --id r-0002 --out "$ca/requests/r-0002.json" >/dev/null || bad "fetch origin request"
issue --request "$ca/requests/r-0002.json" --result "$work/issued-origin.json" --archive >"$work/issue-origin.log" && grep -q "person, origin" "$work/issue-origin.log" && ok "origin certificate issued without an approval: $(cut -d' ' -f2 "$work/issue-origin.log" | cut -c1-16)…" || bad "origin issue: $(cat "$work/issue-origin.log")"
oserial=$(cut -d' ' -f2 "$work/issue-origin.log")
[ "$oserial" = "$(node -e 'import("'"$here"'/lib.mjs").then(m=>process.stdout.write(m.keyId(JSON.parse(require("fs").readFileSync(process.argv[1])).keys)))' "$ca/requests/done/r-0002.json")" ] && [ ${#oserial} = 128 ] && ok "the certificate id is SHA-512 over the request's keys (rule IDS, 128 hex)" || bad "derived id: $oserial"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.origin_cert="0".repeat(128);f.writeFileSync(process.argv[2],JSON.stringify(r))' "$ca/requests/r-0001.json" "$work/wrong-origin.json"
expect_fail "a trusted request naming another origin certificate than the subject's" issue --request "$work/wrong-origin.json" --approvers carol-ca
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.origin_cert=process.argv[2];f.writeFileSync(process.argv[1],JSON.stringify(r,null,2)+"\n")' "$ca/requests/r-0001.json" "$oserial"
node "$here/validate.mjs" request "$ca/requests/r-0001.json" >/dev/null && ok "an issue request with origin_cert (the Worker's record) is valid" || bad "origin_cert in the schema"
issue --request "$ca/requests/r-0001.json" --approvers "carol-ca, erin" --result "$work/issued.json" --archive >"$work/issue.log" && ok "trusted certificate issued by woltrust: $(cut -d' ' -f2 "$work/issue.log" | cut -c1-16)…" || bad "issue: $(cat "$work/issue.log")"
serial=$(cut -d' ' -f2 "$work/issue.log")
[ -f "$ca/certs/$serial.wolcert" ] && [ -f "$ca/requests/done/r-0001.json" ] && ok "certificate written, request archived" || bad "issue files"
node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));const b=JSON.parse(Buffer.from(c.body,"base64url"));const k=b.keys;process.exit(k.x25519&&k["ml-kem-768"]&&b.verified_at===1793750400&&b.subject.org?.login==="examplelabs"&&b.subject.name==="Alice Example"&&JSON.stringify(b.namespaces)==="[\"alice.\"]"&&b.issuer===process.argv[2]&&b.class==="trusted"&&b.origin_cert===process.argv[3]?0:1)' "$ca/certs/$serial.wolcert" "$AUTHORS_SERIAL" "$oserial" && ok "the body carries x25519, ml-kem-768, verified_at, subject.org, class trusted and origin_cert" || bad "certificate body"
HUB_TOKEN=ca-token node "$here/api.mjs" issued --in "$work/issued.json" >/dev/null && grep -q "\"serial\":\"$serial\",\"tier\":\"trusted\"" "$work/received-ca.jsonl" && ok "the Worker was told: r-0001 -> trusted certificate" || bad "issued not posted"
node -e 'const f=require("fs");const a=JSON.parse(f.readFileSync(process.argv[1]+"/"+process.argv[2]+".json")),b=JSON.parse(f.readFileSync(process.argv[1]+"/"+process.argv[3]+".json"));process.exit(a.tier==="trusted"&&a.approved_by[0]==="carol-ca"&&b.tier==="origin"&&b.cla_accepted_at===1793690000?0:1)' "$ca/certs" "$serial" "$oserial" && ok "certs/<serial>.json records the tier (trusted: approved_by; origin: cla_accepted_at)" || bad "tier records"
HUB_TOKEN=ca-token node "$here/api.mjs" issued --in "$work/issued-origin.json" >/dev/null && grep -q "\"serial\":\"$oserial\",\"tier\":\"origin\"" "$work/received-ca.jsonl" && ok "the Worker was told: r-0002 -> origin certificate" || bad "origin issued not posted"
expect_fail "a second origin certificate for the same account" issue --request "$ca/requests/done/r-0002.json"
# The index shows the tier: a file signed with the origin certificate is origin, one signed with the trusted one verified.
node -e 'const f=require("fs");const e=JSON.parse(f.readFileSync(process.argv[1]));e.apps[0].cert=process.argv[2];e.plugins[0].cert=process.argv[3];f.writeFileSync(process.argv[4],JSON.stringify(e))' "$work/export.checked.json" "$serial" "$oserial" "$work/export-tiers.json"
tiers() { node "$here/build-index.mjs" --export "$work/export-tiers.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --certs "$ca/certs" --revocations "$1" --out "$work/index-tiers.json" >/dev/null && node -p 'const i=require(process.argv[1]);i.apps[0].trust+" "+i.plugins[0].trust' "$work/index-tiers.json"; }
[ "$(tiers "$ca/none.json")" = "trusted origin" ] && ok "index: trusted certificate -> trusted, origin certificate -> origin" || bad "index tiers: $(tiers "$ca/none.json")"
node -e 'require("fs").writeFileSync(process.argv[2],JSON.stringify({format:1,entries:[{serial:process.argv[1],at:1793745000,reason:"superseded"}]}))' "$serial" "$work/rev-superseded.json"
[ "$(tiers "$work/rev-superseded.json")" = "origin origin" ] && ok "a trusted certificate revoked as superseded is downgraded: its files show as origin" || bad "downgrade: $(tiers "$work/rev-superseded.json")"
# the new certificate works: a file its owner signs verifies as verified through the chain, inside alice.
node -e 'import("'"$here"'/test-keys.mjs").then(m=>process.stdout.write(m.testKeyText("hub-index-request-alice")))' >"$keys/alice.key"
printf 'a release\n' >"$work/release.bin"
"$WOLTRUST_BIN" sign --purpose package --cert "$serial" --key-file "$keys/alice.key" "$work/release.bin" >"$work/release.wsig"
node -e 'const f=require("fs");f.writeFileSync(process.argv[3],JSON.stringify([JSON.parse(f.readFileSync(process.argv[1])),JSON.parse(f.readFileSync(process.argv[2]))]))' "$ca/certs/$serial.wolcert" "$trust/intermediates/test-authors.wolcert" "$work/chain.json"
vpkg() { "$WOLTRUST_BIN" verify --purpose package --wsig "$work/release.wsig" --chain "$work/chain.json" --roots "$trust/roots" --intermediates "$trust/intermediates" --list "$1" --id "$2" --allow-test --now "$HUB_NOW" "$work/release.bin" >"$work/verify.json"; }
vpkg "$out/revoked.json" alice.notes && grep -q '"trust":"trusted"' "$work/verify.json" && grep -q '"class":"trusted"' "$work/verify.json" && ok "a file signed with the new certificate verifies (trusted, class in the report, alice.)" || bad "new certificate: $(cat "$work/verify.json")"
expect_fail "...but not for an id outside alice." vpkg "$out/revoked.json" bob.notes
expect_fail "a second certificate for the same account" issue --request "$ca/requests/done/r-0001.json" --approvers carol-ca
issue --request "$work/confusable.json" --approvers carol-ca >"$work/h2.log" 2>&1 || true; grep -q "looks like alice." "$work/h2.log" && ok "a look-alike of an issued namespace (a1ice. vs alice.) is refused" || bad "confusable: $(cat "$work/h2.log")"
cp "$fx/request-org.json" "$ca/requests/r-0003.json"
issue --request "$ca/requests/r-0003.json" >"$work/org.log" 2>&1 && grep -q "examplelabs (org, origin), namespaces examplelabs." "$work/org.log" && ok "an organisation certificate, asked by its owner on GitHub: examplelabs." || bad "org issue: $(cat "$work/org.log")"
expect_fail "revoking a serial that was never issued" node "$here/ca.mjs" revoke --approvers carol-ca --request "$ca/requests/request-revoke.json" --certs "$ca/certs" --source "$ca/revocations.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.serial=process.argv[2];r.reason="key-compromise";f.writeFileSync(process.argv[3],JSON.stringify(r))' "$fx/request-revoke.json" "$serial" "$ca/requests/revoke-issued.json"
node "$here/ca.mjs" revoke --approvers carol-ca --request "$ca/requests/revoke-issued.json" --certs "$ca/certs" --source "$ca/revocations.json" >/dev/null && ok "revocation appended to revocations.json" || bad "revoke"
node "$here/build-revoked.mjs" --source "$ca/revocations.json" --out "$work/rev2.json" >/dev/null && grep -q "$serial" "$work/rev2.json" && ok "...and it is in the next revoked.json" || bad "revocation not propagated"
node -e 'const f=require("fs");const s=JSON.parse(f.readFileSync(process.argv[1]));process.exit(s.entries.find(e=>e.serial===process.argv[2]).at===Number(process.argv[3])?0:1)' "$ca/revocations.json" "$serial" "$HUB_NOW" && ok "the revocation time is the job's clock, not the request's at" || bad "revocation at from the request"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.serial=process.argv[2];r.reason="abuse";r.approved_by=["carol-ca","erin"];f.writeFileSync(process.argv[3],JSON.stringify(r))' "$fx/request-revoke.json" "$oserial" "$work/abuse.json"
expect_fail "a revocation approved by someone who is not a CA approver" node "$here/ca.mjs" revoke --approvers carol-ca --request "$work/abuse.json" --certs "$ca/certs" --source "$ca/revocations.json"
node -e 'const f=require("fs");const r=JSON.parse(f.readFileSync(process.argv[1]));r.approved_by=["carol-ca"];f.writeFileSync(process.argv[1],JSON.stringify(r))' "$work/abuse.json"
expect_fail "abuse with one approver" node "$here/ca.mjs" revoke --approvers carol-ca,erin --request "$work/abuse.json" --certs "$ca/certs" --source "$ca/revocations.json"
"$WOLTRUST_BIN" sign --purpose revocation --cert "$INDEX_SERIAL" --key-file "$keys/index.key" "$work/rev2.json" >"$work/rev2.json.wsig"
vpkg "$work/rev2.json" alice.notes || true; grep -q '"trust":"withdrawn"' "$work/verify.json" && ok "...which withdraws the file signed with it (woltrust verify)" || bad "revoked certificate still trusted: $(cat "$work/verify.json")"
[ "$(tiers "$ca/revocations.json")" = "trusted origin" ] && ok "key-compromise is no downgrade: the index is unchanged and woltrust withdraws the signatures, as before" || bad "key-compromise tiers: $(tiers "$ca/revocations.json")"
issue --request "$ca/requests/done/r-0001.json" --approvers carol-ca >"$work/reissue.log" 2>&1 || true; grep -q "new keys" "$work/reissue.log" && ok "after a key-compromise the same keys get no new certificate (the id is the keys): new keys needed" || bad "re-issue with revoked keys: $(cat "$work/reissue.log")"
# A revocation the hub approved (HUB-worker-3's withdraw): fetched by its v- id, published, reported back.
node -e 'const f=require("fs");f.writeFileSync(process.argv[3],JSON.stringify({format:1,action:"revoke",id:"v-0007",serial:process.argv[1],reason:"ceased",approved_by:["carol-ca"],note:"left the project"}))' "$oserial" x "$ca/approved/v-0007.json"
HUB_TOKEN=ca-token node "$here/api.mjs" request --id v-0007 --out "$ca/requests/v-0007.json" >/dev/null && node "$here/validate.mjs" request "$ca/requests/v-0007.json" >/dev/null && ok "revocation v-0007 fetched from the Worker by its id and valid (id, note in the schema)" || bad "fetch revocation"
expect_fail "an issue id answered with a revocation" env HUB_TOKEN=ca-token node "$here/api.mjs" request --id r-0007 --out "$work/x.json"
node "$here/ca.mjs" revoke --approvers carol-ca --request "$ca/requests/v-0007.json" --certs "$ca/certs" --source "$ca/revocations.json" >/dev/null && HUB_TOKEN=ca-token node "$here/api.mjs" revoked --id v-0007 --serial "$oserial" >/dev/null && grep -q "\"revoked\":\"v-0007\",\"serial\":\"$oserial\"" "$work/received-ca.jsonl" && ok "...revoked (ceased) and the Worker told: v-0007 done" || bad "revocation by id"
expect_fail "the Worker is not told of a revocation under an issue id" env HUB_TOKEN=ca-token node "$here/api.mjs" revoked --id r-0001 --serial "$oserial"
# Withdrawing one version: a revocation by statement serial, reason withdrawn-version; the certificate stays.
pserial=$(node -p 'require(process.argv[1]).plugins[0].statement.serial' "$st/out/index.json")
node -e 'const f=require("fs");f.writeFileSync(process.argv[2],JSON.stringify({format:1,action:"revoke",serial:process.argv[1],reason:"withdrawn-version",approved_by:["carol-ca"],at:1793749000}))' "$pserial" "$ca/requests/withdraw.json"
node -e 'const f=require("fs");f.writeFileSync(process.argv[1],JSON.stringify({format:1,action:"revoke",serial:"00000000000000aa",reason:"withdrawn-version",approved_by:["carol-ca"]}))' "$ca/requests/withdraw-bad.json"
expect_fail "withdrawing a version that is not in the index" node "$here/ca.mjs" revoke --approvers carol-ca --request "$ca/requests/withdraw-bad.json" --certs "$ca/certs" --source "$ca/revocations.json" --index "$st/out/index.json"
node "$here/ca.mjs" revoke --approvers carol-ca --request "$ca/requests/withdraw.json" --certs "$ca/certs" --source "$ca/revocations.json" --index "$st/out/index.json" >"$work/withdraw.log" && grep -q "withdrawing alice.weather 1.2" "$work/withdraw.log" && ok "version withdrawn: alice.weather 1.2 (statement $pserial)" || bad "withdraw: $(cat "$work/withdraw.log")"
node "$here/build-index.mjs" --export "$work/export.checked.json" --revoked "$out/revoked.json" --revoked-url https://cdn.wolos.org/plugins/revoked.json --revocations "$ca/revocations.json" --statements "$st/w" --statements-url https://cdn.wolos.org/plugins/statements --out "$work/index-withdrawn.json" >/dev/null
node -e 'const i=require(process.argv[1]);process.exit(i.plugins[0].withdrawn===true&&!i.apps[0].withdrawn&&!i.extensions[0].withdrawn&&i.plugins[0].cert==="fd51eec17572cf6c"&&i.apps[0].cert==="fd51eec17572cf6c"?0:1)' "$work/index-withdrawn.json" && node "$here/validate.mjs" index "$work/index-withdrawn.json" >/dev/null && ok "the index marks that version withdrawn; the other release of the same certificate is untouched" || bad "withdrawn mark"
WOLTRUST_FEATURES='' node "$here/build-revoked.mjs" --source "$ca/revocations.json" --out "$work/rev-w0.json" >/dev/null && ! grep -q "$pserial" "$work/rev-w0.json" && ok "revoked.json leaves withdrawn-version out for a woltrust that cannot read it" || bad "withdrawn-version written without the feature"
node "$here/build-revoked.mjs" --source "$ca/revocations.json" --out "$work/rev-w1.json" >/dev/null && grep -q "$pserial" "$work/rev-w1.json" && node "$here/validate.mjs" revoked "$work/rev-w1.json" >/dev/null && ok "...and writes it for 68b5a03 (tools/woltrust.features: withdrawn-version)" || bad "withdrawn-version with the feature"
"$WOLTRUST_BIN" rkdb make --source "$work/rev-w1.json" --now "$HUB_NOW" --cert "$INDEX_SERIAL" --key-file "$keys/index.key" >"$work/rev-w1.rkdb" && "$WOLTRUST_BIN" rkdb verify --roots "$trust/roots" --intermediates "$trust/intermediates" --allow-test --now "$HUB_NOW" "$work/rev-w1.rkdb" | grep -q "$pserial" && ok "a database with the withdrawn version, 128-hex ids and 16-hex serials together verifies" || bad "rkdb with withdrawn-version"
# The tier in the signed body (TRUST-core-4 class/origin_cert), in an empty certs/: the origin certificate must come first.
rm -rf "$ca/c2"; mkdir -p "$ca/c2"
node "$here/ca.mjs" issue --github-fixture "$fx/github.json" --request "$ca/requests/done/r-0001.json" --certs "$ca/c2" --issuer-serial "$AUTHORS_SERIAL" --key-file "$keys/authors.key" --approvers carol-ca >"$work/class.log" 2>&1 || true; grep -q "origin certificate first" "$work/class.log" && ok "class: a trusted certificate needs the subject's origin certificate first" || bad "class order: $(cat "$work/class.log")"
WOLTRUST_FEATURES=class node "$here/ca.mjs" issue --github-fixture "$fx/github.json" --request "$ca/requests/done/r-0002.json" --certs "$ca/c2" --issuer-serial "$AUTHORS_SERIAL" --key-file "$keys/authors.key" >"$work/class.log" 2>&1 || true; grep -q "person, origin" "$work/class.log" && node -e 'const f=require("fs"),d=process.argv[1];const c=f.readdirSync(d).find(n=>n.endsWith(".wolcert"));const b=JSON.parse(Buffer.from(JSON.parse(f.readFileSync(d+"/"+c)).body,"base64url"));process.exit(b.class==="origin"&&b.origin_cert===undefined?0:1)' "$ca/c2" && ok "class: an origin body carries class origin and no origin_cert (woltrust 68b5a03 signs it)" || bad "class body: $(cat "$work/class.log")"
CA_MJS="$here/ca.mjs" REQ="$ca/requests/done/r-0001.json" node --input-type=module -e 'const m=await import(process.env.CA_MJS);const r=JSON.parse((await import("node:fs")).readFileSync(process.env.REQ));const b=m.certBody(r,{serial:"1".repeat(16),issuer:"2".repeat(16),now:1793750400,identity:{subject:{github_id:1001,login:"alice",name:"Alice Example"},namespaces:["alice."]},withClass:true,originCert:"3".repeat(16)});process.exit(b.class==="trusted"&&b.origin_cert==="3".repeat(16)?0:1)' && ok "class: a trusted body carries class and origin_cert" || bad "class fields"

# 4b. commit-log.sh writes only the published paths, and only to wonderlandos/hub-log (a local bare repository stands in
# for it through a url.insteadOf in a scratch git config; the checkout's origin stays the real URL).
lg=$work/hub-log; mkdir -p "$lg"
(
    export GIT_CONFIG_GLOBAL=$lg/gitconfig GIT_CONFIG_NOSYSTEM=1
    git config --global url."file://$lg/remote.git".insteadOf https://github.com/wonderlandos/hub-log.git
    git config --global init.defaultBranch main
    git init -q --bare "$lg/remote.git"
    git init -q "$lg/seed" && cd "$lg/seed" && mkdir schema && echo '{}' >schema/x.json && echo log >README.md && git add . \
        && git -c user.name=t -c user.email=t@t commit -q -m start && git push -q "file://$lg/remote.git" HEAD:main
    git clone -q https://github.com/wonderlandos/hub-log.git "$lg/log"
) && ok "a stand-in hub-log checked out under its real URL" || bad "hub-log stand-in"
logrun() { (cd "$lg" && GIT_CONFIG_GLOBAL=$lg/gitconfig GIT_CONFIG_NOSYSTEM=1 HUB_LOG_DIR=log "$here/commit-log.sh" "$@"); }
mkdir -p "$lg/log/verdicts/alice.notes" && echo '{"verdict":"pass"}' >"$lg/log/verdicts/alice.notes/1.0.json"
logrun "verdicts: test" verdicts >"$work/log.out" 2>&1 && git --git-dir="$lg/remote.git" show main:verdicts/alice.notes/1.0.json >/dev/null 2>&1 \
    && ok "commit-log.sh pushed verdicts/ to hub-log" || bad "commit-log push: $(cat "$work/log.out")"
logrun "again" verdicts 2>&1 | grep -q "nothing to commit" && ok "nothing new = no commit" || bad "empty commit"
echo changed >"$lg/log/README.md"
expect_fail "commit-log.sh with a path that is not published (README.md)" logrun "x" README.md
expect_fail "commit-log.sh with schema/" logrun "x" schema
expect_fail "commit-log.sh with a .. path" logrun "x" "verdicts/../README.md"
git -C "$lg/log" checkout -q -- README.md
git -C "$lg/log" config remote.origin.url https://github.com/mallory/hub-log.git
mkdir -p "$lg/log/certs" && echo '{}' >"$lg/log/certs/0000000000000001.json"
expect_fail "commit-log.sh into a checkout of another repository" logrun "x" certs
git -C "$lg/log" config remote.origin.url https://github.com/wonderlandos/hub-log.git
logrun "ca: test" certs revocations.json >/dev/null 2>&1 && git --git-dir="$lg/remote.git" show main:certs/0000000000000001.json >/dev/null 2>&1 \
    && ok "commit-log.sh pushed certs/ (revocations.json absent is fine)" || bad "commit-log certs"

mkdir -p "$lg/log/pictures" && cp "$work/stage"/* "$lg/log/pictures/"
logrun "pictures: test" pictures >"$work/log.out" 2>&1 && git --git-dir="$lg/remote.git" show main:pictures/95d648d3d175b7df65af3f36caacaacc448897768f22945b5637685a8d5242f6.png >/dev/null 2>&1 \
    && ok "commit-log.sh pushed pictures/ to hub-log" || bad "commit-log pictures: $(cat "$work/log.out")"

# 5. Optional: keep what was made as the sample (SAMPLE_OUT=fixtures/sample-signed scripts/test.sh).
if [ -n "${SAMPLE_OUT:-}" ]; then
    mkdir -p "$SAMPLE_OUT"
    cp "$out"/* "$SAMPLE_OUT/"
    cp "$keys/legacy.pub.hex" "$SAMPLE_OUT/legacy-test-key.pub.hex"
    echo "sample written to $SAMPLE_OUT"
fi

if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed" >&2; exit 1; fi
echo "all checks passed"
