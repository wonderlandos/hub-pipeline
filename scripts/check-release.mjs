#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The scan step of check.yml: for every pending release, fetch the asset by its tag, pin its size and
// sha256, run the native hubcheck on it and write one verdict. This is the only place an untrusted
// file is opened, and the job that runs it holds no token and no secret.
//
//   check-release.mjs --pending pending.json --out verdicts.json [--work dir] [--pictures dir]
//
// --pictures dir: for every pass or flag, `hubcheck extract` writes the package's icon and screenshots there as
// <sha256>.<png|webp> (the name the Worker's listings carry as `file`); the verdict's facts keep only the pictures
// whose bytes are there and match. Without it the verdict carries the text facts and no picture.
//
// HUBCHECK_BIN    path of the native hubcheck (scripts/tool.sh hubcheck: wonderlandos/hub wasm/, tools/hubcheck.rev).
//                 Missing = nothing is decided: every release gets "not-checked", never "pass".
// HUBCHECK_STORE  the trust store (scripts/store.mjs: pinned roots, intermediates, the last revocation list). Missing =
//                 not-checked as well: a verdict without the signature check is not the check.
// HUBCHECK_SECS   time limit for one file, default 120
// MAX_ASSET       largest file checked, default 1 GiB (ADR 0047 H6)
// HUB_NOW         the time hubcheck checks at (tests), default now
// HUB_TEST=1 with --assets-dir <dir>: take <dir>/<asset_name> instead of downloading (local dry runs only)
//
// hubcheck's command line (wonderlandos/hub wasm/README.md, interface I7), the one this script calls:
//   hubcheck inspect app|plugin|extension FILE --store store.json --now UNIX [--first-seen UNIX]
//   stdout, one line: {"verdict":"pass|flag|block|not-checked","findings":[{"rule","sentence","evidence"}],
//                      "trust":"wolos|verified|community|withdrawn|invalid","cert"?:{"serial",...},"origin"?:{...},
//                      "file"?:{"id","version"?},"facts"?:{name,summary,description?,icon?,screenshots,...}}
//   hubcheck extract FILE --out DIR --kind KIND   writes the pictures of facts as DIR/<sha256>.<png|webp> (f2bce73+)
//   exit 0 whenever a report was printed, 1 when the file could not be read, 2 for a wrong command line.
// The verdict is hubcheck's: this script adds only what hubcheck cannot know (the download, the size GitHub listed, the
// time limit, whether the file's id and version are the listing's: block when not) and turns every failure of the
// tool into not-checked.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { die, jsonText, parseArgs, readJson, sha256Hex, writeAtomic, isSerial } from "./lib.mjs";
import { cleanFacts, keepPictures, pictureFile, pictureThere } from "./facts.mjs";
import { readFileSync } from "node:fs";

const MAX_ASSET = Number(process.env.MAX_ASSET ?? 1 << 30);
const HUBCHECK_SECS = Number(process.env.HUBCHECK_SECS ?? 120);
const VERDICTS = ["pass", "flag", "block", "not-checked"];
const ID = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._,+~-]{0,63}$/;
const REPO = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const SEGMENT = /^[A-Za-z0-9._+~%,-]{1,200}$/;
// hub-worker src/pipeline.ts SIG_TRUST: hubcheck f2bce73+ says trusted or origin from the certificate class, an older one verified.
export const TRUST = ["wolos", "trusted", "origin", "verified", "community", "withdrawn", "invalid"];
const CONTROL = /[\u0000-\u001f\u007f]/g;

const finding = (rule, sentence, evidence = "") => ({ rule, sentence, evidence });

/** A pending row from the Worker, checked before anything is fetched. Returns an error text or null. */
export function badRow(r) {
  if (!r || typeof r !== "object") return "not an object";
  if (typeof r.listing_id !== "string" || !ID.test(r.listing_id) || r.listing_id.length > 64) return "listing_id";
  if (typeof r.version !== "string" || !VERSION.test(r.version)) return "version";
  if (!["app", "plugin", "extension"].includes(r.kind)) return "kind";
  if (typeof r.repo !== "string" || !REPO.test(r.repo)) return "repo";
  if (typeof r.tag !== "string" || !SEGMENT.test(r.tag)) return "tag";
  if (typeof r.asset_name !== "string" || !SEGMENT.test(r.asset_name)) return "asset_name";
  if (r.host != null && (typeof r.host !== "string" || !ID.test(r.host))) return "host";
  if (r.previous != null && (typeof r.previous !== "string" || !VERSION.test(r.previous))) return "previous";
  if (r.size != null && !(Number.isSafeInteger(r.size) && r.size >= 0)) return "size";
  return null;
}

/** The only URL a release may be fetched from: its own GitHub release download. */
export const assetUrl = (r) => `https://github.com/${r.repo}/releases/download/${r.tag}/${r.asset_name}`;

/** What hubcheck printed, cut down to what the Worker accepts. Anything else is "it did not decide". */
export function cleanOutput(text) {
  let o;
  try {
    o = JSON.parse(text);
  } catch {
    return null;
  }
  if (!o || typeof o !== "object" || !VERDICTS.includes(o.verdict) || !Array.isArray(o.findings)) return null;
  const cut = (s, n) => String(s ?? "").replace(CONTROL, " ").slice(0, n);
  const findings = o.findings.slice(0, 200).map((f) => finding(cut(f?.rule, 64) || "check/unnamed", cut(f?.sentence, 500) || "A rule was broken.", cut(f?.evidence, 1000)));
  const out = { verdict: o.verdict, findings };
  // From the trust crate behind hubcheck (I7): what the signature is worth and who signed. The Worker stores them
  // with the verdict (HUB-worker-2); verdicts.mjs passes them through.
  if (TRUST.includes(o.trust)) out.trust = o.trust;
  if (isSerial(o.cert?.serial)) out.cert = o.cert.serial;
  // What the file says it is (hubcheck a0fcf58+: Info.json / plugin.toml / extension.toml); checked against the listing below.
  if (o.file && typeof o.file.id === "string") out.file = { id: o.file.id, ...(typeof o.file.version === "string" ? { version: o.file.version } : {}) };
  // The listing read from the package (hubcheck f2bce73+), in the shape the Worker's metaOf takes.
  const facts = cleanFacts(o.facts);
  if (facts) out.facts = facts;
  return out;
}

function download(r, dest, assetsDir) {
  if (assetsDir) {
    if (process.env.HUB_TEST !== "1") throw new Error("--assets-dir is for local dry runs (HUB_TEST=1)");
    const src = join(assetsDir, r.asset_name);
    if (!existsSync(src)) return "missing";
    copyFileSync(src, dest);
    return null;
  }
  for (let attempt = 1; attempt <= 3; attempt++) {
    const p = spawnSync("curl", [
      "--fail", "--silent", "--show-error", "--location", "--max-redirs", "5",
      "--proto", "=https", "--proto-redir", "=https", "--max-filesize", String(MAX_ASSET),
      "--connect-timeout", "20", "--max-time", "900", "--output", dest, assetUrl(r),
    ], { encoding: "utf8", timeout: 960_000 });
    if (p.status === 0) return null;
    if (p.status === 22 || p.status === 63) return `refused (curl ${p.status})`; // 4xx or too large: final
    if (attempt < 3) spawnSync("sleep", [String(attempt * 5)]);
  }
  return "no answer";
}

function runHubcheck(bin, store, r, file, work) {
  const now = String(Number(process.env.HUB_NOW ?? Math.floor(Date.now() / 1000)));
  const args = ["inspect", r.kind, resolve(file), "--store", store, "--now", now];
  if (Number.isSafeInteger(r.first_seen) && r.first_seen > 0) args.push("--first-seen", String(r.first_seen));
  // An empty environment and a scratch directory: the checker needs nothing else.
  const p = spawnSync(bin, args, { cwd: work, env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: HUBCHECK_SECS * 1000, maxBuffer: 2 << 20 });
  if (p.error?.code === "ETIMEDOUT") return { timeout: true };
  if (p.error || p.status !== 0) return { failed: true };
  return { out: cleanOutput(p.stdout) };
}

/** hubcheck extract into a scratch folder; only pictures that match their reference move on to dir. */
function extractPictures(bin, r, file, work, facts, dir) {
  const scratch = join(work, "extract");
  rmSync(scratch, { recursive: true, force: true });
  mkdirSync(scratch, { recursive: true });
  const p = spawnSync(bin, ["extract", resolve(file), "--out", scratch, "--kind", r.kind], { cwd: work, env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: HUBCHECK_SECS * 1000, maxBuffer: 2 << 20 });
  if (!p.error && p.status === 0) {
    mkdirSync(dir, { recursive: true });
    for (const pic of [facts.icon, ...(facts.screenshots ?? [])]) {
      if (pic && pictureThere(scratch, pic)) copyFileSync(join(scratch, pictureFile(pic)), join(dir, pictureFile(pic)));
    }
  }
  rmSync(scratch, { recursive: true, force: true });
  return keepPictures(facts, existsSync(dir) ? dir : undefined);
}

export function checkOne(r, { work, hubcheck, store, assetsDir, pictures }) {
  const v = (verdict, findings, extra = {}) => ({ listing_id: r.listing_id, version: r.version, verdict, ...extra, findings });
  if (r.size != null && r.size > MAX_ASSET) {
    return v("not-checked", [finding("size/too-large", `The file is larger than the ${MAX_ASSET >> 20} MiB the hub checks, so it was not checked.`)]);
  }
  const file = join(work, "asset.bin");
  rmSync(file, { force: true });
  const why = download(r, file, assetsDir);
  if (why) return v("not-checked", [finding("fetch/failed", "The release file could not be fetched from GitHub, so it was not checked.", why)]);
  const size = statSync(file).size;
  const sha256 = sha256Hex(readFileSync(file));
  if (size === 0) return v("block", [finding("asset/empty", "The release file is empty.")], { sha256, size });
  if (r.size != null && r.size !== size) {
    return v("block", [finding("asset/size-mismatch", "The file is not the one GitHub listed for this release; publish it again as a new version.", `listed ${r.size} bytes, fetched ${size}`)], { sha256, size });
  }
  if (!hubcheck || !existsSync(hubcheck)) {
    return v("not-checked", [finding("check/unavailable", "The checker is not installed in this run, so nothing was decided.")], { sha256, size });
  }
  if (!store || !existsSync(store)) {
    return v("not-checked", [finding("check/unavailable", "The trust store is missing in this run, so nothing was decided.")], { sha256, size });
  }
  const res = runHubcheck(hubcheck, store, r, file, work);
  if (res.timeout) return v("not-checked", [finding("check/timeout", `The checker did not finish in ${HUBCHECK_SECS} seconds, so nothing was decided.`)], { sha256, size });
  if (res.failed || !res.out) return v("not-checked", [finding("check/tool-failed", "The checker stopped before it finished, so nothing was decided.")], { sha256, size });
  const { trust, cert, file: said } = res.out;
  let { verdict, findings } = res.out;
  // A file that is not the release it is listed as is never listed: another id (a release attached to someone else's
  // listing, or a namespace the listing does not own) or another version than the tag's.
  if (verdict !== "not-checked" && said?.id !== r.listing_id) {
    verdict = "block";
    findings = [finding("listing/id-mismatch", "The file inside is not the app, plugin or extension this listing is for.", `file ${said?.id ?? "(no id)"}, listing ${r.listing_id}`), ...findings];
  } else if (verdict !== "not-checked" && said.version !== undefined && said.version !== r.version) {
    verdict = "block";
    findings = [finding("listing/version-mismatch", "The version inside the file is not the version of this release.", `file ${said.version}, release ${r.version}`), ...findings];
  }
  // The listing's facts only from a file that is listed (pass or flag); pictures only when extract wrote them.
  let facts;
  if ((verdict === "pass" || verdict === "flag") && res.out.facts) {
    const pics = res.out.facts.icon || res.out.facts.screenshots;
    facts = pics && pictures ? extractPictures(hubcheck, r, file, work, res.out.facts, pictures) : keepPictures(res.out.facts, undefined);
  }
  return v(verdict, findings.slice(0, 200), { sha256, size, ...(trust ? { trust } : {}), ...(cert ? { cert } : {}), ...(facts ? { facts } : {}) });
}

function main() {
  const { opts } = parseArgs(process.argv.slice(2));
  if (!opts.pending || !opts.out) die("usage: check-release.mjs --pending pending.json --out verdicts.json [--work dir] [--assets-dir dir] [--pictures dir]", 2);
  const work = opts.work ?? join(process.env.RUNNER_TEMP ?? "/tmp", `hub-check-${process.pid}`);
  mkdirSync(work, { recursive: true });
  const { releases } = readJson(opts.pending);
  if (!Array.isArray(releases)) die(`${opts.pending}: no releases list`);
  const hubcheck = process.env.HUBCHECK_BIN;
  const store = process.env.HUBCHECK_STORE ? resolve(process.env.HUBCHECK_STORE) : undefined;
  const verdicts = [];
  for (const r of releases) {
    const bad = badRow(r);
    if (bad) {
      process.stderr.write(`skipped a pending row: ${bad} is not valid\n`);
      continue;
    }
    const v = checkOne(r, { work, hubcheck, store, assetsDir: opts["assets-dir"], pictures: opts.pictures ? resolve(opts.pictures) : undefined });
    process.stdout.write(`${r.listing_id} ${r.version}: ${v.verdict}${v.findings.length ? ` (${v.findings.map((f) => f.rule).join(", ")})` : ""}\n`);
    verdicts.push(v);
  }
  writeAtomic(opts.out, jsonText({ verdicts }));
  rmSync(work, { recursive: true, force: true });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (e) {
    die(e.message);
  }
}
