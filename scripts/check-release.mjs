#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The scan step of check.yml: for every pending release, fetch the asset by its tag, pin its size and
// sha256, run the native hubcheck on it and write one verdict. This is the only place an untrusted
// file is opened, and the job that runs it holds no token and no secret.
//
//   check-release.mjs --pending pending.json --out verdicts.json [--work dir]
//
// HUBCHECK_BIN   path of the native hubcheck (HUB-wasm, wonderlandos/hub wasm/bin/hubcheck). Missing = nothing
//                is decided: every release gets "not-checked", never "pass".
// HUBCHECK_SECS  time limit for one file, default 120
// MAX_ASSET      largest file checked, default 1 GiB (ADR 0047 H6)
// HUB_TEST=1 with --assets-dir <dir>: take <dir>/<asset_name> instead of downloading (local dry runs only)
//
// hubcheck interface this script relies on (to be confirmed by HUB-wasm, ADR 0047):
//   hubcheck --json --kind app|plugin|extension --id ID --version V [--host APP] [--previous-version P] FILE
//   stdout: {"verdict":"pass|flag|block|not-checked","findings":[{"rule","sentence","evidence"}]}
//   exit 0 when it decided; anything else = it did not decide.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { die, jsonText, parseArgs, readJson, sha256Hex, writeAtomic } from "./lib.mjs";
import { readFileSync } from "node:fs";

const MAX_ASSET = Number(process.env.MAX_ASSET ?? 1 << 30);
const HUBCHECK_SECS = Number(process.env.HUBCHECK_SECS ?? 120);
const VERDICTS = ["pass", "flag", "block", "not-checked"];
const ID = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._,+~-]{0,63}$/;
const REPO = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const SEGMENT = /^[A-Za-z0-9._+~%,-]{1,200}$/;
const TRUST = ["wolos", "verified", "community", "withdrawn", "invalid"];
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
  // Optional, from the trust crate behind hubcheck (I7): who signed the file. TODO(ADR 0047): the Worker's
  // verdict endpoint has no trust or cert field yet; it ignores them until it does.
  if (TRUST.includes(o.trust)) out.trust = o.trust;
  if (typeof o.cert?.serial === "string" && /^[0-9a-f]{16}$/.test(o.cert.serial)) out.cert = o.cert.serial;
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

function runHubcheck(bin, r, file, work) {
  const args = ["--json", "--kind", r.kind, "--id", r.listing_id, "--version", r.version];
  if (r.kind === "extension" && r.host) args.push("--host", r.host);
  if (r.previous) args.push("--previous-version", r.previous);
  args.push(file);
  // An empty environment and a scratch directory: the checker needs nothing else.
  const p = spawnSync(bin, args, { cwd: work, env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: HUBCHECK_SECS * 1000, maxBuffer: 2 << 20 });
  if (p.error?.code === "ETIMEDOUT") return { timeout: true };
  if (p.error || p.status !== 0) return { failed: true };
  return { out: cleanOutput(p.stdout) };
}

export function checkOne(r, { work, hubcheck, assetsDir }) {
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
  const res = runHubcheck(hubcheck, r, file, work);
  if (res.timeout) return v("not-checked", [finding("check/timeout", `The checker did not finish in ${HUBCHECK_SECS} seconds, so nothing was decided.`)], { sha256, size });
  if (res.failed || !res.out) return v("not-checked", [finding("check/tool-failed", "The checker stopped before it finished, so nothing was decided.")], { sha256, size });
  const { trust, cert } = res.out;
  return v(res.out.verdict, res.out.findings, { sha256, size, ...(trust ? { trust } : {}), ...(cert ? { cert } : {}) });
}

function main() {
  const { opts } = parseArgs(process.argv.slice(2));
  if (!opts.pending || !opts.out) die("usage: check-release.mjs --pending pending.json --out verdicts.json [--work dir] [--assets-dir dir]", 2);
  const work = opts.work ?? join(process.env.RUNNER_TEMP ?? "/tmp", `hub-check-${process.pid}`);
  mkdirSync(work, { recursive: true });
  const { releases } = readJson(opts.pending);
  if (!Array.isArray(releases)) die(`${opts.pending}: no releases list`);
  const hubcheck = process.env.HUBCHECK_BIN;
  const verdicts = [];
  for (const r of releases) {
    const bad = badRow(r);
    if (bad) {
      process.stderr.write(`skipped a pending row: ${bad} is not valid\n`);
      continue;
    }
    const v = checkOne(r, { work, hubcheck, assetsDir: opts["assets-dir"] });
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
