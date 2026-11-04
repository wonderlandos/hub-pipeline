#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The report job's gate. verdicts.json comes from the scan job, which opened untrusted files; this keeps from it
// only what has exactly the shape the Worker takes, only for releases that were in pending.json, and nothing twice.
// Then (with --log) it writes the public log: verdicts/<id>/<version>.json.
//
//   verdicts.mjs clean --pending pending.json --verdicts verdicts.json --out clean.json
//   verdicts.mjs log   --verdicts clean.json --dir verdicts --run "<run_id>.<attempt>" --workflow-sha SHA [--now unix]
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { die, jsonText, nowSeconds, parseArgs, readJson, writeAtomic, isSerial } from "./lib.mjs";

const VERDICTS = ["pass", "flag", "block", "not-checked"];
const TRUST = ["wolos", "verified", "community", "withdrawn", "invalid"];
const HEX64 = /^[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const text = (s, n) => typeof s === "string" && s.length <= n && !CONTROL.test(s);

export function cleanVerdict(v) {
  if (!v || typeof v !== "object") return null;
  if (!VERDICTS.includes(v.verdict)) return null;
  if (v.sha256 != null && !HEX64.test(v.sha256)) return null;
  if (v.sha256 == null && v.verdict !== "not-checked") return null;
  if (v.size != null && !(Number.isSafeInteger(v.size) && v.size >= 0)) return null;
  if (!Array.isArray(v.findings) || v.findings.length > 200) return null;
  const findings = [];
  for (const f of v.findings) {
    if (!f || !text(f.rule, 64) || !f.rule || !text(f.sentence, 500) || !f.sentence || (f.evidence != null && !text(f.evidence, 1000))) return null;
    findings.push({ rule: f.rule, sentence: f.sentence, ...(f.evidence ? { evidence: f.evidence } : {}) });
  }
  const out = { listing_id: v.listing_id, version: v.version, verdict: v.verdict, ...(v.sha256 ? { sha256: v.sha256 } : {}), ...(v.size != null ? { size: v.size } : {}), findings };
  if (TRUST.includes(v.trust)) out.trust = v.trust;
  if (isSerial(v.cert)) out.cert = v.cert;
  return out;
}

try {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  if (rest[0] === "clean") {
    const wanted = new Set(readJson(opts.pending).releases.map((r) => `${r.listing_id}\u0000${r.version}`));
    const seen = new Set();
    const verdicts = [];
    for (const v of readJson(opts.verdicts).verdicts ?? []) {
      const key = `${v?.listing_id}\u0000${v?.version}`;
      const c = wanted.has(key) && !seen.has(key) ? cleanVerdict(v) : null;
      if (!c) {
        process.stderr.write(`::warning::dropped a verdict for ${v?.listing_id} ${v?.version}: not a pending release, repeated, or malformed\n`);
        continue;
      }
      seen.add(key);
      verdicts.push(c);
    }
    writeAtomic(opts.out, jsonText({ verdicts }));
    process.stdout.write(`${verdicts.length} verdict(s) ready to post\n`);
  } else if (rest[0] === "log") {
    const now = opts.now ? Number(opts.now) : nowSeconds();
    for (const v of readJson(opts.verdicts).verdicts) {
      const dir = join(opts.dir, v.listing_id);
      mkdirSync(dir, { recursive: true });
      writeAtomic(join(dir, `${v.version}.json`), jsonText({ ...v, checked_at: now, run: opts.run, workflow_sha: opts["workflow-sha"] }));
    }
  } else die("usage: verdicts.mjs clean|log ...", 2);
} catch (e) {
  die(e.message);
}
