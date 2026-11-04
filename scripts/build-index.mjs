#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The Worker's export (GET /api/pipeline/export) -> index.json, I3 (schema/index.schema.json).
//
//   build-index.mjs --export export.json --revoked revoked.json --revoked-url URL --out index.json
//                   [--previous signed/index.json] [--intermediates certs/intermediates] [--now unix]
//
// Only the fields of the schema are copied, in a fixed order, entries sorted by id: the same export
// always gives the same bytes. An entry that breaks a rule is dropped with a warning (the rest is
// still published), never repaired. serial = the previous serial + 1; expires = issued + 7 days.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { die, jsonText, nowSeconds, parseArgs, readJson, sha256Hex, writeAtomic } from "./lib.mjs";
import { checkIndex } from "./validate.mjs";

const WEEK = 7 * 86400;
const FIELDS = ["id", "name", "version", "summary", "author", "license", "kinds", "permissions", "min_wolos", "url", "sha256", "size",
  "trust", "cert", "verdict", "findings", "owner", "source", "first_seen", "yanked", "host", "capabilities", "categories"];

const copyEntry = (e) => {
  const out = {};
  for (const k of FIELDS) if (e[k] !== undefined && e[k] !== null) out[k] = e[k];
  if (out.source && out.source.commit == null) delete out.source.commit;
  return out;
};

export function buildIndex(exp, { serial, now, revoked, intermediates = [], bytesHint = 0 }) {
  if (!exp || exp.format !== 1 || exp.preview !== false) throw new Error("the export is not a final format-1 export (preview must be false)");
  const index = { format: 1, serial, issued: now, expires: now + WEEK };
  if (Number.isSafeInteger(exp.generated)) index.generated = exp.generated;
  const dropped = [];
  for (const [list, listName] of [["apps", "app"], ["plugins", "plugin"], ["extensions", "extension"]]) {
    const entries = [];
    for (const raw of Array.isArray(exp[list]) ? exp[list] : []) {
      if (raw?.verdict !== "pass" && raw?.verdict !== "flag") {
        dropped.push(`${listName} ${raw?.id}: verdict ${raw?.verdict} is never listed`);
        continue;
      }
      const e = copyEntry(raw);
      const probe = { ...index, apps: [], plugins: [], extensions: [], [list]: [e] };
      const { errors } = checkIndex(probe, { bytes: bytesHint });
      // ids twice and the other cross-entry rules are checked on the whole index below
      const own = errors.filter((x) => !x.includes("listed twice"));
      if (own.length) dropped.push(`${listName} ${raw?.id}: ${own.join("; ")}`);
      else entries.push(e);
    }
    const seen = new Set();
    index[list] = entries
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .filter((e) => (seen.has(e.id) ? (dropped.push(`${listName} ${e.id}: listed twice in the export`), false) : (seen.add(e.id), true)));
  }
  index.intermediates = intermediates;
  index.revoked = revoked;
  return { index, dropped };
}

function main() {
  const { opts } = parseArgs(process.argv.slice(2), ["strict", "force"]);
  if (!opts.export || !opts.revoked || !opts["revoked-url"] || !opts.out) {
    die("usage: build-index.mjs --export f --revoked revoked.json --revoked-url URL --out index.json [--previous f] [--intermediates dir] [--strict] [--force]", 2);
  }
  const revokedBytes = readFileSync(opts.revoked);
  const revokedList = JSON.parse(revokedBytes.toString("utf8"));
  const previousIndex = opts.previous && existsSync(opts.previous) ? readJson(opts.previous) : null;
  const prev = previousIndex ? previousIndex.serial : 0;
  if (!Number.isSafeInteger(prev) || prev < 0) die(`${opts.previous}: no usable serial`);
  const intermediates = opts.intermediates && existsSync(opts.intermediates)
    ? readdirSync(opts.intermediates).filter((f) => f.endsWith(".wolcert")).sort().map((f) => readJson(join(opts.intermediates, f)))
    : [];
  const { index, dropped } = buildIndex(readJson(opts.export), {
    serial: prev + 1,
    now: opts.now ? Number(opts.now) : nowSeconds(),
    revoked: { url: opts["revoked-url"], sha256: sha256Hex(revokedBytes), serial: revokedList.serial },
    intermediates,
  });
  for (const d of dropped) process.stderr.write(`::warning::dropped ${d}\n`);
  if (dropped.length && opts.strict) die(`${dropped.length} entr${dropped.length === 1 ? "y" : "ies"} dropped and --strict is set`);
  // A broken export must not empty the index: losing more than half of a real index needs a person to say so.
  const count = (i) => ["apps", "plugins", "extensions"].reduce((n, k) => n + (Array.isArray(i?.[k]) ? i[k].length : 0), 0);
  const before = count(previousIndex);
  const after = count(index);
  if (before >= 4 && after * 2 < before && !opts.force) die(`the new index lists ${after} entries, the last one ${before}; check the export, or run again with --force`);
  const text = jsonText(index);
  const { errors, warnings } = checkIndex(index, { bytes: text.length, revoked: { ...revokedList, sha256: sha256Hex(revokedBytes) } });
  for (const w of warnings) process.stderr.write(`note: ${w}\n`);
  if (errors.length) die(`the built index is invalid: ${errors.join("; ")}`);
  writeAtomic(opts.out, text);
  process.stdout.write(`index.json: serial ${index.serial}, ${index.apps.length} app(s), ${index.plugins.length} plugin(s), ${index.extensions.length} extension(s), ${dropped.length} dropped\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (e) {
    die(e.message);
  }
}
