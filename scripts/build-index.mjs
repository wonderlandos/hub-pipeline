#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The Worker's export (GET /api/pipeline/export) -> index.json, I3 (schema/index.schema.json).
//
//   build-index.mjs --export export.json --revoked revoked.json --revoked-url URL --out index.json
//                   [--previous signed/index.json] [--intermediates certs/intermediates] [--now unix]
//                   [--certs certs] [--revocations revocations.json] [--statements DIR --statements-url URL]
//                   [--pictures work/out/pictures]
//
// --certs: the tier of every certificate issued here (certs/<serial>.json, ca.mjs). An entry signed by an origin
// certificate is listed with trust "origin", whatever the export says; so is one signed by a trusted certificate that
// was revoked with reason superseded (the downgrade: the person keeps their origin certificate). key-compromise and
// abuse are not touched here: woltrust withdraws every signature of that certificate on every client.
// Trust "verified" from an older export is written "trusted" (the vocabulary of TRUST-core-4: wolos|trusted|origin|community).
//
// --revocations also marks an entry withdrawn when its release statement serial is revoked with reason withdrawn-version
// (one version withdrawn; it stays listed so clients show why, the author's certificate is untouched).
// --statements DIR writes the body of every listed release's statement (statements.mjs) to DIR/<id>/<version>.body.json
// and points the entry at it: statement {url: URL/<id>/<version>.wsig, serial}. sign-files.sh signs them.
//
// --pictures DIR: the pictures staged for the CDN (pictures.mjs stage, work/out/pictures; publish.sh uploads them before
// index.json). An entry names its listing's icon and screenshots (the Worker's {sha256, mime, w, h, size, file}) by their
// CDN file name <sha256>.<png|webp> (the extension from the picture's type), and only those whose exact bytes (hash, size, type, pixel size) are in DIR under <sha256>.<png|webp>:
// the index never points at a picture the CDN does not get. No --pictures: no picture at all. The description (the
// package's, at most 4000 characters, no control character but tab and line breaks) is copied as text; one that breaks
// that is left out with a note, never cut, and the entry stays (the pictures likewise: a bad one is left out, not the entry).
//
// Only the fields of the schema are copied, in a fixed order, entries sorted by id: the same export
// always gives the same bytes. An entry that breaks a rule is dropped with a warning (the rest is
// still published), never repaired. serial = the previous serial + 1; expires = issued + 7 days.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { die, jsonText, nowSeconds, parseArgs, readJson, sha256Hex, writeAtomic } from "./lib.mjs";
import { checkIndex } from "./validate.mjs";
import { certTiers } from "./ca.mjs";
import { statementSerial, writeBodies } from "./statements.mjs";
import { MAX_SCREENSHOTS, cleanPicture, pictureFile, pictureThere } from "./facts.mjs";

const WEEK = 7 * 86400;
const FIELDS = ["id", "name", "version", "summary", "description", "icon", "screenshots", "author", "license", "kinds", "permissions", "min_wolos", "url", "sha256", "size",
  "trust", "cert", "verdict", "findings", "owner", "source", "first_seen", "yanked", "host", "capabilities", "categories"];

const MAX_DESCRIPTION = 4000;
// C0 but tab and line breaks, DEL and C1 (U+0080-U+009F): what the Rust readers refuse (char::is_control).
const DESCRIPTION_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;

/** The export's picture view {sha256, mime, w, h, size, file} as a reference, or null (a lying `file` name too). */
export function pictureRef(raw) {
  if (!raw || typeof raw !== "object") return null;
  const p = cleanPicture({ path: `${raw.sha256}`, ...raw });
  return p && (raw.file === undefined || raw.file === pictureFile(p)) ? p : null;
}

const copyEntry = (e, pictureOk, notes) => {
  const out = {};
  for (const k of FIELDS) {
    if (e[k] === undefined || e[k] === null) continue;
    if (k === "description") {
      const d = e.description;
      if (typeof d === "string" && d.length >= 1 && [...d].length <= MAX_DESCRIPTION && !DESCRIPTION_CONTROL.test(d)) out.description = d;
      else notes.push(`${e.id}: the description is not text of 1 to ${MAX_DESCRIPTION} characters; left out`);
    } else if (k === "icon") {
      const p = pictureRef(e.icon);
      if (p && pictureOk(p)) out.icon = pictureFile(p);
      else notes.push(`${e.id}: the icon is not a picture staged for the CDN; left out`);
    } else if (k === "screenshots") {
      const shots = (Array.isArray(e.screenshots) ? e.screenshots : []).map(pictureRef).filter((p) => p && pictureOk(p)).map(pictureFile);
      if (shots.length < (Array.isArray(e.screenshots) ? e.screenshots.length : 1)) notes.push(`${e.id}: a screenshot is not a picture staged for the CDN; left out`);
      if (shots.length > MAX_SCREENSHOTS) notes.push(`${e.id}: ${shots.length} screenshots, the first ${MAX_SCREENSHOTS} are listed`);
      if (shots.length) out.screenshots = shots.slice(0, MAX_SCREENSHOTS);
    } else out[k] = e[k];
  }
  if (out.source && out.source.commit == null) delete out.source.commit;
  return out;
};

/** serial -> "origin" for every certificate whose files the index shows as origin. */
export function originSerials(tiers, revocations) {
  const out = new Set([...tiers].filter(([, t]) => t === "origin").map(([s]) => s));
  for (const e of revocations?.entries ?? []) if (e.reason === "superseded" && tiers.get(e.serial) === "trusted") out.add(e.serial);
  return out;
}

export function buildIndex(exp, { serial, now, revoked, intermediates = [], bytesHint = 0, origin = new Set(), withdrawn = new Set(), statementsUrl = null, pictureOk = () => false }) {
  if (!exp || exp.format !== 1 || exp.preview !== false) throw new Error("the export is not a final format-1 export (preview must be false)");
  const index = { format: 1, serial, issued: now, expires: now + WEEK };
  if (Number.isSafeInteger(exp.generated)) index.generated = exp.generated;
  const dropped = [];
  const notes = [];
  for (const [list, listName] of [["apps", "app"], ["plugins", "plugin"], ["extensions", "extension"]]) {
    const entries = [];
    for (const raw of Array.isArray(exp[list]) ? exp[list] : []) {
      if (raw?.verdict !== "pass" && raw?.verdict !== "flag") {
        dropped.push(`${listName} ${raw?.id}: verdict ${raw?.verdict} is never listed`);
        continue;
      }
      const e = copyEntry(raw, pictureOk, notes);
      if (e.trust === "verified") e.trust = "trusted";
      if (e.cert && origin.has(e.cert) && e.trust !== "wolos") e.trust = "origin";
      const st = statementSerial(e.id, e.version, e.sha256);
      if (withdrawn.has(st)) e.withdrawn = true;
      if (statementsUrl) e.statement = { url: `${statementsUrl}/${e.id}/${encodeURIComponent(e.version)}.wsig`, serial: st };
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
  return { index, dropped, notes };
}

function main() {
  const { opts } = parseArgs(process.argv.slice(2), ["strict", "force"]);
  if (!opts.export || !opts.revoked || !opts["revoked-url"] || !opts.out) {
    die("usage: build-index.mjs --export f --revoked revoked.json --revoked-url URL --out index.json [--previous f] [--intermediates dir] [--pictures dir] [--strict] [--force]", 2);
  }
  const revokedBytes = readFileSync(opts.revoked);
  const revokedList = JSON.parse(revokedBytes.toString("utf8"));
  const previousIndex = opts.previous && existsSync(opts.previous) ? readJson(opts.previous) : null;
  const prev = previousIndex ? previousIndex.serial : 0;
  if (!Number.isSafeInteger(prev) || prev < 0) die(`${opts.previous}: no usable serial`);
  const intermediates = opts.intermediates && existsSync(opts.intermediates)
    ? readdirSync(opts.intermediates).filter((f) => f.endsWith(".wolcert")).sort().map((f) => readJson(join(opts.intermediates, f)))
    : [];
  if (opts.statements && !/^https:\/\/[^\s/]+\/\S+[^/]$/.test(opts["statements-url"] ?? "")) die("--statements needs --statements-url https://host/path", 2);
  const revocations = opts.revocations && existsSync(opts.revocations) ? readJson(opts.revocations) : null;
  const picturesDir = opts.pictures && existsSync(opts.pictures) ? opts.pictures : null;
  const { index, dropped, notes } = buildIndex(readJson(opts.export), {
    serial: prev + 1,
    now: opts.now ? Number(opts.now) : nowSeconds(),
    revoked: { url: opts["revoked-url"], sha256: sha256Hex(revokedBytes), serial: revokedList.serial },
    intermediates,
    origin: opts.certs ? originSerials(certTiers(opts.certs), revocations) : new Set(),
    withdrawn: new Set((revocations?.entries ?? []).filter((x) => x.reason === "withdrawn-version").map((x) => x.serial)),
    statementsUrl: opts.statements ? opts["statements-url"] : null,
    pictureOk: picturesDir ? (p) => pictureThere(picturesDir, p) : () => false,
  });
  for (const n of notes) process.stderr.write(`::notice::${n}\n`);
  if (opts.statements) writeBodies(index, opts.statements);
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
