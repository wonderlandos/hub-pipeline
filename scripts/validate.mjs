#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Validator of the files this repository produces.
//
//   validate.mjs index   <index.json> [--revoked <revoked.json>] [--now <unix>]
//   validate.mjs revoked <revoked.json>
//   validate.mjs request <requests/x.json>
//   validate.mjs wsig    <file.wsig>
//
// index: the JSON schema (schema/index.schema.json) plus the rules a schema cannot say: unique
// ids, ids inside the owner's namespace, the asset URL names the source repository and tag, trust
// and certificate agree, a flagged entry has findings, and what the 0.12 plugin reader would
// keep (it drops an entry that breaks its own rules; the rest of the index stays usable).
// Exit 0 = valid, 1 = invalid (every problem is printed), 2 = usage.
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { die, parseArgs, readJson, sha256Hex, validate } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const schema = (name) => readJson(join(here, "..", "schema", `${name}.schema.json`));

const KINDS = ["menubar", "dock", "widget", "panel", "search", "tile", "toggle", "hotkey", "webapp", "theme", "look", "hypr"];
const PERMISSIONS = ["notifications", "run", "http", "clipboard", "open", "toggles"];
const MAX_INDEX = 4 << 20; // the 0.12 reader's cap
const MAX_ENTRIES = 5000;
const WEEK = 7 * 86400;

/** The rules of crates/wopkg/src/index/plugins.rs Entry::is_valid that the schema does not already say. */
function legacyDropReason(e) {
  if (e.id.startsWith("org.wolos.")) return "the id uses the reserved prefix org.wolos.";
  if (!Array.isArray(e.kinds) || e.kinds.length === 0) return "it names no kinds";
  if (!e.kinds.every((k) => KINDS.includes(k))) return "a kind is unknown";
  if (e.permissions && !e.permissions.every((p) => PERMISSIONS.includes(p))) return "a permission is unknown";
  if (e.size > 2 << 20) return "the file is larger than a .wolplug may be (2 MiB)";
  return null;
}

export function checkIndex(index, { now, bytes, revoked } = {}) {
  const errors = validate(schema("index"), index);
  const warnings = [];
  if (errors.length) return { errors, warnings };
  if (bytes > MAX_INDEX) errors.push(`index.json is ${bytes} bytes; the 0.12 reader reads at most ${MAX_INDEX}`);
  if (index.expires <= index.issued) errors.push("expires is not after issued");
  if (index.expires - index.issued > WEEK + 3600) errors.push("expires is more than 7 days after issued");
  if (now !== undefined && index.expires <= now) errors.push("the index is already expired");
  const all = [...index.apps.map((e) => ["app", e]), ...index.plugins.map((e) => ["plugin", e]), ...index.extensions.map((e) => ["extension", e])];
  if (all.length > MAX_ENTRIES) errors.push(`${all.length} entries; shard by kind before ${MAX_ENTRIES}`);
  const seen = new Set();
  const appIds = new Set(index.apps.map((e) => e.id));
  for (const [kind, e] of all) {
    const at = `${kind} ${e.id}`;
    if (seen.has(e.id)) errors.push(`${at}: the id is listed twice`);
    seen.add(e.id);
    const login = e.owner.login.toLowerCase();
    if (e.owner.kind === "wolos") {
      if (!e.id.startsWith("org.wolos.")) errors.push(`${at}: a WolOS-owned id starts with org.wolos.`);
      if (e.trust !== "wolos") errors.push(`${at}: a WolOS-owned entry has trust wolos`);
    } else {
      if (!e.id.startsWith(`${login}.`)) errors.push(`${at}: the id must start with the owner login "${login}."`);
      if (e.trust === "wolos") errors.push(`${at}: only WolOS-owned entries have trust wolos`);
    }
    const m = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\//.exec(e.url);
    if (!m || m[1].toLowerCase() !== e.source.repo.toLowerCase()) errors.push(`${at}: the asset URL is not in source.repo`);
    else if (decodeURIComponent(m[2]) !== e.source.tag) errors.push(`${at}: the asset URL is not at source.tag`);
    if (e.source.repo.split("/")[0].toLowerCase() !== login && e.owner.kind !== "wolos") {
      warnings.push(`${at}: the repository owner differs from the owner login (renamed or transferred; the sign job re-checks the numeric ids)`);
    }
    if (e.trust === "community" && e.cert) errors.push(`${at}: a community entry has no certificate`);
    if (e.trust !== "community" && !e.cert) warnings.push(`${at}: trust ${e.trust} without the signing certificate serial (the Worker export does not carry it yet)`);
    if (e.verdict === "flag" && e.findings.length === 0) errors.push(`${at}: a flagged entry lists its findings`);
    if (kind === "extension" && !appIds.has(e.host)) warnings.push(`${at}: its host ${e.host} is not an app in this index`);
  }
  if (revoked) {
    if (!index.revoked) errors.push("revoked is missing but a revocation list was given");
    else {
      if (index.revoked.sha256 !== revoked.sha256) errors.push("revoked.sha256 is not the sha256 of revoked.json");
      if (index.revoked.serial !== revoked.serial) errors.push("revoked.serial is not the serial of revoked.json");
    }
  }
  index.plugins.forEach((e) => {
    const why = legacyDropReason(e);
    if (why) warnings.push(`plugin ${e.id}: a 0.12 reader drops it (${why}); 0.13 lists it`);
  });
  return { errors, warnings };
}

export function checkRevoked(list) {
  const errors = validate(schema("revoked"), list);
  if (errors.length) return errors;
  if (list.expires <= list.issued) errors.push("expires is not after issued");
  const seen = new Set();
  for (const e of list.entries) {
    if (seen.has(e.serial)) errors.push(`${e.serial}: listed twice`);
    seen.add(e.serial);
  }
  return errors;
}

export function checkRequest(req) {
  // Pick the shape by `action` first, so the errors name the field that is wrong, not "matches 0 shapes".
  const all = schema("request");
  const shape = all.oneOf.find((s) => s.properties.action.const === req?.action);
  if (!shape) return ["$: action must be issue or revoke"];
  const errors = validate(shape, req);
  if (errors.length) return errors;
  if (req.action === "revoke") {
    const people = new Set(req.approved_by.map((s) => s.toLowerCase()));
    if (req.reason === "abuse" && people.size < 2) errors.push("a revocation for abuse needs two different approvers (ADR 0046)");
  } else {
    const login = req.subject.login.toLowerCase();
    if (req.namespaces.some((n) => n.startsWith("org.wolos") || n === "org.")) errors.push("org.wolos. belongs to the Packages CA only");
    if (req.kind === "person" && !req.namespaces.includes(`${login}.`)) errors.push(`a person's namespaces include "${login}."`);
    if (Boolean(req.keys.x25519) !== Boolean(req.keys["ml-kem-768"])) errors.push("keys: x25519 and ml-kem-768 come both or not at all");
    if (req.subject.org && req.kind !== "person") errors.push("subject.org: only a person names an organisation");
    if (req.approved_by.some((a) => a.toLowerCase() === login)) errors.push("approved_by: nobody approves their own certificate");
    if (req.approved_at < req.requested_at) errors.push("approved_at is before requested_at");
  }
  return errors;
}

/** A .wsig is {cert, ed25519, second}: all strings, cert 16 hex, the halves base64url. */
export function checkWsig(w) {
  const errors = [];
  if (!w || typeof w !== "object" || Array.isArray(w)) return ["not an object"];
  const keys = Object.keys(w).sort().join(",");
  if (keys !== "cert,ed25519,second") errors.push(`fields are ${keys}, expected cert, ed25519, second`);
  if (!/^[0-9a-f]{16}$/.test(w.cert ?? "")) errors.push("cert is 16 lowercase hex characters");
  for (const k of ["ed25519", "second"]) if (!/^[A-Za-z0-9_-]+$/.test(w[k] ?? "")) errors.push(`${k} is base64url`);
  if (/^[A-Za-z0-9_-]+$/.test(w.ed25519 ?? "") && Buffer.from(w.ed25519, "base64url").length !== 64) errors.push("ed25519 is 64 bytes");
  return errors;
}

function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  const [what, file] = rest;
  if (!what || !file) die("usage: validate.mjs index|revoked|request|wsig <file> [--revoked file] [--now unix]", 2);
  let errors = [];
  let warnings = [];
  if (what === "index") {
    const revoked = opts.revoked ? { ...readJson(opts.revoked), sha256: sha256Hex(readFileSync(opts.revoked)) } : undefined;
    ({ errors, warnings } = checkIndex(readJson(file), { now: opts.now ? Number(opts.now) : undefined, bytes: statSync(file).size, revoked }));
  } else if (what === "revoked") errors = checkRevoked(readJson(file));
  else if (what === "request") errors = checkRequest(readJson(file));
  else if (what === "wsig") errors = checkWsig(readJson(file));
  else die(`unknown kind ${what}`, 2);
  for (const w of warnings) process.stderr.write(`note: ${w}\n`);
  for (const e of errors) process.stderr.write(`${file}: ${e}\n`);
  if (errors.length) process.exit(1);
  process.stdout.write(`${file}: valid ${what}${warnings.length ? ` (${warnings.length} notes)` : ""}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    die(e.message);
  }
}
