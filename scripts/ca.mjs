#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The Authors CA's two actions, read from a request file under requests/ (schema/request.schema.json).
//
//   ca.mjs issue  --request requests/x.json --certs certs --issuer-serial S [--source revocations.json]
//                 [--key-env NAME | --key-file F] [--passphrase-env NAME] [--approvers login,login] [--result F]
//                 [--intermediates DIR] [--woltrust CMD] [--github-fixture F] [--now unix] [--archive]
//   ca.mjs revoke --request requests/x.json --certs certs --source revocations.json --approvers login,login
//                 [--index signed/index.json] [--now unix] [--archive]
//
// What goes into a certificate (audit-1 H2): only what the requester signed (github_id, kind, keys: the proof covers
// them) and what GitHub itself says about that github_id, asked by this job (github-identity.mjs): the login, the display
// name, a public organisation membership, an organisation owner. The namespace is derived from GitHub's login and must
// be what was asked, must not be reserved, and must not collide (case or look-alike) with another account's active
// certificate. Fields the Worker added (approved_by, cla_accepted_at, verified_at, months, the request's own login,
// name and org) only decide whether the job runs, never what is signed.
//
// issue:  tier origin: issued without an approval, once the CLA is accepted (cla_accepted_at from the Worker's record).
//         tier trusted: only a request that an admin approved (approved_by, written by the hub admin panel through the
//         Worker, or by the CA operator); with --approvers every approver must be one of those logins (repository
//         variable CA_APPROVERS), and a trusted request without --approvers is refused. Both tiers make the same
//         woltrust body (woltrust has no tier yet); the tier is recorded in certs/<serial>.json, which build-index.mjs
//         reads. Builds the certificate body (ADR 0046) as bytes, has `woltrust issue --proof` check the proof
//         of possession and sign exactly those bytes, checks the answer carries the same body, writes
//         certs/<serial>.wolcert. One active certificate per GitHub account and kind: revoke the old one first
//         (reason superseded) per tier: one active origin and one active trusted certificate per account and kind. --result writes {request_id, serial, cert} for `api.mjs issued`. --intermediates: the
//         issuer's certificate is looked up there by serial and the Ed25519 half of the new certificate is checked
//         against it (catches a wrong or swapped CA key before anything is written; clients check both halves).
// revoke: reason withdrawn-version withdraws one version: the serial must be the statement serial of an entry of
//         --index (the last signed index); the author's certificate is untouched. Every other reason revokes a
//         certificate issued here. Appends {serial, at, reason} to revocations.json (the next sign run publishes it, signed,
//         within the hour). A revocation of an unknown serial is refused. abuse needs two approvers.
// --archive moves the request to requests/done/ when it succeeded. The woltrust command: --woltrust, else WOLTRUST
// (env), else `woltrust` on PATH; always the real one (scripts/tool.sh woltrust), dry runs use the TEST Authors CA key.
import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { basename, dirname, join } from "node:path";
import { SERIAL, die, isSerial, jsonText, keyId, nowSeconds, parseArgs, readJson, woltrustFeatures, writeAtomic } from "./lib.mjs";
import { checkRequest, reservedName, skeleton } from "./validate.mjs";
import { githubIdentity } from "./github-identity.mjs";

const MONTH = 30 * 86400;

const decodeBody = (cert) => JSON.parse(Buffer.from(cert.body, "base64url").toString("utf8"));

/** Every .wolcert in certs/ (not the CA's own), with its decoded body. */
export function knownCerts(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".wolcert") && SERIAL.test(f.slice(0, -8))).map((f) => {
    const serial = f.slice(0, -8);
    const meta = join(dir, `${serial}.json`);
    // A certificate from before the two tiers has no record: it was approved by a person, so it counts as trusted.
    return { file: f, body: decodeBody(readJson(join(dir, f))), tier: existsSync(meta) ? readJson(meta).tier : "trusted" };
  });
}

/** serial -> tier of every certificate issued here (certs/<serial>.json). */
export function certTiers(dir) {
  return new Map(knownCerts(dir).map((c) => [c.body.serial, c.tier]));
}

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** True when the Ed25519 half of `cert` is the issuer's (`issuerBody.keys.ed25519`) over label wolos/cert/1. */
export function ed25519HalfOk(cert, issuerBody) {
  const body = Buffer.from(cert.body, "base64url");
  const msg = Buffer.concat([Buffer.from("wolos/cert/1"), Buffer.from([0]), createHash("sha512").update(body).digest()]);
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(issuerBody.keys.ed25519, "base64url")]), format: "der", type: "spki" });
  return verify(null, msg, key, Buffer.from(cert.sig.ed25519, "base64url"));
}

/** The body of the certificate with this serial in `dir` (any file name), or null. */
export function findCert(dir, serial) {
  if (!existsSync(dir)) return null;
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".wolcert"))) {
    const body = decodeBody(readJson(join(dir, f)));
    if (body.serial === serial) return body;
  }
  return null;
}

const BAD_NAME = /[\p{Cc}\p{Cf}\u2028\u2029]/u; // bidi overrides, zero-width joiners, controls (audit-1 L1)

/**
 * Who the certificate is for, from GitHub (gh: github-identity.mjs), checked against the request. Returns
 * {subject, namespaces, notes} or throws with the reason. Nothing of the request's subject is copied.
 */
export async function resolveIdentity(req, gh) {
  const notes = [];
  const acct = req.kind === "org" ? await gh.org(req.subject.github_id) : await gh.user(req.subject.github_id);
  if (!acct) throw new Error(`GitHub knows no ${req.kind === "org" ? "organisation" : "user"} with id ${req.subject.github_id}`);
  if (acct.id !== req.subject.github_id || acct.type !== (req.kind === "org" ? "Organization" : "User")) throw new Error(`GitHub id ${req.subject.github_id} is not a ${req.kind}`);
  if (acct.login.toLowerCase() !== req.subject.login.toLowerCase()) throw new Error(`the request names ${req.subject.login}, but GitHub id ${req.subject.github_id} is ${acct.login}`);
  const login = acct.login;
  let name = (acct.name ?? "").trim();
  if (!name || BAD_NAME.test(name) || [...name].length > 128) {
    if (name) notes.push(`GitHub's display name has characters a certificate does not carry; the login is used`);
    name = login;
  }
  const subject = { github_id: acct.id, login, name };
  if (req.kind === "org") {
    const by = req.requested_by;
    const asker = await gh.user(by.github_id);
    if (!asker || asker.login.toLowerCase() !== by.login.toLowerCase()) throw new Error(`requested_by ${by.login} is not GitHub id ${by.github_id}`);
    if ((await gh.role(login, asker.login)) !== "admin") throw new Error(`${asker.login} is not an owner of the organisation ${login} on GitHub (or this job cannot see it)`);
  } else if (req.subject.org) {
    const o = await gh.org(req.subject.org.github_id);
    if (o && o.type === "Organization" && o.login.toLowerCase() === req.subject.org.login.toLowerCase() && (await gh.publicMember(o.login, login))) subject.org = { github_id: o.id, login: o.login };
    else notes.push(`organisation ${req.subject.org.login} left out: GitHub does not show ${login} as a public member`);
  }
  const namespaces = [`${login.toLowerCase()}.`];
  if (req.namespaces.length !== 1 || req.namespaces[0] !== namespaces[0]) throw new Error(`the request asks for ${req.namespaces.join(" ")}, the account's prefix is ${namespaces[0]}`);
  const reserved = reservedName(login);
  if (reserved) throw new Error(`${login} is reserved or looks like "${reserved}"`);
  return { subject, namespaces, notes };
}

/** Another account's active certificate whose namespace is the same or looks the same; null when free. */
export function namespaceClash(namespaces, githubId, known, revokedSerials, now) {
  for (const c of known) {
    if (c.body.subject?.github_id === githubId || c.body.not_after <= now || revokedSerials.has(c.body.serial)) continue;
    for (const theirs of c.body.namespaces ?? []) for (const ours of namespaces) if (skeleton(theirs) === skeleton(ours)) return { serial: c.body.serial, theirs, ours };
  }
  return null;
}

export function certBody(req, { serial, issuer, now, identity, withClass = false, originCert = null }) {
  const months = 12; // the requester's months is not signed: every certificate runs a year
  const { subject, namespaces } = identity;
  const keys = { ed25519: req.keys.ed25519, "ml-dsa-65": req.keys["ml-dsa-65"] };
  // Encryption keys (wolos/seal/1): both or none, as the request has them; the proof covers them too.
  if (req.keys.x25519 && req.keys["ml-kem-768"]) Object.assign(keys, { x25519: req.keys.x25519, "ml-kem-768": req.keys["ml-kem-768"] });
  const notAfter = now + months * MONTH;
  return {
    serial,
    kind: req.kind,
    subject,
    namespaces,
    usage: ["sign-package", "sign-plugin", "sign-extension"],
    keys,
    issuer,
    not_before: now,
    not_after: notAfter,
    level: "verified",
    // This job checked the account with GitHub just now.
    verified_at: now,
    // TRUST-core-4 (chat 7293): the tier in the signed bytes, a trusted certificate linked to the subject's origin one.
    // Only when the pinned woltrust reads it (tools/woltrust.features: class); fe64176 refuses unknown body keys.
    ...(withClass ? { class: req.tier, ...(req.tier === "trusted" ? { origin_cert: originCert } : {}) } : {}),
  };
}

async function issue(opts, req) {
  for (const o of ["certs", "issuer-serial"]) if (!opts[o]) die(`issue needs --${o}`, 2);
  if (!isSerial(opts["issuer-serial"])) die("--issuer-serial is the Authors CA certificate id (128 lowercase hex characters; 16 for the TEST authority)", 2);
  const now = opts.now ? Number(opts.now) : nowSeconds();
  if (req.tier === "trusted") {
    if (opts.approvers === undefined) die("a trusted certificate needs --approvers (the repository variable CA_APPROVERS)");
    const allowed = new Set(String(opts.approvers).split(/[\s,]+/).filter(Boolean).map((s) => s.toLowerCase()));
    const outside = req.approved_by.filter((a) => !allowed.has(a.toLowerCase()));
    if (!allowed.size) die("--approvers is empty: nobody may approve a certificate (set the repository variable CA_APPROVERS)");
    if (outside.length) die(`approved by ${outside.join(", ")}, who is not a CA approver (CA_APPROVERS)`);
  }
  const issuerBody = opts.intermediates ? findCert(opts.intermediates, opts["issuer-serial"]) : null;
  if (opts.intermediates && !issuerBody) die(`no certificate ${opts["issuer-serial"]} in ${opts.intermediates}`);
  const known = knownCerts(opts.certs);
  const revokedSerials = new Set(opts.source && existsSync(opts.source) ? readJson(opts.source).entries.map((e) => e.serial) : []);
  const identity = await resolveIdentity(req, githubIdentity(opts["github-fixture"])).catch((e) => die(`refused: ${e.message}`));
  for (const n of identity.notes) process.stderr.write(`note: ${n}\n`);
  const clash = namespaceClash(identity.namespaces, req.subject.github_id, known, revokedSerials, now);
  if (clash) die(`refused: ${clash.ours} is taken or looks like ${clash.theirs} (certificate ${clash.serial} of another account)`);
  const dup = known.find((c) => c.body.kind === req.kind && c.tier === req.tier && c.body.subject?.github_id === req.subject.github_id && c.body.not_after > now && !revokedSerials.has(c.body.serial));
  if (dup) die(`GitHub account ${req.subject.login} already has the active ${req.tier} certificate ${dup.body.serial}; revoke it first (reason superseded)`);
  // The proof covers login, name, organisation and namespaces as the requester signed them (woltrust 68b5a03
  // request::Claimed): a body with GitHub's values that differ would not verify. Refuse with the reason, so the author
  // re-requests with what GitHub shows now.
  const signed = JSON.stringify({ login: req.subject.login, name: req.subject.name, org: req.subject.org ?? null });
  const found = JSON.stringify({ login: identity.subject.login, name: identity.subject.name, org: identity.subject.org ?? null });
  if (signed !== found) die(`refused: the request signed ${signed}, GitHub shows ${found}; the proof covers these, so the author requests again with what GitHub shows`);
  const withClass = woltrustFeatures().has("class");
  let originCert = null;
  if (withClass && req.tier === "trusted") {
    const o = known.find((c) => c.tier === "origin" && c.body.kind === req.kind && c.body.subject?.github_id === req.subject.github_id && c.body.not_after > now && !revokedSerials.has(c.body.serial));
    if (!o) die(`a trusted certificate links to the subject's origin certificate: issue ${req.subject.login}'s origin certificate first`);
    originCert = o.body.serial;
    // The Worker names the origin certificate it approved the trusted one on (ADR 0047); it must be the live one found here.
    if (req.origin_cert && req.origin_cert !== originCert) die(`the request names origin certificate ${req.origin_cert}, but ${req.subject.login}'s active origin certificate is ${originCert}`);
  }
  // Rule "IDS" (woltrust 68b5a03): the serial is SHA-512 over the public keys, so the same keys always give the same
  // certificate id. A second certificate for the same keys is refused: a revoked key stays revoked, an active one is
  // already that certificate; the author makes new keys.
  const serial = keyId(req.keys);
  const same = known.find((c) => c.body.serial === serial);
  if (same) die(revokedSerials.has(serial) ? `these keys were revoked (certificate ${serial}); a new certificate needs new keys` : `these keys already hold certificate ${serial} (${same.tier})`);
  if (serial === opts["issuer-serial"]) die("the request carries the CA's own keys");
  const body = Buffer.from(JSON.stringify(certBody(req, { serial, issuer: opts["issuer-serial"], now, identity, withClass, originCert })));
  mkdirSync(opts.certs, { recursive: true });
  const tmp = join(mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), "ca-")), "body.json"); // public data only
  writeAtomic(tmp, body);
  const proofFile = join(dirname(tmp), "proof.json");
  writeAtomic(proofFile, jsonText(req.proof));
  const cmd = (opts.woltrust ?? process.env.WOLTRUST ?? "woltrust").split(" ");
  const keyArgs = opts["key-env"] ? ["--key-env", opts["key-env"]] : opts["key-file"] ? ["--key-file", opts["key-file"]] : [];
  if (opts["passphrase-env"]) keyArgs.push("--passphrase-env", opts["passphrase-env"]);
  const p = spawnSync(cmd[0], [...cmd.slice(1), "issue", "--body", tmp, "--proof", proofFile, ...keyArgs], { encoding: "utf8", maxBuffer: 1 << 20, env: process.env });
  rmSync(dirname(tmp), { recursive: true, force: true });
  if (p.error || p.status !== 0) die(`woltrust issue failed: ${p.error?.message ?? p.stderr.trim().slice(0, 300)}`);
  const cert = JSON.parse(p.stdout);
  if (cert.format !== 1 || typeof cert.body !== "string" || !cert.sig?.ed25519 || !cert.sig?.second) die("woltrust issue returned something that is not a .wolcert");
  if (!Buffer.from(cert.body, "base64url").equals(body)) die("the certificate body is not the body that was asked for; refusing it");
  if (issuerBody && !ed25519HalfOk(cert, issuerBody)) die(`the certificate is not signed by ${opts["issuer-serial"]}'s key (wrong key material for the CA?); refusing it`);
  const text = p.stdout; // the exact bytes woltrust wrote
  writeAtomic(join(opts.certs, `${serial}.wolcert`), text);
  const record = { serial, tier: req.tier, kind: req.kind, github_id: identity.subject.github_id, login: identity.subject.login, request_id: req.id ?? null, issued_at: now };
  if (req.requested_by) record.requested_by = req.requested_by;
  if (req.tier === "trusted") Object.assign(record, { approved_by: req.approved_by, approved_at: req.approved_at });
  else record.cla_accepted_at = req.cla_accepted_at;
  writeAtomic(join(opts.certs, `${serial}.json`), jsonText(record));
  if (opts.result) writeAtomic(opts.result, jsonText({ request_id: req.id ?? null, serial, tier: req.tier, cert: text }));
  const why = req.tier === "trusted" ? `approved by ${req.approved_by.join(", ")}` : `CLA accepted at ${req.cla_accepted_at}`;
  process.stdout.write(`issued ${serial} to ${identity.subject.login} (${req.kind}, ${req.tier}), namespaces ${identity.namespaces.join(" ")}, ${why}\n`);
  return serial;
}

function revoke(opts, req) {
  for (const o of ["certs", "source"]) if (!opts[o]) die(`revoke needs --${o}`, 2);
  // The job's clock, never the request's at (audit-1 M4: a future at would keep every file valid).
  const now = opts.now ? Number(opts.now) : nowSeconds();
  if (opts.approvers === undefined) die("revoke needs --approvers (the repository variable CA_APPROVERS)");
  const allowed = new Set(String(opts.approvers).split(/[\s,]+/).filter(Boolean).map((s) => s.toLowerCase()));
  const counted = new Set(req.approved_by.map((a) => a.toLowerCase()).filter((a) => allowed.has(a)));
  if (counted.size < req.approved_by.length) die(`approved by someone who is not a CA approver (CA_APPROVERS): ${req.approved_by.join(", ")}`);
  if (req.reason === "abuse" && counted.size < 2) die("a revocation for abuse needs two different CA approvers");
  const source = existsSync(opts.source) ? readJson(opts.source) : { format: 1, entries: [] };
  if (source.format !== 1 || !Array.isArray(source.entries)) die(`${opts.source}: expected {format:1, entries:[...]}`);
  if (source.entries.some((e) => e.serial === req.serial)) die(`${req.serial} is already on the revocation list`);
  if (req.reason === "withdrawn-version") {
    if (!opts.index || !existsSync(opts.index)) die("withdrawn-version needs --index (the last signed index.json)");
    const idx = readJson(opts.index);
    const hit = ["apps", "plugins", "extensions"].flatMap((l) => idx[l] ?? []).find((e) => e.statement?.serial === req.serial);
    if (!hit) die(`${req.serial} is not the release statement of a version in ${opts.index}; refusing`);
    process.stdout.write(`withdrawing ${hit.id} ${hit.version} (statement ${req.serial}); certificate ${hit.cert ?? "(none)"} untouched\n`);
  } else if (!opts["allow-unknown"] && !knownCerts(opts.certs).some((c) => c.body.serial === req.serial)) die(`${req.serial} is not a certificate issued here (certs/); refusing to revoke an unknown serial`);
  source.entries.push({ serial: req.serial, at: now, reason: req.reason });
  source.entries.sort((a, b) => a.at - b.at || (a.serial < b.serial ? -1 : 1));
  writeAtomic(opts.source, jsonText({ format: 1, entries: source.entries }));
  process.stdout.write(`revoked ${req.serial}, reason ${req.reason}, approved by ${req.approved_by.join(", ")}\n`);
}

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2), ["archive", "allow-unknown"]);
  const [action] = rest;
  if (!["issue", "revoke"].includes(action) || !opts.request) die("usage: ca.mjs issue|revoke --request requests/x.json ...", 2);
  const req = readJson(opts.request);
  const errors = checkRequest(req);
  if (errors.length) die(`${opts.request}: ${errors.join("; ")}`);
  if (req.action !== action) die(`${opts.request} asks to ${req.action}, not to ${action}`);
  if (action === "issue") await issue(opts, req);
  else revoke(opts, req);
  if (opts.archive) {
    const done = join(dirname(opts.request), "done");
    mkdirSync(done, { recursive: true });
    renameSync(opts.request, join(done, basename(opts.request)));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => die(e.message));
}
