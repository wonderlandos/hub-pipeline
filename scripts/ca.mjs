#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The Authors CA's two actions, read from a request file under requests/ (schema/request.schema.json).
//
//   ca.mjs issue  --request requests/x.json --certs certs --issuer-serial S [--source revocations.json]
//                 [--key-env NAME | --key-file F] [--passphrase-env NAME] [--approvers login,login] [--result F]
//                 [--intermediates DIR] [--woltrust CMD] [--now unix] [--archive]
//   ca.mjs revoke --request requests/x.json --certs certs --source revocations.json [--now unix] [--archive]
//
// issue:  only a request that an admin approved (approved_by, written by the hub admin panel through the Worker, or by
//         the CA operator); with --approvers every approver must be one of those logins (repository variable
//         CA_APPROVERS). Builds the certificate body (ADR 0046) as bytes, has `woltrust issue --proof` check the proof
//         of possession and sign exactly those bytes, checks the answer carries the same body, writes
//         certs/<serial>.wolcert. One active certificate per GitHub account and kind: revoke the old one first
//         (reason superseded). --result writes {request_id, serial, cert} for `api.mjs issued`. --intermediates: the
//         issuer's certificate is looked up there by serial and the Ed25519 half of the new certificate is checked
//         against it (catches a wrong or swapped CA key before anything is written; clients check both halves).
// revoke: appends {serial, at, reason} to revocations.json (the next sign run publishes it, signed,
//         within the hour). A revocation of an unknown serial is refused. abuse needs two approvers.
// --archive moves the request to requests/done/ when it succeeded. The woltrust command: --woltrust, else WOLTRUST
// (env), else `woltrust` on PATH; always the real one (scripts/tool.sh woltrust), dry runs use the TEST Authors CA key.
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { basename, dirname, join } from "node:path";
import { die, jsonText, nowSeconds, parseArgs, readJson, writeAtomic } from "./lib.mjs";
import { checkRequest } from "./validate.mjs";

const MONTH = 30 * 86400;

const decodeBody = (cert) => JSON.parse(Buffer.from(cert.body, "base64url").toString("utf8"));

/** Every .wolcert in certs/ (not the CA's own), with its decoded body. */
export function knownCerts(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^[0-9a-f]{16}\.wolcert$/.test(f)).map((f) => ({ file: f, body: decodeBody(readJson(join(dir, f))) }));
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

export function certBody(req, { serial, issuer, now }) {
  const months = req.months ?? 12;
  const subject = { github_id: req.subject.github_id, login: req.subject.login, name: req.subject.name };
  // A person who belongs to an organisation the hub knows (ADR 0046, origin): set by the Worker from GitHub membership.
  if (req.kind === "person" && req.subject.org) subject.org = { github_id: req.subject.org.github_id, login: req.subject.org.login };
  const keys = { ed25519: req.keys.ed25519, "ml-dsa-65": req.keys["ml-dsa-65"] };
  // Encryption keys (wolos/seal/1): both or none, as the request has them; the proof covers them too.
  if (req.keys.x25519 && req.keys["ml-kem-768"]) Object.assign(keys, { x25519: req.keys.x25519, "ml-kem-768": req.keys["ml-kem-768"] });
  const notAfter = now + months * MONTH;
  return {
    serial,
    kind: req.kind,
    subject,
    namespaces: req.namespaces,
    usage: ["sign-package", "sign-plugin", "sign-extension"],
    keys,
    issuer,
    not_before: now,
    not_after: notAfter,
    level: "verified",
    // When the hub last verified the account (the Worker's verified_at), else now: the CA checks it at this moment.
    verified_at: Math.min(req.verified_at ?? now, notAfter - 1),
  };
}

function issue(opts, req) {
  for (const o of ["certs", "issuer-serial"]) if (!opts[o]) die(`issue needs --${o}`, 2);
  if (!/^[0-9a-f]{16}$/.test(opts["issuer-serial"])) die("--issuer-serial is 16 lowercase hex characters", 2);
  const now = opts.now ? Number(opts.now) : nowSeconds();
  if (opts.approvers !== undefined) {
    const allowed = new Set(String(opts.approvers).split(/[\s,]+/).filter(Boolean).map((s) => s.toLowerCase()));
    const outside = req.approved_by.filter((a) => !allowed.has(a.toLowerCase()));
    if (!allowed.size) die("--approvers is empty: nobody may approve a certificate (set the repository variable CA_APPROVERS)");
    if (outside.length) die(`approved by ${outside.join(", ")}, who is not a CA approver (CA_APPROVERS)`);
  }
  const issuerBody = opts.intermediates ? findCert(opts.intermediates, opts["issuer-serial"]) : null;
  if (opts.intermediates && !issuerBody) die(`no certificate ${opts["issuer-serial"]} in ${opts.intermediates}`);
  const known = knownCerts(opts.certs);
  const revokedSerials = new Set(opts.source && existsSync(opts.source) ? readJson(opts.source).entries.map((e) => e.serial) : []);
  const dup = known.find((c) => c.body.kind === req.kind && c.body.subject?.github_id === req.subject.github_id && c.body.not_after > now && !revokedSerials.has(c.body.serial));
  if (dup) die(`GitHub account ${req.subject.login} already has the active certificate ${dup.body.serial}; revoke it first (reason superseded)`);
  let serial;
  do serial = randomBytes(8).toString("hex");
  while (known.some((c) => c.body.serial === serial) || serial === opts["issuer-serial"]);
  const body = Buffer.from(JSON.stringify(certBody(req, { serial, issuer: opts["issuer-serial"], now })));
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
  if (opts.result) writeAtomic(opts.result, jsonText({ request_id: req.id ?? null, serial, cert: text }));
  process.stdout.write(`issued ${serial} to ${req.subject.login} (${req.kind}), namespaces ${req.namespaces.join(" ")}, approved by ${req.approved_by.join(", ")}\n`);
  return serial;
}

function revoke(opts, req) {
  for (const o of ["certs", "source"]) if (!opts[o]) die(`revoke needs --${o}`, 2);
  const now = req.at ?? (opts.now ? Number(opts.now) : nowSeconds());
  const source = existsSync(opts.source) ? readJson(opts.source) : { format: 1, entries: [] };
  if (source.format !== 1 || !Array.isArray(source.entries)) die(`${opts.source}: expected {format:1, entries:[...]}`);
  if (source.entries.some((e) => e.serial === req.serial)) die(`${req.serial} is already on the revocation list`);
  if (!opts["allow-unknown"] && !knownCerts(opts.certs).some((c) => c.body.serial === req.serial)) die(`${req.serial} is not a certificate issued here (certs/); refusing to revoke an unknown serial`);
  source.entries.push({ serial: req.serial, at: now, reason: req.reason });
  source.entries.sort((a, b) => a.at - b.at || (a.serial < b.serial ? -1 : 1));
  writeAtomic(opts.source, jsonText({ format: 1, entries: source.entries }));
  process.stdout.write(`revoked ${req.serial}, reason ${req.reason}, approved by ${req.approved_by.join(", ")}\n`);
}

function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2), ["archive", "allow-unknown"]);
  const [action] = rest;
  if (!["issue", "revoke"].includes(action) || !opts.request) die("usage: ca.mjs issue|revoke --request requests/x.json ...", 2);
  const req = readJson(opts.request);
  const errors = checkRequest(req);
  if (errors.length) die(`${opts.request}: ${errors.join("; ")}`);
  if (req.action !== action) die(`${opts.request} asks to ${req.action}, not to ${action}`);
  if (action === "issue") issue(opts, req);
  else revoke(opts, req);
  if (opts.archive) {
    const done = join(dirname(opts.request), "done");
    mkdirSync(done, { recursive: true });
    renameSync(opts.request, join(done, basename(opts.request)));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (e) {
    die(e.message);
  }
}
