#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The Authors CA's two actions, read from a request file under requests/ (schema/request.schema.json).
//
//   ca.mjs issue  --request requests/x.json --certs certs --issuer-serial S [--source revocations.json]
//                 [--key-env NAME | --key-file F] [--woltrust CMD...] [--now unix] [--archive]
//   ca.mjs revoke --request requests/x.json --certs certs --source revocations.json [--now unix] [--archive]
//
// issue:  builds the certificate body (ADR 0046) as bytes, has `woltrust issue` sign exactly those bytes,
//         checks the answer carries the same body, writes certs/<serial>.wolcert. One active certificate
//         per GitHub account and kind: revoke the old one first (reason superseded).
// revoke: appends {serial, at, reason} to revocations.json (the next sign run publishes it, signed,
//         within the hour). A revocation of an unknown serial is refused. abuse needs two approvers.
// --archive moves the request to requests/done/ when it succeeded. WOLTRUST (env) names the command:
// default `woltrust`; dry runs set it to the stub.
import { randomBytes } from "node:crypto";
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

export function certBody(req, { serial, issuer, now }) {
  const months = req.months ?? 12;
  return {
    serial,
    kind: req.kind,
    subject: { github_id: req.subject.github_id, login: req.subject.login, name: req.subject.name },
    namespaces: req.namespaces,
    usage: ["sign-package", "sign-plugin", "sign-extension"],
    keys: { ed25519: req.keys.ed25519, "ml-dsa-65": req.keys["ml-dsa-65"] },
    issuer,
    not_before: now,
    not_after: now + months * MONTH,
    level: "verified",
  };
}

function issue(opts, req) {
  for (const o of ["certs", "issuer-serial"]) if (!opts[o]) die(`issue needs --${o}`, 2);
  if (!/^[0-9a-f]{16}$/.test(opts["issuer-serial"])) die("--issuer-serial is 16 lowercase hex characters", 2);
  const now = opts.now ? Number(opts.now) : nowSeconds();
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
  const p = spawnSync(cmd[0], [...cmd.slice(1), "issue", "--body", tmp, "--proof", proofFile, ...keyArgs], { encoding: "utf8", maxBuffer: 1 << 20, env: process.env });
  rmSync(dirname(tmp), { recursive: true, force: true });
  if (p.error || p.status !== 0) die(`woltrust issue failed: ${p.error?.message ?? p.stderr.trim().slice(0, 300)}`);
  const cert = JSON.parse(p.stdout);
  if (cert.format !== 1 || typeof cert.body !== "string" || !cert.sig?.ed25519 || !cert.sig?.second) die("woltrust issue returned something that is not a .wolcert");
  if (!Buffer.from(cert.body, "base64url").equals(body)) die("the certificate body is not the body that was asked for; refusing it");
  writeAtomic(join(opts.certs, `${serial}.wolcert`), jsonText(cert));
  process.stdout.write(`issued ${serial} to ${req.subject.login} (${req.kind}), namespaces ${req.namespaces.join(" ")}\n`);
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
