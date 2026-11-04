#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Release statements (lead decision 2026-11-04; shape: TRUST-core-4, chat 7293): every listed version gets its own
// statement, signed by the Index intermediate with label wolos/release/1, published as
// plugins/statements/<id>/<version>.wsig and committed to signed/statements/<id>/<version>.wsig.
//
//   statement file  {"format":1,"body":b64url(body bytes),"cert":"<Index serial>","sig":{"ed25519","second"}}
//   body            {"format":1,"serial","sha256","id","version","kind":"package|plugin|extension",
//                    "origin"?:{"repo","tag","commit"},"verdict","findings":<count>,"checked_at","cert"?:"<author serial>"}
//
// Withdrawing one version = a revocation entry {serial: <statement serial>, reason: "withdrawn-version"} in revoked.json
// (ca.mjs revoke); the index entry is then marked withdrawn; the author's certificate is untouched.
//
//   statements.mjs sign --dir DIR --cert SERIAL (--key-file F | --key-env NAME [--passphrase-env NAME])
//       every DIR/<id>/<version>.body.json -> DIR/<id>/<version>.wsig, through `woltrust sign --purpose release`
//       (WOLTRUST_BIN). Needs the word "statements" in tools/woltrust.features: the woltrust of fe64176 has no such purpose.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { die, parseArgs, woltrustFeatures, writeAtomic } from "./lib.mjs";

export const LABEL = "wolos/release/1";
const KIND = { apps: "package", plugins: "plugin", extensions: "extension" };

/** 16 hex characters naming one release file: stable for the same id, version and bytes, so re-signing keeps it. */
export const statementSerial = (id, version, sha256) =>
  createHash("sha256").update(`${LABEL}\u0000${id}\u0000${version}\u0000${sha256}`).digest().subarray(0, 8).toString("hex");

/** The body bytes for an index entry of `list` (apps, plugins, extensions), keys in the frozen order. */
export function statementBody(list, e) {
  const b = { format: 1, serial: statementSerial(e.id, e.version, e.sha256), sha256: e.sha256, id: e.id, version: e.version, kind: KIND[list] };
  if (e.source?.commit) b.origin = { repo: `https://github.com/${e.source.repo}`, tag: e.source.tag, commit: e.source.commit };
  Object.assign(b, { verdict: e.verdict, findings: e.findings.length, checked_at: e.checked_at ?? e.first_seen });
  if (e.cert) b.cert = e.cert;
  return Buffer.from(JSON.stringify(b));
}

/** Writes DIR/<id>/<version>.body.json for every entry and returns {list, id, version, serial} for each. */
export function writeBodies(index, dir) {
  const out = [];
  for (const list of ["apps", "plugins", "extensions"]) {
    for (const e of index[list]) {
      const f = join(dir, e.id, `${e.version}.body.json`);
      mkdirSync(dirname(f), { recursive: true });
      writeAtomic(f, statementBody(list, e));
      out.push({ list, id: e.id, version: e.version, serial: statementSerial(e.id, e.version, e.sha256) });
    }
  }
  return out;
}

/** The statement file from the body bytes and woltrust's detached signature over them. */
export function assemble(body, wsig) {
  return JSON.stringify({ format: 1, body: body.toString("base64url"), cert: wsig.cert, sig: { ed25519: wsig.ed25519, second: wsig.second } });
}

function sign(opts) {
  if (!woltrustFeatures().has("statements")) die("the pinned woltrust cannot sign release statements yet (no 'statements' in tools/woltrust.features)");
  const bin = process.env.WOLTRUST_BIN;
  if (!bin || !existsSync(bin)) die("WOLTRUST_BIN is not set");
  const keyArgs = opts["key-file"] ? ["--key-file", opts["key-file"]] : ["--key-env", opts["key-env"]];
  if (opts["passphrase-env"]) keyArgs.push("--passphrase-env", opts["passphrase-env"]);
  let n = 0;
  for (const id of readdirSync(opts.dir).sort()) {
    for (const f of readdirSync(join(opts.dir, id)).filter((x) => x.endsWith(".body.json")).sort()) {
      const bodyFile = join(opts.dir, id, f);
      const p = spawnSync(bin, ["sign", "--purpose", "release", "--cert", opts.cert, ...keyArgs, bodyFile], { encoding: "utf8", maxBuffer: 1 << 20 });
      if (p.status !== 0) die(`woltrust sign --purpose release ${bodyFile}: ${p.stderr.trim().slice(0, 300)}`);
      writeAtomic(join(opts.dir, id, f.replace(/\.body\.json$/, ".wsig")), assemble(readFileSync(bodyFile), JSON.parse(p.stdout)));
      n++;
    }
  }
  process.stdout.write(`${n} release statement(s) signed as ${opts.cert}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const { opts, rest } = parseArgs(process.argv.slice(2));
    if (rest[0] !== "sign" || !opts.dir || !/^[0-9a-f]{16}$/.test(opts.cert ?? "") || !(opts["key-file"] || opts["key-env"])) die("usage: statements.mjs sign --dir DIR --cert SERIAL (--key-file F | --key-env NAME)", 2);
    sign(opts);
  } catch (e) {
    die(e.message);
  }
}
