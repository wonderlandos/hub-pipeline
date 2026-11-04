#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// A stand-in for the `woltrust` command line in local dry runs and this repository's CI. It is NOT the
// signer. It follows the contract the workflows rely on (README, "Tooling contract"), signs the Ed25519
// half with a fixed TEST key and writes an unmistakable placeholder as the second half, so nothing it
// makes can verify in woltrust. A workflow that is not a dry run refuses to run with it.
// TODO(ADR 0046): replace by the real `woltrust` binary (crate woltrust, wave3/trust-core has the library
// and woltrust-vectors only) pinned in tools/woltrust.rev.
//
//   woltrust-stub sign  --purpose index|revocation|package|plugin|extension --cert SERIAL [--key-env NAME | --key-file F] FILE
//        -> stdout: the .wsig  {"cert","ed25519","second"}
//   woltrust-stub issue --body BODY.json [--proof PROOF.json] --key-env NAME|--key-file F
//        -> stdout: the .wolcert {"format":1,"body":b64url(exact bytes),"sig":{"ed25519","second"}}
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs, die } from "./lib.mjs";
import { testKey } from "./test-keys.mjs";

const LABELS = { cert: "wolos/cert/1", package: "wolos/package/1", plugin: "wolos/plugin/1", extension: "wolos/extension/1", index: "wolos/index/1", revocation: "wolos/revocation/1" };
const STUB_SECOND = Buffer.from("woltrust-stub: not a signature").toString("base64url");

function key(opts, fallback) {
  if (opts["key-env"]) {
    const pem = process.env[opts["key-env"]];
    return pem ? createPrivateKey(pem) : die(`${opts["key-env"]} is not set`);
  }
  if (opts["key-file"]) return createPrivateKey(readFileSync(opts["key-file"]));
  return testKey(fallback);
}

/** label || 0x00 || SHA-512(content): the one signed message of ADR 0046. */
const message = (label, content) => Buffer.concat([Buffer.from(label), Buffer.from([0]), createHash("sha512").update(content).digest()]);

const { opts, rest } = parseArgs(process.argv.slice(2));
const [cmd, file] = rest;
try {
  if (cmd === "sign") {
    const label = LABELS[opts.purpose];
    if (!label || !/^[0-9a-f]{16}$/.test(opts.cert ?? "") || !file) die("usage: sign --purpose P --cert SERIAL FILE", 2);
    const ed = sign(null, message(label, readFileSync(file)), key(opts, "index")).toString("base64url");
    process.stdout.write(JSON.stringify({ cert: opts.cert, ed25519: ed, second: STUB_SECOND }));
  } else if (cmd === "issue") {
    if (!opts.body) die("usage: issue --body BODY.json", 2);
    const body = readFileSync(opts.body);
    const ed = sign(null, message(LABELS.cert, body), key(opts, "ca")).toString("base64url");
    process.stdout.write(JSON.stringify({ format: 1, body: body.toString("base64url"), sig: { ed25519: ed, second: STUB_SECOND } }));
  } else die("usage: woltrust-stub sign|issue ...", 2);
} catch (e) {
  die(e.message);
}
