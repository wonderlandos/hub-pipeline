#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Throw-away keys for local dry runs and this repository's CI. Nothing here protects anything; no private key is
// ever committed: every key derives from a public name.
//
//   test-keys.mjs <dir>    writes (mode 600) legacy.pem + legacy.pub.hex, and index.key + authors.key with
//                          index.serial + authors.serial
//
// legacy:  Ed25519 from the seed [1;32] (the legacy key of the 0.12 index, index.json.sig).
// index:   woltrust key material of the TEST Index intermediate ("test-index" of woltrust::pki, the TEST authority
//          the woltrust vectors and hubcheck use): seed = SHA-512("woltrust/testseed/test-index")[0..32].
// authors: the same for the TEST Authors CA ("test-authors").
// Their certificates are fixtures/trust/ (test-root-a, test-index, test-authors; labels test-..., which every
// store refuses unless allow_test).
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const sha512 = (s) => createHash("sha512").update(s).digest();

export const legacyKey = () => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, 1)]), format: "der", type: "pkcs8" });
export const publicHex = (key) => createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
/** woltrust::pki::serial(name) */
export const testSerial = (name) => sha512(`woltrust/serial/${name}`).subarray(0, 8).toString("hex");
/** The key material text (woltrust::key::KeyMaterial) of woltrust::pki identity `name`. */
export const testKeyText = (name) => JSON.stringify({ format: 1, seed: sha512(`woltrust/testseed/${name}`).subarray(0, 32).toString("base64url"), second: "ml-dsa-65" });

export const TEST = { index: "test-index", authors: "test-authors" };

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write("usage: test-keys.mjs <dir>\n");
    process.exit(2);
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const legacy = legacyKey();
  writeFileSync(join(dir, "legacy.pem"), legacy.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  writeFileSync(join(dir, "legacy.pub.hex"), publicHex(legacy) + "\n");
  for (const [role, name] of Object.entries(TEST)) {
    writeFileSync(join(dir, `${role}.key`), testKeyText(name), { mode: 0o600 });
    writeFileSync(join(dir, `${role}.serial`), testSerial(name) + "\n");
  }
}
