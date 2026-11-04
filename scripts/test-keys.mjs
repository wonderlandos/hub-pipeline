#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Throw-away Ed25519 keys for local dry runs and this repository's CI, derived from fixed seeds so no
// private key is ever committed. They protect nothing and are labelled test everywhere.
//
//   test-keys.mjs <dir>     writes legacy.pem, index.pem, ca.pem (mode 600) and <name>.pub.hex (raw 32-byte public key)
//
// Seeds: legacy = [1;32], index = [2;32], ca = [3;32] (the Rust tests use [3;32] style seeds too).
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
export const SEEDS = { legacy: 1, index: 2, ca: 3 };

export const testKey = (name) => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, SEEDS[name])]), format: "der", type: "pkcs8" });
export const publicHex = (key) => createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write("usage: test-keys.mjs <dir>\n");
    process.exit(2);
  }
  mkdirSync(dir, { recursive: true });
  for (const name of Object.keys(SEEDS)) {
    const key = testKey(name);
    writeFileSync(join(dir, `${name}.pem`), key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
    writeFileSync(join(dir, `${name}.pub.hex`), publicHex(key) + "\n");
  }
}
