#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// What a 0.12 client does with index.json, in Node (a port of crates/wopkg/src/index/plugins.rs `verify` and
// `parse_full`, the wolos checkout at 8ff1148): the Ed25519 signature over the exact bytes first, then format 1, then
// each plugin entry on its own rules (a bad one is dropped, the rest stays). Unknown keys are ignored, as there.
// The real Rust test of the same thing is in README, "Checked against the 0.12 reader".
//
//   legacy-check.mjs <index.json> <index.json.sig> <ed25519 public key, 64 hex>     exit 0 when verified and parsed
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { die } from "./lib.mjs";

const KINDS = ["menubar", "dock", "widget", "panel", "search", "tile", "toggle", "hotkey", "webapp", "theme", "look", "hypr"];
const PERMS = ["notifications", "run", "http", "clipboard", "open", "toggles"];
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const text_ok = (s, max) => typeof s === "string" && Buffer.byteLength(s) <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(s);
const hex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const is_version = (s) => typeof s === "string" && s.length > 0 && s.length <= 64 && /^[A-Za-z0-9][A-Za-z0-9._,+~-]*$/.test(s);
const is_plugin_id = (s) => typeof s === "string" && s.length > 0 && s.length <= 64 && s.split(".").length >= 2 && s.split(".").every((p) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(p));
const url_ok = (s) => typeof s === "string" && s.length <= 512 && /^https:\/\/[^/]+\/\S*\.wolplug$/.test(s) && /^[\x21-\x7e]*$/.test(s);
const wolos_version = (s) => /^[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,4})?$/.test(s);

export function entryValid(e) {
  return is_plugin_id(e.id) && !e.id.startsWith("org.wolos.") && typeof e.name === "string" && e.name.trim() !== "" && text_ok(e.name, 40) &&
    is_version(e.version) && text_ok(e.summary ?? "", 200) && text_ok(e.author ?? "", 200) && text_ok(e.license ?? "", 64) &&
    Array.isArray(e.kinds) && e.kinds.length > 0 && e.kinds.length <= 16 && e.kinds.every((k) => KINDS.includes(k)) &&
    (e.permissions ?? []).length <= 16 && (e.permissions ?? []).every((p) => PERMS.includes(p)) &&
    ((e.min_wolos ?? "") === "" || wolos_version(e.min_wolos)) && url_ok(e.url) && hex64(e.sha256) &&
    Number.isInteger(e.size) && e.size > 0 && e.size <= 2 << 20;
}

try {
  const [file, sigFile, pub] = process.argv.slice(2);
  if (!file || !sigFile || !/^[0-9a-f]{64}$/.test(pub ?? "")) die("usage: legacy-check.mjs <index.json> <index.json.sig> <pubkey hex>", 2);
  const bytes = readFileSync(file);
  const sig = readFileSync(sigFile);
  if (bytes.length > 4 << 20) die("the plugin list is too large");
  if (sig.length !== 64) die("bad index signature size");
  const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pub, "hex")]), format: "der", type: "spki" });
  if (!verify(null, bytes, key, sig)) die("index signature not from a trusted key");
  const raw = JSON.parse(bytes.toString("utf8"));
  if (raw.format !== 1) die("the plugin list is in an unknown format");
  if (raw.serial !== undefined && !Number.isInteger(raw.serial)) die("serial is not an unsigned number");
  if (raw.expires !== undefined && !Number.isInteger(raw.expires)) die("expires is not an unsigned number");
  const kept = [];
  const seen = new Set();
  for (const e of Array.isArray(raw.plugins) ? raw.plugins : []) {
    if (kept.length >= 5000 || !e || typeof e !== "object") continue;
    if (entryValid(e) && !seen.has(e.id)) {
      seen.add(e.id);
      kept.push(e);
    }
  }
  const total = (raw.plugins ?? []).length;
  process.stdout.write(`0.12 reader: signature verified, format 1, serial ${raw.serial}, ${kept.length} of ${total} plugin entr${total === 1 ? "y" : "ies"} kept${kept.length ? `: ${kept.map((e) => e.id).join(", ")}` : ""}\n`);
} catch (e) {
  die(e.message);
}
