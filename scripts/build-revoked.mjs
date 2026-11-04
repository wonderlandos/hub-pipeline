#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// revocations.json (the entries, appended by the ca workflow) -> revoked.json (the bytes that get signed).
//
//   build-revoked.mjs --source revocations.json --previous signed/revoked.json --out revoked.json [--now unix]
//
// {format:1, serial, issued, expires = issued + 7 days, entries:[{serial, at, reason}]}, the exact shape
// of woltrust revoked.rs (unknown keys are refused there). The serial grows with every publication.
// Re-issued at least daily by sign.yml, so a list never goes stale while the pipeline lives.
import { existsSync } from "node:fs";
import { die, jsonText, nowSeconds, parseArgs, readJson, writeAtomic } from "./lib.mjs";
import { checkRevoked } from "./validate.mjs";

const WEEK = 7 * 86400;

export function buildRevoked(source, previousSerial, now) {
  if (source.format !== 1 || !Array.isArray(source.entries)) throw new Error("revocations.json: expected {format:1, entries:[...]}");
  const entries = source.entries
    .map(({ serial, at, reason }) => ({ serial, at, reason }))
    .sort((a, b) => a.at - b.at || (a.serial < b.serial ? -1 : 1));
  const list = { format: 1, serial: previousSerial + 1, issued: now, expires: now + WEEK, entries };
  const errors = checkRevoked(list);
  if (errors.length) throw new Error(errors.join("; "));
  return list;
}

function main() {
  const { opts } = parseArgs(process.argv.slice(2));
  if (!opts.source || !opts.out) die("usage: build-revoked.mjs --source revocations.json [--previous signed/revoked.json] --out revoked.json", 2);
  const prev = opts.previous && existsSync(opts.previous) ? readJson(opts.previous).serial : 0;
  if (!Number.isSafeInteger(prev) || prev < 0) die(`${opts.previous}: no usable serial`);
  const list = buildRevoked(readJson(opts.source), prev, opts.now ? Number(opts.now) : nowSeconds());
  writeAtomic(opts.out, jsonText(list));
  process.stdout.write(`revoked.json: serial ${list.serial}, ${list.entries.length} entr${list.entries.length === 1 ? "y" : "ies"}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (e) {
    die(e.message);
  }
}
