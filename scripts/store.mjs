#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The trust store hubcheck checks signatures against (hubcheck README: `--store store.json`), from this repository's
// public files: the pinned roots, the known intermediates and the revocation list the sign job last published.
//
//   store.mjs --roots certs/roots [--intermediates certs/intermediates] [--list signed/revoked.json] [--allow-test] --out store.json
//
// --list reads <list> and <list>.wsig; a missing list is left out (hubcheck then says why a signature does not count).
// --allow-test lets the TEST root of woltrust count (labels test-...): dry runs and scripts/test.sh only.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { die, parseArgs, writeAtomic } from "./lib.mjs";

const certs = (dir) => (dir && existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".wolcert")).sort().map((f) => readFileSync(join(dir, f), "utf8")) : []);

export function buildStore({ roots, intermediates, list, allowTest }) {
  const revoked = list && existsSync(list) && existsSync(`${list}.wsig`) ? [{ list: readFileSync(list, "utf8"), wsig: readFileSync(`${list}.wsig`, "utf8") }] : [];
  return { roots: certs(roots), intermediates: certs(intermediates), allow_test: Boolean(allowTest), revoked };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const { opts } = parseArgs(process.argv.slice(2), ["allow-test"]);
    if (!opts.roots || !opts.out) die("usage: store.mjs --roots DIR [--intermediates DIR] [--list revoked.json] [--allow-test] --out store.json", 2);
    if (opts["allow-test"] && process.env.HUB_TEST !== "1" && process.env.DRY_RUN !== "1") die("--allow-test is for dry runs and tests only (HUB_TEST=1 or DRY_RUN=1)");
    const s = buildStore({ roots: opts.roots, intermediates: opts.intermediates, list: opts.list, allowTest: opts["allow-test"] });
    writeAtomic(opts.out, JSON.stringify(s) + "\n");
    process.stdout.write(`store: ${s.roots.length} root(s), ${s.intermediates.length} intermediate(s), ${s.revoked.length} revocation list(s)${s.allow_test ? ", TEST root allowed" : ""}\n`);
  } catch (e) {
    die(e.message);
  }
}
