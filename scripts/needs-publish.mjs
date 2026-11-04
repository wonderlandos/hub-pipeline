#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Decides whether the signed copy must be replaced: yes when the listings or the revocations changed, or when the
// last one is older than MAX_AGE (default 20 hours: an index is re-signed at least daily, it expires in 7 days).
//
//   needs-publish.mjs --index new/index.json --revoked new/revoked.json --previous signed [--force] [--now unix]
//   prints "yes <why>" or "no <why>", exit 0 either way.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { nowSeconds, parseArgs, readJson, die } from "./lib.mjs";

const MAX_AGE = Number(process.env.MAX_AGE ?? 20 * 3600);
const body = (i) => JSON.stringify([i.apps, i.plugins, i.extensions, i.intermediates ?? []]);

try {
  const { opts } = parseArgs(process.argv.slice(2), ["force"]);
  if (!opts.index || !opts.revoked || !opts.previous) die("usage: needs-publish.mjs --index f --revoked f --previous dir [--force]", 2);
  const now = opts.now ? Number(opts.now) : nowSeconds();
  const pi = join(opts.previous, "index.json");
  const pr = join(opts.previous, "revoked.json");
  const say = (yes, why) => process.stdout.write(`${yes ? "yes" : "no"} ${why}\n`);
  if (opts.force) say(true, "forced");
  else if (!existsSync(pi) || !existsSync(pr)) say(true, "nothing was published yet");
  else {
    const [a, b, ra, rb] = [readJson(opts.index), readJson(pi), readJson(opts.revoked), readJson(pr)];
    if (body(a) !== body(b)) say(true, "the listings changed");
    else if (JSON.stringify(ra.entries) !== JSON.stringify(rb.entries)) say(true, "the revocations changed");
    else if (now - b.issued >= MAX_AGE) say(true, "the signed copy is a day old");
    else say(false, "nothing changed and the signed copy is recent");
  }
} catch (e) {
  die(e.message);
}
