#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The sign job's pictures: every icon and screenshot the Worker's export names (apps, plugins, extensions; each
// {sha256, mime, w, h, size, file}) is taken from the public log's pictures/ (written there by check.yml's report
// job from hubcheck extract) and checked again (hash, size, type, pixel size) before publish.sh puts it on the CDN
// as plugins/pictures/<sha256>.<png|webp>. A picture that is missing or does not match is left out and named.
//
//   pictures.mjs stage --export export.json --from log/pictures --out work/out/pictures
import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { die, parseArgs, readJson } from "./lib.mjs";
import { cleanPicture, pictureFile, pictureThere } from "./facts.mjs";

/** Every picture reference of an export, cleaned, once each. */
export function exportPictures(exp) {
  const seen = new Map();
  for (const kind of ["apps", "plugins", "extensions"]) {
    for (const e of exp?.[kind] ?? []) {
      for (const raw of [e?.icon, ...(Array.isArray(e?.screenshots) ? e.screenshots : [])]) {
        const p = cleanPicture(raw && { path: pictureFile({ sha256: raw.sha256, mime: raw.mime }), ...raw });
        if (p && !seen.has(p.sha256)) seen.set(p.sha256, { ...p, id: e.id });
      }
    }
  }
  return [...seen.values()];
}

try {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  if (rest[0] !== "stage" || !opts.export || !opts.from || !opts.out) die("usage: pictures.mjs stage --export export.json --from dir --out dir", 2);
  let staged = 0;
  for (const p of exportPictures(readJson(opts.export))) {
    if (!pictureThere(opts.from, p)) { process.stderr.write(`::warning::${p.id}: picture ${pictureFile(p)} is not in ${opts.from} with its hash and size; left out\n`); continue; }
    mkdirSync(opts.out, { recursive: true });
    copyFileSync(join(opts.from, pictureFile(p)), join(opts.out, pictureFile(p)));
    staged++;
  }
  process.stdout.write(`${staged} picture(s) staged\n`);
} catch (e) {
  die(e.message);
}
