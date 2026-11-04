// SPDX-License-Identifier: GPL-2.0-or-later
// The listing facts hubcheck reads from the package (report key facts, hubcheck f2bce73+; wonderlandos/hub
// wasm/README.md) cut down to exactly what the Worker's metaOf takes (hub-worker src/pipeline.ts): name (80, one
// line), summary (200, one line), description (4000), icon and up to 8 screenshots as {path, mime, w, h, size,
// sha256}. A field the Worker would refuse is left out here (one bad field must not cost the whole batch its
// verdicts). categories, homepage and licence are not kept by the Worker and are not sent.
//
// The pictures themselves: hubcheck extract writes them as <sha256>.<png|webp> (the Worker's `file` name,
// listings.ts pictureView); keepPictures() drops every reference whose bytes are not there, with that hash, size,
// type and pixel size, so a listing never points at a picture the CDN does not have.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export const MAX_SCREENSHOTS = 8;
export const MAX_PICTURE = 2 * 1024 * 1024;
const MIMES = { "image/png": "png", "image/webp": "webp" };
const HEX64 = /^[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/; // C1 too, as the Worker and the Rust readers
const PATH_CONTROL = /[\u0000-\u001f\u007f]/;

const text = (v, max, oneLine) => {
  if (typeof v !== "string") return undefined;
  const s = v.trim();
  if (!s || s.length > max || CONTROL.test(s) || (oneLine && /[\n\r\t]/.test(s))) return undefined;
  return s;
};

/** One picture reference in the Worker's shape, or null. */
export function cleanPicture(p) {
  if (!p || typeof p !== "object" || Array.isArray(p)) return null;
  const ok = typeof p.sha256 === "string" && HEX64.test(p.sha256) && Object.hasOwn(MIMES, p.mime)
    && typeof p.path === "string" && p.path.length >= 1 && p.path.length <= 200 && !PATH_CONTROL.test(p.path)
    && [p.w, p.h].every((n) => Number.isSafeInteger(n) && n >= 1 && n <= 4096)
    && Number.isSafeInteger(p.size) && p.size >= 1 && p.size <= MAX_PICTURE;
  return ok ? { path: p.path, mime: p.mime, w: p.w, h: p.h, size: p.size, sha256: p.sha256 } : null;
}

/** The CDN and extract name of a picture: <sha256>.<png|webp>. */
export const pictureFile = (p) => `${p.sha256}.${MIMES[p.mime]}`;

/** hubcheck's facts in the shape metaOf takes, or undefined when nothing is left. */
export function cleanFacts(f) {
  if (!f || typeof f !== "object" || Array.isArray(f)) return undefined;
  const out = {};
  const name = text(f.name, 80, true), summary = text(f.summary, 200, true), description = text(f.description, 4000, false);
  if (name) out.name = name;
  if (summary) out.summary = summary;
  if (description) out.description = description;
  const icon = cleanPicture(f.icon);
  if (icon) out.icon = icon;
  if (Array.isArray(f.screenshots)) {
    const shots = f.screenshots.slice(0, MAX_SCREENSHOTS).map(cleanPicture).filter(Boolean);
    if (shots.length) out.screenshots = shots;
  }
  return Object.keys(out).length ? out : undefined;
}

/** [mime, w, h] read from the header of PNG or WebP bytes, else null (the same reading as the hub site's facts.mjs). */
export function header(b) {
  if (b.length > 24 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    && b.toString("latin1", 12, 16) === "IHDR") return ["image/png", b.readUInt32BE(16), b.readUInt32BE(20)];
  if (b.length > 30 && b.toString("latin1", 0, 4) === "RIFF" && b.toString("latin1", 8, 12) === "WEBP") {
    const id = b.toString("latin1", 12, 16), d = 20;
    if (id === "VP8X") return ["image/webp", b.readUIntLE(d + 4, 3) + 1, b.readUIntLE(d + 7, 3) + 1];
    if (id === "VP8L") { const v = b.readUInt32LE(d + 1); return ["image/webp", (v & 0x3fff) + 1, ((v >> 14) & 0x3fff) + 1]; }
    if (id === "VP8 ") return ["image/webp", b.readUInt16LE(d + 6) & 0x3fff, b.readUInt16LE(d + 8) & 0x3fff];
  }
  return null;
}

/** True when <dir>/<sha256>.<ext> holds exactly the picture the reference names. */
export function pictureThere(dir, p) {
  const f = join(dir, pictureFile(p));
  if (!existsSync(f) || statSync(f).size !== p.size) return false; // size first: never read a huge file whole
  const b = readFileSync(f);
  if (b.length !== p.size || createHash("sha256").update(b).digest("hex") !== p.sha256) return false;
  const h = header(b);
  return !!h && h[0] === p.mime && h[1] === p.w && h[2] === p.h;
}

/** The facts with only the pictures whose bytes are in dir (no dir: no pictures at all). */
export function keepPictures(facts, dir) {
  if (!facts) return facts;
  const out = { ...facts };
  if (out.icon && !(dir && pictureThere(dir, out.icon))) delete out.icon;
  if (out.screenshots) {
    out.screenshots = out.screenshots.filter((s) => dir && pictureThere(dir, s));
    if (!out.screenshots.length) delete out.screenshots;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Every picture a list of verdicts names, by file name. */
export const picturesOf = (verdicts) => {
  const names = new Set();
  for (const v of verdicts) for (const p of [v.facts?.icon, ...(v.facts?.screenshots ?? [])]) if (p) names.add(pictureFile(p));
  return [...names].sort();
};
