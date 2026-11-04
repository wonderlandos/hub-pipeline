#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The sign job's own look at GitHub (ADR 0047, publish flow step 5): every entry that is new since the
// last signed index is checked against GitHub itself, so a Worker that was taken over cannot attach a
// release to somebody else's id. Entries that fail are left out of the export and named in the log.
//
//   verify-owners.mjs --export export.json --previous signed/index.json --out export.checked.json
//                     [--fixture github.json]        (HUB_TEST=1 only: no network, answers from the file)
//
// For a new or changed entry:
//   1. repository by NUMERIC id (/repositories/<repo_id>): full_name is source.repo, the owner's numeric id is
//      owner.github_id (owner.kind person or org); the repository is public and not archived-away (not 404);
//   2. the release at source.tag is published (not a draft) and has an asset whose download URL is the entry's
//      url and whose size is the entry's size;
//   3. if the id was listed before, its owner id is the same one (an id never changes hands here).
// Entries owned by WolOS (org.wolos.*) are checked the same way against the numeric id of the organisation.
// An answer that is not a clear yes (404, 5xx, no answer) leaves the entry out until the next run.
import { existsSync } from "node:fs";
import { die, jsonText, parseArgs, readJson, writeAtomic } from "./lib.mjs";

const API = "https://api.github.com";

function makeGithub(fixturePath) {
  if (fixturePath) {
    if (process.env.HUB_TEST !== "1") throw new Error("--fixture is for local dry runs (HUB_TEST=1)");
    const fx = readJson(fixturePath);
    return {
      repo: async (id) => fx.repos?.[id] ?? null,
      release: async (repo, tag) => fx.releases?.[`${repo.toLowerCase()}@${tag}`] ?? null,
    };
  }
  const token = process.env.GITHUB_TOKEN;
  const get = async (path) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt) await new Promise((r) => setTimeout(r, 2000 * attempt));
      try {
        const res = await fetch(`${API}${path}`, {
          headers: { accept: "application/vnd.github+json", "x-github-version": "2022-11-28", "user-agent": "wolos-hub-index", ...(token ? { authorization: `Bearer ${token}` } : {}) },
          signal: AbortSignal.timeout(30_000),
        });
        if (res.status === 404) return null;
        if (res.ok) return await res.json();
      } catch {
        /* try again */
      }
    }
    throw new Error(`GitHub did not answer ${path}`);
  };
  return {
    repo: (id) => get(`/repositories/${id}`),
    release: (repo, tag) => get(`/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`),
  };
}

const same = (a, b) => a && b && a.id === b.id && a.version === b.version && a.sha256 === b.sha256 && a.url === b.url &&
  a.owner.github_id === b.owner.github_id && a.source.repo_id === b.source.repo_id;

export async function verifyEntry(e, previous, gh) {
  if (previous && previous.owner.github_id !== e.owner.github_id) return "the id was listed before under another owner";
  if (same(previous, e)) return null;
  const repo = await gh.repo(e.source.repo_id);
  if (!repo) return "GitHub has no repository with that numeric id";
  if (repo.private) return "the repository is not public";
  if (String(repo.full_name).toLowerCase() !== e.source.repo.toLowerCase()) return `the repository is now ${repo.full_name}, not ${e.source.repo}`;
  if (repo.owner?.id !== e.owner.github_id) return "the repository belongs to another GitHub account than the listed owner";
  const rel = await gh.release(e.source.repo, e.source.tag);
  if (!rel || rel.draft) return "there is no published release at that tag";
  const asset = (rel.assets ?? []).find((a) => a.browser_download_url === e.url);
  if (!asset) return "the release has no file at the listed URL";
  if (asset.size !== e.size) return "the file on GitHub has another size than the listed one";
  return null;
}

async function main() {
  const { opts } = parseArgs(process.argv.slice(2));
  if (!opts.export || !opts.out) die("usage: verify-owners.mjs --export f --previous f --out f [--fixture f]", 2);
  const exp = readJson(opts.export);
  const prevIndex = opts.previous && existsSync(opts.previous) ? readJson(opts.previous) : null;
  const prev = new Map();
  for (const k of ["apps", "plugins", "extensions"]) for (const e of prevIndex?.[k] ?? []) prev.set(e.id, e);
  const gh = makeGithub(opts.fixture);
  const out = { ...exp };
  let dropped = 0;
  for (const k of ["apps", "plugins", "extensions"]) {
    out[k] = [];
    for (const e of exp[k] ?? []) {
      let why;
      try {
        why = await verifyEntry(e, prev.get(e.id), gh);
      } catch (err) {
        why = err.message;
      }
      if (why) {
        dropped++;
        process.stderr.write(`::warning::left out ${e.id} ${e.version}: ${why}\n`);
      } else out[k].push(e);
    }
  }
  writeAtomic(opts.out, jsonText(out));
  process.stdout.write(`owners: ${dropped} entr${dropped === 1 ? "y" : "ies"} left out\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => die(e.message));
