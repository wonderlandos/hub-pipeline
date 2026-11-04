#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The pipeline's side of the hub Worker's API (I4/I9). No shared secret: the caller proves who it
// is with the OIDC token GitHub issues to this very job (audience hub.wolos.org), which the
// Worker checks against repository, workflow, environment and branch.
//
//   api.mjs pending  --out pending.json        GET  /api/pipeline/pending   (check)
//   api.mjs verdicts --in verdicts.json        POST /api/pipeline/verdicts  (check)
//   api.mjs export   --out export.json         GET  /api/pipeline/export    (sign)
//
// HUB_API        base URL, default https://hub.wolos.org (https only; http://127.0.0.1 only with HUB_TEST=1)
// HUB_TOKEN      a token to use as is (tests); otherwise one is requested from GitHub for this job
// HUB_AUDIENCE   default hub.wolos.org
import { readJson, writeAtomic, jsonText, parseArgs, die } from "./lib.mjs";

const AUDIENCE = process.env.HUB_AUDIENCE ?? "hub.wolos.org";
const BASE = (process.env.HUB_API ?? "https://hub.wolos.org").replace(/\/+$/, "");
const MAX_BODY = 8 << 20;
const BATCH = 50; // the Worker takes 1..100 and 256 KiB per call

export function checkBase(base, test) {
  const u = new URL(base);
  const local = u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
  if (u.protocol !== "https:" && !(local && test)) throw new Error(`${base}: the hub is reached over https only`);
}

async function token() {
  if (process.env.HUB_TOKEN) return process.env.HUB_TOKEN;
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) throw new Error("no OIDC token available: the job needs `permissions: id-token: write`");
  const res = await fetch(`${url}${url.includes("?") ? "&" : "?"}audience=${encodeURIComponent(AUDIENCE)}`, {
    headers: { authorization: `bearer ${bearer}`, accept: "application/json" },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`GitHub refused the OIDC token request (${res.status})`);
  const { value } = await res.json();
  if (typeof value !== "string" || value.split(".").length !== 3) throw new Error("GitHub sent no token");
  process.stdout.write(`::add-mask::${value}\n`); // never in a log, whatever happens next
  return value;
}

async function call(method, path, body) {
  checkBase(BASE, process.env.HUB_TEST === "1");
  const jwt = await token();
  let last = "";
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt) await new Promise((r) => setTimeout(r, 2000 * attempt));
    let res;
    try {
      res = await fetch(`${BASE}${path}`, {
        method,
        headers: { authorization: `Bearer ${jwt}`, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(60_000),
      });
    } catch (e) {
      last = `no answer (${e.cause?.code ?? e.name})`;
      continue;
    }
    const text = await res.text();
    if (text.length > MAX_BODY) throw new Error("the Worker's answer is too large");
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      /* an error page, not ours */
    }
    if (res.ok && data) return data;
    last = `${res.status} ${data?.sentence ?? data?.error ?? "no sentence"}`;
    if (res.status !== 429 && res.status < 500) break; // 4xx is final: the token or the body is wrong
  }
  throw new Error(`${method} ${path}: ${last}`);
}

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  const [cmd] = rest;
  if (cmd === "pending") {
    if (!opts.out) die("pending needs --out", 2);
    const data = await call("GET", "/api/pipeline/pending");
    if (!Array.isArray(data.releases)) throw new Error("the answer has no releases list");
    writeAtomic(opts.out, jsonText(data));
    process.stdout.write(`${data.releases.length} release(s) waiting\n`);
  } else if (cmd === "verdicts") {
    if (!opts.in) die("verdicts needs --in", 2);
    const { verdicts } = readJson(opts.in);
    if (!Array.isArray(verdicts)) throw new Error(`${opts.in}: no verdicts list`);
    const results = [];
    for (let i = 0; i < verdicts.length; i += BATCH) {
      const r = await call("POST", "/api/pipeline/verdicts", { verdicts: verdicts.slice(i, i + BATCH) });
      results.push(...r.results);
    }
    for (const r of results) process.stdout.write(`${r.listing_id} ${r.version}: ${r.stored}\n`);
    if (opts.out) writeAtomic(opts.out, jsonText({ results }));
  } else if (cmd === "export") {
    if (!opts.out) die("export needs --out", 2);
    const data = await call("GET", "/api/pipeline/export");
    if (data.preview !== false) throw new Error("the export is marked as a preview; not signing it");
    writeAtomic(opts.out, jsonText(data));
    process.stdout.write(`export: ${data.apps.length} app(s), ${data.plugins.length} plugin(s), ${data.extensions.length} extension(s)\n`);
  } else die("usage: api.mjs pending|verdicts|export ...", 2);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => die(e.message));
