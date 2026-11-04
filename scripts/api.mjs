#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The pipeline's side of the hub Worker's API (I4/I9). No shared secret: the caller proves who it
// is with the OIDC token GitHub issues to this very job (audience hub.wolos.org), which the
// Worker checks against repository, workflow, environment and branch.
//
//   api.mjs pending  --out pending.json        GET  /api/pipeline/pending   (check)
//   api.mjs verdicts --in verdicts.json        POST /api/pipeline/verdicts  (check)
//   api.mjs export   --out export.json         GET  /api/pipeline/export    (sign)
//   api.mjs request  --id ID --out requests/ID.json   GET  /api/pipeline/requests/ID   (ca: an approved issue request, or an
//                                              approved revocation / version withdrawal when ID starts with v-)
//   api.mjs issued   --in result.json          POST /api/pipeline/certs     (ca: {request_id, serial, tier, cert})
//   api.mjs revoked  --id ID --serial S        POST /api/pipeline/revocations  (ca: the revocation ID of S is on revocations.json)
//
// HUB_API        base URL, default https://hub.wolos.org (https only; http://127.0.0.1 only with HUB_TEST=1)
// HUB_TOKEN      a token to use as is (tests); otherwise one is requested from GitHub for this job
// HUB_AUDIENCE   default hub.wolos.org
import { readJson, writeAtomic, jsonText, parseArgs, die, isSerial } from "./lib.mjs";

const AUDIENCE = process.env.HUB_AUDIENCE ?? "hub.wolos.org";
const BASE = (process.env.HUB_API ?? "https://hub.wolos.org").replace(/\/+$/, "");
const MAX_BODY = 8 << 20;
const BATCH = 50; // the Worker takes 1..100 and 256 KiB per call
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/; // schema/request.schema.json, id

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
  } else if (cmd === "request") {
    if (!opts.id || !opts.out) die("request needs --id and --out", 2);
    if (!REQUEST_ID.test(opts.id)) throw new Error(`${opts.id}: not a request id`);
    const data = await call("GET", `/api/pipeline/requests/${opts.id}`);
    // The Worker answers with the request file itself; the ca workflow validates it against the schema next.
    // A v- id is a revocation (a certificate, or one version with reason withdrawn-version); every other id an issue request.
    const want = opts.id.startsWith("v-") ? "revoke" : "issue";
    if (data.id !== opts.id || data.action !== want) throw new Error(`the answer is not the ${want} request ${opts.id}`);
    writeAtomic(opts.out, jsonText(data));
    if (want === "revoke") process.stdout.write(`revocation ${opts.id}: ${data.serial} (${data.reason}), approved by ${(data.approved_by ?? []).join(", ") || "nobody"}\n`);
    else process.stdout.write(`request ${opts.id}: ${data.kind} ${data.subject?.login}, approved by ${(data.approved_by ?? []).join(", ") || "nobody"}\n`);
  } else if (cmd === "issued") {
    if (!opts.in) die("issued needs --in", 2);
    const r = readJson(opts.in);
    if (!REQUEST_ID.test(r.request_id ?? "") || !isSerial(r.serial) || typeof r.cert !== "string") throw new Error(`${opts.in}: not an issue result`);
    if (!["origin", "trusted"].includes(r.tier)) throw new Error(`${opts.in}: no tier`);
    await call("POST", "/api/pipeline/certs", { request_id: r.request_id, serial: r.serial, tier: r.tier, cert: r.cert });
    process.stdout.write(`the hub knows certificate ${r.serial} for request ${r.request_id}\n`);
  } else if (cmd === "revoked") {
    if (!opts.id || !opts.serial) die("revoked needs --id and --serial", 2);
    if (!REQUEST_ID.test(opts.id) || !opts.id.startsWith("v-")) throw new Error(`${opts.id}: not a revocation id`);
    if (!isSerial(opts.serial)) throw new Error(`${opts.serial}: not a certificate id or statement serial`);
    await call("POST", "/api/pipeline/revocations", { request_id: opts.id, serial: opts.serial });
    process.stdout.write(`the hub knows revocation ${opts.id} of ${opts.serial} is published\n`);
  } else die("usage: api.mjs pending|verdicts|export|request|issued|revoked ...", 2);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => die(e.message));
