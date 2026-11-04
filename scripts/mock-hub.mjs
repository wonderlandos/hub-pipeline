#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// A stand-in for the hub Worker's pipeline endpoints, for local dry runs only (127.0.0.1).
// It keeps the Worker's separation of duties: the "check" token reads pending and posts verdicts,
// the "sign" token exports, and neither may do the other's job. It checks the shape of a verdict
// like the Worker does (pipeline.ts). Real OIDC checking is the Worker's and is NOT done here.
//
//   mock-hub.mjs --port 8787 --pending f --export f --received f
import { createServer } from "node:http";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "./lib.mjs";

const { opts } = parseArgs(process.argv.slice(2));
const pending = readFileSync(opts.pending, "utf8");
const exported = readFileSync(opts.export, "utf8");
writeFileSync(opts.received, "");
const HEX64 = /^[0-9a-f]{64}$/;
const VERDICTS = ["pass", "flag", "block", "not-checked"];

const send = (res, code, body) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};
const deny = (res, code, error, sentence) => send(res, code, { error, sentence });

createServer((req, res) => {
  const who = { "Bearer check-token": "check", "Bearer sign-token": "sign" }[req.headers.authorization ?? ""];
  if (!who) return deny(res, 401, "pipeline-token", "The pipeline token was refused: not a token.");
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const url = req.url;
    if (req.method === "GET" && url === "/api/pipeline/pending") return who === "check" ? send(res, 200, pending) : deny(res, 401, "pipeline-token", "The pipeline token was refused: wrong workflow.");
    if (req.method === "GET" && url === "/api/pipeline/export") return who === "sign" ? send(res, 200, exported) : deny(res, 401, "pipeline-token", "The pipeline token was refused: wrong workflow.");
    if (req.method === "POST" && url === "/api/pipeline/verdicts") {
      if (who !== "check") return deny(res, 401, "pipeline-token", "The pipeline token was refused: wrong workflow.");
      let b;
      try {
        b = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return deny(res, 400, "bad-json", "Send a JSON body.");
      }
      if (!Array.isArray(b.verdicts) || b.verdicts.length < 1 || b.verdicts.length > 100) return deny(res, 400, "bad-verdicts", "Send 'verdicts' as a list of 1 to 100 entries.");
      const results = [];
      for (const v of b.verdicts) {
        if (!VERDICTS.includes(v.verdict)) return deny(res, 400, "bad-verdict", "verdict is pass, flag, block or not-checked.");
        if (v.sha256 == null && v.verdict !== "not-checked") return deny(res, 400, "bad-sha256", "Only a not-checked verdict may come without sha256.");
        if (v.sha256 != null && !HEX64.test(v.sha256)) return deny(res, 400, "bad-sha256", "sha256 is 64 hex digits.");
        if (!Array.isArray(v.findings ?? []) || (v.findings ?? []).length > 200) return deny(res, 400, "bad-findings", "findings is a list of at most 200 entries.");
        appendFileSync(opts.received, JSON.stringify(v) + "\n");
        results.push({ listing_id: v.listing_id, version: v.version, stored: v.verdict });
      }
      return send(res, 200, { results });
    }
    deny(res, 404, "not-found", "There is nothing here.");
  });
}).listen(Number(opts.port ?? 8787), "127.0.0.1", () => process.stdout.write(`mock hub on ${opts.port ?? 8787}\n`));
