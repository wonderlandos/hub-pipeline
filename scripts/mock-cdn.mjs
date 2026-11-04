#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// A stand-in for the WolOS CDN's upload and read side, for local tests only (127.0.0.1): what tools/cdn-put speaks
// (PUT parts with Content-Range, POST ?complete=1 with X-Content-Sha256, the Bearer token) and what publish.sh reads
// back (GET with the type the real server gives: wolos-cdn bucket.rs serve, tower-http ServeFile, types a file by its
// extension). --png-type TYPE serves .png files with another type, so a test can see publish.sh refuse it.
// The real server's storage, cache and limits are NOT modelled.
//
//   mock-cdn.mjs --port 18790 --token T [--png-type TYPE]
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { parseArgs } from "./lib.mjs";

const { opts } = parseArgs(process.argv.slice(2));
const TYPES = { png: opts["png-type"] ?? "image/png", webp: "image/webp", json: "application/json" };
const files = new Map(); // path -> Buffer
const uploads = new Map(); // path -> { size, parts: [[start, Buffer]] }

createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const path = url.pathname;
  const end = (code, body = "", type = "text/plain") => { res.writeHead(code, { "content-type": type, "x-content-type-options": "nosniff" }); res.end(body); };
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    if (req.method === "GET" || req.method === "HEAD") {
      const f = files.get(path);
      if (!f) return end(404, "not found\n");
      const ext = path.split(".").pop();
      res.writeHead(200, { "content-type": TYPES[ext] ?? "application/octet-stream", "content-length": f.length, "x-content-type-options": "nosniff" });
      return res.end(req.method === "HEAD" ? undefined : f);
    }
    if (req.headers.authorization !== `Bearer ${opts.token}`) return end(401, "unauthorized\n");
    if (req.method === "PUT") {
      const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(req.headers["content-range"] ?? "");
      if (!m) { files.set(path, body); return end(201); }
      const u = uploads.get(path) ?? { size: Number(m[3]), parts: [] };
      u.parts.push([Number(m[1]), body]);
      uploads.set(path, u);
      return end(202);
    }
    if (req.method === "POST" && url.searchParams.get("complete") === "1") {
      const u = uploads.get(path);
      if (!u) return end(404, "no upload\n");
      const whole = Buffer.alloc(u.size);
      for (const [at, b] of u.parts) b.copy(whole, at);
      const sum = createHash("sha256").update(whole).digest("hex");
      if (sum !== req.headers["x-content-sha256"]) return end(422, "sha256 mismatch\n");
      uploads.delete(path);
      files.set(path, whole);
      return end(201, JSON.stringify({ path, size: whole.length, sha256: sum }), "application/json");
    }
    if (req.method === "DELETE") { uploads.delete(path); return end(204); }
    end(405, "method not allowed\n");
  });
}).listen(Number(opts.port), "127.0.0.1");
