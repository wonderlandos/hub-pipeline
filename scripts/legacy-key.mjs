#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// The legacy Ed25519 index key (index.json.sig, the reader of WolOS 0.12 and 0.13: raw Ed25519 over the bytes of index.json
// by any key in /usr/share/wolos/keys) taken from the Index intermediate's own key, so the sign job needs no second secret.
//
//   legacy-key.mjs derive (--key-env NAME | --key-file F) [--passphrase-env NAME] --cert SERIAL --intermediates DIR --out F.pem
//       Opens the Index key material (plain, or a locked .wolkey, as `woltrust sign` does), derives its Ed25519 half and
//       writes it as PKCS#8 PEM (mode 600) to --out. It refuses unless that half is keys.ed25519 of the PUBLIC certificate
//       SERIAL in DIR: a key that is not the certificate's never signs.
//   legacy-key.mjs pub <certificate.wolcert>
//       Prints the certificate's Ed25519 public key as PEM SPKI (what `openssl pkey -pubout` prints: the format of
//       /usr/share/wolos/keys/*.pub). Public data only.
//
// woltrust (crates/woltrust key.rs, wolkey.rs; crates/wolcrypt lib.rs derive, sign.rs SigningKey::from_seed, at tools/woltrust.rev):
//   key material  {"format":1,"seed":"<b64url 32>","second":"ml-dsa-65"}
//   .wolkey       {"format":1,"name":SERIAL,"kdf":"pbkdf2-hmac-sha512","rounds":N,"salt","aead":"chacha20-poly1305","nonce","sealed"}
//                 key = PBKDF2-HMAC-SHA512(passphrase, salt, N, 32); aad = "wolos/wolkey/1" 0 name 0 decimal(N) 0 salt;
//                 sealed = ChaCha20-Poly1305(key material text) || tag(16)
//   Ed25519 half  the Ed25519 key whose 32-byte seed is SHA-512("woltrust/ed25519" 0x00 seed)[0..32]
// Nothing secret is ever printed; a refusal names the step, not the material.
import { createDecipheriv, createHash, createPrivateKey, createPublicKey, pbkdf2Sync } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const MIN_ROUNDS = 210000, MAX_ROUNDS = 10000000, MAX_TEXT = 4096;
const fail = (m, code = 1) => { process.stderr.write(`legacy-key: ${m}\n`); process.exit(code); };
const b64 = (s, n) => { if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) return null; const b = Buffer.from(s, "base64url"); return n === undefined || b.length === n ? b : null; };
const isSerial = (s) => typeof s === "string" && /^([0-9a-f]{16}|[0-9a-f]{128})$/.test(s);

/** The 32-byte seed of woltrust key material text (plain or a locked .wolkey stored under `name`). */
export function openKey(text, name, passphrase) {
  if (text.length > MAX_TEXT) throw new Error("the key material is too large");
  let j;
  try { j = JSON.parse(text.toString("utf8").trim()); } catch { throw new Error("the key material is not woltrust key material"); }
  if (j && typeof j === "object" && "kdf" in j) {
    const ok = j.format === 1 && j.kdf === "pbkdf2-hmac-sha512" && j.aead === "chacha20-poly1305" && isSerial(j.name) &&
      Number.isInteger(j.rounds) && j.rounds >= MIN_ROUNDS && j.rounds <= MAX_ROUNDS;
    if (!ok) throw new Error("the .wolkey is damaged");
    if (name !== undefined && j.name !== name) throw new Error("the .wolkey belongs to another certificate");
    if (typeof passphrase !== "string" || passphrase === "") throw new Error("the .wolkey is locked and no passphrase was given");
    const salt = b64(j.salt), nonce = b64(j.nonce, 12), sealed = b64(j.sealed);
    if (!salt || salt.length > 64 || !nonce || !sealed || sealed.length < 16) throw new Error("the .wolkey is damaged");
    const key = pbkdf2Sync(Buffer.from(passphrase, "utf8"), salt, j.rounds, 32, "sha512");
    const aad = Buffer.concat([Buffer.from("wolos/wolkey/1\0"), Buffer.from(j.name), Buffer.from([0]), Buffer.from(String(j.rounds)), Buffer.from([0]), salt]);
    const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d.setAAD(aad, { plaintextLength: sealed.length - 16 });
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    let plain;
    try { plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]); } catch { throw new Error("the passphrase does not open the .wolkey (or the file was changed)"); }
    key.fill(0);
    try { return openKey(plain, undefined, undefined); } finally { plain.fill(0); }
  }
  const keys = j && typeof j === "object" ? Object.keys(j).sort().join(",") : "";
  if (keys !== "format,second,seed" || j.format !== 1) throw new Error("the key material is not woltrust key material");
  if (j.second !== "ml-dsa-65") throw new Error("the key material is not an intermediate's (a root key never signs an index)");
  const seed = b64(j.seed, 32);
  if (!seed) throw new Error("the key material seed is malformed");
  return seed;
}

/** woltrust's Ed25519 half of `seed`: its private key object. */
export function ed25519Half(seed) {
  const ed = createHash("sha512").update("woltrust/ed25519").update(Buffer.from([0])).update(seed).digest().subarray(0, 32);
  try { return createPrivateKey({ key: Buffer.concat([PKCS8, ed]), format: "der", type: "pkcs8" }); } finally { ed.fill(0); }
}

/** keys.ed25519 of a .wolcert (32 bytes), with its serial. */
export function certEd25519(text) {
  const c = JSON.parse(text);
  const body = JSON.parse(Buffer.from(c.body, "base64url").toString("utf8"));
  const k = b64(body?.keys?.ed25519, 32);
  if (!k || !isSerial(body.serial)) throw new Error("the certificate has no Ed25519 key");
  return { serial: body.serial, key: k, usage: body.usage ?? [] };
}

export const pemOf = (raw) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: "der", type: "spki" }).export({ format: "pem", type: "spki" });
const rawOf = (key) => createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);

function opts(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--") || argv[i + 1] === undefined) fail(`unexpected ${argv[i]}`, 2);
    o[argv[i].slice(2)] = argv[i + 1];
  }
  return o;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "pub" && rest.length === 1) {
    try { process.stdout.write(pemOf(certEd25519(readFileSync(rest[0], "utf8")).key)); } catch (e) { fail(`${rest[0]}: ${e.message}`); }
  } else if (cmd === "derive") {
    const o = opts(rest);
    for (const k of ["cert", "intermediates", "out"]) if (!o[k]) fail(`give --${k}`, 2);
    if (!!o["key-env"] === !!o["key-file"]) fail("give --key-env NAME or --key-file F", 2);
    if (!isSerial(o.cert)) fail("--cert is a certificate id (128 hex, 16 for the TEST authority)", 2);
    const want = readdirSync(o.intermediates).filter((f) => f.endsWith(".wolcert")).map((f) => {
      try { return certEd25519(readFileSync(join(o.intermediates, f), "utf8")); } catch { return null; }
    }).find((c) => c && c.serial === o.cert);
    if (!want) fail(`no certificate ${o.cert} in ${o.intermediates}`);
    if (!want.usage.includes("sign-index")) fail(`certificate ${o.cert} may not sign an index`);
    let text;
    if (o["key-env"]) { text = process.env[o["key-env"]]; if (!text) fail(`${o["key-env"]} is not set`); text = Buffer.from(text, "utf8"); }
    else text = readFileSync(o["key-file"]);
    const pass = o["passphrase-env"] ? process.env[o["passphrase-env"]] : undefined;
    let key;
    try { const seed = openKey(text, o.cert, pass); key = ed25519Half(seed); seed.fill(0); } catch (e) { fail(e.message); }
    if (!rawOf(key).equals(want.key)) fail(`the key given is not the key of certificate ${o.cert} (its Ed25519 half differs)`);
    writeFileSync(o.out, key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
  } else fail("usage: legacy-key.mjs derive KEY --cert SERIAL --intermediates DIR --out F.pem | legacy-key.mjs pub CERT.wolcert", 2);
}
