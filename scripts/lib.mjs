// SPDX-License-Identifier: GPL-2.0-or-later
// Shared helpers of the hub-pipeline scripts. No dependencies: Node 20 or later.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";

export const sha256Hex = (buf) => createHash("sha256").update(buf).digest("hex");

export const readJson = (path) => {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(`${path}: cannot be read (${e.code ?? e.message})`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${path}: is not JSON`);
  }
};

/** Atomic write: a half-written file never replaces a good one. */
export const writeAtomic = (path, data) => {
  const tmp = `${path}.tmp${process.pid}`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
};

/** Stable text of a JSON value: object keys keep the order the code built them in; one line per file, final newline. */
export const jsonText = (value, pretty = true) => JSON.stringify(value, null, pretty ? 2 : 0) + "\n";

/** Command line: `--name value` pairs and bare words. */
export const parseArgs = (argv, flags = []) => {
  const opts = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const name = a.slice(2);
      if (flags.includes(name)) opts[name] = true;
      else if (i + 1 < argv.length) opts[name] = argv[++i];
      else throw new Error(`${a} needs a value`);
    } else rest.push(a);
  }
  return { opts, rest };
};

export const die = (msg, code = 1) => {
  process.stderr.write(`${process.argv[1].split("/").pop()}: ${msg}\n`);
  process.exit(code);
};

export const nowSeconds = () => (process.env.HUB_NOW ? Number(process.env.HUB_NOW) : Math.floor(Date.now() / 1000));

/**
 * A small JSON Schema checker: the keywords the schemas in schema/ use and no others
 * (type, enum, const, pattern, min/max for strings, numbers, arrays, required, properties,
 * additionalProperties, items, $ref into #/$defs, allOf, oneOf, boolean schemas). An unknown
 * keyword is an error, so a schema never silently checks less than it says.
 */
const KNOWN = new Set([
  "$schema", "$id", "$defs", "$ref", "title", "description", "type", "enum", "const", "pattern",
  "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "required", "properties",
  "additionalProperties", "items", "allOf", "oneOf",
]);

const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);

export function validate(schema, value, root = schema, path = "$", errors = []) {
  if (schema === true) return errors;
  if (schema === false) {
    errors.push(`${path}: is not allowed here`);
    return errors;
  }
  for (const k of Object.keys(schema)) if (!KNOWN.has(k)) throw new Error(`schema keyword ${k} is not supported`);
  if (schema.$ref) {
    const m = /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(schema.$ref);
    if (!m || !root.$defs?.[m[1]]) throw new Error(`schema reference ${schema.$ref} is not known`);
    validate(root.$defs[m[1]], value, root, path, errors);
  }
  const t = typeOf(value);
  if (schema.type !== undefined) {
    const want = [].concat(schema.type);
    const ok = want.includes(t) || (t === "integer" && want.includes("number"));
    if (!ok) {
      errors.push(`${path}: is ${t}, expected ${want.join(" or ")}`);
      return errors;
    }
  }
  if (schema.const !== undefined && value !== schema.const) errors.push(`${path}: must be ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: must be one of ${schema.enum.join(", ")}`);
  if (typeof value === "string") {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) errors.push(`${path}: is shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) errors.push(`${path}: is longer than ${schema.maxLength}`);
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) errors.push(`${path}: does not match ${schema.pattern}`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: is below ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: is above ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path}: has fewer than ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: has more than ${schema.maxItems} items`);
    if (schema.items) value.forEach((v, i) => validate(schema.items, v, root, `${path}[${i}]`, errors));
  }
  if (t === "object") {
    for (const r of schema.required ?? []) if (!(r in value)) errors.push(`${path}: ${r} is missing`);
    const props = schema.properties ?? {};
    for (const [k, v] of Object.entries(value)) {
      if (k in props) validate(props[k], v, root, `${path}.${k}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: ${k} is not a known field`);
      else if (typeof schema.additionalProperties === "object") validate(schema.additionalProperties, v, root, `${path}.${k}`, errors);
    }
  }
  for (const s of schema.allOf ?? []) validate(s, value, root, path, errors);
  if (schema.oneOf) {
    const hits = schema.oneOf.filter((s) => validate(s, value, root, path, []).length === 0).length;
    if (hits !== 1) errors.push(`${path}: matches ${hits} of the allowed shapes, expected exactly 1`);
  }
  return errors;
}

/** The words of tools/woltrust.features (what the pinned woltrust can do beyond fe64176). WOLTRUST_FEATURES overrides (tests). */
export const woltrustFeatures = () => {
  if (process.env.WOLTRUST_FEATURES !== undefined) return new Set(process.env.WOLTRUST_FEATURES.split(/[\s,]+/).filter(Boolean));
  const file = new URL("../tools/woltrust.features", import.meta.url);
  return new Set(readFileSync(file, "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean));
};
