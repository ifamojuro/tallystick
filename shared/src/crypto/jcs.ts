// RFC 8785 (JCS) canonical JSON, implemented in-module: signed bytes must
// not depend on a third crypto-adjacent dependency.
//
// JCS = JSON with: object keys sorted by UTF-16 code units, ECMAScript
// number serialization, standard JSON string escaping, no whitespace.
// JSON.stringify already implements the number and string rules; the work
// here is recursion, key sorting, and rejecting non-JSON values loudly.

import { EncodingError } from "./errors.ts";

export type JsonValue =
  null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new EncodingError("JCS: NaN/Infinity are not JSON");
    }
    return JSON.stringify(value); // ECMAScript number-to-string, per JCS
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object") {
    // default sort compares UTF-16 code units — exactly JCS key order
    const keys = Object.keys(value).sort();
    const parts = keys.map((k) => {
      const v = value[k];
      if (v === undefined) {
        throw new EncodingError(`JCS: undefined value at key "${k}"`);
      }
      return JSON.stringify(k) + ":" + canonicalJson(v);
    });
    return "{" + parts.join(",") + "}";
  }
  throw new EncodingError(`JCS: unsupported type ${typeof value}`);
}

const encoder = new TextEncoder();

/** Canonical UTF-8 bytes of a JSON value — the input to every signature and keyed tag. */
export function canonicalize(value: JsonValue): Uint8Array {
  return encoder.encode(canonicalJson(value));
}
