// Crockford base32 for the printed formats: no I, L, O, U in
// the alphabet; decoding folds case and maps the confusables back.

import { EncodingError } from "./errors.ts";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function crockfordEncode(bytes: Uint8Array): string {
  let acc = 0;
  let bits = 0;
  let out = "";
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

export function crockfordDecode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  let acc = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new EncodingError(`invalid character "${ch}" in printed code`);
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bytes.push((acc >> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(bytes);
}
