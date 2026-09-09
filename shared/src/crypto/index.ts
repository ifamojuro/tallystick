// The crypto module.
// Wraps libsodium-wrappers-sumo 0.7.16 + @serenity-kit/opaque 0.8.4 and
// exposes only the operations the protocol needs. Nothing else
// imports the crypto libraries directly.
//
// Rules: callers never supply nonces; AAD is passed as
// structured objects and canonicalized here; no options, no algorithm
// choices; verification/decryption failure throws.

import _sodium from "libsodium-wrappers-sumo";
import * as opaqueLib from "@serenity-kit/opaque";
import { canonicalJson, canonicalize, type JsonObject, type JsonValue } from "./jcs.ts";
import { crockfordEncode, crockfordDecode } from "./base32.ts";
import { AuthFailed, BadSignature, ChecksumError, DecryptFailed, EncodingError } from "./errors.ts";

export { canonicalJson, canonicalize } from "./jcs.ts";
export type { JsonObject, JsonValue } from "./jcs.ts";
export * from "./errors.ts";

export interface BoxKeyPair {
  publicKey: Uint8Array; // 32B X25519
  privateKey: Uint8Array; // 32B
}

export interface SignKeyPair {
  publicKey: Uint8Array; // 32B Ed25519
  privateKey: Uint8Array; // 64B
}

// ---------------------------------------------------------------- init --

let sodium: typeof _sodium | undefined;

/** Must resolve before any other call; everything throws until it does. */
export async function init(): Promise<void> {
  await _sodium.ready;
  await opaqueLib.ready;
  sodium = _sodium;
}

function so(): typeof _sodium {
  if (!sodium) throw new Error("crypto module not initialized: await init() first");
  return sodium;
}

function assertLen(bytes: Uint8Array, len: number, what: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== len) {
    throw new EncodingError(`${what} must be ${len} bytes`);
  }
}

const KEY = 32;

// -------------------------------------------------------------- random --

export const newId = (): Uint8Array => so().randombytes_buf(16);
export const newSalt = (): Uint8Array => so().randombytes_buf(so().crypto_pwhash_SALTBYTES);
export const newInviteCode = (): Uint8Array => so().randombytes_buf(20);
export const newKey = (): Uint8Array => so().randombytes_buf(KEY);

export function newBoxKeyPair(): BoxKeyPair {
  const kp = so().crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function newSignKeyPair(): SignKeyPair {
  const kp = so().crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

// ----------------------------------------------------------------- kdf --

// Argon2id v1.3, 32B out, opslimit=2, memlimit=64MiB [REVIEW],
// then two independent subkeys — kWrap (identity keys) and kAuth (OPAQUE
// input). Parameters are constants, not arguments.
export function deriveFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
): { kWrap: Uint8Array; kAuth: Uint8Array } {
  const s = so();
  assertLen(salt, s.crypto_pwhash_SALTBYTES, "salt");
  const master = s.crypto_pwhash(
    KEY,
    passphrase,
    salt,
    2,
    64 * 1024 * 1024,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const kWrap = s.crypto_kdf_derive_from_key(KEY, 1, "tallystk", master);
  const kAuth = s.crypto_kdf_derive_from_key(KEY, 2, "tallystk", master);
  s.memzero(master);
  return { kWrap, kAuth };
}

// ---------------------------------------------------------------- aead --

const NONCE = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

/** XChaCha20-Poly1305. Fresh internal nonce; output = nonce ‖ ciphertext. */
export function aeadSeal(key: Uint8Array, plaintext: Uint8Array, aad: JsonObject): Uint8Array {
  const s = so();
  assertLen(key, KEY, "key");
  const nonce = s.randombytes_buf(NONCE);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    canonicalJson(aad),
    null,
    nonce,
    key,
  );
  const out = new Uint8Array(NONCE + ct.length);
  out.set(nonce);
  out.set(ct, NONCE);
  return out;
}

export function aeadOpen(key: Uint8Array, sealed: Uint8Array, aad: JsonObject): Uint8Array {
  const s = so();
  assertLen(key, KEY, "key");
  if (sealed.length < NONCE + s.crypto_aead_xchacha20poly1305_ietf_ABYTES) {
    throw new DecryptFailed("ciphertext too short");
  }
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      sealed.subarray(NONCE),
      canonicalJson(aad),
      sealed.subarray(0, NONCE),
      key,
    );
  } catch {
    throw new DecryptFailed();
  }
}

// ---------------------------------------------------------- sealed box --

// X25519 sealed boxes. Authenticity comes from the signature on the
// enclosing event, never from the box itself.
export function sealTo(recipientPk: Uint8Array, bytes: Uint8Array): Uint8Array {
  assertLen(recipientPk, KEY, "recipient public key");
  return so().crypto_box_seal(bytes, recipientPk);
}

/** X25519 public key from a private key (crypto_scalarmult_base) — used by
 * login (rebuild keypair from the identity blob) and the recovery ceremony
 * (check the reconstructed key against the pinned value). */
export function boxPkFromSk(sk: Uint8Array): Uint8Array {
  assertLen(sk, KEY, "box private key");
  return so().crypto_scalarmult_base(sk);
}

export function openSealed(kp: BoxKeyPair, sealedBox: Uint8Array): Uint8Array {
  try {
    return so().crypto_box_seal_open(sealedBox, kp.publicKey, kp.privateKey);
  } catch {
    throw new DecryptFailed("sealed box");
  }
}

// ------------------------------------------------------------- signing --

// Ed25519 over JCS(envelope minus sig) — the strip/canonicalize/sign rule
// lives here so no caller reimplements it.
export function signEvent(kp: SignKeyPair, envelope: JsonObject): string {
  if ("sig" in envelope) throw new EncodingError("envelope already contains sig");
  return toB64u(so().crypto_sign_detached(canonicalize(envelope), kp.privateKey));
}

export function verifyEvent(pk: Uint8Array, signed: JsonObject): void {
  assertLen(pk, KEY, "signing public key");
  const { sig, ...rest } = signed;
  if (typeof sig !== "string") throw new BadSignature();
  let ok = false;
  try {
    ok = so().crypto_sign_verify_detached(fromB64u(sig), canonicalize(rest), pk);
  } catch {
    ok = false;
  }
  if (!ok) throw new BadSignature();
}

// ------------------------------------------------------------- hashing --

/** BLAKE2b-256 — the hash wherever one is needed (prev_hash,
 * proposal digests, K_invite = hash(invite code), head-package key). */
export const hash = (data: Uint8Array): Uint8Array => so().crypto_generichash(KEY, data);

/** Keyed BLAKE2b over JCS(obj) — the invite binding tag. */
export function keyedTag(key: Uint8Array, obj: JsonObject): Uint8Array {
  assertLen(key, KEY, "tag key");
  return so().crypto_generichash(KEY, canonicalize(obj), key);
}

// -------------------------------------------------- 2-of-2 recovery split --

// The only permitted secret-sharing construction (requirements): share A is
// uniform random, share B = secret ⊕ A; both required, either alone useless.
export function xorSplit(secret: Uint8Array): [Uint8Array, Uint8Array] {
  const a = so().randombytes_buf(secret.length);
  const b = secret.map((byte, i) => byte ^ a[i]!);
  return [a, b];
}

export function xorJoin(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new EncodingError("shares differ in length");
  return a.map((byte, i) => byte ^ b[i]!);
}

// ------------------------------------------------------ printed format --

// Crockford base32 in groups of 4 with a 4-byte BLAKE2b
// checksum suffix. Detects transcription errors only — no integrity claim
// against a malicious share.
const CHECKSUM = 4;

function checksum(payload: Uint8Array): Uint8Array {
  // generichash minimum output is 16B; truncate to the 4-byte suffix
  return so().crypto_generichash(16, payload).subarray(0, CHECKSUM);
}

export function encodePrinted(secret: Uint8Array): string {
  const withCheck = new Uint8Array(secret.length + CHECKSUM);
  withCheck.set(secret);
  withCheck.set(checksum(secret), secret.length);
  return crockfordEncode(withCheck).replace(/(.{4})(?=.)/g, "$1-");
}

export function decodePrinted(text: string): Uint8Array {
  const raw = crockfordDecode(text); // throws EncodingError on bad chars
  if (raw.length <= CHECKSUM) throw new ChecksumError();
  const payload = raw.subarray(0, raw.length - CHECKSUM);
  const check = raw.subarray(raw.length - CHECKSUM);
  const expect = checksum(payload);
  for (let i = 0; i < CHECKSUM; i++) {
    if (check[i] !== expect[i]) throw new ChecksumError();
  }
  return payload;
}

// ------------------------------------------------------------ encoding --

export const toB64u = (bytes: Uint8Array): string =>
  so().to_base64(bytes, so().base64_variants.URLSAFE_NO_PADDING);

export function fromB64u(text: string): Uint8Array {
  try {
    return so().from_base64(text, so().base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new EncodingError("invalid base64url");
  }
}

// -------------------------------------------------------------- opaque --

// Thin adapter over @serenity-kit/opaque. kAuth (not the passphrase) is the
// password input; the library's internal KSF is not configurable — the
// resulting double stretch is accepted and [REVIEW]-flagged.
// The library signals failure with a falsy return; normalize to AuthFailed.

const opaquePassword = (kAuth: Uint8Array): string => {
  assertLen(kAuth, KEY, "kAuth");
  return toB64u(kAuth);
};

export const opaqueRegister = {
  start(kAuth: Uint8Array): { state: string; registrationRequest: string } {
    so();
    const r = opaqueLib.client.startRegistration({ password: opaquePassword(kAuth) });
    return { state: r.clientRegistrationState, registrationRequest: r.registrationRequest };
  },
  finish(
    kAuth: Uint8Array,
    state: string,
    registrationResponse: string,
  ): { registrationRecord: string } {
    so();
    const r = opaqueLib.client.finishRegistration({
      clientRegistrationState: state,
      registrationResponse,
      password: opaquePassword(kAuth),
    });
    if (!r) throw new AuthFailed("registration failed");
    return { registrationRecord: r.registrationRecord };
  },
};

export const opaqueLogin = {
  start(kAuth: Uint8Array): { state: string; startLoginRequest: string } {
    so();
    const r = opaqueLib.client.startLogin({ password: opaquePassword(kAuth) });
    return { state: r.clientLoginState, startLoginRequest: r.startLoginRequest };
  },
  finish(
    kAuth: Uint8Array,
    state: string,
    loginResponse: string,
  ): { finishLoginRequest: string; sessionKey: string } {
    so();
    const r = opaqueLib.client.finishLogin({
      clientLoginState: state,
      loginResponse,
      password: opaquePassword(kAuth),
    });
    if (!r) throw new AuthFailed("login failed: wrong passphrase or corrupted response");
    return { finishLoginRequest: r.finishLoginRequest, sessionKey: r.sessionKey };
  },
};
