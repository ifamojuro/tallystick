// All crypto failures throw; nothing returns null/undefined on tamper
//. Errors carry no key material.

export class CryptoError extends Error {}

/** AEAD tag or sealed-box failure: tamper, wrong key, or wrong AAD. */
export class DecryptFailed extends CryptoError {
  constructor(what = "decryption failed") {
    super(what);
  }
}

/** Ed25519 verification failure. */
export class BadSignature extends CryptoError {
  constructor() {
    super("signature verification failed");
  }
}

/** Printed-format checksum mismatch — a transcription error; re-typing may fix it. */
export class ChecksumError extends CryptoError {
  constructor() {
    super("printed-code checksum mismatch: check for typos and try again");
  }
}

/** OPAQUE login/registration failure (wrong passphrase or corrupted message). */
export class AuthFailed extends CryptoError {
  constructor(what = "authentication failed") {
    super(what);
  }
}

/** Malformed base64url / base32 / JCS input. */
export class EncodingError extends CryptoError {}
