import { beforeAll, describe, expect, it } from "vitest";
// Test-only: the server half of OPAQUE, to exercise the client adapter.
// App code must never import the library directly (crypto module boundary).
import * as opaqueServer from "@serenity-kit/opaque";
import {
  init,
  newId,
  newSalt,
  newInviteCode,
  newKey,
  newBoxKeyPair,
  newSignKeyPair,
  deriveFromPassphrase,
  aeadSeal,
  aeadOpen,
  sealTo,
  openSealed,
  signEvent,
  verifyEvent,
  hash,
  keyedTag,
  xorSplit,
  xorJoin,
  encodePrinted,
  decodePrinted,
  toB64u,
  fromB64u,
  opaqueRegister,
  opaqueLogin,
  DecryptFailed,
  BadSignature,
  ChecksumError,
  AuthFailed,
  EncodingError,
  type JsonObject,
} from "./index.ts";

beforeAll(async () => {
  await init();
});

const te = new TextEncoder();

describe("random", () => {
  it("produces the specified sizes", () => {
    expect(newId().length).toBe(16);
    expect(newSalt().length).toBe(16);
    expect(newInviteCode().length).toBe(20);
    expect(newKey().length).toBe(32);
    expect(newBoxKeyPair().publicKey.length).toBe(32);
    expect(newBoxKeyPair().privateKey.length).toBe(32);
    expect(newSignKeyPair().publicKey.length).toBe(32);
    expect(newSignKeyPair().privateKey.length).toBe(64);
  });
});

describe("deriveFromPassphrase", () => {
  it("is deterministic per salt, subkeys independent, salts independent", () => {
    const salt = newSalt();
    const a = deriveFromPassphrase("correct horse", salt);
    const b = deriveFromPassphrase("correct horse", salt);
    expect(toB64u(a.kWrap)).toBe(toB64u(b.kWrap));
    expect(toB64u(a.kAuth)).toBe(toB64u(b.kAuth));
    expect(toB64u(a.kWrap)).not.toBe(toB64u(a.kAuth));
    const c = deriveFromPassphrase("correct horse", newSalt());
    expect(toB64u(c.kWrap)).not.toBe(toB64u(a.kWrap));
  });
});

describe("aead", () => {
  const aad: JsonObject = {
    v: 1,
    org: "b3JnMTIzNDU2Nzg5MDEy",
    case: "Y2FzZTEyMzQ1Njc4OTAx",
    epoch: 3,
    record: "cmVjMTIzNDU2Nzg5MDEy",
  };
  const plaintext = te.encode("case note: synthetic data only");

  it("round-trips", () => {
    const key = newKey();
    const ct = aeadSeal(key, plaintext, aad);
    expect(ct.length).toBe(24 + plaintext.length + 16); // nonce + pt + tag
    expect(Array.from(aeadOpen(key, ct, aad))).toEqual(Array.from(plaintext));
  });

  it("fails on a flipped ciphertext byte", () => {
    const key = newKey();
    const ct = aeadSeal(key, plaintext, aad);
    ct[30] = ct[30]! ^ 1;
    expect(() => aeadOpen(key, ct, aad)).toThrow(DecryptFailed);
  });

  it("fails when any AAD field changes", () => {
    const key = newKey();
    const ct = aeadSeal(key, plaintext, aad);
    for (const [field, value] of [
      ["v", 2],
      ["org", "AAAAAAAAAAAAAAAAAAAAAA"],
      ["case", "AAAAAAAAAAAAAAAAAAAAAA"],
      ["epoch", 4],
      ["record", "AAAAAAAAAAAAAAAAAAAAAA"],
    ] as const) {
      expect(
        () => aeadOpen(key, ct, { ...aad, [field]: value }),
        `changed AAD field: ${field}`,
      ).toThrow(DecryptFailed);
    }
  });

  it("fails with the wrong key and rejects wrong-length keys", () => {
    const ct = aeadSeal(newKey(), plaintext, aad);
    expect(() => aeadOpen(newKey(), ct, aad)).toThrow(DecryptFailed);
    expect(() => aeadSeal(newId(), plaintext, aad)).toThrow(EncodingError); // 16B ≠ 32B
  });

  it("never repeats a nonce and never emits identical ciphertext", () => {
    const key = newKey();
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const ct = aeadSeal(key, plaintext, aad);
      seen.add(toB64u(ct.subarray(0, 24)));
    }
    expect(seen.size).toBe(200);
  });
});

describe("sealed boxes", () => {
  it("round-trips to the right keypair only", () => {
    const kp = newBoxKeyPair();
    const key = newKey();
    const box = sealTo(kp.publicKey, key);
    expect(Array.from(openSealed(kp, box))).toEqual(Array.from(key));
    expect(() => openSealed(newBoxKeyPair(), box)).toThrow(DecryptFailed);
  });
});

describe("signEvent / verifyEvent", () => {
  const envelope: JsonObject = {
    v: 1,
    type: "case_grant",
    event_id: "ZXZlbnQxMjM0NTY3ODkw",
    org_id: "b3JnMTIzNDU2Nzg5MDEy",
    actor: "dXNlcjEyMzQ1Njc4OTAx",
    payload: { case: "Y2FzZTEyMzQ1Njc4OTAx", epoch: 1 },
  };

  it("signs and verifies; key order does not matter", () => {
    const kp = newSignKeyPair();
    const sig = signEvent(kp, envelope);
    verifyEvent(kp.publicKey, { ...envelope, sig });
    // same envelope, different insertion order → same canonical bytes
    const reordered: JsonObject = {
      payload: { epoch: 1, case: "Y2FzZTEyMzQ1Njc4OTAx" },
      actor: "dXNlcjEyMzQ1Njc4OTAx",
      org_id: "b3JnMTIzNDU2Nzg5MDEy",
      event_id: "ZXZlbnQxMjM0NTY3ODkw",
      type: "case_grant",
      v: 1,
      sig,
    };
    verifyEvent(kp.publicKey, reordered);
  });

  it("rejects any mutation, the wrong key, and a pre-signed envelope", () => {
    const kp = newSignKeyPair();
    const sig = signEvent(kp, envelope);
    expect(() =>
      verifyEvent(kp.publicKey, { ...envelope, actor: "ZXZpbDEyMzQ1Njc4OTAx", sig }),
    ).toThrow(BadSignature);
    expect(() => verifyEvent(newSignKeyPair().publicKey, { ...envelope, sig })).toThrow(
      BadSignature,
    );
    expect(() => verifyEvent(kp.publicKey, { ...envelope, sig: "not-base64!!" })).toThrow(
      BadSignature,
    );
    expect(() => signEvent(kp, { ...envelope, sig })).toThrow(EncodingError);
  });
});

describe("hash and keyedTag", () => {
  it("hashes to 32 bytes; tags bind to key and content", () => {
    expect(hash(te.encode("x")).length).toBe(32);
    const k1 = newKey();
    const k2 = newKey();
    const claim: JsonObject = { user: "u", enc: "e", sign: "s", invite: "i" };
    expect(toB64u(keyedTag(k1, claim))).toBe(toB64u(keyedTag(k1, claim)));
    expect(toB64u(keyedTag(k2, claim))).not.toBe(toB64u(keyedTag(k1, claim)));
    expect(toB64u(keyedTag(k1, { ...claim, enc: "evil" }))).not.toBe(toB64u(keyedTag(k1, claim)));
  });
});

describe("xor split", () => {
  it("round-trips; a single share reveals nothing recognizable", () => {
    const secret = newKey();
    const [a, b] = xorSplit(secret);
    expect(Array.from(xorJoin(a, b))).toEqual(Array.from(secret));
    expect(toB64u(a)).not.toBe(toB64u(secret));
    expect(toB64u(b)).not.toBe(toB64u(secret));
    expect(() => xorJoin(a, newId())).toThrow(EncodingError);
  });
});

describe("printed format", () => {
  it("round-trips through hostile transcription", () => {
    const secret = newKey();
    const printed = encodePrinted(secret);
    expect(printed).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{1,4})*$/);
    expect(printed).not.toMatch(/[ILOU]/); // Crockford excludes these
    // lowercase, extra whitespace, and confusable substitutions must decode
    const mangled = printed.toLowerCase().replace(/-/g, " ").replace(/0/g, "O").replace(/1/g, "l");
    expect(Array.from(decodePrinted(mangled))).toEqual(Array.from(secret));
  });

  it("catches typos and rejects garbage", () => {
    const printed = encodePrinted(newKey());
    // replace one character with a different valid alphabet character
    const i = 2;
    const wrong = printed[i] === "7" ? "9" : "7";
    const typo = printed.slice(0, i) + wrong + printed.slice(i + 1);
    expect(() => decodePrinted(typo)).toThrow(ChecksumError);
    expect(() => decodePrinted("ABCU-1234")).toThrow(EncodingError); // U invalid
    expect(() => decodePrinted("AAAA")).toThrow(ChecksumError); // too short
  });
});

describe("base64url", () => {
  it("round-trips unpadded and rejects malformed input", () => {
    const bytes = newInviteCode();
    const s = toB64u(bytes);
    expect(s).not.toMatch(/[+/=]/);
    expect(Array.from(fromB64u(s))).toEqual(Array.from(bytes));
    expect(() => fromB64u("!!!")).toThrow(EncodingError);
  });
});

describe("opaque adapter", () => {
  it("registers and logs in against the server half; wrong kAuth throws", () => {
    const kAuth = newKey();
    const serverSetup = opaqueServer.server.createSetup();

    const reg = opaqueRegister.start(kAuth);
    const { registrationResponse } = opaqueServer.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: "user-1",
      registrationRequest: reg.registrationRequest,
    });
    const { registrationRecord } = opaqueRegister.finish(kAuth, reg.state, registrationResponse);

    const login = opaqueLogin.start(kAuth);
    const sl = opaqueServer.server.startLogin({
      serverSetup,
      userIdentifier: "user-1",
      registrationRecord,
      startLoginRequest: login.startLoginRequest,
    });
    const done = opaqueLogin.finish(kAuth, login.state, sl.loginResponse);
    const serverDone = opaqueServer.server.finishLogin({
      serverLoginState: sl.serverLoginState,
      finishLoginRequest: done.finishLoginRequest,
    });
    expect(done.sessionKey).toBe(serverDone.sessionKey);

    // wrong kAuth → the library's falsy return must surface as AuthFailed
    const bad = opaqueLogin.start(newKey());
    const badSl = opaqueServer.server.startLogin({
      serverSetup,
      userIdentifier: "user-1",
      registrationRecord,
      startLoginRequest: bad.startLoginRequest,
    });
    expect(() => opaqueLogin.finish(newKey(), bad.state, badSl.loginResponse)).toThrow(AuthFailed);
  });
});
