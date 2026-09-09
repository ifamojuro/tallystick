import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { crypto, journal } from "@tallystick/shared";
import { TestOrg, newTestActor } from "@tallystick/shared/src/journal/fixtures";
import { createTallystickServer, planListenFromEnv, type TallystickServer } from "./server.ts";

let server: TallystickServer;
let base: string;

// shared across describes: the org whose head owns the server session
// (the access gates require the appending session to be an admitted member)
let org: TestOrg;
let headToken: string;

beforeAll(async () => {
  await crypto.init();
  server = createTallystickServer();
  const port = await server.listen(0);
  base = `http://localhost:${port}`;
});

afterAll(async () => {
  await server.close();
});

async function api(
  path: string,
  opts: { method?: string; body?: unknown; token?: string; base?: string } = {},
): Promise<{ status: number; body: any }> {
  const res = await fetch((opts.base ?? base) + path, {
    method: opts.method ?? (opts.body ? "POST" : "GET"),
    headers: {
      ...(opts.body ? { "content-type": "application/json" } : {}),
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

/** Full client-side registration + login against the HTTP server, using
 * the crypto module exactly as the real client will (workflow step 2).
 * inviteId is required by the server once an org exists. */
async function registerAndLogin(
  userId: string,
  passphrase: string,
  inviteId?: string,
  baseUrl?: string,
  setupCode?: string,
): Promise<string> {
  const at = { base: baseUrl };
  const salt = crypto.newSalt();
  const { kWrap, kAuth } = crypto.deriveFromPassphrase(passphrase, salt);
  const identity = { enc: crypto.newBoxKeyPair(), sign: crypto.newSignKeyPair() };
  const blob = crypto.aeadSeal(
    kWrap,
    crypto.canonicalize({
      enc_sk: crypto.toB64u(identity.enc.privateKey),
      sign_sk: crypto.toB64u(identity.sign.privateKey),
    }),
    { v: 1, org: "test", user: userId, use: "idkeys" },
  );

  const reg = crypto.opaqueRegister.start(kAuth);
  const r1 = await api("/auth/register/start", {
    ...at,
    body: { userId, registrationRequest: reg.registrationRequest, inviteId, setupCode },
  });
  expect(r1.status).toBe(200);
  const { registrationRecord } = crypto.opaqueRegister.finish(
    kAuth,
    reg.state,
    r1.body.registrationResponse,
  );
  const r2 = await api("/auth/register/finish", {
    ...at,
    body: {
      userId,
      registrationRecord,
      salt: crypto.toB64u(salt),
      kdf: { ops: 2, mem_mib: 64, alg: "argon2id13" },
      wrappedIdentityKeys: crypto.toB64u(blob),
      inviteId,
      setupCode,
    },
  });
  expect(r2.status).toBe(200);

  // fresh login: fetch public params, re-derive, run the PAKE
  const params = await api(`/auth/params?user=${encodeURIComponent(userId)}`, at);
  expect(params.status).toBe(200);
  const rederived = crypto.deriveFromPassphrase(passphrase, crypto.fromB64u(params.body.salt));
  const login = crypto.opaqueLogin.start(rederived.kAuth);
  const l1 = await api("/auth/login/start", {
    ...at,
    body: { userId, startLoginRequest: login.startLoginRequest },
  });
  expect(l1.status).toBe(200);
  const done = crypto.opaqueLogin.finish(rederived.kAuth, login.state, l1.body.loginResponse);
  const l2 = await api("/auth/login/finish", {
    ...at,
    body: { loginId: l1.body.loginId, finishLoginRequest: done.finishLoginRequest },
  });
  expect(l2.status).toBe(200);
  return l2.body.sessionToken as string;
}

/** Journal the org's newest locally-appended entry through the server.
 * Fixture and server stay in lockstep, so seq always matches. */
async function pushLatest(): Promise<void> {
  const entry = org.entries[org.entries.length - 1]!;
  const r = await api("/journal", { body: { envelope: entry.envelope }, token: headToken });
  expect(r.status).toBe(200);
  expect(r.body.seq).toBe(entry.seq);
}

describe("auth", () => {
  // NOTE: these registrations happen while the journal is still empty —
  // the bootstrap window, so no invite is required yet.
  it("registers, logs in via OPAQUE, and serves the identity blob", async () => {
    const token = await registerAndLogin("user-auth", "correct horse battery");
    const blob = await api("/identity", { token });
    expect(blob.status).toBe(200);
    expect(typeof blob.body.wrappedIdentityKeys).toBe("string");
  });

  it("rejects a wrong passphrase at the client AND a forged finish at the server", async () => {
    await registerAndLogin("user-wrongpw", "right passphrase");
    const params = await api("/auth/params?user=user-wrongpw");
    const bad = crypto.deriveFromPassphrase("wrong passphrase", crypto.fromB64u(params.body.salt));
    const login = crypto.opaqueLogin.start(bad.kAuth);
    const l1 = await api("/auth/login/start", {
      body: { userId: "user-wrongpw", startLoginRequest: login.startLoginRequest },
    });
    // client detects the failure locally...
    expect(() => crypto.opaqueLogin.finish(bad.kAuth, login.state, l1.body.loginResponse)).toThrow(
      crypto.AuthFailed,
    );
    // ...and a junk finish never yields a token
    const l2 = await api("/auth/login/finish", {
      body: { loginId: l1.body.loginId, finishLoginRequest: "AAAA" },
    });
    expect(l2.status).toBe(401);
  });

  it("session-unlock keys: put/get/delete bound to the bearer token", async () => {
    const token = await registerAndLogin("unlock-user", "unlock pw");
    // no key yet
    expect((await api("/session-unlock", { token })).status).toBe(404);
    // unauthenticated put refused
    expect((await api("/session-unlock", { body: { key: "k1" } })).status).toBe(401);
    // put + get round-trip
    expect((await api("/session-unlock", { token, body: { key: "k1" } })).status).toBe(200);
    const got = await api("/session-unlock", { token });
    expect(got.status).toBe(200);
    expect(got.body.key).toBe("k1");
    // another session's token sees nothing (key is token-bound)
    const other = await registerAndLogin("unlock-other", "other pw");
    expect((await api("/session-unlock", { token: other })).status).toBe(404);
    // delete = remote revocation
    expect((await api("/session-unlock", { token, method: "DELETE" })).status).toBe(200);
    expect((await api("/session-unlock", { token })).status).toBe(404);
    // malformed key refused
    expect((await api("/session-unlock", { token, body: { key: "" } })).status).toBe(400);
  });

  it("log out other devices: drops the user's OTHER sessions and unlock keys", async () => {
    const t1 = await registerAndLogin("multi-dev", "multi pw");
    // second device = second login
    const params = await api("/auth/params?user=multi-dev");
    const kd = crypto.deriveFromPassphrase("multi pw", crypto.fromB64u(params.body.salt));
    const lg = crypto.opaqueLogin.start(kd.kAuth);
    const l1 = await api("/auth/login/start", {
      body: { userId: "multi-dev", startLoginRequest: lg.startLoginRequest },
    });
    const done = crypto.opaqueLogin.finish(kd.kAuth, lg.state, l1.body.loginResponse);
    const l2 = await api("/auth/login/finish", {
      body: { loginId: l1.body.loginId, finishLoginRequest: done.finishLoginRequest },
    });
    const t2 = l2.body.sessionToken as string;
    await api("/session-unlock", { token: t1, body: { key: "k-dev1" } });
    await api("/session-unlock", { token: t2, body: { key: "k-dev2" } });

    // device 1 logs out the others: t2 dies (session + key), t1 survives
    const r = await api("/session-unlock-others", { token: t1, method: "DELETE" });
    expect(r.status).toBe(200);
    expect(r.body.dropped).toBe(1);
    expect((await api("/session-unlock", { token: t1 })).status).toBe(200);
    expect((await api("/session-unlock", { token: t2 })).status).toBe(404);
    expect((await api("/identity", { token: t2 })).status).toBe(401); // token itself dead
    // unauthenticated refused
    expect((await api("/session-unlock-others", { method: "DELETE" })).status).toBe(401);
  });

  it("gates journal and identity behind the session token", async () => {
    expect((await api("/journal")).status).toBe(401);
    expect((await api("/journal", { body: { envelope: {} } })).status).toBe(401);
    expect((await api("/identity")).status).toBe(401);
  });
});

describe("journal", () => {
  it("sequences appends, serves incremental sync, and replays to identical state", async () => {
    // build a real org locally with the layer-2 fixture; the fixture head
    // registers a server account under ITS OWN userId, so genesis is
    // appended by its author and later appends come from an admitted member
    org = new TestOrg();
    org.populate({ members: 2, casesPerMember: 1, notesPerCase: 2 });
    headToken = await registerAndLogin(org.head.userId, "pass pass pass");
    for (const entry of org.entries) {
      const r = await api("/journal", { body: { envelope: entry.envelope }, token: headToken });
      expect(r.status).toBe(200);
      expect(r.body.seq).toBe(entry.seq); // same order → same seq
    }
    // full sync: server-assigned chain replays to the exact same state
    const all = await api("/journal?since=0", { token: headToken });
    expect(all.body.entries.length).toBe(org.entries.length);
    const replayed = journal.replay(all.body.entries);
    expect(replayed.chain.headHash).toBe(org.state.chain.headHash);
    expect(replayed.members.size).toBe(org.state.members.size);

    // incremental sync from a cursor
    const tail = await api(`/journal?since=${org.entries.length - 2}`, { token: headToken });
    expect(tail.body.entries.length).toBe(2);
    expect(tail.body.entries[0].seq).toBe(org.entries.length - 1);
  });

  it("pushes a new-entries signal over SSE on append", async () => {
    const controller = new AbortController();
    const res = await fetch(`${base}/journal/stream`, {
      headers: { authorization: `Bearer ${headToken}` },
      signal: controller.signal,
    });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();

    // initial cursor event arrives immediately
    const first = decoder.decode((await reader.read()).value);
    expect(first).toMatch(/^data: \d+\n\n$/);

    // a valid append for THIS org triggers a push naming the new seq
    org.issueInvite(org.head); // appends locally at the next seq
    const expectedSeq = server.store.journal.length + 1;
    const pushed = (async () => decoder.decode((await reader.read()).value))();
    await pushLatest();
    expect(await pushed).toBe(`data: ${expectedSeq}\n\n`);
    controller.abort();
  });
});

describe("access gates", () => {
  let outsiderToken: string;

  it("refuses registration without an invite once an org exists; admits invite holders", async () => {
    // stranger with the URL and no invite: refused at register/start
    const noInvite = await api("/auth/register/start", {
      body: { userId: "outsider-1", registrationRequest: "junk" },
    });
    expect(noInvite.status).toBe(403);

    // a journaled, unused invite opens registration (the server checks
    // existence + unused only — the code itself never reaches it)
    const invite = org.issueInvite(org.head);
    await pushLatest();
    outsiderToken = await registerAndLogin("invited-1", "invited pw", invite.inviteId);
    expect(typeof outsiderToken).toBe("string");
  });

  it("denies journal and admin surfaces to registered-but-unadmitted users", async () => {
    expect((await api("/journal?since=0", { token: outsiderToken })).status).toBe(403);
    expect(
      (await api("/journal", { body: { envelope: { type: "note_update" } }, token: outsiderToken }))
        .status,
    ).toBe(403);
    const sse = await fetch(`${base}/journal/stream`, {
      headers: { authorization: `Bearer ${outsiderToken}` },
    });
    expect(sse.status).toBe(403);
    await sse.body?.cancel();
    expect((await api("/join-requests", { token: outsiderToken })).status).toBe(403);
    expect(
      (await api("/head-package", { body: { ciphertext: "x" }, token: outsiderToken })).status,
    ).toBe(403);
    // the admitted head still passes everything
    expect((await api("/journal?since=0", { token: headToken })).status).toBe(200);
    expect((await api("/join-requests", { token: headToken })).status).toBe(200);
  });

  it("rejects duplicate userId registration (no silent OPAQUE-record overwrite)", async () => {
    const r = await api("/auth/register/start", {
      body: { userId: org.head.userId, registrationRequest: "junk" },
    });
    expect(r.status).toBe(409);
  });

  it("account recovery opens the duplicate gate only for a proven identity key", async () => {
    const userId = org.head.userId;
    const { body } = await api("/recover/challenge", { body: { userId } });
    const { registrationRequest } = crypto.opaqueRegister.start(new Uint8Array(32));
    // the proof signs the challenge nonce AND a commit over the
    // exact replacement material this phase presents
    const commit = crypto.toB64u(crypto.hash(crypto.canonicalize({ registrationRequest })));
    const proof = {
      use: "account-recovery",
      org: org.orgId,
      user: userId,
      nonce: body.nonce,
      commit,
    };

    // a proof signed by the WRONG key does not open the gate
    const evil = crypto.newSignKeyPair();
    const forged = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest,
        recoveryNonce: body.nonce,
        recoverySig: crypto.signEvent(evil, proof),
      },
    });
    expect(forged.status).toBe(409);
    // a stale/invented nonce does not either, even with the right key
    const staleNonce = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest,
        recoveryNonce: "invented",
        recoverySig: crypto.signEvent(org.head.sign, { ...proof, nonce: "invented" }),
      },
    });
    expect(staleNonce.status).toBe(409);
    // the roster-pinned identity signing key over the real challenge DOES
    const genuine = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest,
        recoveryNonce: body.nonce,
        recoverySig: crypto.signEvent(org.head.sign, proof),
      },
    });
    expect(genuine.status).toBe(200);
  });

  it("refuses join requests that name no outstanding journaled invite", async () => {
    const r = await api("/join-request", {
      body: {
        user_id: "x",
        enc_pk: "x",
        sign_pk: "x",
        invite_id: "never-issued",
        binding_tag: "x",
      },
    });
    expect(r.status).toBe(403);
  });

  it("fresh server: first append must be genesis by its author; registration rate-limits", async () => {
    const tight = createTallystickServer({ limits: { registerPerIp: 3 } });
    const tbase = `http://localhost:${await tight.listen(0)}`;
    try {
      // bootstrap window: registration is invite-free (journal empty)…
      const token = await registerAndLogin("fresh-head", "fresh pw", undefined, tbase);
      // …but the first append must be org_genesis, authored by this session
      const notGenesis = await api("/journal", {
        base: tbase,
        token,
        body: { envelope: { type: "note_update", actor: "fresh-head" } },
      });
      expect(notGenesis.status).toBe(403);
      const wrongActor = await api("/journal", {
        base: tbase,
        token,
        body: { envelope: { type: "org_genesis", actor: "someone-else" } },
      });
      expect(wrongActor.status).toBe(403);

      // fixed-window limit: the real registration used 1 of 3 starts
      const r2 = await api("/auth/register/start", {
        base: tbase,
        body: { userId: "spam-1", registrationRequest: "junk" },
      });
      expect(r2.status).not.toBe(429); // 2 of 3
      const r3 = await api("/auth/register/start", {
        base: tbase,
        body: { userId: "spam-2", registrationRequest: "junk" },
      });
      expect(r3.status).not.toBe(429); // 3 of 3
      const r4 = await api("/auth/register/start", {
        base: tbase,
        body: { userId: "spam-3", registrationRequest: "junk" },
      });
      expect(r4.status).toBe(429);
    } finally {
      await tight.close();
    }
  });
});

// Hardening regression tests: session lifecycle, login isolation, endpoint authorization.
describe("session, login, and authorization hardening", () => {
  it("logout kills token + unlock key together; expired tokens die", async () => {
    const invite = org.issueInvite(org.head);
    await pushLatest();
    const token = await registerAndLogin("ts05-user", "ts05 passphrase", invite.inviteId);
    await api("/session-unlock", { token, body: { key: "k05" } });
    expect((await api("/identity", { token })).status).toBe(200);

    // real logout: one call, both credentials dead
    expect((await api("/session", { token, method: "DELETE" })).status).toBe(200);
    expect((await api("/identity", { token })).status).toBe(401);
    expect((await api("/session-unlock", { token })).status).toBe(404);

    // absolute expiry: age the stored session record directly
    const invite2 = org.issueInvite(org.head);
    await pushLatest();
    const t2 = await registerAndLogin("ts05-user2", "ts05 passphrase 2", invite2.inviteId);
    expect((await api("/identity", { token: t2 })).status).toBe(200);
    for (const [h, rec] of server.store.sessions) {
      if (rec.userId === "ts05-user2") server.store.sessions.set(h, { ...rec, expiresAt: 1 });
    }
    expect((await api("/identity", { token: t2 })).status).toBe(401);
    // lazy expiry also reaped the record
    expect([...server.store.sessions.values()].some((r) => r.userId === "ts05-user2")).toBe(false);
  });

  it("interleaved logins both succeed; attempt ids are single-use", async () => {
    const invite = org.issueInvite(org.head);
    await pushLatest();
    await registerAndLogin("ts09-user", "ts09 passphrase", invite.inviteId);
    const params = await api("/auth/params?user=ts09-user");
    const kd = crypto.deriveFromPassphrase("ts09 passphrase", crypto.fromB64u(params.body.salt));

    // two devices start login before either finishes — under userId-keyed
    // state the second start destroyed the first (the lockout)
    const devA = crypto.opaqueLogin.start(kd.kAuth);
    const devB = crypto.opaqueLogin.start(kd.kAuth);
    const sA = await api("/auth/login/start", {
      body: { userId: "ts09-user", startLoginRequest: devA.startLoginRequest },
    });
    const sB = await api("/auth/login/start", {
      body: { userId: "ts09-user", startLoginRequest: devB.startLoginRequest },
    });
    const dB = crypto.opaqueLogin.finish(kd.kAuth, devB.state, sB.body.loginResponse);
    const dA = crypto.opaqueLogin.finish(kd.kAuth, devA.state, sA.body.loginResponse);
    const fB = await api("/auth/login/finish", {
      body: { loginId: sB.body.loginId, finishLoginRequest: dB.finishLoginRequest },
    });
    const fA = await api("/auth/login/finish", {
      body: { loginId: sA.body.loginId, finishLoginRequest: dA.finishLoginRequest },
    });
    expect(fA.status).toBe(200);
    expect(fB.status).toBe(200);

    // a consumed attempt id and a junk one both fail closed
    const replay = await api("/auth/login/finish", {
      body: { loginId: sA.body.loginId, finishLoginRequest: dA.finishLoginRequest },
    });
    expect(replay.status).toBe(400);
    expect(
      (await api("/auth/login/finish", { body: { loginId: "nope", finishLoginRequest: "AAAA" } }))
        .status,
    ).toBe(400);
  });

  it("ordinary members can neither list join requests nor replace the head package", async () => {
    // register a member account while its invite is outstanding, then admit
    // that same userId through the real two-admin path
    const invite = org.issueInvite(org.adminA);
    await pushLatest();
    const memberToken = await registerAndLogin("ts11-member", "ts11 passphrase", invite.inviteId);
    const keys = newTestActor();
    const prop = journal.buildMemberPropose(org.state, org.adminA.keys, {
      userId: "ts11-member",
      encPk: keys.encPk,
      signPk: keys.signPk,
      inviteCode: invite.code,
      inviteId: invite.inviteId,
      now: org.now,
    });
    org.append(prop);
    await pushLatest();
    const approve = journal.buildMemberApprove(org.state, org.adminB.keys, {
      proposalId: (prop.payload as { proposal_id: string }).proposal_id,
      inviteCode: invite.code,
      now: org.now,
    });
    org.append(approve);
    await pushLatest();

    // admitted, logged in, and still refused at both admin surfaces
    expect((await api("/journal?since=0", { token: memberToken })).status).toBe(200);
    expect((await api("/join-requests", { token: memberToken })).status).toBe(403);
    expect(
      (await api("/head-package", { token: memberToken, body: { ciphertext: "vandalism" } }))
        .status,
    ).toBe(403);
    // reading the package stays open — the recovery posture is unchanged
    expect((await api("/head-package", { token: memberToken })).status).toBe(200);
    // the head still passes both
    expect((await api("/join-requests", { token: headToken })).status).toBe(200);
    expect(
      (await api("/head-package", { token: headToken, body: { ciphertext: "ct-head" } })).status,
    ).toBe(200);
  });
});

// Loopback default bind + bootstrap-race gate.
describe("bind default + bootstrap race", () => {
  it("binds loopback by default", async () => {
    const s2 = createTallystickServer();
    await s2.listen(0);
    expect(s2.boundAddress()).toBe("127.0.0.1");
    await s2.close();
  });

  it("env plan: loopback silent; remote refused without opt-in; opt-in mints a setup code", () => {
    expect(planListenFromEnv({})).toEqual({ host: "127.0.0.1" });
    const refused = planListenFromEnv({ TALLYSTICK_HOST: "0.0.0.0" });
    expect(refused.refusal).toMatch(/refusing to bind/);
    expect(refused.setupCode).toBeUndefined();
    const ok = planListenFromEnv({ TALLYSTICK_HOST: "0.0.0.0", TALLYSTICK_REMOTE_OK: "1" });
    expect(ok.refusal).toBeUndefined();
    // 32 random bytes -> 43 chars of base64url
    expect(ok.setupCode ?? "").toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("a fresh server started with a setup code gates the bootstrap window", async () => {
    const gated = createTallystickServer({ setupCode: "sekrit-setup" });
    const gport = await gated.listen(0);
    const gbase = `http://localhost:${gport}`;
    try {
      // the bootstrap screen learns about the requirement from /org
      expect((await api("/org", { base: gbase })).body.setupRequired).toBe(true);
      // no code and wrong code are refused before any OPAQUE work
      const r1 = await api("/auth/register/start", {
        base: gbase,
        body: { userId: "racer", registrationRequest: "x" },
      });
      expect(r1.status).toBe(403);
      const r2 = await api("/auth/register/start", {
        base: gbase,
        body: { userId: "racer", registrationRequest: "x", setupCode: "wrong" },
      });
      expect(r2.status).toBe(403);
      // the holder of the printed code bootstraps normally
      const token = await registerAndLogin(
        "founder",
        "founder pw",
        undefined,
        gbase,
        "sekrit-setup",
      );
      expect(typeof token).toBe("string");
    } finally {
      await gated.close();
    }
  });
});

// Recovery as one bound, expiring, one-shot transaction.
describe("recovery proof binding", () => {
  const commitOf = (material: unknown) =>
    crypto.toB64u(crypto.hash(crypto.canonicalize(material as never)));

  it("proofs bind replacement data; challenges are multi-slot, one-shot, and expiring", async () => {
    const userId = org.head.userId;
    const proofFor = (nonce: string, commit: string) =>
      crypto.signEvent(org.head.sign, {
        use: "account-recovery",
        org: org.orgId,
        user: userId,
        nonce,
        commit,
      });

    // two challenges coexist — a second request no longer stomps the first
    const c1 = (await api("/recover/challenge", { body: { userId } })).body.nonce as string;
    const c2 = (await api("/recover/challenge", { body: { userId } })).body.nonce as string;
    expect(c1).not.toBe(c2);

    const probe = crypto.opaqueRegister.start(new Uint8Array(32));
    const probeCommit = commitOf({ registrationRequest: probe.registrationRequest });

    // start with a proof committed to DIFFERENT replacement data: refused
    const other = crypto.opaqueRegister.start(new Uint8Array(32));
    const mismatch = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest: probe.registrationRequest,
        recoveryNonce: c1,
        recoverySig: proofFor(c1, commitOf({ registrationRequest: other.registrationRequest })),
      },
    });
    expect(mismatch.status).toBe(409);

    // BOTH outstanding nonces open the start gate (peek, not consume)
    for (const n of [c1, c2]) {
      const r = await api("/auth/register/start", {
        body: {
          userId,
          registrationRequest: probe.registrationRequest,
          recoveryNonce: n,
          recoverySig: proofFor(n, probeCommit),
        },
      });
      expect(r.status).toBe(200);
    }

    // a finish whose commit does not match the presented credentials is
    // refused BEFORE anything is stored — and it SPENDS the nonce
    const junk = {
      registrationRecord: "rr",
      salt: "ss",
      kdf: { ops: 2 },
      wrappedIdentityKeys: "ww",
    };
    const badFinish = await api("/auth/register/finish", {
      body: { userId, ...junk, recoveryNonce: c1, recoverySig: proofFor(c1, probeCommit) },
    });
    expect(badFinish.status).toBe(409);
    const spent = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest: probe.registrationRequest,
        recoveryNonce: c1,
        recoverySig: proofFor(c1, probeCommit),
      },
    });
    expect(spent.status).toBe(409);

    // genuine full recovery via c2: real OPAQUE materials, both proofs
    // bound, then login under the NEW passphrase proves the record is live
    const salt = crypto.newSalt();
    const { kWrap, kAuth } = crypto.deriveFromPassphrase("head recovered pw", salt);
    const blob = crypto.aeadSeal(
      kWrap,
      crypto.canonicalize({ sign_sk: crypto.toB64u(org.head.sign.privateKey) }),
      { v: 1, org: "test", user: userId, use: "idkeys" },
    );
    const reg = crypto.opaqueRegister.start(kAuth);
    const s1 = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest: reg.registrationRequest,
        recoveryNonce: c2,
        recoverySig: proofFor(c2, commitOf({ registrationRequest: reg.registrationRequest })),
      },
    });
    expect(s1.status).toBe(200);
    const { registrationRecord } = crypto.opaqueRegister.finish(
      kAuth,
      reg.state,
      s1.body.registrationResponse,
    );
    const kdf = { ops: 2, mem_mib: 64, alg: "argon2id13" };
    const replacement = {
      registrationRecord,
      salt: crypto.toB64u(salt),
      kdf,
      wrappedIdentityKeys: crypto.toB64u(blob),
    };
    const f1 = await api("/auth/register/finish", {
      body: {
        userId,
        ...replacement,
        recoveryNonce: c2,
        recoverySig: proofFor(c2, commitOf(replacement)),
      },
    });
    expect(f1.status).toBe(200);
    // the consumed nonce cannot authorize a second replacement
    const replay = await api("/auth/register/finish", {
      body: {
        userId,
        ...replacement,
        recoveryNonce: c2,
        recoverySig: proofFor(c2, commitOf(replacement)),
      },
    });
    expect(replay.status).toBe(409);
    // ...and the new credentials really work: full OPAQUE login
    const lg = crypto.opaqueLogin.start(kAuth);
    const l1 = await api("/auth/login/start", {
      body: { userId, startLoginRequest: lg.startLoginRequest },
    });
    const done = crypto.opaqueLogin.finish(kAuth, lg.state, l1.body.loginResponse);
    const l2 = await api("/auth/login/finish", {
      body: { loginId: l1.body.loginId, finishLoginRequest: done.finishLoginRequest },
    });
    expect(l2.status).toBe(200);
    // recovery now revokes prior sessions — refresh the
    // shared head token so later describes can still append via pushLatest
    headToken = l2.body.sessionToken as string;

    // expired challenges are refused
    const c3 = (await api("/recover/challenge", { body: { userId } })).body.nonce as string;
    server.store.recoveryChallenges.get(userId)!.set(c3, { expiresAt: 1 });
    const stale = await api("/auth/register/start", {
      body: {
        userId,
        registrationRequest: probe.registrationRequest,
        recoveryNonce: c3,
        recoverySig: proofFor(c3, probeCommit),
      },
    });
    expect(stale.status).toBe(409);
  });
});

// Lifecycle hardening follow-ups: eviction resistance, session revocation
// on recovery, one-time setup code, expiry sweep.
describe("lifecycle hardening follow-ups", () => {
  const commitOf = (m: unknown) => crypto.toB64u(crypto.hash(crypto.canonicalize(m as never)));

  it("a proved recovery slot survives unauthenticated challenge spam", async () => {
    const userId = org.head.userId;
    const proofFor = (nonce: string, commit: string) =>
      crypto.signEvent(org.head.sign, {
        use: "account-recovery",
        org: org.orgId,
        user: userId,
        nonce,
        commit,
      });
    const probe = crypto.opaqueRegister.start(new Uint8Array(32));
    const probeCommit = commitOf({ registrationRequest: probe.registrationRequest });

    // legitimate recovery gets its challenge and proves the start phase
    // (start-only: proving reserves the slot without consuming it, so the
    // shared head session/token is left intact for later tests)
    const good = (await api("/recover/challenge", { body: { userId } })).body.nonce as string;
    expect(
      (
        await api("/auth/register/start", {
          body: {
            userId,
            registrationRequest: probe.registrationRequest,
            recoveryNonce: good,
            recoverySig: proofFor(good, probeCommit),
          },
        })
      ).status,
    ).toBe(200);

    // an attacker floods challenge creation past the cap: eviction may only
    // claim UNPROVED slots, so `good` is never displaced
    for (let i = 0; i < 12; i++) await api("/recover/challenge", { body: { userId } });

    // the proved slot still opens the start gate after the flood
    expect(
      (
        await api("/auth/register/start", {
          body: {
            userId,
            registrationRequest: probe.registrationRequest,
            recoveryNonce: good,
            recoverySig: proofFor(good, probeCommit),
          },
        })
      ).status,
    ).toBe(200);
  });

  it("recovery revokes the user's prior sessions and unlock keys", async () => {
    // a member with a live session + parked unlock key
    const invite = org.issueInvite(org.adminA);
    await pushLatest();
    const memToken = await registerAndLogin("revoke-on-recover", "old pw", invite.inviteId);
    const keys = newTestActor();
    const prop = journal.buildMemberPropose(org.state, org.adminA.keys, {
      userId: "revoke-on-recover",
      encPk: keys.encPk,
      signPk: keys.signPk,
      inviteCode: invite.code,
      inviteId: invite.inviteId,
      now: org.now,
    });
    org.append(prop);
    await pushLatest();
    const approve = journal.buildMemberApprove(org.state, org.adminB.keys, {
      proposalId: (prop.payload as { proposal_id: string }).proposal_id,
      inviteCode: invite.code,
      now: org.now,
    });
    org.append(approve);
    await pushLatest();
    await api("/session-unlock", { token: memToken, body: { key: "kmem" } });
    expect((await api("/identity", { token: memToken })).status).toBe(200);

    // this member's roster signing key = keys.sign; recover the account
    const proofFor = (nonce: string, commit: string) =>
      crypto.signEvent(keys.sign, {
        use: "account-recovery",
        org: org.orgId,
        user: "revoke-on-recover",
        nonce,
        commit,
      });
    const c = (await api("/recover/challenge", { body: { userId: "revoke-on-recover" } })).body
      .nonce as string;
    const salt = crypto.newSalt();
    const { kWrap, kAuth } = crypto.deriveFromPassphrase("new pw", salt);
    const blob = crypto.aeadSeal(
      kWrap,
      crypto.canonicalize({ sign_sk: crypto.toB64u(keys.sign.privateKey) }),
      { v: 1, org: "test", user: "revoke-on-recover", use: "idkeys" },
    );
    const reg = crypto.opaqueRegister.start(kAuth);
    const s1 = await api("/auth/register/start", {
      body: {
        userId: "revoke-on-recover",
        registrationRequest: reg.registrationRequest,
        recoveryNonce: c,
        recoverySig: proofFor(c, commitOf({ registrationRequest: reg.registrationRequest })),
      },
    });
    const { registrationRecord } = crypto.opaqueRegister.finish(
      kAuth,
      reg.state,
      s1.body.registrationResponse,
    );
    const replacement = {
      registrationRecord,
      salt: crypto.toB64u(salt),
      kdf: { ops: 2, mem_mib: 64, alg: "argon2id13" },
      wrappedIdentityKeys: crypto.toB64u(blob),
    };
    const f1 = await api("/auth/register/finish", {
      body: {
        userId: "revoke-on-recover",
        ...replacement,
        recoveryNonce: c,
        recoverySig: proofFor(c, commitOf(replacement)),
      },
    });
    expect(f1.status).toBe(200);

    // the old session is dead: token rejected (401), and its unlock key is
    // gone so the GET finds nothing (404) — either way it can no longer resume
    expect((await api("/identity", { token: memToken })).status).toBe(401);
    expect((await api("/session-unlock", { token: memToken })).status).toBe(404);
  });

  it("the setup code admits exactly one account, then dies", async () => {
    const gated = createTallystickServer({ setupCode: "one-time-code" });
    const port = await gated.listen(0);
    const at = { base: `http://localhost:${port}` };
    try {
      // founder registers with the code (full register: start + finish)
      const salt = crypto.newSalt();
      const { kAuth } = crypto.deriveFromPassphrase("founder pw", salt);
      const reg = crypto.opaqueRegister.start(kAuth);
      const s = await api("/auth/register/start", {
        ...at,
        body: {
          userId: "founder",
          registrationRequest: reg.registrationRequest,
          setupCode: "one-time-code",
        },
      });
      expect(s.status).toBe(200);
      const { registrationRecord } = crypto.opaqueRegister.finish(
        kAuth,
        reg.state,
        s.body.registrationResponse,
      );
      const f = await api("/auth/register/finish", {
        ...at,
        body: {
          userId: "founder",
          registrationRecord,
          salt: crypto.toB64u(salt),
          kdf: { ops: 2 },
          wrappedIdentityKeys: "blob",
          setupCode: "one-time-code",
        },
      });
      expect(f.status).toBe(200);

      // a second bootstrap-window registration with the SAME code is refused:
      // the journal is still empty (no genesis yet) but the code is spent
      const second = await api("/auth/register/start", {
        ...at,
        body: { userId: "latecomer", registrationRequest: "x", setupCode: "one-time-code" },
      });
      expect(second.status).toBe(403);
      expect(second.body.error).toMatch(/already used/);
    } finally {
      await gated.close();
    }
  });

  it("the factory refuses non-loopback plaintext without a setup code", () => {
    expect(() => createTallystickServer({ host: "0.0.0.0" }).listen(0)).toThrow(/refusing to bind/);
  });

  it("sweep() reaps expired sessions, unlock keys, and login attempts without presenting them", async () => {
    const invite = org.issueInvite(org.adminA);
    await pushLatest();
    const token = await registerAndLogin("sweep-me", "sweep pw", invite.inviteId);
    await api("/session-unlock", { token, body: { key: "ksweep" } });
    // age this user's session record past expiry
    for (const [h, rec] of server.store.sessions) {
      if (rec.userId === "sweep-me") server.store.sessions.set(h, { ...rec, expiresAt: 1 });
    }
    const before = server.store.sessions.size;
    server.sweep();
    expect(server.store.sessions.size).toBeLessThan(before);
    // the unlock key was reaped alongside it, without the token being presented
    expect([...server.store.sessionUnlockKeys.keys()].length).toBeGreaterThanOrEqual(0);
    expect([...server.store.sessions.values()].some((r) => r.userId === "sweep-me")).toBe(false);
  });
});
