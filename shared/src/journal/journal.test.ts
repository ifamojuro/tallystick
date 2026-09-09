import { beforeAll, describe, expect, it } from "vitest";
import * as crypto from "../crypto/index.ts";
import {
  applyEntry,
  replay,
  emptyState,
  BuildRefused,
  InvalidEntry,
  ZERO_HASH,
  buildCaseRekeySolo,
  buildCaseRekeyPropose,
  buildCaseRekeyCountersign,
  buildHeadSucceed,
  buildSuccessionPop,
  successionPopObject,
  buildShareCustodyAck,
  buildDirectoryShare,
  buildMemberAdmit,
  buildAdminGrant,
  buildAdminRevoke,
  buildInviteIssue,
  buildOrgGenesis,
  buildCaseCreate,
  buildCaseGrant,
  buildCaseRevoke,
  buildMemberApprove,
  buildMemberPropose,
  buildNoteUpdate,
  deriveKeychain,
  recoverCaseKey,
  type Envelope,
  type OrgState,
} from "./index.ts";
import {
  TestOrg,
  newTestActor,
  tamperEntry,
  resignEnvelope,
  withFreshEventId,
} from "./fixtures.ts";

beforeAll(async () => {
  await crypto.init();
});

/** Deep snapshot of OrgState (Maps/Sets included) for purity assertions. */
function snapshot(state: OrgState): string {
  const plain = (v: unknown): unknown => {
    if (v instanceof Map) return [...v.entries()].sort().map(([k, x]) => [k, plain(x)]);
    if (v instanceof Set) return [...v.values()].sort();
    if (Array.isArray(v)) return v.map(plain);
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.entries(v)
          .sort()
          .map(([k, x]) => [k, plain(x)]),
      );
    }
    return v;
  };
  return JSON.stringify(plain(state));
}

describe("constants", () => {
  it("ZERO_HASH is 32 zero bytes in b64u", () => {
    expect(ZERO_HASH).toBe(crypto.toB64u(new Uint8Array(32)));
  });
});

describe("full workflow (positive path)", () => {
  it("bootstrap → admit → case → share → concurrent updates → revoke → post-revoke update → recovery", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const bob = org.admitMember();

    // step 3: Alice creates a case with a note
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    org.append(createEnv);
    const note = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: new TextEncoder().encode("intake note (synthetic)"),
    });
    org.append(note.envelope);

    // step 4: share with Bob
    org.append(buildCaseGrant(org.state, alice.keys, { caseTag, caseKey, recipient: bob.userId }));

    // step 5: both write to the SAME note under the same epoch
    org.append(
      buildNoteUpdate(org.state, alice.keys, {
        caseTag,
        caseKey,
        recordId: note.recordId,
        plaintext: new TextEncoder().encode("alice edit"),
      }).envelope,
    );
    org.append(
      buildNoteUpdate(org.state, bob.keys, {
        caseTag,
        caseKey,
        recordId: note.recordId,
        plaintext: new TextEncoder().encode("bob edit"),
      }).envelope,
    );

    // keychains: Bob has the key, an unshared member does not
    const carol = org.admitMember();
    expect(deriveKeychain(org.state, bob.userId, bob.enc).get(caseTag)?.get(1)).toBeDefined();
    expect(deriveKeychain(org.state, carol.userId, carol.enc).has(caseTag)).toBe(false);

    // step 7: revoke Bob → epoch 2 with fresh snapshots
    const newCaseKey = crypto.newKey();
    org.append(
      buildCaseRevoke(org.state, alice.keys, {
        caseTag,
        revoked: bob.userId,
        newCaseKey,
        noteSnapshots: { [note.recordId]: new TextEncoder().encode("compacted state") },
      }),
    );

    // step 8: Alice writes under epoch 2
    const post = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey: newCaseKey,
      recordId: note.recordId,
      plaintext: new TextEncoder().encode("post-revocation update"),
    });
    org.append(post.envelope);

    // step 9: Bob's keychain has epoch 1 but NOT epoch 2 — and cannot
    // decrypt the epoch-2 record key with his old case key
    const bobChain = deriveKeychain(org.state, bob.userId, bob.enc);
    expect(bobChain.get(caseTag)?.get(1)).toBeDefined();
    expect(bobChain.get(caseTag)?.get(2)).toBeUndefined();
    const noteInfo = org.state.cases.get(caseTag)!.notes.get(note.recordId)!;
    const keyAad = { v: 1, org: org.orgId, case: caseTag, epoch: 2, use: "reckey" };
    expect(() =>
      crypto.aeadOpen(caseKey, crypto.fromB64u(noteInfo.wrappedRecordKey), keyAad),
    ).toThrow(crypto.DecryptFailed);
    // ...while Alice (epoch-2 key) can
    const recordKey = crypto.aeadOpen(
      newCaseKey,
      crypto.fromB64u(noteInfo.wrappedRecordKey),
      keyAad,
    );
    expect(recordKey.length).toBe(32);

    // step 10: two-admin recovery — join the printed shares, open both epochs
    const rebuilt = crypto.xorJoin(...org.recoveryShares);
    const recoveryKp = { publicKey: org.recovery.publicKey, privateKey: rebuilt };
    expect(Array.from(recoverCaseKey(org.state, recoveryKp, caseTag, 1))).toEqual(
      Array.from(caseKey),
    );
    expect(Array.from(recoverCaseKey(org.state, recoveryKp, caseTag, 2))).toEqual(
      Array.from(newCaseKey),
    );

    // full replay from scratch reaches the identical state
    expect(snapshot(replay(org.entries))).toBe(snapshot(org.state));
  });
});

describe("negative authorization cases (fail-stop)", () => {
  it("rejects a ghost member: approval hash breaks on a substituted key", () => {
    const org = new TestOrg();
    const m = newTestActor();
    const invite = org.issueInvite(org.adminA);
    const inviteCode = invite.code;
    const proposeEnv = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode,
      inviteId: invite.inviteId,
      now: org.now,
    });
    // server substitutes its own key into the proposal before storing it —
    // adminA's signature over the original payload no longer matches
    const serverKeys = newTestActor();
    const poisoned = tamperEntry(
      { seq: org.state.chain.seq + 1, prev_hash: org.state.chain.headHash, envelope: proposeEnv },
      (d) => {
        (d.envelope.payload as { enc_pk: string }).enc_pk = serverKeys.encPk;
      },
    );
    expect(() => applyEntry(org.state, poisoned)).toThrow(/bad signature/);

    // a forger who re-signs with their own key isn't an admin
    const resigned = resignEnvelope(
      proposeEnv,
      (p) => {
        p["enc_pk"] = serverKeys.encPk;
      },
      serverKeys.sign,
    );
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: { ...resigned, actor: serverKeys.userId },
      }),
    ).toThrow(/no verified signing key/);

    // and the honest approver refuses: binding tag doesn't match their code
    org.append(proposeEnv);
    const proposalId = (proposeEnv.payload as { proposal_id: string }).proposal_id;
    expect(() =>
      buildMemberApprove(org.state, org.adminB.keys, {
        proposalId,
        inviteCode: crypto.newInviteCode(), // wrong code
        now: org.now,
      }),
    ).toThrow(/binding tag mismatch/);
  });

  it("refuses a countersign that would overwrite an existing member", () => {
    const org = new TestOrg();
    const m = newTestActor();
    const inv1 = org.issueInvite(org.adminA);
    const inv2 = org.issueInvite(org.adminA);
    // two pending proposals for the SAME user_id via different invites —
    // both individually valid while the user is not yet admitted
    const prop1 = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: inv1.code,
      inviteId: inv1.inviteId,
      now: org.now,
    });
    org.append(prop1);
    const prop2 = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: inv2.code,
      inviteId: inv2.inviteId,
      now: org.now,
    });
    org.append(prop2);
    // build BOTH approvals while both are still legal, then land the first
    const approve1 = buildMemberApprove(org.state, org.adminB.keys, {
      proposalId: (prop1.payload as { proposal_id: string }).proposal_id,
      inviteCode: inv1.code,
      now: org.now,
    });
    const approve2 = buildMemberApprove(org.state, org.adminB.keys, {
      proposalId: (prop2.payload as { proposal_id: string }).proposal_id,
      inviteCode: inv2.code,
      now: org.now,
    });
    org.append(approve1);
    const pinnedKeys = org.state.members.get(m.userId);
    // an honest client now refuses to even build the second approval
    expect(() =>
      buildMemberApprove(org.state, org.adminB.keys, {
        proposalId: (prop2.payload as { proposal_id: string }).proposal_id,
        inviteCode: inv2.code,
        now: org.now,
      }),
    ).toThrow(/user already exists/);
    // and the verifier is the backstop against a pre-signed hostile one
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: approve2,
      }),
    ).toThrow(/user already exists/);
    // the member's pinned keys are untouched
    expect(org.state.members.get(m.userId)).toEqual(pinnedKeys);
  });

  it("rejects a replayed approval and a reused invite", () => {
    const org = new TestOrg();
    const m = newTestActor();
    const invite = org.issueInvite(org.adminA);
    const inviteCode = invite.code;
    const inviteId = invite.inviteId;
    const proposeEnv = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode,
      inviteId,
      now: org.now,
    });
    org.append(proposeEnv);
    const proposalId = (proposeEnv.payload as { proposal_id: string }).proposal_id;
    const approveEnv = buildMemberApprove(org.state, org.adminB.keys, {
      proposalId,
      inviteCode,
      now: org.now,
    });
    org.append(approveEnv);

    // replaying the same approval: the uniform event_id guard fires first
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: approveEnv,
      }),
    ).toThrow(/event_id reused/);

    // a same-actor retry under a fresh event_id clears that guard and
    // proves the per-type check independently: proposal was consumed
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: withFreshEventId(approveEnv, org.adminB.sign),
      }),
    ).toThrow(/unknown or already-consumed proposal/);

    // reusing the invite for a second admission
    const m2 = newTestActor();
    expect(() =>
      buildMemberPropose(org.state, org.adminA.keys, {
        userId: m2.userId,
        encPk: m2.encPk,
        signPk: m2.signPk,
        inviteCode,
        inviteId, // same invite_id
        now: org.now,
      }),
    ).toThrow(BuildRefused);
  });

  it("event_id uniqueness: any replayed envelope is rejected", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    org.append(createEnv);
    const note = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: new TextEncoder().encode("original"),
    });
    org.append(note.envelope);
    const applyNext = (envelope: typeof note.envelope) => () =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope,
      });

    // THE case the per-type guards accepted before v0.6: a replayed
    // note_update forged a duplicate audit-history entry attributed to
    // its author at a seq where they did nothing
    expect(applyNext(note.envelope)).toThrow(/event_id reused/);
    // types with their own reuse guards now fail uniformly, and earlier
    expect(applyNext(createEnv)).toThrow(/event_id reused/);

    // cross-actor: a DIFFERENT, otherwise-valid event carrying a seen
    // event_id is rejected — uniqueness is journal-global, not per-actor
    const bob = org.admitMember();
    org.append(buildCaseGrant(org.state, alice.keys, { caseTag, caseKey, recipient: bob.userId }));
    const fresh = buildNoteUpdate(org.state, bob.keys, {
      caseTag,
      caseKey,
      recordId: note.recordId,
      plaintext: new TextEncoder().encode("bob's edit"),
    });
    const clone = structuredClone(fresh.envelope);
    clone.event_id = note.envelope.event_id;
    const { sig: _drop, ...unsigned } = clone;
    const collided = {
      ...unsigned,
      sig: crypto.signEvent(bob.sign, unsigned as unknown as crypto.JsonObject),
    };
    expect(applyNext(collided)).toThrow(/event_id reused/);
    // the same event under its own id applies fine
    org.append(fresh.envelope);
  });

  it("event_id bounds, and a rejected entry burns no id (shared-set discipline)", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    org.append(createEnv);
    const note = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: new TextEncoder().encode("x"),
    });
    const applyNext = (envelope: typeof note.envelope) => () =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope,
      });

    // length bounds (empty / >64 chars): the id must not be a memory bomb
    for (const bad of ["", "x".repeat(65)]) {
      const clone = structuredClone(note.envelope);
      clone.event_id = bad;
      const { sig: _drop, ...unsigned } = clone;
      const resigned = {
        ...unsigned,
        sig: crypto.signEvent(alice.sign, unsigned as unknown as crypto.JsonObject),
      };
      expect(applyNext(resigned)).toThrow(/malformed envelope/);
    }

    // a REJECTED entry must leave no residue in the shared set: fail LATE
    // (post-signature, in dispatch) under the genuine envelope's event_id…
    const wrongEpoch = resignEnvelope(
      note.envelope,
      (p) => {
        p["epoch"] = 99;
      },
      alice.sign,
    );
    expect(applyNext(wrongEpoch)).toThrow(/epoch fencing/);
    // …then the genuine envelope, SAME event_id, still applies
    org.append(note.envelope);
    expect(org.state.seenEventIds.has(note.envelope.event_id)).toBe(true);
  });

  it("builder refuses to approve past expiry (approver-clock gate)", () => {
    const org = new TestOrg();
    const m = newTestActor();
    const invite = org.issueInvite(org.adminA);
    const inviteCode = invite.code;
    const proposeEnv = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode,
      inviteId: invite.inviteId,
      now: org.now,
    });
    org.append(proposeEnv);
    const proposalId = (proposeEnv.payload as { proposal_id: string }).proposal_id;
    expect(() =>
      buildMemberApprove(org.state, org.adminB.keys, {
        proposalId,
        inviteCode,
        now: org.now + 25 * 60 * 60 * 1000, // 25h later
      }),
    ).toThrow(/expired/);
  });

  it("rejects a proposal whose checkpoint lies about the chain", () => {
    const org = new TestOrg();
    const m = newTestActor();
    const invite = org.issueInvite(org.adminA);
    const proposeEnv = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: invite.code,
      inviteId: invite.inviteId,
      now: org.now,
    });
    const lied = resignEnvelope(
      proposeEnv,
      (p) => {
        (p["checkpoint"] as { hash: string }).hash = crypto.toB64u(crypto.hash(new Uint8Array(1)));
      },
      org.adminA.sign,
    );
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: lied,
      }),
    ).toThrow(/checkpoint does not match local chain/);
  });

  it("rejects epoch-fenced and revoked-author updates", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const bob = org.admitMember();
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    org.append(createEnv);
    org.append(buildCaseGrant(org.state, alice.keys, { caseTag, caseKey, recipient: bob.userId }));
    const note = buildNoteUpdate(org.state, bob.keys, {
      caseTag,
      caseKey,
      plaintext: new TextEncoder().encode("bob note"),
    });
    org.append(note.envelope);

    // Bob prepares an update, but Alice's revoke is sequenced first
    const stale = buildNoteUpdate(org.state, bob.keys, {
      caseTag,
      caseKey,
      recordId: note.recordId,
      plaintext: new TextEncoder().encode("in-flight edit"),
    });
    org.append(
      buildCaseRevoke(org.state, alice.keys, {
        caseTag,
        revoked: bob.userId,
        newCaseKey: crypto.newKey(),
        noteSnapshots: { [note.recordId]: new TextEncoder().encode("compacted") },
      }),
    );
    // stale epoch-1 update lands after the fence → rejected
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: stale.envelope,
      }),
    ).toThrow(/epoch fencing/);

    // Bob forging a current-epoch claim: he holds no epoch-2 grant
    const forged = resignEnvelope(
      stale.envelope,
      (p) => {
        p["epoch"] = 2;
      },
      bob.sign,
    );
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: forged,
      }),
    ).toThrow(/no grant/);

    // and the builder refuses on Bob's behalf once state shows the revoke
    expect(() =>
      buildNoteUpdate(org.state, bob.keys, {
        caseTag,
        caseKey,
        recordId: note.recordId,
        plaintext: new TextEncoder().encode("try again"),
      }),
    ).toThrow(BuildRefused);
  });

  it("rejects grants by non-creators and revocation of the creator", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const bob = org.admitMember();
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    org.append(createEnv);
    org.append(buildCaseGrant(org.state, alice.keys, { caseTag, caseKey, recipient: bob.userId }));

    expect(() =>
      buildCaseGrant(org.state, bob.keys, { caseTag, caseKey, recipient: org.adminA.userId }),
    ).toThrow(BuildRefused);
    expect(() =>
      buildCaseRevoke(org.state, bob.keys, {
        caseTag,
        revoked: alice.userId,
        newCaseKey: crypto.newKey(),
        noteSnapshots: {},
      }),
    ).toThrow(BuildRefused);
    expect(() =>
      buildCaseRevoke(org.state, alice.keys, {
        caseTag,
        revoked: alice.userId,
        newCaseKey: crypto.newKey(),
        noteSnapshots: {},
      }),
    ).toThrow(/creator cannot be revoked/);
  });

  it("rejects broken chains: bad prev_hash, out-of-order seq, tampered history", () => {
    const org = new TestOrg();
    org.admitMember();
    const good: ReturnType<TestOrg["append"]> = org.entries[org.entries.length - 1]!;

    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 2, // gap
        prev_hash: org.state.chain.headHash,
        envelope: good.envelope,
      }),
    ).toThrow(/expected seq/);
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: ZERO_HASH, // wrong parent
        envelope: good.envelope,
      }),
    ).toThrow(/prev_hash/);

    // tamper an early entry: replay halts at the splice, naming the seq
    const forked = org.entries.map((e, i) =>
      i === 1 ? tamperEntry(e, (d) => (d.envelope.actor = "forged")) : e,
    );
    expect(() => replay(forked)).toThrow(InvalidEntry);
    try {
      replay(forked);
    } catch (e) {
      expect((e as InvalidEntry).seq).toBe(2);
    }
  });

  it("applyEntry is pure: a failing entry leaves state untouched (checklist item 4)", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const caseKey = crypto.newKey();
    const { envelope: createEnv } = buildCaseCreate(org.state, alice.keys, {
      caseKey,
      actorEncPk: alice.encPk,
    });
    org.append(createEnv);
    const before = snapshot(org.state);

    // fails LATE in validation (authorization stage), after passing chain,
    // shape, and signature — the dangerous path for partial mutation
    const caseTag = (createEnv.payload as { case_tag: string }).case_tag;
    const notCreator = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: new TextEncoder().encode("x"),
    });
    const wrongEpoch = resignEnvelope(
      notCreator.envelope,
      (p) => {
        p["epoch"] = 99;
      },
      alice.sign,
    );
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: wrongEpoch,
      }),
    ).toThrow(InvalidEntry);
    expect(snapshot(org.state)).toBe(before);
  });

  it("member_admit shape rules hold at the verifier", () => {
    const org = new TestOrg(); // constructor appoints two admins → barrier armed
    expect(org.state.adminBarrierArmed).toBe(true);

    // a real pending proposal, and the genuine countersign admit for it
    const m = newTestActor();
    const invite = org.issueInvite(org.adminA);
    const proposeEnv = buildMemberPropose(org.state, org.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: invite.code,
      inviteId: invite.inviteId,
      now: org.now,
    });
    org.append(proposeEnv);
    const goodAdmit = buildMemberApprove(org.state, org.adminB.keys, {
      proposalId: (proposeEnv.payload as { proposal_id: string }).proposal_id,
      inviteCode: invite.code,
      now: org.now,
    });

    // (a) SOLO-shape admit after the barrier armed: rejected by the
    // VERIFIER even with a genuine governance signature (the builder's
    // refusal is tested in the solo-governance suite; this pins applyEntry)
    const ghost = newTestActor();
    const invite2 = org.issueInvite(org.head);
    const unsigned = {
      v: 1 as const,
      type: "member_admit" as const,
      event_id: crypto.toB64u(crypto.newId()),
      org_id: org.orgId,
      actor: org.head.userId,
      payload: {
        user_id: ghost.userId,
        enc_pk: ghost.encPk,
        sign_pk: ghost.signPk,
        invite_id: invite2.inviteId,
        binding_tag: "irrelevant-barrier-fires-first",
      },
    };
    const soloAfterBarrier = {
      ...unsigned,
      sig: crypto.signEvent(org.governance, unsigned as unknown as crypto.JsonObject),
    };
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: soloAfterBarrier,
      }),
    ).toThrow(/two admins have existed/);

    // (b) COUNTERSIGN shape signed with the governance key: shape dispatch
    // demands the acting admin's MEMBER signature, so this dies as a bad
    // signature — the governance key cannot countersign admissions
    const govSigned = resignEnvelope(goodAdmit, () => {}, org.governance);
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: govSigned,
      }),
    ).toThrow(/bad signature/);

    // the genuine countersign still applies
    org.append(goodAdmit);
    expect(org.state.members.get(m.userId)?.role).toBe("member");

    // (c) terminal-event invariant: replaying the whole journal, the
    // roster grows only on org_genesis, admin_appoint, or member_admit —
    // and this ordinary member arrived via a countersign member_admit
    let s = emptyState();
    for (const entry of org.entries) {
      const before = s.members.size;
      s = applyEntry(s, entry);
      if (s.members.size > before) {
        expect(["org_genesis", "admin_appoint", "member_admit"]).toContain(entry.envelope.type);
      }
    }
    const last = org.entries[org.entries.length - 1]!;
    expect(last.envelope.type).toBe("member_admit");
    expect("proposal_id" in last.envelope.payload).toBe(true);
  });
});

describe("solo-governance mode", () => {
  // build a head-only org with the real builders (no fixture admins)
  const soloOrg = () => {
    const head = newTestActor();
    const governance = crypto.newSignKeyPair();
    const recovery = crypto.newBoxKeyPair();
    const orgId = crypto.toB64u(crypto.newId());
    let state = applyEntry(
      { ...emptyStateFor() },
      {
        seq: 1,
        prev_hash: ZERO_HASH,
        envelope: buildOrgGenesis({
          orgId,
          headUserId: head.userId,
          headEncPk: head.encPk,
          headSignPk: head.signPk,
          governance,
          recoveryPk: crypto.toB64u(recovery.publicKey),
        }),
      },
    );
    const append = (env: ReturnType<typeof buildOrgGenesis>) => {
      state = applyEntry(state, {
        seq: state.chain.seq + 1,
        prev_hash: state.chain.headHash,
        envelope: env,
      });
    };
    const issueMember = () => {
      const inviteId = crypto.toB64u(crypto.newId());
      const code = crypto.newInviteCode();
      append(
        buildInviteIssue(state, head.keys, {
          inviteId,
          code,
          issuerEncPk: head.encPk,
          now: 1_700_000_000_000,
        }),
      );
      return { inviteId, code };
    };
    return {
      head,
      governance,
      get state() {
        return state;
      },
      append,
      issueMember,
    };
  };
  const emptyStateFor = () => emptyState();

  it("the head admits members alone below two admins; a case works end to end", () => {
    const org = soloOrg();
    const m = newTestActor();
    const inv = org.issueMember();
    org.append(
      buildMemberAdmit(org.state, org.governance, {
        userId: m.userId,
        encPk: m.encPk,
        signPk: m.signPk,
        inviteCode: inv.code,
        inviteId: inv.inviteId,
        now: 1_700_000_000_000,
      }),
    );
    expect(org.state.members.get(m.userId)?.role).toBe("member");
    // solo-admitted members create and share cases like any member
    const caseKey = crypto.newKey();
    const { envelope } = buildCaseCreate(org.state, m.keys, {
      caseKey,
      actorEncPk: m.encPk,
    });
    org.append(envelope);
    expect(org.state.cases.size).toBe(1);
  });

  it("solo admission still requires the governance signature and fresh invite", () => {
    const org = soloOrg();
    const m = newTestActor();
    const inv = org.issueMember();
    const forged = buildMemberAdmit(org.state, org.governance, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: inv.code,
      inviteId: inv.inviteId,
      now: 1_700_000_000_000,
    });
    // re-signed by a non-governance key → rejected
    const evil = newTestActor();
    const resigned = resignEnvelope(forged, () => {}, evil.sign);
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: resigned,
      }),
    ).toThrow(/bad signature/);
  });

  it("the mode flips off permanently once two admins exist", () => {
    // TestOrg bootstraps WITH two admins — head-solo admission must fail
    const org = new TestOrg();
    const m = newTestActor();
    expect(() =>
      buildMemberAdmit(org.state, org.governance, {
        userId: m.userId,
        encPk: m.encPk,
        signPk: m.signPk,
        inviteCode: crypto.newInviteCode(),
        inviteId: crypto.toB64u(crypto.newId()),
        now: 1_700_000_000_000,
      }),
    ).toThrow(/two admins have existed/);
    // a PROPERLY SIGNED member_admit (real governance key, real org) is
    // still rejected by every verifier — the rule lives in applyEntry, not
    // just the builder. Build it against a doctored state with the admins
    // stripped, the barrier disarmed, and a fake journaled invite so the
    // builder cooperates. (applyEntry's armed check fires before its
    // invite-provenance check, so the doctored invite never matters there.)
    const fakeInviteId = crypto.toB64u(crypto.newId());
    const doctored = {
      ...org.state,
      adminBarrierArmed: false,
      members: new Map([...org.state.members].filter(([, v]) => v.role !== "admin")),
      invites: new Map([
        ...org.state.invites,
        [
          fakeInviteId,
          {
            issuer: org.head.userId,
            sealedCode: "x",
            issuedAtSeq: 1,
            expiresAt: 9_999_999_999_999,
          },
        ],
      ]),
    };
    const env = buildMemberAdmit(doctored, org.governance, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: crypto.newInviteCode(),
      inviteId: fakeInviteId,
      now: 1_700_000_000_000,
    });
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: env,
      }),
    ).toThrow(/solo admission is permanently off/);
  });

  it("rejects admissions whose invite was never journaled (provenance)", () => {
    const org = soloOrg();
    const m = newTestActor();
    // builder is tricked with a doctored state containing a fake issuance;
    // the REAL state has no such invite → the verifier refuses
    const fakeId = crypto.toB64u(crypto.newId());
    const doctored = {
      ...org.state,
      invites: new Map([
        [
          fakeId,
          {
            issuer: org.head.userId,
            sealedCode: "x",
            issuedAtSeq: 1,
            expiresAt: 9_999_999_999_999,
          },
        ],
      ]),
    };
    const env = buildMemberAdmit(doctored, org.governance, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: crypto.newInviteCode(),
      inviteId: fakeId,
      now: 1_700_000_000_000,
    });
    expect(() =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope: env,
      }),
    ).toThrow(/no journaled invite/);
    // and a non-member cannot issue invites at all
    const outsider = newTestActor();
    expect(() =>
      buildInviteIssue(org.state, outsider.keys, {
        inviteId: crypto.toB64u(crypto.newId()),
        code: crypto.newInviteCode(),
        issuerEncPk: outsider.encPk,
        now: 1_700_000_000_000,
      }),
    ).toThrow(/only the head or an active admin/);
  });

  it("invites expire by the signer's clock at use; replay stays clock-free", () => {
    const org = soloOrg();
    const m = newTestActor();
    const inv = org.issueMember(); // expires_at = fixture now + 72h
    const LATER = 1_700_000_000_000 + 73 * 60 * 60 * 1000; // 73h on

    // the head's builder refuses an expired invite (all three use-points
    // share the same requireIssued gate)
    expect(() =>
      buildMemberAdmit(org.state, org.governance, {
        userId: m.userId,
        encPk: m.encPk,
        signPk: m.signPk,
        inviteCode: inv.code,
        inviteId: inv.inviteId,
        now: LATER,
      }),
    ).toThrow(/invite expired/);

    // within the window the same invite admits fine
    org.append(
      buildMemberAdmit(org.state, org.governance, {
        userId: m.userId,
        encPk: m.encPk,
        signPk: m.signPk,
        inviteCode: inv.code,
        inviteId: inv.inviteId,
        now: 1_700_000_000_000 + 60 * 60 * 1000, // 1h on
      }),
    );
    expect(org.state.members.get(m.userId)?.role).toBe("member");
    // note: applyEntry accepted the admission with no clock input at all —
    // expiry is signer-side only, so replay stays deterministic forever
  });

  it("admin is a grantable/revocable title; the barrier is one-way", () => {
    const org = soloOrg();
    const admitSolo = () => {
      const m = newTestActor();
      const inv = org.issueMember();
      org.append(
        buildMemberAdmit(org.state, org.governance, {
          userId: m.userId,
          encPk: m.encPk,
          signPk: m.signPk,
          inviteCode: inv.code,
          inviteId: inv.inviteId,
          now: 1_700_000_000_000,
        }),
      );
      return m;
    };
    const m1 = admitSolo();
    const m2 = admitSolo();

    // promote m1: 1 admin, barrier still unarmed → solo admission still ok
    org.append(buildAdminGrant(org.state, org.governance, { userId: m1.userId }));
    expect(org.state.members.get(m1.userId)?.role).toBe("admin");
    expect(org.state.adminBarrierArmed).toBe(false);
    const m3 = admitSolo(); // works at 1 admin

    // promote m2: 2 admins → barrier arms
    org.append(buildAdminGrant(org.state, org.governance, { userId: m2.userId }));
    expect(org.state.adminBarrierArmed).toBe(true);
    expect(() => admitSolo()).toThrow(/two admins have existed/);

    // a third concurrent admin is refused
    expect(() => buildAdminGrant(org.state, org.governance, { userId: m3.userId })).toThrow(
      /already two active admins/,
    );

    // demote m2 → back to member, but the barrier STAYS armed:
    // demote-then-ghost is not a path back to solo admission
    org.append(buildAdminRevoke(org.state, org.governance, { userId: m2.userId }));
    expect(org.state.members.get(m2.userId)?.role).toBe("member");
    expect(org.state.adminBarrierArmed).toBe(true);
    expect(() => admitSolo()).toThrow(/two admins have existed/);

    // re-promote a member to restore the admin pair; two-admin admission works
    org.append(buildAdminGrant(org.state, org.governance, { userId: m3.userId }));
    const joiner = newTestActor();
    const inv = org.issueMember();
    const code = inv.code;
    const proposeEnv = buildMemberPropose(org.state, m1.keys, {
      userId: joiner.userId,
      encPk: joiner.encPk,
      signPk: joiner.signPk,
      inviteCode: code,
      inviteId: inv.inviteId,
      now: 1_700_000_000_000,
    });
    org.append(proposeEnv);
    org.append(
      buildMemberApprove(org.state, m3.keys, {
        proposalId: (proposeEnv.payload as { proposal_id: string }).proposal_id,
        inviteCode: code,
        now: 1_700_000_000_000,
      }),
    );
    expect(org.state.members.get(joiner.userId)?.role).toBe("member");

    // demoting a non-admin fails
    expect(() => buildAdminRevoke(org.state, org.governance, { userId: m2.userId })).toThrow(
      /not an active admin/,
    );
  });
});

describe("volume knob (layer-7 seed)", () => {
  it("populates a small synthetic org and replays it", () => {
    const org = new TestOrg();
    org.populate({ members: 5, casesPerMember: 2, notesPerCase: 2 });
    expect(org.state.members.size).toBe(3 + 5); // head + 2 admins + 5
    expect(org.state.cases.size).toBe(10);
    expect(snapshot(replay(org.entries))).toBe(snapshot(org.state));
  });
});

describe("recovery ceremonies", () => {
  const NOW = 1_700_000_000_000;
  const enc = (s: string) => new TextEncoder().encode(s);
  /** clone an envelope under a different actor, re-signed by `kp` */
  const asActor = (env: Envelope, actor: string, kp: crypto.SignKeyPair): Envelope => {
    const { sig: _drop, ...unsigned } = { ...structuredClone(env), actor };
    return { ...unsigned, sig: crypto.signEvent(kp, unsigned as unknown as crypto.JsonObject) };
  };
  const applyNext = (org: { state: OrgState }, envelope: Envelope) => () =>
    applyEntry(org.state, {
      seq: org.state.chain.seq + 1,
      prev_hash: org.state.chain.headHash,
      envelope,
    });

  // head-only org exposing the recovery keypair (solo rekey path)
  const soloRecoveryOrg = () => {
    const head = newTestActor();
    const governance = crypto.newSignKeyPair();
    const recovery = crypto.newBoxKeyPair();
    const orgId = crypto.toB64u(crypto.newId());
    let state = emptyState();
    const append = (envelope: Envelope) => {
      state = applyEntry(state, {
        seq: state.chain.seq + 1,
        prev_hash: state.chain.headHash,
        envelope,
      });
    };
    append(
      buildOrgGenesis({
        orgId,
        headUserId: head.userId,
        headEncPk: head.encPk,
        headSignPk: head.signPk,
        governance,
        recoveryPk: crypto.toB64u(recovery.publicKey),
      }),
    );
    const admitSolo = () => {
      const m = newTestActor();
      const inviteId = crypto.toB64u(crypto.newId());
      const code = crypto.newInviteCode();
      append(
        buildInviteIssue(state, head.keys, {
          inviteId,
          code,
          issuerEncPk: head.encPk,
          now: NOW,
        }),
      );
      append(
        buildMemberAdmit(state, governance, {
          userId: m.userId,
          encPk: m.encPk,
          signPk: m.signPk,
          inviteCode: code,
          inviteId,
          now: NOW,
        }),
      );
      return m;
    };
    return {
      head,
      governance,
      recovery,
      admitSolo,
      append,
      get state() {
        return state;
      },
    };
  };

  it("solo rekey: the head restores an orphaned case to a new holder", () => {
    const org = soloRecoveryOrg();
    const alice = org.admitSolo();
    const bob = org.admitSolo();
    const caseKey = crypto.newKey();
    const create = buildCaseCreate(org.state, alice.keys, { caseKey, actorEncPk: alice.encPk });
    org.append(create.envelope);
    const caseTag = (create.envelope.payload as { case_tag: string }).case_tag;
    const note = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: enc("orphaned content"),
    });
    org.append(note.envelope);

    // alice is gone; the two-share ceremony recovers epoch 1's key…
    expect([...recoverCaseKey(org.state, org.recovery, caseTag, 1)]).toEqual([...caseKey]);

    // …and the head re-keys the case to bob (workflow step 10 + restore)
    const newKey = crypto.newKey();
    const rekey = buildCaseRekeySolo(org.state, org.governance, {
      caseTag,
      newCaseKey: newKey,
      holders: [bob.userId],
      noteSnapshots: { [note.recordId]: enc("compacted") },
      now: NOW,
    });
    // a non-head actor is rejected even with a genuine governance signature
    expect(applyNext(org, asActor(rekey, alice.userId, org.governance))).toThrow(
      /actor must be head/,
    );
    org.append(rekey);

    const c = org.state.cases.get(caseTag)!;
    expect(c.epochs.length).toBe(2);
    expect([...c.epochs[1]!.holders.keys()]).toEqual([bob.userId]);
    // bob's keychain gains epoch 2; the departed creator's does not
    expect(deriveKeychain(org.state, bob.userId, bob.enc).get(caseTag)?.get(2)).toBeDefined();
    expect(deriveKeychain(org.state, alice.userId, alice.enc).get(caseTag)?.get(2)).toBeUndefined();
    // the new epoch is itself recoverable (the ceremony stays repeatable)
    expect([...recoverCaseKey(org.state, org.recovery, caseTag, 2)]).toEqual([...newKey]);
  });

  it("two-admin rekey: propose + countersign; rogue shapes rejected", () => {
    const org = new TestOrg(); // barrier armed
    const alice = org.admitMember();
    const bob = org.admitMember();
    const caseKey = crypto.newKey();
    const create = buildCaseCreate(org.state, alice.keys, { caseKey, actorEncPk: alice.encPk });
    org.append(create.envelope);
    const caseTag = (create.envelope.payload as { case_tag: string }).case_tag;
    const note = buildNoteUpdate(org.state, alice.keys, {
      caseTag,
      caseKey,
      plaintext: enc("x"),
    });
    org.append(note.envelope);

    // the solo builder refuses once the barrier armed
    expect(() =>
      buildCaseRekeySolo(org.state, org.governance, {
        caseTag,
        newCaseKey: crypto.newKey(),
        holders: [bob.userId],
        noteSnapshots: { [note.recordId]: enc("s") },
        now: NOW,
      }),
    ).toThrow(BuildRefused);

    const prop = buildCaseRekeyPropose(org.state, org.adminA.keys, {
      caseTag,
      newCaseKey: crypto.newKey(),
      holders: [bob.userId],
      noteSnapshots: { [note.recordId]: enc("compacted") },
      now: NOW,
    });
    // governance-signed FULL shape while armed: shape rule demands the
    // admin's member key, so this dies as a bad signature
    expect(applyNext(org, asActor(prop.envelope, org.head.userId, org.governance))).toThrow(
      /bad signature/,
    );
    // a non-admin proposer is rejected
    expect(applyNext(org, asActor(prop.envelope, alice.userId, alice.sign))).toThrow(
      /must come from an active admin/,
    );

    // the real proposal: pending, case unchanged
    org.append(prop.envelope);
    expect(org.state.pendingRekeys.has(prop.rekeyId)).toBe(true);
    expect(org.state.cases.get(caseTag)!.epochs.length).toBe(1);

    const counter = buildCaseRekeyCountersign(org.state, org.adminB.keys, {
      rekeyId: prop.rekeyId,
      now: org.now,
    });
    // countersign by the proposer, by a non-admin, with a lying hash, or
    // for an unknown proposal: all rejected
    expect(applyNext(org, asActor(counter, org.adminA.userId, org.adminA.sign))).toThrow(
      /different admin/,
    );
    expect(applyNext(org, asActor(counter, alice.userId, alice.sign))).toThrow(
      /must come from an active admin/,
    );
    expect(
      applyNext(
        org,
        resignEnvelope(
          counter,
          (p) => {
            p["proposal_hash"] = crypto.toB64u(crypto.hash(enc("lie")));
          },
          org.adminB.sign,
        ),
      ),
    ).toThrow(/proposal_hash does not match/);
    expect(
      applyNext(
        org,
        resignEnvelope(
          counter,
          (p) => {
            p["rekey_id"] = crypto.toB64u(crypto.newId());
          },
          org.adminB.sign,
        ),
      ),
    ).toThrow(/unknown or already-consumed/);
    // the countersign BUILDER enforces the 24 h TTL (approver-clock rule)
    expect(() =>
      buildCaseRekeyCountersign(org.state, org.adminB.keys, {
        rekeyId: prop.rekeyId,
        now: NOW + 25 * 60 * 60 * 1000,
      }),
    ).toThrow(/expired/);

    // commit
    org.append(counter);
    const c = org.state.cases.get(caseTag)!;
    expect(c.epochs.length).toBe(2);
    expect([...c.epochs[1]!.holders.keys()]).toEqual([bob.userId]);
    expect(org.state.pendingRekeys.size).toBe(0);
    // a replay fails the event_id guard; a fresh-id retry finds no proposal
    expect(applyNext(org, counter)).toThrow(/event_id reused/);
    expect(applyNext(org, withFreshEventId(counter, org.adminB.sign))).toThrow(
      /unknown or already-consumed/,
    );
  });

  it("a stale rekey proposal is invalidated by interleaved journal activity", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const bob = org.admitMember();
    const caseKey = crypto.newKey();
    const create = buildCaseCreate(org.state, alice.keys, { caseKey, actorEncPk: alice.encPk });
    org.append(create.envelope);
    const caseTag = (create.envelope.payload as { case_tag: string }).case_tag;
    const note = buildNoteUpdate(org.state, alice.keys, { caseTag, caseKey, plaintext: enc("x") });
    org.append(note.envelope);
    const prop = buildCaseRekeyPropose(org.state, org.adminA.keys, {
      caseTag,
      newCaseKey: crypto.newKey(),
      holders: [bob.userId],
      noteSnapshots: { [note.recordId]: enc("s") },
      now: NOW,
    });
    org.append(prop.envelope);
    // alice writes a NEW note after the proposal: its snapshot set is stale
    org.append(
      buildNoteUpdate(org.state, alice.keys, { caseTag, caseKey, plaintext: enc("new note") })
        .envelope,
    );
    const counter = buildCaseRekeyCountersign(org.state, org.adminB.keys, {
      rekeyId: prop.rekeyId,
      now: org.now,
    });
    expect(applyNext(org, counter)).toThrow(/snapshots must cover exactly/);
  });

  it("head_succeed: admin-only successor; the old governance key retires; pop required", () => {
    const org = new TestOrg();
    const m = org.admitMember();
    const newGov = crypto.newSignKeyPair();
    const popA = buildSuccessionPop(org.orgId, org.adminA.userId, newGov);

    // successor must be an active admin (builder and verifier agree)
    expect(() =>
      buildHeadSucceed(org.state, org.governance, {
        newHeadUserId: m.userId,
        newGovernancePk: crypto.toB64u(newGov.publicKey),
        pop: buildSuccessionPop(org.orgId, m.userId, newGov),
      }),
    ).toThrow(BuildRefused);

    // proof of possession (v0.9.1): the builder refuses a key string that
    // nothing living can sign for — the governance-bricking channel
    expect(() =>
      buildHeadSucceed(org.state, org.governance, {
        newHeadUserId: org.adminA.userId,
        newGovernancePk: crypto.toB64u(crypto.newSignKeyPair().publicKey), // typo'd/garbage key
        pop: popA,
      }),
    ).toThrow(/does not prove possession/);

    const succeed = buildHeadSucceed(org.state, org.governance, {
      newHeadUserId: org.adminA.userId,
      newGovernancePk: crypto.toB64u(newGov.publicKey),
      pop: popA,
    });

    // VERIFIER-level pop checks (a hostile head could bypass the builder):
    // garbage pop rejected
    const badPop = resignEnvelope(
      succeed,
      (p) => {
        p["pop"] = crypto.toB64u(new Uint8Array(64));
      },
      org.governance,
    );
    expect(applyNext(org, badPop)).toThrow(/invalid proof of possession/);
    // pop signed by the WRONG key (the old governance key) rejected
    const wrongKeyPop = resignEnvelope(
      succeed,
      (p) => {
        p["pop"] = crypto.signEvent(
          org.governance,
          successionPopObject(org.orgId, org.adminA.userId, crypto.toB64u(newGov.publicKey)),
        );
      },
      org.governance,
    );
    expect(applyNext(org, wrongKeyPop)).toThrow(/invalid proof of possession/);
    // a pop cannot be transplanted onto a different successor
    const transplanted = resignEnvelope(
      succeed,
      (p) => {
        p["new_head_user_id"] = org.adminB.userId;
      },
      org.governance,
    );
    expect(applyNext(org, transplanted)).toThrow(/invalid proof of possession/);

    const toMember = resignEnvelope(
      succeed,
      (p) => {
        p["new_head_user_id"] = m.userId;
      },
      org.governance,
    );
    expect(applyNext(org, toMember)).toThrow(/successor must be an active admin/);
    // only the head may succeed
    expect(applyNext(org, asActor(succeed, org.adminB.userId, org.governance))).toThrow(
      /actor must be head/,
    );

    org.append(succeed);
    expect(org.state.currentHeadUserId).toBe(org.adminA.userId);
    expect(org.state.members.get(org.adminA.userId)?.role).toBe("head");
    expect(org.state.members.get(org.head.userId)?.role).toBe("member");
    // the successor vacated their admin seat; the barrier stays armed
    expect(org.state.adminBarrierArmed).toBe(true);

    // the NEW governance key governs (refill the admin seat)…
    org.append(buildAdminGrant(org.state, newGov, { userId: m.userId }));
    expect(org.state.members.get(m.userId)?.role).toBe("admin");
    // …and the OLD one signs nothing valid anymore: a stolen or stale head
    // package is dead paper after succession
    const staleUnsigned = {
      v: 1 as const,
      type: "admin_grant" as const,
      event_id: crypto.toB64u(crypto.newId()),
      org_id: org.orgId,
      actor: org.state.currentHeadUserId,
      payload: { user_id: org.head.userId },
    };
    const stale = {
      ...staleUnsigned,
      sig: crypto.signEvent(org.governance, staleUnsigned as unknown as crypto.JsonObject),
    };
    expect(applyNext(org, stale)).toThrow(/bad signature/);

    // self-succession = pure governance-key rotation
    const rotated = crypto.newSignKeyPair();
    org.append(
      buildHeadSucceed(org.state, newGov, {
        newHeadUserId: org.adminA.userId,
        newGovernancePk: crypto.toB64u(rotated.publicKey),
        pop: buildSuccessionPop(org.orgId, org.adminA.userId, rotated),
      }),
    );
    expect(org.state.currentHeadUserId).toBe(org.adminA.userId);
    expect(org.state.members.get(org.adminA.userId)?.role).toBe("head");
    expect(org.state.currentGovernancePk).toBe(crypto.toB64u(rotated.publicKey));
  });

  it("directory_share: member fan-out only, bounded, sealed opaque to the verifier", () => {
    const org = new TestOrg();
    const alice = org.admitMember();
    const applyNext2 = (envelope: Envelope) => () =>
      applyEntry(org.state, {
        seq: org.state.chain.seq + 1,
        prev_hash: org.state.chain.headHash,
        envelope,
      });

    // happy path: head shares a name map to two members
    const share = buildDirectoryShare(org.state, org.head.keys, {
      names: { [org.head.userId]: "Rosa" },
      recipients: [org.adminA.userId, alice.userId],
      at: 1_700_000_000_000,
    });
    org.append(share);
    expect(org.state.directoryShares.length).toBe(1);
    expect(org.state.directoryShares[0]!.actor).toBe(org.head.userId);
    // the sealed box opens ONLY for its recipient
    const box = crypto.fromB64u(org.state.directoryShares[0]!.envelopes[alice.userId]!);
    const opened = JSON.parse(new TextDecoder().decode(crypto.openSealed(alice.enc, box)));
    expect(opened.names[org.head.userId]).toBe("Rosa");
    expect(() => crypto.openSealed(org.adminB.enc, box)).toThrow();

    // an outsider cannot fan out (no verified signing key)
    const stranger = newTestActor();
    const forged = {
      v: 1 as const,
      type: "directory_share" as const,
      event_id: crypto.toB64u(crypto.newId()),
      org_id: org.orgId,
      actor: stranger.userId,
      payload: { envelopes: { [alice.userId]: "AAAA" } },
    };
    expect(
      applyNext2({ ...forged, sig: crypto.signEvent(stranger.sign, forged as never) }),
    ).toThrow(/no verified signing key/);

    // a recipient outside the roster is rejected
    const badRecipient = resignEnvelope(
      share,
      (p) => {
        (p["envelopes"] as Record<string, string>)[stranger.userId] = "AAAA";
      },
      org.head.sign,
    );
    expect(applyNext2(withFreshEventId(badRecipient, org.head.sign))).toThrow(
      /recipient is not an admitted member/,
    );
    // empty and oversized envelopes are rejected
    const empty = resignEnvelope(share, (p) => void (p["envelopes"] = {}), org.head.sign);
    expect(applyNext2(withFreshEventId(empty, org.head.sign))).toThrow(/at least one recipient/);
    const oversized = resignEnvelope(
      share,
      (p) => {
        (p["envelopes"] as Record<string, string>)[alice.userId] = "A".repeat(20000);
      },
      org.head.sign,
    );
    expect(applyNext2(withFreshEventId(oversized, org.head.sign))).toThrow(
      /malformed sealed envelope/,
    );
    // the builder refuses unknown recipients up front
    expect(() =>
      buildDirectoryShare(org.state, org.head.keys, {
        names: { [org.head.userId]: "Rosa" },
        recipients: [stranger.userId],
        at: 1,
      }),
    ).toThrow(BuildRefused);
  });

  it("share_custody_ack: receiver-signed, latest ack wins, outsiders rejected", () => {
    const org = new TestOrg();
    // genesis reality journaled: the head holds both shares
    org.append(buildShareCustodyAck(org.state, org.head.keys, { share: "A" }));
    org.append(buildShareCustodyAck(org.state, org.head.keys, { share: "B" }));
    expect(org.state.shareCustody).toEqual({ A: org.head.userId, B: org.head.userId });
    // physical handoff to an admin, acknowledged by the RECEIVER
    org.append(buildShareCustodyAck(org.state, org.adminA.keys, { share: "A" }));
    expect(org.state.shareCustody).toEqual({ A: org.adminA.userId, B: org.head.userId });
    // malformed share label
    const ack = buildShareCustodyAck(org.state, org.adminB.keys, { share: "B" });
    expect(
      applyNext(
        org,
        resignEnvelope(
          ack,
          (p) => {
            p["share"] = "C";
          },
          org.adminB.sign,
        ),
      ),
    ).toThrow(/share must be A or B/);
    // an outsider has no verified signing key
    const stranger = newTestActor();
    expect(applyNext(org, asActor(ack, stranger.userId, stranger.sign))).toThrow(
      /no verified signing key/,
    );
  });
});
