// TestOrg: a synthetic org built
// by running the REAL builders through a fake sequencing server. Negative
// tests append hostile entries; the `members` count knob is the seed of the
// layer-7 synthetic-volume generator. Synthetic data only, by construction.

import * as crypto from "../crypto/index.ts";
import type { JsonObject } from "../crypto/index.ts";
import * as b from "./builders.ts";
import { applyEntry, entryHash, ZERO_HASH } from "./state.ts";
import { emptyState } from "./state.ts";
import type { Envelope, OrgState, SignedEntry } from "./types.ts";

export interface TestActor {
  userId: string;
  enc: crypto.BoxKeyPair;
  sign: crypto.SignKeyPair;
  encPk: string;
  signPk: string;
  keys: b.ActorKeys;
}

export function newTestActor(): TestActor {
  const enc = crypto.newBoxKeyPair();
  const sign = crypto.newSignKeyPair();
  const userId = crypto.toB64u(crypto.newId());
  return {
    userId,
    enc,
    sign,
    encPk: crypto.toB64u(enc.publicKey),
    signPk: crypto.toB64u(sign.publicKey),
    keys: { userId, sign },
  };
}

export class TestOrg {
  state: OrgState = emptyState();
  entries: SignedEntry[] = [];
  orgId = crypto.toB64u(crypto.newId());
  now = 1_700_000_000_000; // fixed synthetic clock for expiry-gated builders

  head = newTestActor();
  governance = crypto.newSignKeyPair();
  recovery = crypto.newBoxKeyPair();
  recoveryShares: [Uint8Array, Uint8Array];
  adminA = newTestActor();
  adminB = newTestActor();

  constructor() {
    this.recoveryShares = crypto.xorSplit(this.recovery.privateKey);
    // workflow step 1: bootstrap governance
    this.append(
      b.buildOrgGenesis({
        orgId: this.orgId,
        headUserId: this.head.userId,
        headEncPk: this.head.encPk,
        headSignPk: this.head.signPk,
        governance: this.governance,
        recoveryPk: crypto.toB64u(this.recovery.publicKey),
      }),
    );
    // admins are never invited as admins — everyone enters as an
    // ordinary member (solo-admitted here, below the barrier) and the head
    // PROMOTES them; the barrier arms at the second grant.
    for (const admin of [this.adminA, this.adminB]) {
      const invite = this.issueInvite(this.head);
      this.append(
        b.buildMemberAdmit(this.state, this.governance, {
          userId: admin.userId,
          encPk: admin.encPk,
          signPk: admin.signPk,
          inviteCode: invite.code,
          inviteId: invite.inviteId,
          now: this.now,
        }),
      );
      this.append(b.buildAdminGrant(this.state, this.governance, { userId: admin.userId }));
    }
  }

  /** Journal an invite issuance and return its secrets. */
  issueInvite(issuer: TestActor): { inviteId: string; code: Uint8Array } {
    const inviteId = crypto.toB64u(crypto.newId());
    const code = crypto.newInviteCode();
    this.append(
      b.buildInviteIssue(this.state, issuer.keys, {
        inviteId,
        code,
        issuerEncPk: issuer.encPk,
        now: this.now,
      }),
    );
    return { inviteId, code };
  }

  /** The fake server: assign seq + prev_hash, then verify + apply for real. */
  append(envelope: Envelope): SignedEntry {
    const entry: SignedEntry = {
      seq: this.state.chain.seq + 1,
      prev_hash: this.state.chain.headHash,
      envelope,
    };
    this.state = applyEntry(this.state, entry);
    this.entries.push(entry);
    return entry;
  }

  /** Two-admin admission of a fresh member (workflow step 2, minus PAKE). */
  admitMember(): TestActor {
    const m = newTestActor();
    const invite = this.issueInvite(this.adminA);
    const proposeEnv = b.buildMemberPropose(this.state, this.adminA.keys, {
      userId: m.userId,
      encPk: m.encPk,
      signPk: m.signPk,
      inviteCode: invite.code,
      inviteId: invite.inviteId,
      now: this.now,
    });
    this.append(proposeEnv);
    const proposalId = (proposeEnv.payload as { proposal_id: string }).proposal_id;
    this.append(
      b.buildMemberApprove(this.state, this.adminB.keys, {
        proposalId,
        inviteCode: invite.code,
        now: this.now,
      }),
    );
    return m;
  }

  /** Build a synthetic org of the given size (layer-7 volume knob).
   * `notePlaintext` lets callers supply realistic payloads (e.g. valid
   * Yjs updates for the search benchmark); defaults to plain UTF-8. */
  populate(opts: {
    members: number;
    casesPerMember?: number;
    notesPerCase?: number;
    notePlaintext?: (member: number, cse: number, note: number) => Uint8Array;
  }): TestActor[] {
    const casesPer = opts.casesPerMember ?? 0;
    const notesPer = opts.notesPerCase ?? 0;
    const mk =
      opts.notePlaintext ??
      ((i: number, c: number, n: number) =>
        new TextEncoder().encode(`synthetic note ${i}/${c}/${n}`));
    const actors: TestActor[] = [];
    for (let i = 0; i < opts.members; i++) {
      const m = this.admitMember();
      actors.push(m);
      for (let cse = 0; cse < casesPer; cse++) {
        const caseKey = crypto.newKey();
        const { envelope } = b.buildCaseCreate(this.state, m.keys, {
          caseKey,
          actorEncPk: m.encPk,
        });
        const caseTag = (envelope.payload as { case_tag: string }).case_tag;
        this.append(envelope);
        for (let n = 0; n < notesPer; n++) {
          const { envelope: upd } = b.buildNoteUpdate(this.state, m.keys, {
            caseTag,
            caseKey,
            plaintext: mk(i, cse, n),
          });
          this.append(upd);
        }
      }
    }
    return actors;
  }
}

// ---- tamper helpers -----------------------------------------------------

/** Corrupt an entry without re-signing (server/wire tamper). */
export function tamperEntry(
  entry: SignedEntry,
  mutate: (draft: { seq: number; prev_hash: string; envelope: Envelope }) => void,
): SignedEntry {
  const draft: SignedEntry = structuredClone(entry);
  mutate(draft);
  return draft;
}

/** Clone an envelope under a FRESH event_id, re-signed by the given key —
 * a same-actor retry that must clear the event_id replay guard so the
 * check behind it can be exercised. */
export function withFreshEventId(envelope: Envelope, signKp: crypto.SignKeyPair): Envelope {
  const clone = structuredClone(envelope);
  clone.event_id = crypto.toB64u(crypto.newId());
  const { sig: _drop, ...unsigned } = clone;
  return { ...unsigned, sig: crypto.signEvent(signKp, unsigned as unknown as JsonObject) };
}

/** Rebuild an envelope with a mutated payload, re-signed by an arbitrary
 * key (a forger who controls a real key but lacks authorization). */
export function resignEnvelope(
  envelope: Envelope,
  mutatePayload: (payload: Record<string, unknown>) => void,
  signKp: crypto.SignKeyPair,
): Envelope {
  const clone = structuredClone(envelope);
  mutatePayload(clone.payload);
  const { sig: _drop, ...unsigned } = clone;
  return { ...unsigned, sig: crypto.signEvent(signKp, unsigned as unknown as JsonObject) };
}

export { entryHash, ZERO_HASH };
