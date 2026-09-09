// applyEntry: the pure verifier.
// (state, entry) → new state, or throws InvalidEntry. No I/O, no clock.
//
// Discipline (review checklist item 4): every handler is two-phase — all
// checks and throws BEFORE any write; the commit phase path-copies only the
// containers it touches and cannot throw. applyEntry never mutates its
// input state, with ONE sanctioned exception: seenEventIds is an append-only
// set shared across state generations (see its OrgState doc) — applyEntry
// adds to it in the commit step, so a SUCCESSFUL apply is visible through
// old state references, while a rejected entry still leaves no trace.

import * as crypto from "../crypto/index.ts";
import type { JsonObject } from "../crypto/index.ts";
import { InvalidEntry } from "./errors.ts";
import type {
  AdminRolePayload,
  InviteIssuePayload,
  CaseCreatePayload,
  CaseGrantPayload,
  CaseInfo,
  CaseRekeyPayload,
  CaseRekeyCountersignPayload,
  CaseRevokePayload,
  DirectorySharePayload,
  HeadSucceedPayload,
  ShareCustodyAckPayload,
  Envelope,
  GenesisPayload,
  MemberAdmitPayload,
  MemberAdmitCountersignPayload,
  MemberProposePayload,
  NoteUpdatePayload,
  OrgState,
  SignedEntry,
} from "./types.ts";

export const ZERO_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes, b64u

export function emptyState(): OrgState {
  return {
    orgId: "",
    genesis: null,
    chain: { seq: 0, headHash: ZERO_HASH, hashLog: null },
    currentHeadUserId: "",
    currentGovernancePk: "",
    members: new Map(),
    proposals: new Map(),
    pendingRekeys: new Map(),
    shareCustody: {},
    directoryShares: [],
    invites: new Map(),
    usedInviteIds: new Set(),
    seenEventIds: new Set(),
    cases: new Map(),
    adminBarrierArmed: false,
  };
}

/** BLAKE2b-256 of the canonical stored entry (seq + prev_hash + envelope). */
export function entryHash(entry: SignedEntry): string {
  return crypto.toB64u(crypto.hash(crypto.canonicalize(entry as unknown as JsonObject)));
}

/** The ONE definition of the bytes welded into the countersign
 * member_admit's proposal_hash.
 * Builder and verifier both call this (review checklist item 3a). */
export function admissionPayloadBytes(payload: MemberProposePayload): Uint8Array {
  return crypto.canonicalize(payload as unknown as JsonObject);
}

export function admissionPayloadHash(payload: MemberProposePayload): string {
  return crypto.toB64u(crypto.hash(admissionPayloadBytes(payload)));
}

/** The ONE definition of the succession proof-of-possession context
 * (v0.9.1) — signed by the NEW governance key at prepare time, verified
 * against the payload's own values at apply time, so a pop cannot be
 * transplanted onto a different successor, key, or org. */
export function successionPopObject(
  orgId: string,
  newHeadUserId: string,
  newGovernancePk: string,
): JsonObject {
  return {
    use: "head-succeed-pop",
    org: orgId,
    new_head_user_id: newHeadUserId,
    new_governance_pk: newGovernancePk,
  };
}

/** The ONE definition of the bytes welded into the countersign
 * case_rekey's proposal_hash (same discipline as
 * admissionPayloadHash — builder and verifier both call this). */
export function rekeyPayloadHash(payload: CaseRekeyPayload): string {
  return crypto.toB64u(crypto.hash(crypto.canonicalize(payload as unknown as JsonObject)));
}

// ---- shared authorization predicates (builders reuse these) -------------

export function activeAdmins(state: OrgState): string[] {
  return [...state.members.entries()].filter(([, m]) => m.role === "admin").map(([id]) => id);
}

export function isAdmitted(state: OrgState, userId: string): boolean {
  return state.members.has(userId);
}

export function currentEpoch(c: CaseInfo): number {
  return c.epochs.length;
}

export function isHolder(c: CaseInfo, userId: string): boolean {
  return c.epochs[c.epochs.length - 1]!.holders.has(userId);
}

// ---- applyEntry ---------------------------------------------------------

export function applyEntry(state: OrgState, entry: SignedEntry): OrgState {
  const fail = (reason: string): never => {
    throw new InvalidEntry(entry.seq, reason);
  };

  // 1. chain check
  if (!Number.isInteger(entry.seq) || entry.seq !== state.chain.seq + 1) {
    fail(`expected seq ${state.chain.seq + 1}, got ${entry.seq}`);
  }
  if (entry.prev_hash !== state.chain.headHash) {
    fail("prev_hash does not match chain head");
  }

  // 2. shape check
  const env = entry.envelope;
  if (
    !env ||
    env.v !== 1 ||
    typeof env.type !== "string" ||
    typeof env.event_id !== "string" ||
    env.event_id.length === 0 ||
    env.event_id.length > 64 || // bounds seenEventIds memory per entry
    typeof env.org_id !== "string" ||
    typeof env.actor !== "string" ||
    typeof env.sig !== "string" ||
    typeof env.payload !== "object" ||
    env.payload === null
  ) {
    fail("malformed envelope");
  }
  if (state.genesis === null) {
    if (env.type !== "org_genesis") fail("first entry must be org_genesis");
  } else if (env.org_id !== state.orgId) {
    fail("wrong org_id");
  }
  // replay guard: a signature covers the envelope but
  // not seq, so without this any captured envelope could be re-appended —
  // by the server or any member — fabricating activity records and letting
  // the server add entries it cannot author. Uniqueness makes replay
  // safety uniform instead of an emergent property of per-type guards.
  if (state.seenEventIds.has(env.event_id)) fail("event_id reused");

  // 3. signature check — against the key verified state assigns the actor
  const signerPk = signerFor(state, env);
  if (signerPk === null) fail("no verified signing key for actor");
  try {
    crypto.verifyEvent(crypto.fromB64u(signerPk!), env as unknown as JsonObject);
  } catch {
    fail("bad signature");
  }

  // 4. per-type authorization + state transition
  const next = dispatch(state, entry, fail);

  // 5. advance the chain — O(1) pure append via structural sharing
  const h = entryHash(entry);
  next.chain = {
    seq: entry.seq,
    headHash: h,
    hashLog: { seq: entry.seq, hash: h, prev: state.chain.hashLog },
  };
  // commit the replay guard LAST: the set is shared across generations
  // (see OrgState doc), so this must be unreachable on any failure path
  next.seenEventIds.add(env.event_id);
  return next;
}

/** Hash of the entry at a past seq, from the structurally-shared log. */
export function hashAtSeq(state: OrgState, seq: number): string | null {
  let node = state.chain.hashLog;
  while (node && node.seq > seq) node = node.prev;
  return node && node.seq === seq ? node.hash : null;
}

export function replay(entries: SignedEntry[]): OrgState {
  return entries.reduce(applyEntry, emptyState());
}

function signerFor(state: OrgState, env: Envelope): string | null {
  // governance-signed types verify against the CURRENT
  // governance key (state), not the genesis payload — head_succeed is what
  // moves it, retiring the old key for every later entry.
  const governancePk = state.currentGovernancePk || null;
  if (env.type === "org_genesis") {
    const p = env.payload as unknown as GenesisPayload;
    return typeof p.governance_pk === "string" ? p.governance_pk : null;
  }
  if (env.type === "member_admit") {
    // shape dispatch: the countersign shape is an ordinary
    // admin signature; the solo shape is governance-signed. A malformed
    // payload falls to the solo branch and dies in dispatch's shape checks.
    return "proposal_id" in env.payload
      ? (state.members.get(env.actor)?.signPk ?? null)
      : governancePk;
  }
  if (env.type === "case_rekey") {
    // shape dispatch: the countersign shape and the armed
    // FULL shape (a proposal) carry an admin's member signature; the solo
    // FULL shape is governance-signed, mirroring member_admit.
    return "proposal_hash" in env.payload || state.adminBarrierArmed
      ? (state.members.get(env.actor)?.signPk ?? null)
      : governancePk;
  }
  if (env.type === "admin_grant" || env.type === "admin_revoke" || env.type === "head_succeed") {
    return governancePk;
  }
  return state.members.get(env.actor)?.signPk ?? null;
}

// dispatch returns a SHALLOW copy of state with the touched containers
// path-copied; applyEntry then replaces chain. Handlers never mutate input.
function dispatch(state: OrgState, entry: SignedEntry, fail: (reason: string) => never): OrgState {
  const env = entry.envelope;
  switch (env.type) {
    case "org_genesis": {
      const p = env.payload as unknown as GenesisPayload;
      // checks
      if (state.genesis !== null) fail("duplicate genesis");
      for (const f of [
        p.head_user_id,
        p.head_enc_pk,
        p.head_sign_pk,
        p.governance_pk,
        p.recovery_pk,
      ]) {
        if (typeof f !== "string" || f.length === 0) fail("malformed genesis");
      }
      if (env.actor !== p.head_user_id) fail("genesis actor must be head");
      // commit
      const members = new Map(state.members);
      members.set(p.head_user_id, {
        encPk: p.head_enc_pk,
        signPk: p.head_sign_pk,
        role: "head",
        admittedAtSeq: entry.seq,
      });
      return {
        ...state,
        orgId: env.org_id,
        genesis: p,
        members,
        currentHeadUserId: p.head_user_id,
        currentGovernancePk: p.governance_pk,
      };
    }

    case "invite_issue": {
      // provenance for every later admission: the invite exists in the
      // journal, issued by an authorized member, code sealed to the
      // ISSUER's own key (the server transports ciphertext, never the code)
      const p = env.payload as unknown as InviteIssuePayload;
      // checks
      const issuer = state.members.get(env.actor);
      if (!issuer || (issuer.role !== "head" && issuer.role !== "admin")) {
        fail("only the head or an active admin may issue invites");
      }
      if (state.invites.has(p.invite_id)) fail("invite_id already issued");
      if (state.usedInviteIds.has(p.invite_id)) fail("invite_id reused");
      if (typeof p.sealed_code !== "string" || p.sealed_code.length === 0) {
        fail("missing sealed code");
      }
      // expiry is shape-checked only: enforcement is signer-clock at use
      // (builders); verifiers have no clock
      if (!Number.isFinite(p.expires_at) || p.expires_at <= 0) fail("malformed expiry");
      // commit
      const invites = new Map(state.invites);
      invites.set(p.invite_id, {
        issuer: env.actor,
        sealedCode: p.sealed_code,
        issuedAtSeq: entry.seq,
        expiresAt: p.expires_at,
      });
      return { ...state, invites };
    }

    case "admin_grant": {
      // head promotes an EXISTING member. No invite binding:
      // the member's keys are already journal-verified.
      const p = env.payload as unknown as AdminRolePayload;
      // checks
      if (env.actor !== state.currentHeadUserId) fail("actor must be head");
      const target = state.members.get(p.user_id);
      if (!target) fail("unknown member");
      if (target!.role !== "member") fail("target is not an ordinary member");
      if (activeAdmins(state).length >= 2) fail("already two active admins");
      // commit
      const members = new Map(state.members);
      members.set(p.user_id, { ...target!, role: "admin" });
      return {
        ...state,
        members,
        adminBarrierArmed: state.adminBarrierArmed || activeAdmins(state).length + 1 >= 2,
      };
    }

    case "admin_revoke": {
      const p = env.payload as unknown as AdminRolePayload;
      // checks
      if (env.actor !== state.currentHeadUserId) fail("actor must be head");
      const target = state.members.get(p.user_id);
      if (!target || target.role !== "admin") fail("target is not an active admin");
      // commit — role reverts; adminBarrierArmed deliberately UNCHANGED
      // (one-way), and any printed recovery share they hold is a physical
      // fact software cannot revoke
      const members = new Map(state.members);
      members.set(p.user_id, { ...target!, role: "member" });
      return { ...state, members };
    }

    case "member_admit": {
      // THE terminal admission event: the roster grows on
      // member_admit and nothing else. Two shapes, dispatched on the
      // presence of proposal_id:
      // countersign — admin 2 consumes a pending member_propose
      // (formerly the member_approve event; rules unchanged);
      // solo — the head admits alone,
      // ONLY while the two-admin barrier has never armed (monotonic).
      if ("proposal_id" in env.payload) {
        const p = env.payload as unknown as MemberAdmitCountersignPayload;
        // checks
        if (state.members.get(env.actor)?.role !== "admin") fail("actor is not an active admin");
        const prop = state.proposals.get(p.proposal_id);
        if (!prop) fail("unknown or already-consumed proposal");
        if (prop!.proposedBy === env.actor) fail("approver must be the other admin");
        if (p.proposal_hash !== admissionPayloadHash(prop!.payload)) {
          fail("proposal_hash does not match proposed payload");
        }
        if (state.usedInviteIds.has(prop!.payload.invite_id)) fail("invite_id reused");
        // two proposals may target the same user_id; the first
        // countersign admits — a second must never overwrite pinned keys
        if (state.members.has(prop!.payload.user_id)) fail("user already exists");
        // commit — the member exists only from this point
        const members = new Map(state.members);
        members.set(prop!.payload.user_id, {
          encPk: prop!.payload.enc_pk,
          signPk: prop!.payload.sign_pk,
          role: "member",
          admittedAtSeq: entry.seq,
        });
        const proposals = new Map(state.proposals);
        proposals.delete(p.proposal_id);
        const usedInviteIds = new Set(state.usedInviteIds);
        usedInviteIds.add(prop!.payload.invite_id);
        return { ...state, members, proposals, usedInviteIds };
      }
      const p = env.payload as unknown as MemberAdmitPayload;
      // checks
      if (env.actor !== state.currentHeadUserId) fail("actor must be head");
      if (state.adminBarrierArmed) {
        fail("solo admission is permanently off: two admins have existed");
      }
      if (state.members.has(p.user_id)) fail("user already exists");
      if (state.usedInviteIds.has(p.invite_id)) fail("invite_id reused");
      if (!state.invites.has(p.invite_id)) {
        fail("no journaled invite for this invite_id");
      }
      if (typeof p.binding_tag !== "string" || p.binding_tag.length === 0) {
        fail("missing invite binding tag");
      }
      // commit
      const members = new Map(state.members);
      members.set(p.user_id, {
        encPk: p.enc_pk,
        signPk: p.sign_pk,
        role: "member",
        admittedAtSeq: entry.seq,
      });
      const usedInviteIds = new Set(state.usedInviteIds);
      usedInviteIds.add(p.invite_id);
      return { ...state, members, usedInviteIds };
    }

    case "member_propose": {
      const p = env.payload as unknown as MemberProposePayload;
      // checks
      if (state.members.get(env.actor)?.role !== "admin") fail("actor is not an active admin");
      if (state.proposals.has(p.proposal_id)) fail("proposal_id reused");
      if (state.members.has(p.user_id)) fail("user already exists");
      if (state.usedInviteIds.has(p.invite_id)) fail("invite_id reused");
      if (!state.invites.has(p.invite_id)) {
        fail("no journaled invite for this invite_id");
      }
      if (typeof p.binding_tag !== "string" || p.binding_tag.length === 0) {
        fail("missing invite binding tag");
      }
      // checkpoint truth check (checklist item 3b): the claimed hash must
      // match the entry actually at that seq in OUR chain
      const cp = p.checkpoint;
      if (
        !cp ||
        !Number.isInteger(cp.seq) ||
        cp.seq < 1 ||
        cp.seq > state.chain.seq ||
        hashAtSeq(state, cp.seq) !== cp.hash
      ) {
        fail("checkpoint does not match local chain (possible fork)");
      }
      // NOTE: expiry is NOT checked here — approver-clock-gated at signing
      //. Binding tag is verifiable
      // only by code holders (approvers), not by third-party verifiers.
      // commit
      const proposals = new Map(state.proposals);
      proposals.set(p.proposal_id, {
        payload: p,
        proposedBy: env.actor,
        proposedAtSeq: entry.seq,
      });
      return { ...state, proposals };
    }

    case "case_create": {
      const p = env.payload as unknown as CaseCreatePayload;
      // checks
      if (!isAdmitted(state, env.actor)) fail("actor is not an admitted member");
      if (state.cases.has(p.case_tag)) fail("case_tag already exists");
      if (p.epoch !== 1) fail("case_create must be epoch 1");
      if (typeof p.sealed_key !== "string" || typeof p.recovery_envelope !== "string") {
        fail("missing envelopes");
      }
      // commit
      const cases = new Map(state.cases);
      cases.set(p.case_tag, {
        creatorId: env.actor,
        epochs: [
          {
            startSeq: entry.seq,
            holders: new Map([[env.actor, p.sealed_key]]),
            recoveryEnvelope: p.recovery_envelope,
          },
        ],
        notes: new Map(),
      });
      return { ...state, cases };
    }

    case "case_grant": {
      const p = env.payload as unknown as CaseGrantPayload;
      // checks
      const c = state.cases.get(p.case_tag);
      if (!c) fail("unknown case");
      if (c!.creatorId !== env.actor) fail("only the case creator may grant");
      if (p.epoch !== currentEpoch(c!)) fail("grant epoch is not current");
      if (!isAdmitted(state, p.recipient)) fail("recipient is not an admitted member");
      // commit
      const epochs = [...c!.epochs];
      const last = epochs[epochs.length - 1]!;
      const holders = new Map(last.holders);
      holders.set(p.recipient, p.sealed_key);
      epochs[epochs.length - 1] = { ...last, holders };
      const cases = new Map(state.cases);
      cases.set(p.case_tag, { ...c!, epochs });
      return { ...state, cases };
    }

    case "case_revoke": {
      const p = env.payload as unknown as CaseRevokePayload;
      // checks
      const c = state.cases.get(p.case_tag);
      if (!c) fail("unknown case");
      if (c!.creatorId !== env.actor) fail("only the case creator may revoke");
      if (p.revoked === c!.creatorId) fail("the creator cannot be revoked");
      const cur = c!.epochs[c!.epochs.length - 1]!;
      if (!cur.holders.has(p.revoked)) fail("revoked user holds no grant");
      if (p.new_epoch !== currentEpoch(c!) + 1) fail("new_epoch must increment");
      const remaining = [...cur.holders.keys()].filter((u) => u !== p.revoked);
      const envKeys = Object.keys(p.envelopes ?? {}).sort();
      if (envKeys.join() !== [...remaining].sort().join()) {
        fail("revoke envelopes must cover exactly the remaining holders");
      }
      if (typeof p.recovery_envelope !== "string") fail("missing recovery envelope");
      const noteKeys = Object.keys(p.snapshots ?? {}).sort();
      if (noteKeys.join() !== [...c!.notes.keys()].sort().join()) {
        fail("revoke snapshots must cover exactly the existing notes");
      }
      // commit
      const holders = new Map(remaining.map((u) => [u, p.envelopes[u]!]));
      const epochs = [
        ...c!.epochs,
        { startSeq: entry.seq, holders, recoveryEnvelope: p.recovery_envelope },
      ];
      const notes = new Map(c!.notes);
      for (const [recordId, snap] of Object.entries(p.snapshots)) {
        const note = notes.get(recordId)!;
        notes.set(recordId, {
          ...note,
          wrappedRecordKey: snap.wrapped_record_key,
          snapshot: { seq: entry.seq, epoch: p.new_epoch, ct: snap.ct },
        });
      }
      const cases = new Map(state.cases);
      cases.set(p.case_tag, { ...c!, epochs, notes });
      return { ...state, cases };
    }

    case "note_update": {
      const p = env.payload as unknown as NoteUpdatePayload;
      // checks
      const c = state.cases.get(p.case_tag);
      if (!c) fail("unknown case");
      // epoch fencing: applied in order, the fence collapses
      // to "claimed epoch must be the current one"
      if (p.epoch !== currentEpoch(c!)) fail("epoch fencing violation");
      if (!isHolder(c!, env.actor)) fail("author holds no grant at this seq");
      const existing = c!.notes.get(p.record_id);
      if (!existing && typeof p.wrapped_record_key !== "string") {
        fail("first update for a record must carry the wrapped record key");
      }
      if (existing && p.wrapped_record_key !== undefined) {
        fail("wrapped record key only allowed on the first update");
      }
      if (typeof p.ct !== "string" || p.ct.length === 0) fail("missing ciphertext");
      // commit
      const update = { seq: entry.seq, epoch: p.epoch, author: env.actor, ct: p.ct };
      const notes = new Map(c!.notes);
      notes.set(
        p.record_id,
        existing
          ? { ...existing, updates: [...existing.updates, update] }
          : { wrappedRecordKey: p.wrapped_record_key!, updates: [update] },
      );
      const cases = new Map(state.cases);
      cases.set(p.case_tag, { ...c!, notes });
      return { ...state, cases };
    }

    case "case_rekey": {
      // org-authority re-key.
      // Shape dispatch on `proposal_hash` presence, mirroring member_admit.
      if ("proposal_hash" in env.payload) {
        // COUNTERSIGN shape: second admin consumes the pending proposal
        const p = env.payload as unknown as CaseRekeyCountersignPayload;
        // checks
        if (state.members.get(env.actor)?.role !== "admin") {
          fail("countersign must come from an active admin");
        }
        const pending = state.pendingRekeys.get(p.rekey_id);
        if (!pending) fail("unknown or already-consumed rekey proposal");
        if (pending!.proposedBy === env.actor) {
          fail("countersign must come from a different admin");
        }
        if (rekeyPayloadHash(pending!.payload) !== p.proposal_hash) {
          fail("proposal_hash does not match the pending rekey");
        }
        if (pending!.payload.case_tag !== p.case_tag) fail("case_tag mismatch");
        // re-validate against CURRENT state: a revoke or note interleaved
        // since the proposal invalidates it (re-propose is the recovery)
        checkRekeyAgainstState(state, pending!.payload, fail);
        // commit
        const pendingRekeys = new Map(state.pendingRekeys);
        pendingRekeys.delete(p.rekey_id);
        return { ...commitRekey(state, pending!.payload, entry.seq), pendingRekeys };
      }
      // FULL shape: solo commit (governance-signed, barrier never armed) or
      // two-admin proposal (proposing admin's member signature)
      const p = env.payload as unknown as CaseRekeyPayload;
      // checks (shared shape + state validation)
      if (typeof p.rekey_id !== "string" || p.rekey_id.length === 0 || p.rekey_id.length > 64) {
        fail("malformed rekey_id");
      }
      if (typeof p.proposed_at !== "number") fail("missing proposed_at");
      checkRekeyAgainstState(state, p, fail);
      if (!state.adminBarrierArmed) {
        // SOLO: the head commits alone, exactly as they admit alone
        if (env.actor !== state.currentHeadUserId) fail("actor must be head");
        // commit
        return commitRekey(state, p, entry.seq);
      }
      // ARMED: this entry is a PROPOSAL — no case change yet
      if (state.members.get(env.actor)?.role !== "admin") {
        fail("rekey proposal must come from an active admin");
      }
      if (state.pendingRekeys.has(p.rekey_id)) fail("rekey_id already pending");
      // commit
      const pendingRekeys = new Map(state.pendingRekeys);
      pendingRekeys.set(p.rekey_id, {
        payload: p,
        proposedBy: env.actor,
        proposedAtSeq: entry.seq,
      });
      return { ...state, pendingRekeys };
    }

    case "head_succeed": {
      // governance root moves:
      // signed by the CURRENT governance key (signerFor); successor must be
      // an active admin, or the head themself (pure key rotation).
      const p = env.payload as unknown as HeadSucceedPayload;
      // checks
      if (env.actor !== state.currentHeadUserId) fail("actor must be head");
      if (
        typeof p.new_governance_pk !== "string" ||
        p.new_governance_pk.length === 0 ||
        p.new_governance_pk.length > 64
      ) {
        fail("malformed new_governance_pk");
      }
      const successor = state.members.get(p.new_head_user_id);
      if (!successor) fail("successor is not an admitted member");
      if (p.new_head_user_id !== env.actor && successor!.role !== "admin") {
        fail("successor must be an active admin");
      }
      // proof of possession (v0.9.1): the NEW key must have signed this
      // exact succession — without this, a well-formed garbage key string
      // (typo'd in transit, or hostile) bricks governance permanently at
      // commit, since retired keys never sign again by design
      if (typeof p.pop !== "string" || p.pop.length === 0 || p.pop.length > 128) {
        fail("malformed proof of possession");
      }
      try {
        crypto.verifyEvent(crypto.fromB64u(p.new_governance_pk), {
          ...successionPopObject(state.orgId, p.new_head_user_id, p.new_governance_pk),
          sig: p.pop,
        });
      } catch {
        fail("invalid proof of possession for the new governance key");
      }
      // commit — old head drops to ordinary member; the successor vacates
      // their admin seat (the barrier stays armed: one-way, unchanged)
      const members = new Map(state.members);
      if (p.new_head_user_id !== env.actor) {
        members.set(env.actor, { ...state.members.get(env.actor)!, role: "member" });
      }
      members.set(p.new_head_user_id, { ...successor!, role: "head" });
      return {
        ...state,
        members,
        currentHeadUserId: p.new_head_user_id,
        currentGovernancePk: p.new_governance_pk,
      };
    }

    case "directory_share": {
      // display-name fan-out. The verifier checks
      // WHO may fan out to WHOM and bounds the size; it cannot see the
      // sealed names (invite-code posture). signerFor already required an
      // admitted member's signature for the actor.
      const p = env.payload as unknown as DirectorySharePayload;
      // checks
      if (typeof p.envelopes !== "object" || p.envelopes === null || Array.isArray(p.envelopes)) {
        fail("malformed envelopes");
      }
      const recipients = Object.keys(p.envelopes);
      if (recipients.length === 0) fail("directory share needs at least one recipient");
      if (recipients.length > state.members.size) fail("more recipients than members");
      for (const r of recipients) {
        if (!state.members.has(r)) fail("recipient is not an admitted member");
        const box = p.envelopes[r];
        if (typeof box !== "string" || box.length === 0 || box.length > 16384) {
          fail("malformed sealed envelope");
        }
      }
      // commit
      return {
        ...state,
        directoryShares: [
          ...state.directoryShares,
          { seq: entry.seq, actor: env.actor, envelopes: p.envelopes },
        ],
      };
    }

    case "share_custody_ack": {
      // receiver-signed custody record; signerFor already required an admitted member's signature
      const p = env.payload as unknown as ShareCustodyAckPayload;
      // checks
      if (p.share !== "A" && p.share !== "B") fail("share must be A or B");
      // commit
      return { ...state, shareCustody: { ...state.shareCustody, [p.share]: env.actor } };
    }

    default:
      return fail(`unknown event type "${env.type}"`);
  }
}

/** case_rekey validity against a given state — used at solo commit, at
 * proposal time, AND re-run at countersign commit so interleaved revokes
 * or new notes invalidate a stale proposal. Checks only; never writes. */
function checkRekeyAgainstState(
  state: OrgState,
  p: CaseRekeyPayload,
  fail: (reason: string) => never,
): void {
  const c = state.cases.get(p.case_tag);
  if (!c) fail("unknown case");
  if (p.new_epoch !== currentEpoch(c!) + 1) fail("new_epoch must increment");
  const holders = Object.keys(p.envelopes ?? {});
  if (holders.length === 0) fail("rekey must designate at least one holder");
  for (const userId of holders) {
    if (!state.members.has(userId)) fail("designated holder is not admitted");
  }
  if (typeof p.recovery_envelope !== "string") fail("missing recovery envelope");
  const noteKeys = Object.keys(p.snapshots ?? {}).sort();
  if (noteKeys.join() !== [...c!.notes.keys()].sort().join()) {
    fail("rekey snapshots must cover exactly the existing notes");
  }
}

/** Shared commit for both case_rekey commit sites — the same epoch-push +
 * note-compaction shape as case_revoke's commit. Cannot throw. */
function commitRekey(state: OrgState, p: CaseRekeyPayload, seq: number): OrgState {
  const c = state.cases.get(p.case_tag)!;
  const holders = new Map(Object.entries(p.envelopes));
  const epochs = [...c.epochs, { startSeq: seq, holders, recoveryEnvelope: p.recovery_envelope }];
  const notes = new Map(c.notes);
  for (const [recordId, snap] of Object.entries(p.snapshots)) {
    const note = notes.get(recordId)!;
    notes.set(recordId, {
      ...note,
      wrappedRecordKey: snap.wrapped_record_key,
      snapshot: { seq, epoch: p.new_epoch, ct: snap.ct },
    });
  }
  const cases = new Map(state.cases);
  cases.set(p.case_tag, { ...c, epochs, notes });
  return { ...state, cases };
}
