// Produce side: one builder per event type.
// Each takes (state, actor keys, params), does the crypto via the crypto module only,
// and returns an unsequenced signed envelope. Builders refuse to build what
// applyEntry would reject, using the same predicates. seq/prev_hash are the
// server's to assign — never set here.
//
// Clock rule: builders that enforce
// expiry take `now` as a parameter — this module stays clock-free.

import * as crypto from "../crypto/index.ts";
import type { JsonObject } from "../crypto/index.ts";
import { BuildRefused } from "./errors.ts";
import {
  activeAdmins,
  admissionPayloadHash,
  currentEpoch,
  isAdmitted,
  isHolder,
  rekeyPayloadHash,
  successionPopObject,
} from "./state.ts";
import type {
  CaseInfo,
  Envelope,
  EventType,
  GenesisPayload,
  MemberProposePayload,
  OrgState,
} from "./types.ts";

export const PROPOSAL_TTL_MS = 24 * 60 * 60 * 1000; // 24 h
/** Invite lifetime: longer than proposals because it spans
 * the whole "joiner hasn't shown up yet" gap. Signer-clock enforced. */
export const INVITE_TTL_MS = 72 * 60 * 60 * 1000;

// AAD objects — ONE definition each; writers (below) and readers
// (client flows) must produce byte-identical AAD or decryption fails.
export const noteAad = (orgId: string, caseTag: string, epoch: number, recordId: string) =>
  ({ v: 1, org: orgId, case: caseTag, epoch, record: recordId }) as JsonObject;
export const recordKeyAad = (orgId: string, caseTag: string, epoch: number) =>
  ({ v: 1, org: orgId, case: caseTag, epoch, use: "reckey" }) as JsonObject;
const INVITE_TAG_FIELDS = (userId: string, encPk: string, signPk: string, inviteId: string) =>
  ({ user: userId, enc: encPk, sign: signPk, invite: inviteId }) as JsonObject;

export interface ActorKeys {
  userId: string;
  sign: crypto.SignKeyPair;
}

function envelope(
  type: EventType,
  orgId: string,
  actor: string,
  payload: JsonObject,
  signKp: crypto.SignKeyPair,
): Envelope {
  const unsigned = {
    v: 1 as const,
    type,
    event_id: crypto.toB64u(crypto.newId()),
    org_id: orgId,
    actor,
    payload,
  };
  return { ...unsigned, sig: crypto.signEvent(signKp, unsigned as unknown as JsonObject) };
}

/** Invite binding tag: keyed BLAKE2b under K_invite = hash(code). */
export function inviteBindingTag(
  inviteCode: Uint8Array,
  userId: string,
  encPk: string,
  signPk: string,
  inviteId: string,
): string {
  return crypto.toB64u(
    crypto.keyedTag(crypto.hash(inviteCode), INVITE_TAG_FIELDS(userId, encPk, signPk, inviteId)),
  );
}

export function buildOrgGenesis(params: {
  orgId: string;
  headUserId: string;
  headEncPk: string;
  headSignPk: string;
  governance: crypto.SignKeyPair;
  recoveryPk: string;
}): Envelope {
  const payload: GenesisPayload = {
    head_user_id: params.headUserId,
    head_enc_pk: params.headEncPk,
    head_sign_pk: params.headSignPk,
    governance_pk: crypto.toB64u(params.governance.publicKey),
    recovery_pk: params.recoveryPk,
    kdf: { ops: 2, mem_mib: 64, alg: "argon2id13" },
  };
  return envelope(
    "org_genesis",
    params.orgId,
    params.headUserId,
    payload as unknown as JsonObject,
    params.governance,
  );
}

/** Journal an issued invite: the code is sealed to the
 * ISSUER's own encryption public key, so any device holding that identity
 * can recover it after sync; the server transports only ciphertext. */
export function buildInviteIssue(
  state: OrgState,
  actor: ActorKeys,
  params: {
    inviteId: string;
    code: Uint8Array;
    issuerEncPk: string;
    now: number;
  },
): Envelope {
  const role = state.members.get(actor.userId)?.role;
  if (role !== "head" && role !== "admin") {
    throw new BuildRefused("only the head or an active admin may issue invites");
  }
  if (state.invites.has(params.inviteId) || state.usedInviteIds.has(params.inviteId)) {
    throw new BuildRefused("invite_id already issued or used");
  }
  const payload = {
    invite_id: params.inviteId,
    sealed_code: crypto.toB64u(crypto.sealTo(crypto.fromB64u(params.issuerEncPk), params.code)),
    expires_at: params.now + INVITE_TTL_MS,
  };
  return envelope("invite_issue", state.orgId, actor.userId, payload, actor.sign);
}

/** Signer-clock gate at every invite use: journaled and not expired by
 * the SIGNING client's clock (verifiers never re-check). */
function requireIssued(state: OrgState, inviteId: string, now: number): void {
  const inv = state.invites.get(inviteId);
  if (!inv) throw new BuildRefused("no journaled invite for this invite_id");
  if (now > inv.expiresAt) {
    throw new BuildRefused("invite expired — issue a fresh one");
  }
}

/** Head promotes an existing member to org admin. */
export function buildAdminGrant(
  state: OrgState,
  governance: crypto.SignKeyPair,
  params: { userId: string },
): Envelope {
  if (!state.genesis) throw new BuildRefused("no genesis");
  const target = state.members.get(params.userId);
  if (!target) throw new BuildRefused("unknown member");
  if (target.role !== "member") throw new BuildRefused("target is not an ordinary member");
  if (activeAdmins(state).length >= 2) throw new BuildRefused("already two active admins");
  return envelope(
    "admin_grant",
    state.orgId,
    state.currentHeadUserId,
    { user_id: params.userId },
    governance,
  );
}

/** Head demotes an org admin back to member. The two-admin barrier stays
 * armed (one-way), and any printed recovery share they hold is physical. */
export function buildAdminRevoke(
  state: OrgState,
  governance: crypto.SignKeyPair,
  params: { userId: string },
): Envelope {
  if (!state.genesis) throw new BuildRefused("no genesis");
  const target = state.members.get(params.userId);
  if (!target || target.role !== "admin") throw new BuildRefused("target is not an active admin");
  return envelope(
    "admin_revoke",
    state.orgId,
    state.currentHeadUserId,
    { user_id: params.userId },
    governance,
  );
}

/** member_admit, SOLO shape: head-signed ordinary-member
 * admission, buildable only until the two-admin barrier first arms. */
export function buildMemberAdmit(
  state: OrgState,
  governance: crypto.SignKeyPair,
  params: {
    userId: string;
    encPk: string;
    signPk: string;
    inviteCode: Uint8Array;
    inviteId: string;
    now: number;
  },
): Envelope {
  if (!state.genesis) throw new BuildRefused("no genesis");
  if (state.adminBarrierArmed) {
    throw new BuildRefused(
      "solo admission is permanently off: two admins have existed — use propose/approve",
    );
  }
  if (state.members.has(params.userId)) throw new BuildRefused("user already exists");
  if (state.usedInviteIds.has(params.inviteId)) throw new BuildRefused("invite_id reused");
  requireIssued(state, params.inviteId, params.now);
  const payload = {
    user_id: params.userId,
    enc_pk: params.encPk,
    sign_pk: params.signPk,
    invite_id: params.inviteId,
    binding_tag: inviteBindingTag(
      params.inviteCode,
      params.userId,
      params.encPk,
      params.signPk,
      params.inviteId,
    ),
  };
  return envelope(
    "member_admit",
    state.orgId,
    state.currentHeadUserId,
    payload as unknown as JsonObject,
    governance,
  );
}

export function buildMemberPropose(
  state: OrgState,
  actor: ActorKeys,
  params: {
    userId: string;
    encPk: string;
    signPk: string;
    inviteCode: Uint8Array;
    inviteId: string;
    now: number;
  },
): Envelope {
  if (state.members.get(actor.userId)?.role !== "admin") {
    throw new BuildRefused("proposer is not an active admin");
  }
  if (state.members.has(params.userId)) throw new BuildRefused("user already exists");
  if (state.usedInviteIds.has(params.inviteId)) throw new BuildRefused("invite_id reused");
  requireIssued(state, params.inviteId, params.now);
  if (state.chain.seq < 1) throw new BuildRefused("no journal to checkpoint");
  const payload: MemberProposePayload = {
    proposal_id: crypto.toB64u(crypto.newId()),
    expires_at: params.now + PROPOSAL_TTL_MS,
    checkpoint: {
      seq: state.chain.seq,
      hash: state.chain.headHash,
    },
    user_id: params.userId,
    enc_pk: params.encPk,
    sign_pk: params.signPk,
    invite_id: params.inviteId,
    binding_tag: inviteBindingTag(
      params.inviteCode,
      params.userId,
      params.encPk,
      params.signPk,
      params.inviteId,
    ),
  };
  return envelope(
    "member_propose",
    state.orgId,
    actor.userId,
    payload as unknown as JsonObject,
    actor.sign,
  );
}

/** member_admit, COUNTERSIGN shape (formerly the
 * member_approve event): admin 2 approves a pending proposal, emitting the
 * terminal admission event. The function keeps its name — the ACTION is
 * approving; the EVENT it produces is the admission. */
export function buildMemberApprove(
  state: OrgState,
  actor: ActorKeys,
  params: { proposalId: string; inviteCode: Uint8Array; now: number },
): Envelope {
  if (state.members.get(actor.userId)?.role !== "admin") {
    throw new BuildRefused("approver is not an active admin");
  }
  const prop = state.proposals.get(params.proposalId);
  if (!prop) throw new BuildRefused("unknown proposal");
  if (prop.proposedBy === actor.userId) throw new BuildRefused("approver must be the other admin");
  // Mirror of the verifier: a parallel proposal for an already-admitted
  // user must not produce an admission that would overwrite their keys
  if (state.members.has(prop.payload.user_id)) throw new BuildRefused("user already exists");
  // approver-clock expiry gate: an honest approver never
  // signs past expires_at; verifiers do NOT re-check this
  if (params.now > prop.payload.expires_at) throw new BuildRefused("proposal expired");
  // independent invite-binding verification from the code THIS approver holds
  const expectTag = inviteBindingTag(
    params.inviteCode,
    prop.payload.user_id,
    prop.payload.enc_pk,
    prop.payload.sign_pk,
    prop.payload.invite_id,
  );
  if (expectTag !== prop.payload.binding_tag) {
    throw new BuildRefused("invite binding tag mismatch: keys were not authenticated by this code");
  }
  const payload = {
    proposal_id: params.proposalId,
    proposal_hash: admissionPayloadHash(prop.payload),
  };
  return envelope("member_admit", state.orgId, actor.userId, payload, actor.sign);
}

export function buildCaseCreate(
  state: OrgState,
  actor: ActorKeys,
  params: { caseKey: Uint8Array; actorEncPk: string },
): { envelope: Envelope; caseTag: string } {
  if (!isAdmitted(state, actor.userId)) throw new BuildRefused("actor is not admitted");
  const caseTag = crypto.toB64u(crypto.newId());
  const payload = {
    case_tag: caseTag,
    epoch: 1,
    sealed_key: crypto.toB64u(crypto.sealTo(crypto.fromB64u(params.actorEncPk), params.caseKey)),
    recovery_envelope: crypto.toB64u(
      crypto.sealTo(crypto.fromB64u(state.genesis!.recovery_pk), params.caseKey),
    ),
  };
  return {
    envelope: envelope("case_create", state.orgId, actor.userId, payload, actor.sign),
    caseTag,
  };
}

export function buildCaseGrant(
  state: OrgState,
  actor: ActorKeys,
  params: { caseTag: string; caseKey: Uint8Array; recipient: string },
): Envelope {
  const c = state.cases.get(params.caseTag);
  if (!c) throw new BuildRefused("unknown case");
  if (c.creatorId !== actor.userId) throw new BuildRefused("only the case creator may grant");
  if (!isAdmitted(state, params.recipient)) throw new BuildRefused("recipient is not admitted");
  const recipientPk = state.members.get(params.recipient)!.encPk;
  const payload = {
    case_tag: params.caseTag,
    epoch: currentEpoch(c),
    recipient: params.recipient,
    sealed_key: crypto.toB64u(crypto.sealTo(crypto.fromB64u(recipientPk), params.caseKey)),
  };
  return envelope("case_grant", state.orgId, actor.userId, payload, actor.sign);
}

export function buildCaseRevoke(
  state: OrgState,
  actor: ActorKeys,
  params: {
    caseTag: string;
    revoked: string;
    newCaseKey: Uint8Array;
    /** plaintext snapshot bytes per existing record_id (notes.ts supplies
     * compacted CRDT states; tests supply arbitrary bytes) */
    noteSnapshots: Record<string, Uint8Array>;
  },
): Envelope {
  const c = state.cases.get(params.caseTag);
  if (!c) throw new BuildRefused("unknown case");
  if (c.creatorId !== actor.userId) throw new BuildRefused("only the case creator may revoke");
  if (params.revoked === c.creatorId) throw new BuildRefused("the creator cannot be revoked");
  if (!isHolder(c, params.revoked)) throw new BuildRefused("revoked user holds no grant");
  const snapKeys = Object.keys(params.noteSnapshots).sort();
  if (snapKeys.join() !== [...c.notes.keys()].sort().join()) {
    throw new BuildRefused("snapshots must cover exactly the existing notes");
  }
  const newEpoch = currentEpoch(c) + 1;
  const remaining = [...c.epochs[c.epochs.length - 1]!.holders.keys()].filter(
    (u) => u !== params.revoked,
  );
  const envelopes: Record<string, string> = {};
  for (const userId of remaining) {
    const pk = state.members.get(userId)!.encPk;
    envelopes[userId] = crypto.toB64u(crypto.sealTo(crypto.fromB64u(pk), params.newCaseKey));
  }
  const snapshots: Record<string, { wrapped_record_key: string; ct: string }> = {};
  for (const [recordId, plaintext] of Object.entries(params.noteSnapshots)) {
    const recordKey = crypto.newKey();
    snapshots[recordId] = {
      wrapped_record_key: crypto.toB64u(
        crypto.aeadSeal(
          params.newCaseKey,
          recordKey,
          recordKeyAad(state.orgId, params.caseTag, newEpoch),
        ),
      ),
      ct: crypto.toB64u(
        crypto.aeadSeal(
          recordKey,
          plaintext,
          noteAad(state.orgId, params.caseTag, newEpoch, recordId),
        ),
      ),
    };
  }
  const payload = {
    case_tag: params.caseTag,
    new_epoch: newEpoch,
    revoked: params.revoked,
    envelopes,
    recovery_envelope: crypto.toB64u(
      crypto.sealTo(crypto.fromB64u(state.genesis!.recovery_pk), params.newCaseKey),
    ),
    snapshots,
  };
  return envelope(
    "case_revoke",
    state.orgId,
    actor.userId,
    payload as unknown as JsonObject,
    actor.sign,
  );
}

export function buildNoteUpdate(
  state: OrgState,
  actor: ActorKeys,
  params: {
    caseTag: string;
    caseKey: Uint8Array;
    recordId?: string; // omit to create a new note (fresh record id + key)
    plaintext: Uint8Array; // notes.ts supplies CRDT update bytes
  },
): { envelope: Envelope; recordId: string } {
  const c = state.cases.get(params.caseTag);
  if (!c) throw new BuildRefused("unknown case");
  if (!isHolder(c, actor.userId)) throw new BuildRefused("actor holds no grant");
  const epoch = currentEpoch(c);
  const isNew = params.recordId === undefined;
  const recordId = params.recordId ?? crypto.toB64u(crypto.newId());

  let recordKey: Uint8Array;
  let wrappedRecordKey: string | undefined;
  if (isNew) {
    recordKey = crypto.newKey();
    wrappedRecordKey = crypto.toB64u(
      crypto.aeadSeal(params.caseKey, recordKey, recordKeyAad(state.orgId, params.caseTag, epoch)),
    );
  } else {
    const note = c.notes.get(recordId);
    if (!note) throw new BuildRefused("unknown record");
    // the current wrap's epoch: set at the note's creation or the last revoke
    const wrapEpoch = note.snapshot?.epoch ?? note.updates[0]!.epoch;
    recordKey = crypto.aeadOpen(
      params.caseKey,
      crypto.fromB64u(note.wrappedRecordKey),
      recordKeyAad(state.orgId, params.caseTag, wrapEpoch),
    );
  }
  const payload: JsonObject = {
    case_tag: params.caseTag,
    epoch,
    record_id: recordId,
    ct: crypto.toB64u(
      crypto.aeadSeal(
        recordKey,
        params.plaintext,
        noteAad(state.orgId, params.caseTag, epoch, recordId),
      ),
    ),
  };
  if (wrappedRecordKey !== undefined) payload["wrapped_record_key"] = wrappedRecordKey;
  return {
    envelope: envelope("note_update", state.orgId, actor.userId, payload, actor.sign),
    recordId,
  };
}

// ---- recovery ceremonies -----------

export interface CaseRekeyParams {
  caseTag: string;
  newCaseKey: Uint8Array;
  /** the DESIGNATED holder set of the new epoch (successors after loss, or
   * everyone-but-the-compromised for containment); admitted members only */
  holders: string[];
  /** plaintext compacted snapshot bytes per existing record_id (the
   * ceremony recovers and merges these via the recovery keypair) */
  noteSnapshots: Record<string, Uint8Array>;
  now: number;
}

/** Shared FULL-shape payload assembly (solo commit and armed proposal). */
function rekeyPayload(state: OrgState, params: CaseRekeyParams): JsonObject {
  const c = state.cases.get(params.caseTag);
  if (!c) throw new BuildRefused("unknown case");
  if (params.holders.length === 0) throw new BuildRefused("designate at least one holder");
  for (const userId of params.holders) {
    if (!isAdmitted(state, userId)) throw new BuildRefused("designated holder is not admitted");
  }
  const snapKeys = Object.keys(params.noteSnapshots).sort();
  if (snapKeys.join() !== [...c.notes.keys()].sort().join()) {
    throw new BuildRefused("snapshots must cover exactly the existing notes");
  }
  const newEpoch = currentEpoch(c) + 1;
  const envelopes: Record<string, string> = {};
  for (const userId of params.holders) {
    const pk = state.members.get(userId)!.encPk;
    envelopes[userId] = crypto.toB64u(crypto.sealTo(crypto.fromB64u(pk), params.newCaseKey));
  }
  const snapshots: Record<string, { wrapped_record_key: string; ct: string }> = {};
  for (const [recordId, plaintext] of Object.entries(params.noteSnapshots)) {
    const recordKey = crypto.newKey();
    snapshots[recordId] = {
      wrapped_record_key: crypto.toB64u(
        crypto.aeadSeal(
          params.newCaseKey,
          recordKey,
          recordKeyAad(state.orgId, params.caseTag, newEpoch),
        ),
      ),
      ct: crypto.toB64u(
        crypto.aeadSeal(
          recordKey,
          plaintext,
          noteAad(state.orgId, params.caseTag, newEpoch, recordId),
        ),
      ),
    };
  }
  return {
    case_tag: params.caseTag,
    rekey_id: crypto.toB64u(crypto.newId()),
    new_epoch: newEpoch,
    envelopes,
    recovery_envelope: crypto.toB64u(
      crypto.sealTo(crypto.fromB64u(state.genesis!.recovery_pk), params.newCaseKey),
    ),
    snapshots,
    proposed_at: params.now,
  } as JsonObject;
}

/** case_rekey, SOLO shape: the head re-keys alone, exactly as they admit
 * alone — buildable only while the two-admin barrier has never armed. */
export function buildCaseRekeySolo(
  state: OrgState,
  governance: crypto.SignKeyPair,
  params: CaseRekeyParams,
): Envelope {
  if (!state.genesis) throw new BuildRefused("no genesis");
  if (state.adminBarrierArmed) {
    throw new BuildRefused("two admins have existed: rekey needs propose + countersign");
  }
  return envelope(
    "case_rekey",
    state.orgId,
    state.currentHeadUserId,
    rekeyPayload(state, params),
    governance,
  );
}

/** case_rekey, FULL shape as a PROPOSAL (two-admin mode): the proposing
 * admin's member signature; a different admin countersigns to commit. */
export function buildCaseRekeyPropose(
  state: OrgState,
  actor: ActorKeys,
  params: CaseRekeyParams,
): { envelope: Envelope; rekeyId: string } {
  if (!state.adminBarrierArmed) {
    throw new BuildRefused("barrier never armed: use the solo rekey");
  }
  if (state.members.get(actor.userId)?.role !== "admin") {
    throw new BuildRefused("only an active admin may propose a rekey");
  }
  const payload = rekeyPayload(state, params);
  return {
    envelope: envelope("case_rekey", state.orgId, actor.userId, payload, actor.sign),
    rekeyId: payload["rekey_id"] as string,
  };
}

/** case_rekey, COUNTERSIGN shape: the second admin's consent commits the
 * pending proposal. Clock rule: the 24 h TTL is enforced HERE, by the
 * countersigner's clock — verifiers never re-check. */
export function buildCaseRekeyCountersign(
  state: OrgState,
  actor: ActorKeys,
  params: { rekeyId: string; now: number },
): Envelope {
  if (state.members.get(actor.userId)?.role !== "admin") {
    throw new BuildRefused("only an active admin may countersign a rekey");
  }
  const pending = state.pendingRekeys.get(params.rekeyId);
  if (!pending) throw new BuildRefused("unknown or already-consumed rekey proposal");
  if (pending.proposedBy === actor.userId) {
    throw new BuildRefused("countersign must come from a different admin");
  }
  if (params.now > pending.payload.proposed_at + PROPOSAL_TTL_MS) {
    throw new BuildRefused("rekey proposal expired");
  }
  const payload = {
    case_tag: pending.payload.case_tag,
    rekey_id: params.rekeyId,
    proposal_hash: rekeyPayloadHash(pending.payload),
  };
  return envelope("case_rekey", state.orgId, actor.userId, payload, actor.sign);
}

/** head_succeed: the current governance key signs
 * the successor — an active admin, or the head themself with a fresh key
 * (pure governance rotation). The successor generates the new keypair;
 * this builder only ever sees its PUBLIC half. */
/** Produced at PREPARE time by whoever holds the new governance private
 * key (the successor, or the head when rotating): the proof of
 * possession the verifier demands (v0.9.1). */
export function buildSuccessionPop(
  orgId: string,
  newHeadUserId: string,
  newGovernance: crypto.SignKeyPair,
): string {
  return crypto.signEvent(
    newGovernance,
    successionPopObject(orgId, newHeadUserId, crypto.toB64u(newGovernance.publicKey)),
  );
}

export function buildHeadSucceed(
  state: OrgState,
  governance: crypto.SignKeyPair,
  params: { newHeadUserId: string; newGovernancePk: string; pop: string },
): Envelope {
  if (!state.genesis) throw new BuildRefused("no genesis");
  const successor = state.members.get(params.newHeadUserId);
  if (!successor) throw new BuildRefused("successor is not an admitted member");
  if (params.newHeadUserId !== state.currentHeadUserId && successor.role !== "admin") {
    throw new BuildRefused("successor must be an active admin");
  }
  // refuse to build what the verifier would reject: check the pop here too
  try {
    crypto.verifyEvent(crypto.fromB64u(params.newGovernancePk), {
      ...successionPopObject(state.orgId, params.newHeadUserId, params.newGovernancePk),
      sig: params.pop,
    });
  } catch {
    throw new BuildRefused(
      "the succession code does not prove possession of the new governance key — re-run Prepare and re-copy it",
    );
  }
  return envelope(
    "head_succeed",
    state.orgId,
    state.currentHeadUserId,
    {
      new_head_user_id: params.newHeadUserId,
      new_governance_pk: params.newGovernancePk,
      pop: params.pop,
    },
    governance,
  );
}

/** directory_share: fan a display-name map out
 * as one sealed box per recipient. `names` maps userId -> display name
 * (empty string clears); `at` is the writer's clock, used only for the
 * client-side latest-wins merge. */
export function buildDirectoryShare(
  state: OrgState,
  actor: ActorKeys,
  params: { names: Record<string, string>; recipients: string[]; at: number },
): Envelope {
  if (!isAdmitted(state, actor.userId)) throw new BuildRefused("actor is not admitted");
  if (params.recipients.length === 0) throw new BuildRefused("no recipients");
  if (Object.keys(params.names).length === 0) throw new BuildRefused("no names to share");
  const plaintext = crypto.canonicalize({
    names: params.names,
    at: params.at,
  } as unknown as JsonObject);
  const envelopes: Record<string, string> = {};
  for (const userId of params.recipients) {
    const m = state.members.get(userId);
    if (!m) throw new BuildRefused("recipient is not an admitted member");
    envelopes[userId] = crypto.toB64u(crypto.sealTo(crypto.fromB64u(m.encPk), plaintext));
  }
  return envelope("directory_share", state.orgId, actor.userId, { envelopes }, actor.sign);
}

/** share_custody_ack: the RECEIVER journals that
 * they hold printed share A or B. */
export function buildShareCustodyAck(
  state: OrgState,
  actor: ActorKeys,
  params: { share: "A" | "B" },
): Envelope {
  if (!isAdmitted(state, actor.userId)) throw new BuildRefused("actor is not admitted");
  return envelope(
    "share_custody_ack",
    state.orgId,
    actor.userId,
    { share: params.share },
    actor.sign,
  );
}
