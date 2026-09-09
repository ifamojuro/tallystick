// Envelope and state types for the journal state machine.
// All binary values are unpadded base64url strings.

export type EventType =
  | "org_genesis"
  | "invite_issue" // head/admin records an issued invite; code sealed to the ISSUER's own key
  | "member_admit" // THE terminal admission event, two payload shapes:
  // solo shape (head/governance-signed, full keys+invite binding) —
  // valid only until the two-admin barrier first arms;
  // countersign shape (admin 2, {proposal_id, proposal_hash}) —
  // consumes a pending member_propose. "Member exists" always
  // corresponds to a member_admit entry, in every mode.
  | "admin_grant" // head promotes an existing member to org admin
  | "admin_revoke" // head demotes an org admin back to member (barrier stays armed)
  | "member_propose"
  | "case_create"
  | "case_grant"
  | "case_revoke"
  | "note_update"
  | "case_rekey" // org-authority re-key:
  // restore after loss / containment after compromise. Two payload
  // shapes, dispatched on `proposal_hash` presence: the FULL shape
  // (case_revoke minus the creator rule) commits directly in solo mode
  // (governance-signed) or records a pending proposal in two-admin mode
  // (proposing admin's key); the COUNTERSIGN shape (second admin,
  // {rekey_id, proposal_hash}) consumes the pending proposal.
  | "head_succeed" // governance root moves: current
  // governance key signs the successor (an active admin, or self for
  // pure key rotation) and the NEW governance public key
  | "share_custody_ack" // receiver journals custody of printed recovery
  // share A or B
  | "directory_share"; // display names, sealed per-recipient: the actor fans a small name-map out as one sealed
// box per recipient — the server transports ciphertext between user IDs
// it already knows; names never reach it. The verifier cannot check the
// sealed contents (invite-code posture); clients apply the merge rule
// (self-authored beats relayed, latest wins).

/** Common envelope. Signed bytes = JCS(envelope minus sig). */
export interface Envelope {
  v: 1;
  type: EventType;
  event_id: string;
  /** Domain separator, NOT redundant with one-org-per-server: signed in
   * every envelope and baked into every AAD, so events and
   * ciphertexts from one org can never be replayed into another's
   * journal, and the "nothing may assume one journal
   * forever" foundation (per-program partitioning) stays open. */
  org_id: string;
  actor: string;
  payload: Record<string, unknown>;
  sig: string;
}

/** A stored journal entry: the server assigns seq and prev_hash.
 * Author signatures deliberately do not cover them. */
export interface SignedEntry {
  seq: number;
  prev_hash: string;
  envelope: Envelope;
}

// ---- payloads ----------------------------------------

export interface GenesisPayload {
  head_user_id: string;
  head_enc_pk: string;
  head_sign_pk: string;
  governance_pk: string;
  recovery_pk: string;
  kdf: { ops: number; mem_mib: number; alg: "argon2id13" };
}

/** member_admit, SOLO shape: head admits alone, only while the two-admin
 * barrier has never armed. Since v0.8 this is THE only admission shape a
 * new person can arrive by (with the countersign shape below) — admins
 * exist solely by promoting existing members (admin_grant). */
export interface MemberAdmitPayload {
  user_id: string;
  enc_pk: string;
  sign_pk: string;
  invite_id: string;
  binding_tag: string;
}

/** member_admit, COUNTERSIGN shape (formerly the
 * member_approve payload): admin 2's hash-bound countersignature that
 * consumes a pending proposal and creates the member. Shape dispatch is
 * on the presence of `proposal_id`. */
export interface MemberAdmitCountersignPayload {
  proposal_id: string;
  proposal_hash: string; // BLAKE2b-256 of admissionPayloadBytes(propose payload)
}

/** Head-signed role change for an EXISTING member: no
 * invite binding — the member's keys are already journal-verified. */
export interface AdminRolePayload {
  user_id: string;
}

/** Invite issuance: makes admission provenance verifiable
 * and the ceremony device-independent. The CODE never reaches the server
 * in cleartext — sealed_code is an X25519 sealed box to the issuer's OWN
 * identity encryption key; other devices of the same identity unseal it
 * after sync. */
export interface InviteIssuePayload {
  invite_id: string;
  sealed_code: string;
  /** ms epoch. Like proposal expiry: enforced by the SIGNER's clock at the
   * moment of use (admit/appoint/propose builders refuse expired invites);
   * verifiers never re-check — replay stays deterministic. */
  expires_at: number;
}

export interface MemberProposePayload {
  proposal_id: string;
  expires_at: number; // ms epoch; approver-clock-gated at signing, NOT verifier-checked
  checkpoint: { seq: number; hash: string };
  user_id: string;
  enc_pk: string;
  sign_pk: string;
  invite_id: string;
  binding_tag: string;
}

export interface CaseCreatePayload {
  case_tag: string;
  epoch: 1;
  sealed_key: string; // case key sealed to the creator
  recovery_envelope: string; // case key sealed to the recovery public key
}

export interface CaseGrantPayload {
  case_tag: string;
  epoch: number;
  recipient: string;
  sealed_key: string;
}

export interface CaseRevokePayload {
  case_tag: string;
  new_epoch: number;
  revoked: string;
  /** new case key sealed per remaining holder, keyed by user_id */
  envelopes: Record<string, string>;
  recovery_envelope: string;
  /** one compacted snapshot per existing note, keyed by record_id */
  snapshots: Record<string, { wrapped_record_key: string; ct: string }>;
}

/** FULL shape of case_rekey: case_revoke's mechanics under
 * org authority instead of the creator's — restore (successor holder set
 * after loss) or containment (holder set minus a compromised account). */
export interface CaseRekeyPayload {
  case_tag: string;
  /** proposal handle: lets the countersign shape reference this payload */
  rekey_id: string;
  new_epoch: number;
  /** new case key sealed per DESIGNATED holder, keyed by user_id */
  envelopes: Record<string, string>;
  recovery_envelope: string;
  /** one compacted snapshot per existing note, keyed by record_id */
  snapshots: Record<string, { wrapped_record_key: string; ct: string }>;
  /** proposer's clock at build; the countersign BUILDER enforces the 24 h
   * TTL — verifiers never re-check clocks */
  proposed_at: number;
}

/** COUNTERSIGN shape of case_rekey: second admin consumes the pending
 * proposal (two-admin mode only). Dispatch is on `proposal_hash`. */
export interface CaseRekeyCountersignPayload {
  case_tag: string;
  rekey_id: string;
  /** BLAKE2b-256 of the canonical proposed FULL payload */
  proposal_hash: string;
}

/** Governance succession: signed by the CURRENT governance
 * key; the successor must be an active admin (or the head themself with a
 * fresh key = pure governance-key rotation). */
export interface HeadSucceedPayload {
  new_head_user_id: string;
  new_governance_pk: string;
  /** proof of possession (v0.9.1): a signature BY the new governance key
   * over the succession context — a committed succession therefore
   * guarantees the new key's private half exists and was bound to
   * exactly this successor and org. Closes the governance-bricking
   * channel (typo'd or hostile key string). */
  pop: string;
}

/** Receiver-signed custody record for one printed recovery share. */
export interface ShareCustodyAckPayload {
  share: "A" | "B";
}

/** Display-name fan-out: one sealed box per
 * recipient, each containing JCS({names: {userId: name}, at}) sealed to
 * that recipient's identity encryption key. */
export interface DirectorySharePayload {
  /** recipient userId -> sealed box (b64u) */
  envelopes: Record<string, string>;
}

export interface NoteUpdatePayload {
  case_tag: string;
  epoch: number;
  record_id: string;
  ct: string;
  /** present iff this is the first update for record_id */
  wrapped_record_key?: string;
}

// ---- verified state --------------------------

export type Role = "head" | "admin" | "member";

export interface MemberInfo {
  encPk: string;
  signPk: string;
  role: Role;
  admittedAtSeq: number;
}

export interface PendingProposal {
  payload: MemberProposePayload;
  proposedBy: string;
  proposedAtSeq: number;
}

export interface EpochInfo {
  startSeq: number;
  /** grant set AS OF this epoch: user_id -> sealed case key */
  holders: Map<string, string>;
  recoveryEnvelope: string;
}

export interface NoteInfo {
  wrappedRecordKey: string; // current epoch's wrap
  updates: Array<{ seq: number; epoch: number; author: string; ct: string }>;
  snapshot?: { seq: number; epoch: number; ct: string };
}

export interface CaseInfo {
  creatorId: string;
  /** index 0 = epoch 1; APPEND-ONLY — history is the point, never collapse */
  epochs: EpochInfo[];
  notes: Map<string, NoteInfo>;
}

export interface HashLogNode {
  seq: number;
  hash: string;
  prev: HashLogNode | null;
}

export interface OrgState {
  orgId: string;
  genesis: GenesisPayload | null; // null only before seq 1
  chain: {
    seq: number;
    headHash: string;
    /** every applied entry's hash as a structurally-shared cons list —
     * O(1) pure append (an array spread made replay O(n²); caught by the
     * layer-7 bench). Enables real proposal-checkpoint verification (a
     * cheap fork-detection tripwire); lookup walks back from the head,
     * which is fine — proposals checkpoint recent heads. */
    hashLog: HashLogNode | null;
  };
  /** The governance root AS STATE: initialized from genesis,
   * moved ONLY by head_succeed. Verifiers read these — never the genesis
   * payload — after seq 1, which is what retires an old governance key
   * (and any stolen head package holding it) by construction. */
  currentHeadUserId: string;
  currentGovernancePk: string;
  members: Map<string, MemberInfo>;
  proposals: Map<string, PendingProposal>;
  /** rekey_id -> pending case_rekey proposal awaiting countersign
   * (two-admin mode); consumed by the countersign shape */
  pendingRekeys: Map<
    string,
    { payload: CaseRekeyPayload; proposedBy: string; proposedAtSeq: number }
  >;
  /** who journaled custody of each printed recovery share (D4); the
   * CAN-see cost of this row is recorded in the threat model */
  shareCustody: { A?: string; B?: string };
  /** directory fan-outs in journal order: clients unseal the
   * envelopes addressed to them and merge names client-side */
  directoryShares: Array<{ seq: number; actor: string; envelopes: Record<string, string> }>;
  /** invite_id -> issuance record. Admissions must reference an issued
   * invite; pending = issued, unexpired (signer-clock), not yet used. */
  invites: Map<
    string,
    {
      issuer: string;
      sealedCode: string;
      issuedAtSeq: number;
      expiresAt: number;
    }
  >;
  usedInviteIds: Set<string>;
  /** Every applied envelope's `event_id` — the uniform replay guard
   *: a captured signed envelope cannot be re-appended
   * at a later seq. DELIBERATELY SHARED across state generations and
   * mutated append-only in applyEntry's commit step — a per-entry copy
   * would make replay O(n²) (the hashLog lesson, but a cons list can't
   * give O(1) lookup). Discipline: only applyEntry writes it, strictly
   * after every check has passed (a rejected entry leaves no residue —
   * test-pinned), and nothing may fold entries onto an old state
   * snapshot; rebuilds always start from emptyState(). */
  seenEventIds: Set<string>;
  cases: Map<string, CaseInfo>;
  /** ONE-WAY: set the first time two admins are simultaneously active,
   * never unset — admin demotion must not re-open solo admission, or a
   * compromised head could demote-then-ghost. */
  adminBarrierArmed: boolean;
}
