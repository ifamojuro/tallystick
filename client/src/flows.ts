// Flows: governance bootstrap, invite-code
// admission, PAKE registration/login. Pure orchestration over the api +
// @tallystick/shared — no DOM. The UI is a thin skin over this module, and the
// flows test exercises it end-to-end against the real server.
//
// Memory rules: sessions hold unwrapped keys and verified
// state in memory only. Nothing here writes secrets to storage.

import { crypto, journal } from "@tallystick/shared";
import { server, type Api } from "./api.ts";
import * as notes from "./notes.ts";
import * as searchMod from "./search.ts";

export interface JoinRequest {
  user_id: string;
  enc_pk: string;
  sign_pk: string;
  invite_id: string;
  binding_tag: string;
}

export interface Session {
  api: Api;
  userId: string;
  orgId: string;
  enc: crypto.BoxKeyPair;
  sign: crypto.SignKeyPair;
  governance?: crypto.SignKeyPair; // head only
  state: journal.OrgState;
  /** set when sync hit an invalid entry: fail-stop — the UI
   * must surface this and stop; we never skip past it */
  halted?: journal.InvalidEntry;
}

export function role(s: Session): journal.Role | undefined {
  return s.state.members.get(s.userId)?.role;
}

/** Pull new entries and fold them through applyEntry. Fail-stop on the
 * first invalid entry: record it, keep verified prefix, never skip. */
export async function sync(s: Session): Promise<Session> {
  if (s.halted) return s;
  const { entries } = await server.journalSince(s.api, s.state.chain.seq);
  for (const entry of entries) {
    try {
      s.state = journal.applyEntry(s.state, entry);
    } catch (e) {
      s.halted = e as journal.InvalidEntry;
      break;
    }
  }
  return s;
}

// ---- invites ------------------------------------------------------------

/** One printed string carries invite_id (16B, server-visible) + code (20B,
 * never seen by the server in cleartext). Delivered out of band. */
export interface Invite {
  inviteId: string;
  code: Uint8Array;
  printed: string;
}

function printedFrom(idBytes: Uint8Array, code: Uint8Array): string {
  const joined = new Uint8Array(36);
  joined.set(idBytes);
  joined.set(code, 16);
  return crypto.encodePrinted(joined);
}

/** Issue an invite THROUGH THE JOURNAL: admissions must
 * reference a journaled issuance, and any device holding this identity
 * recovers pending invites after sync — the code travels only as a sealed
 * box to the issuer's own encryption key. */
export async function issueInvite(s: Session, now: number = Date.now()): Promise<Invite> {
  const idBytes = crypto.newId();
  const code = crypto.newInviteCode();
  const inviteId = crypto.toB64u(idBytes);
  const env = journal.buildInviteIssue(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      inviteId,
      code,
      issuerEncPk: crypto.toB64u(s.enc.publicKey),
      now,
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
  return { inviteId, code, printed: printedFrom(idBytes, code) };
}

/** Pending invites THIS session issued, recovered from verified journal
 * state — device-independent by construction. Pending = journaled and not
 * yet consumed by an admission. */
export function myPendingInvites(
  s: Session,
  now: number = Date.now(),
): Array<{ invite: Invite; expiresAt: number }> {
  const out: Array<{ invite: Invite; expiresAt: number }> = [];
  for (const [inviteId, rec] of s.state.invites) {
    if (rec.issuer !== s.userId || s.state.usedInviteIds.has(inviteId)) continue;
    if (now > rec.expiresAt) continue; // expired: unusable, drop from pending
    try {
      const code = crypto.openSealed(s.enc, crypto.fromB64u(rec.sealedCode));
      out.push({
        expiresAt: rec.expiresAt,
        invite: { inviteId, code, printed: printedFrom(crypto.fromB64u(inviteId), code) },
      });
    } catch {
      /* not decryptable by this session's keys: skip */
    }
  }
  return out;
}

export function parseInvite(printed: string): { inviteId: string; code: Uint8Array } {
  const bytes = crypto.decodePrinted(printed); // throws ChecksumError on typo
  if (bytes.length !== 36) throw new crypto.EncodingError("not an invite code");
  return { inviteId: crypto.toB64u(bytes.subarray(0, 16)), code: bytes.subarray(16) };
}

// ---- registration (shared by bootstrap and join) ------------------------

const KDF_PARAMS = { ops: 2, mem_mib: 64, alg: "argon2id13" } as const;

interface Registered {
  userId: string;
  enc: crypto.BoxKeyPair;
  sign: crypto.SignKeyPair;
  token: string;
}

async function registerAccount(
  api: Api,
  passphrase: string,
  orgId: string,
  extraSecrets: Record<string, string> = {},
  inviteId?: string, // required by the server once an org exists
  setupCode?: string, // required by a fresh remotely-reachable server
): Promise<Registered> {
  const userId = crypto.toB64u(crypto.newId());
  const salt = crypto.newSalt();
  const { kWrap, kAuth } = crypto.deriveFromPassphrase(passphrase, salt);
  const enc = crypto.newBoxKeyPair();
  const sign = crypto.newSignKeyPair();

  const blob = crypto.aeadSeal(
    kWrap,
    crypto.canonicalize({
      enc_sk: crypto.toB64u(enc.privateKey),
      sign_sk: crypto.toB64u(sign.privateKey),
      ...extraSecrets,
    }),
    { v: 1, org: orgId, user: userId, use: "idkeys" },
  );

  const reg = crypto.opaqueRegister.start(kAuth);
  const { registrationResponse } = await server.registerStart(
    api,
    userId,
    reg.registrationRequest,
    inviteId,
    undefined,
    setupCode,
  );
  const { registrationRecord } = crypto.opaqueRegister.finish(
    kAuth,
    reg.state,
    registrationResponse,
  );
  await server.registerFinish(api, {
    userId,
    registrationRecord,
    salt: crypto.toB64u(salt),
    kdf: KDF_PARAMS,
    wrappedIdentityKeys: crypto.toB64u(blob),
    inviteId,
    setupCode,
  });

  const token = await pakeLogin(api, userId, kAuth);
  return { userId, enc, sign, token };
}

async function pakeLogin(api: Api, userId: string, kAuth: Uint8Array): Promise<string> {
  const login = crypto.opaqueLogin.start(kAuth);
  const { loginResponse, loginId } = await server.loginStart(api, userId, login.startLoginRequest);
  const done = crypto.opaqueLogin.finish(kAuth, login.state, loginResponse); // throws AuthFailed
  const { sessionToken } = await server.loginFinish(api, loginId, done.finishLoginRequest);
  return sessionToken;
}

// ---- workflow step 1: governance bootstrap ------------------------------

export interface BootstrapResult {
  session: Session;
  /** printed ceremony artifacts — shown once, confirmed, never stored */
  headRecoverySecretPrinted: string;
  recoveryShareAPrinted: string;
  recoveryShareBPrinted: string;
  /** fourth artifact: the head-package
   * CIPHERTEXT, so head recovery survives server loss */
  headPackageCtPrinted: string;
  /** the head's personal account-recovery code (D1) — for the head this
   * paper also guards governance; the ceremony copy says so */
  accountRecoveryPrinted: string;
}

export async function bootstrapOrg(
  api: Api,
  passphrase: string,
  setupCode?: string, // from the fresh remote server's startup log
): Promise<BootstrapResult> {
  const existing = await server.org(api);
  if (existing.orgId) throw new Error("this server already hosts an organization");
  const orgId = crypto.toB64u(crypto.newId());
  const governance = crypto.newSignKeyPair();
  const recovery = crypto.newBoxKeyPair();

  const reg = await registerAccount(
    api,
    passphrase,
    orgId,
    { gov_sk: crypto.toB64u(governance.privateKey) },
    undefined,
    setupCode,
  );
  const authed = { ...api, token: reg.token };

  // genesis pins head, governance key, and recovery public key
  const genesis = journal.buildOrgGenesis({
    orgId,
    headUserId: reg.userId,
    headEncPk: crypto.toB64u(reg.enc.publicKey),
    headSignPk: crypto.toB64u(reg.sign.publicKey),
    governance,
    recoveryPk: crypto.toB64u(recovery.publicKey),
  });
  await server.journalAppend(authed, genesis);

  // case-recovery private key → two printed shares; the private key is
  // discarded after this function returns
  const [shareA, shareB] = crypto.xorSplit(recovery.privateKey);

  const session: Session = {
    api: authed,
    userId: reg.userId,
    orgId,
    enc: reg.enc,
    sign: reg.sign,
    governance,
    state: journal.emptyState(),
  };
  await sync(session);

  // offline head recovery package: printed secret + encrypted key backup;
  // ciphertext duplicate to the server AND printed (fourth artifact, D4)
  const headPackage = await createHeadPackage(session);
  // the head's personal account-recovery package (D1)
  const accountRecoveryPrinted = await createRecoveryPackage(session);
  // journal the genesis custody reality: the head holds BOTH shares — the
  // solo-org residual becomes a recorded fact, not folklore (D4); handoff
  // acks supersede these when custody actually moves
  await ackShareCustody(session, "A");
  await ackShareCustody(session, "B");

  return {
    session,
    headRecoverySecretPrinted: headPackage.headSecretPrinted,
    recoveryShareAPrinted: crypto.encodePrinted(shareA),
    recoveryShareBPrinted: crypto.encodePrinted(shareB),
    headPackageCtPrinted: headPackage.headPackageCtPrinted,
    accountRecoveryPrinted,
  };
}

// ---- joining (admin candidate or ordinary member) -----------------------

export interface JoinResult {
  userId: string;
  /** keep to log in after approval; joining grants nothing by itself */
  api: Api;
  /** personal account-recovery code — printed at
   * join so every member holds one from day zero */
  recoveryPrinted: string;
}

export async function joinWithInvite(
  api: Api,
  passphrase: string,
  printedInvite: string,
): Promise<JoinResult> {
  const { inviteId, code } = parseInvite(printedInvite);
  const { orgId } = await server.org(api);
  if (!orgId) throw new Error("no organization on this server yet");
  const reg = await registerAccount(api, passphrase, orgId, {}, inviteId);
  const encPk = crypto.toB64u(reg.enc.publicKey);
  const signPk = crypto.toB64u(reg.sign.publicKey);
  await server.joinRequestPost(api, {
    user_id: reg.userId,
    enc_pk: encPk,
    sign_pk: signPk,
    invite_id: inviteId,
    binding_tag: journal.inviteBindingTag(code, reg.userId, encPk, signPk, inviteId),
  });
  const authed = { ...api, token: reg.token };
  const recoveryPrinted = await postRecoveryPackage(authed, orgId, reg.userId, {
    enc_sk: crypto.toB64u(reg.enc.privateKey),
    sign_sk: crypto.toB64u(reg.sign.privateKey),
  });
  return { userId: reg.userId, api: authed, recoveryPrinted };
}

// ---- approvals ----------------------------------------------------------

/** Recompute the binding tag from the code THIS approver holds; a mismatch
 * means the server (or anyone in between) substituted the keys. */
function checkBinding(req: JoinRequest, code: Uint8Array, inviteId: string): void {
  if (req.invite_id !== inviteId) throw new Error("join request is for a different invite");
  const expect = journal.inviteBindingTag(code, req.user_id, req.enc_pk, req.sign_pk, inviteId);
  if (expect !== req.binding_tag) {
    throw new Error(
      "GHOST-KEY WARNING: the joining keys were not authenticated by this invite code — refuse this admission",
    );
  }
}

/** Solo-governance mode: the head admits an ordinary member
 * alone — only while fewer than two admins exist. Same invite binding,
 * same ghost-key refusal; what's missing is the second person. */
export async function admitMemberSolo(
  s: Session,
  req: JoinRequest,
  printedInvite: string,
  now: number = Date.now(),
): Promise<void> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const { inviteId, code } = parseInvite(printedInvite);
  checkBinding(req, code, inviteId);
  const env = journal.buildMemberAdmit(s.state, s.governance, {
    userId: req.user_id,
    encPk: req.enc_pk,
    signPk: req.sign_pk,
    inviteCode: code,
    inviteId,
    now,
  });
  await server.journalAppend(s.api, env);
  await sync(s);
  await relayDirectory(s, req.user_id); // newcomer learns existing names
}

/** Head promotes an existing member to org admin (title, not identity). */
export async function promoteToAdmin(s: Session, userId: string): Promise<void> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const env = journal.buildAdminGrant(s.state, s.governance, { userId });
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** Head demotes an org admin back to member. The two-admin barrier stays
 * armed, and any printed recovery share they hold stays in their hands —
 * paper does not obey software. */
export async function demoteAdmin(s: Session, userId: string): Promise<void> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const env = journal.buildAdminRevoke(s.state, s.governance, { userId });
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** Admin 1 proposes an ordinary member from a join request (workflow step 2). */
export async function proposeMember(
  s: Session,
  req: JoinRequest,
  printedInvite: string,
  now: number,
): Promise<void> {
  const { inviteId, code } = parseInvite(printedInvite);
  checkBinding(req, code, inviteId);
  const env = journal.buildMemberPropose(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      userId: req.user_id,
      encPk: req.enc_pk,
      signPk: req.sign_pk,
      inviteCode: code,
      inviteId,
      now,
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** Admin 2 independently verifies the binding from their own copy of the
 * code and countersigns (workflow step 2). */
export async function approveMember(
  s: Session,
  proposalId: string,
  printedInvite: string,
  now: number,
): Promise<void> {
  const { code } = parseInvite(printedInvite);
  const admittedUserId = s.state.proposals.get(proposalId)?.payload.user_id;
  const env = journal.buildMemberApprove(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      proposalId,
      inviteCode: code,
      now,
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
  if (admittedUserId) await relayDirectory(s, admittedUserId); // newcomer learns names
}

// ---- login (workflow step 2's PAKE) -------------------------------------

export async function login(api: Api, userId: string, passphrase: string): Promise<Session> {
  const params = await server.params(api, userId);
  const { kWrap, kAuth } = crypto.deriveFromPassphrase(passphrase, crypto.fromB64u(params.salt));
  const token = await pakeLogin(api, userId, kAuth);
  const authed = { ...api, token };

  const { orgId } = await server.org(authed);
  if (!orgId) throw new Error("no organization on this server");
  const blob = await server.identity(authed);
  if (!blob.wrappedIdentityKeys) throw new Error("no identity blob for this user");
  const secrets = JSON.parse(
    new TextDecoder().decode(
      crypto.aeadOpen(kWrap, crypto.fromB64u(blob.wrappedIdentityKeys), {
        v: 1,
        org: orgId,
        user: userId,
        use: "idkeys",
      }),
    ),
  ) as { enc_sk: string; sign_sk: string; gov_sk?: string };

  const encSk = crypto.fromB64u(secrets.enc_sk);
  const signSk = crypto.fromB64u(secrets.sign_sk);
  const session: Session = {
    api: authed,
    userId,
    orgId,
    enc: { privateKey: encSk, publicKey: crypto.boxPkFromSk(encSk) },
    // an Ed25519 private key's last 32 bytes are the public key
    sign: { privateKey: signSk, publicKey: signSk.subarray(32) },
    state: journal.emptyState(),
  };
  if (secrets.gov_sk) {
    const gov = crypto.fromB64u(secrets.gov_sk);
    session.governance = { privateKey: gov, publicKey: gov.subarray(32) };
  }
  await sync(session);
  return session;
}

// ---- layers 5+6: the case layer (workflow steps 3, 4, 5, 7, 8, 9) -------
//
// Note content is a Yjs CRDT document (notes.ts): every
// note_update payload is one encrypted Yjs update; reading a note merges
// the snapshot (if any) with all post-snapshot updates, so concurrent
// authorized edits converge identically on every client.

/** caseTag -> per-epoch case keys, derived on demand from verified state
 * and memoized per chain seq. Memory only, like everything else here. */
const keychainCache = new WeakMap<Session, { seq: number; kc: journal.Keychain }>();
export function keychain(s: Session): journal.Keychain {
  const cached = keychainCache.get(s);
  if (cached && cached.seq === s.state.chain.seq) return cached.kc;
  const kc = journal.deriveKeychain(s.state, s.userId, s.enc);
  keychainCache.set(s, { seq: s.state.chain.seq, kc });
  return kc;
}

export interface NoteView {
  recordId: string;
  /** merged CRDT text, or null when this session cannot decrypt
   * (e.g. revoked: no key for the current epoch) */
  text: string | null;
  locked: boolean;
  /** seq of the note's first update — stable identity for ordering (survives
   * snapshot compaction, since revokes never drop updates[0]) */
  createdSeq: number;
  lastSeq: number;
  lastAuthor: string;
  /** typed-record kind: validated client convention —
   * anything unknown or malformed reads as "note" (fail-open) */
  kind: RecordKind;
  /** raw meta claims from the encrypted doc; readers validate per kind */
  meta: Record<string, unknown>;
}

export type RecordKind = "header" | "profile" | "contact" | "task" | "note";
const CONTACT_CHANNELS = ["call", "visit", "court", "accompaniment", "message", "other"] as const;
export type ContactChannel = (typeof CONTACT_CHANNELS)[number];
const CASE_STATUSES = ["open", "closed", "archived"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

/** Validate a doc's claimed kind — the fail-open gate: a hostile or buggy
 * client's malformed meta demotes the record to a plain note, never
 * crashes a reader. */
function validKind(meta: Record<string, unknown>): RecordKind {
  const k = meta["kind"];
  if (k === "header") {
    return typeof meta["title"] === "string" && CASE_STATUSES.includes(meta["status"] as CaseStatus)
      ? "header"
      : "note";
  }
  if (k === "profile") return "profile";
  if (k === "contact") {
    return CONTACT_CHANNELS.includes(meta["channel"] as ContactChannel) ? "contact" : "note";
  }
  if (k === "task") return typeof meta["done"] === "boolean" ? "task" : "note";
  return "note";
}

/** Client-claimed wall-clock of the last edit (meta.at) — display only;
 * journal seq stays the cryptographic ordering. */
export function recordAt(r: NoteView): number | null {
  return typeof r.meta["at"] === "number" ? (r.meta["at"] as number) : null;
}

export interface CaseView {
  caseTag: string;
  creatorId: string;
  epoch: number;
  amCreator: boolean;
  /** current-epoch grant holders (who can read new updates) */
  holders: string[];
  /** ALL decryptable records, creation order — the search surface */
  records: NoteView[];
  /** plain freeform notes only (kind "note"), creation order */
  notes: NoteView[];
  header?: NoteView;
  profile?: NoteView;
  /** contact-log entries, newest first by claimed time (seq tiebreak) */
  contacts: NoteView[];
  /** tasks: open before done, then by due date (undated last) */
  tasks: NoteView[];
  /** header title, or the legacy first-line fallback */
  title: string;
  status: CaseStatus;
  /** alias of title (pre-v2 name, kept for search/UI compat) */
  label: string;
}

/** All cases THIS session can see — i.e. cases in the keychain. A case the
 * user was never granted simply does not appear (acceptance criterion). */
export function listCases(s: Session): CaseView[] {
  return [...keychain(s).keys()]
    .map((tag) => readCase(s, tag))
    .filter((c): c is CaseView => c !== null);
}

export function readCase(s: Session, caseTag: string): CaseView | null {
  const c = s.state.cases.get(caseTag);
  const keys = keychain(s).get(caseTag);
  if (!c || !keys) return null;
  const records: NoteView[] = [...c.notes.entries()]
    .map(([recordId, note]) => readNote(s, caseTag, recordId, note, keys))
    .sort((a, b) => a.createdSeq - b.createdSeq); // creation order: stable under edits
  const header = records.find((r) => r.kind === "header");
  const profile = records.find((r) => r.kind === "profile");
  const plainNotes = records.filter((r) => r.kind === "note");
  const contacts = records
    .filter((r) => r.kind === "contact")
    .sort((a, b) => (recordAt(b) ?? b.createdSeq) - (recordAt(a) ?? a.createdSeq));
  const tasks = records
    .filter((r) => r.kind === "task")
    .sort((a, b) => {
      const doneDiff = Number(a.meta["done"] === true) - Number(b.meta["done"] === true);
      if (doneDiff !== 0) return doneDiff; // open tasks first
      const da = typeof a.meta["due"] === "number" ? (a.meta["due"] as number) : Infinity;
      const db = typeof b.meta["due"] === "number" ? (b.meta["due"] as number) : Infinity;
      return da - db;
    });
  const first = plainNotes[0];
  const title =
    (typeof header?.meta["title"] === "string" && (header.meta["title"] as string).trim()) ||
    (first?.text != null ? (first.text.split("\n")[0] ?? "").slice(0, 60) : "") ||
    `case ${caseTag.slice(0, 8)}…`;
  const status = (header?.meta["status"] as CaseStatus | undefined) ?? "open";
  return {
    caseTag,
    creatorId: c.creatorId,
    epoch: journal.currentEpoch(c),
    amCreator: c.creatorId === s.userId,
    holders: [...c.epochs[c.epochs.length - 1]!.holders.keys()],
    records,
    notes: plainNotes,
    header,
    profile,
    contacts,
    tasks,
    title,
    status,
    label: title,
  };
}

/** One decrypted journal event of a note: a Yjs update plus its journal
 * coordinates. `author` is null for the compaction snapshot a revoke
 * writes (it aggregates earlier authors' work). */
interface NotePart {
  seq: number;
  epoch: number;
  author: string | null;
  bytes: Uint8Array;
}

/** Decrypt a note's payload set, in journal order. Returns null when this
 * session lacks the current epoch's key (locked).
 * `maxSeq` cuts the sequence at that journal seq — the state a reader
 * actually saw — so an edit diffed against it stays concurrent with (and
 * mergeable against) updates that landed later. Ignored when a snapshot
 * has already compacted that history away. */
function decryptNoteParts(
  s: Session,
  caseTag: string,
  recordId: string,
  note: journal.NoteInfo,
  keys: Map<number, Uint8Array>,
  maxSeq?: number,
): NotePart[] | null {
  // the record key's current wrap epoch: creation epoch, or the last revoke
  const wrapEpoch = note.snapshot?.epoch ?? note.updates[0]!.epoch;
  const caseKey = keys.get(wrapEpoch);
  if (!caseKey) return null;
  const cap =
    maxSeq !== undefined && (!note.snapshot || note.snapshot.seq <= maxSeq) ? maxSeq : Infinity;
  try {
    const recordKey = crypto.aeadOpen(
      caseKey,
      crypto.fromB64u(note.wrappedRecordKey),
      journal.recordKeyAad(s.orgId, caseTag, wrapEpoch),
    );
    const parts: { seq: number; epoch: number; author: string | null; ct: string }[] = [
      ...(note.snapshot
        ? [
            {
              seq: note.snapshot.seq,
              epoch: note.snapshot.epoch,
              author: null,
              ct: note.snapshot.ct,
            },
          ]
        : []),
      ...note.updates
        .filter((u) => (!note.snapshot || u.seq > note.snapshot.seq) && u.seq <= cap)
        .map((u) => ({ seq: u.seq, epoch: u.epoch, author: u.author as string | null, ct: u.ct })),
    ];
    return parts.map((p) => ({
      seq: p.seq,
      epoch: p.epoch,
      author: p.author,
      bytes: crypto.aeadOpen(
        recordKey,
        crypto.fromB64u(p.ct),
        journal.noteAad(s.orgId, caseTag, p.epoch, recordId),
      ),
    }));
  } catch {
    return null;
  }
}

/** Decrypt a note's payload set and merge it into a Y.Doc (see
 * decryptNoteParts for the null and maxSeq semantics). */
function openNoteDoc(
  s: Session,
  caseTag: string,
  recordId: string,
  note: journal.NoteInfo,
  keys: Map<number, Uint8Array>,
  maxSeq?: number,
): ReturnType<typeof notes.docFrom> | null {
  const parts = decryptNoteParts(s, caseTag, recordId, note, keys, maxSeq);
  return parts && notes.docFrom(parts.map((p) => p.bytes));
}

function readNote(
  s: Session,
  caseTag: string,
  recordId: string,
  note: journal.NoteInfo,
  keys: Map<number, Uint8Array>,
): NoteView {
  const post = note.updates.filter((u) => !note.snapshot || u.seq > note.snapshot.seq);
  const last = post[post.length - 1];
  const createdSeq = note.updates[0]!.seq;
  const lastSeq = last?.seq ?? note.snapshot!.seq;
  const lastAuthor = last?.author ?? "(snapshot)";
  const doc = openNoteDoc(s, caseTag, recordId, note, keys);
  if (!doc) {
    return {
      recordId,
      text: null,
      locked: true,
      createdSeq,
      lastSeq,
      lastAuthor,
      kind: "note",
      meta: {},
    };
  }
  const meta = notes.metaOf(doc);
  return {
    recordId,
    text: notes.textOf(doc),
    locked: false,
    createdSeq,
    lastSeq,
    lastAuthor,
    kind: validKind(meta),
    meta,
  };
}

// ---- note history (cleanup backlog item 5, idea 3) ----------------------

export interface NoteHistoryStep {
  seq: number;
  epoch: number;
  /** null for the compaction snapshot a revoke writes — it aggregates all
   * pre-rotation authors' work into one step and is labeled as such */
  author: string | null;
  /** full merged text as of this step (view-as-of-seq) */
  text: string;
  /** the contiguous run this step changed (common prefix/suffix delta) */
  added: string;
  removed: string;
}

/** Minimal common-prefix/suffix delta between two texts — the same diff
 * shape editUpdate posts, recovered for display. */
function textDelta(oldText: string, newText: string): { added: string; removed: string } {
  let prefix = 0;
  while (prefix < oldText.length && prefix < newText.length && oldText[prefix] === newText[prefix])
    prefix++;
  let suffix = 0;
  while (
    suffix < oldText.length - prefix &&
    suffix < newText.length - prefix &&
    oldText[oldText.length - 1 - suffix] === newText[newText.length - 1 - suffix]
  )
    suffix++;
  return {
    removed: oldText.slice(prefix, oldText.length - suffix),
    added: newText.slice(prefix, newText.length - suffix),
  };
}

/** A note's audit trail, oldest first: one step per journal event still in
 * state, each with attribution and the text it produced. After a revoke,
 * everything before the rotation is one snapshot step (author null) —
 * compaction is shown honestly, not hidden. Derived entirely from
 * verified journal data (no new server visibility); event_id uniqueness
 * guarantees replays cannot forge duplicate steps.
 * Returns null when this session cannot decrypt the note. */
export function noteHistory(
  s: Session,
  caseTag: string,
  recordId: string,
): NoteHistoryStep[] | null {
  const note = s.state.cases.get(caseTag)?.notes.get(recordId);
  const keys = keychain(s).get(caseTag);
  if (!note || !keys) return null;
  const parts = decryptNoteParts(s, caseTag, recordId, note, keys);
  if (!parts) return null;
  const texts = notes.textTimeline(parts.map((p) => p.bytes));
  return parts.map((p, i) => ({
    seq: p.seq,
    epoch: p.epoch,
    author: p.author,
    text: texts[i]!,
    ...textDelta(i === 0 ? "" : texts[i - 1]!, texts[i]!),
  }));
}

// ---- local search (memory-only, keychain-scoped) ---------------

const indexCache = new WeakMap<Session, { seq: number; index: searchMod.SearchIndex }>();

/** The session's search index: built from keychain-decryptable notes only,
 * memoized per chain seq, discarded with the session. */
export function searchIndex(s: Session): searchMod.SearchIndex {
  const cached = indexCache.get(s);
  if (cached && cached.seq === s.state.chain.seq) return cached.index;
  const index = searchMod.buildIndex(listCases(s));
  indexCache.set(s, { seq: s.state.chain.seq, index });
  return index;
}

export function searchNotes(s: Session, query: string): searchMod.SearchHit[] {
  return searchMod.search(searchIndex(s), query);
}

/** Workflow step 3: create a case: a header record
 * carries the explicit title + status; the given text (if any) becomes
 * the first freeform note. The title defaults to the text's first line
 * so the pre-v2 call shape keeps working. */
export async function createCase(s: Session, firstNote: string, title?: string): Promise<string> {
  const caseKey = crypto.newKey();
  const { envelope, caseTag } = journal.buildCaseCreate(
    s.state,
    { userId: s.userId, sign: s.sign },
    { caseKey, actorEncPk: crypto.toB64u(s.enc.publicKey) },
  );
  await server.journalAppend(s.api, envelope);
  await sync(s);
  await createRecord(s, caseTag, {
    kind: "header",
    title: (title ?? firstNote.split("\n")[0] ?? "").slice(0, 120),
    status: "open",
    openedAt: Date.now(),
  });
  if (firstNote.trim()) await writeNote(s, caseTag, undefined, firstNote);
  return caseTag;
}

/** Create a typed record: meta + optional body, sealed
 * like any note — the journal sees only ciphertext. */
export async function createRecord(
  s: Session,
  caseTag: string,
  meta: Record<string, notes.MetaValue>,
  text = "",
): Promise<string> {
  const plaintext = notes.newRecordUpdate({ ...meta, at: Date.now() }, text);
  const { envelope, recordId } = journal.buildNoteUpdate(
    s.state,
    { userId: s.userId, sign: s.sign },
    { caseTag, caseKey: currentCaseKey(s, caseTag), plaintext },
  );
  await server.journalAppend(s.api, envelope);
  await sync(s);
  return recordId;
}

/** Set meta fields on an existing record (status flip, task toggle, title
 * or profile edit) — an incremental CRDT update; Y.Map gives per-field
 * last-writer-wins, the right merge for scalars. */
export async function setRecordMeta(
  s: Session,
  caseTag: string,
  recordId: string,
  fields: Record<string, notes.MetaValue>,
): Promise<void> {
  const c = s.state.cases.get(caseTag);
  const note = c?.notes.get(recordId);
  if (!note) throw new Error("unknown record");
  const doc = openNoteDoc(s, caseTag, recordId, note, keychain(s).get(caseTag) ?? new Map());
  if (!doc) throw new Error("no key for this case's current epoch (revoked?)");
  const plaintext = notes.metaUpdate(doc, { ...fields, at: Date.now() });
  const { envelope } = journal.buildNoteUpdate(
    s.state,
    { userId: s.userId, sign: s.sign },
    { caseTag, caseKey: currentCaseKey(s, caseTag), recordId, plaintext },
  );
  await server.journalAppend(s.api, envelope);
  await sync(s);
}

export interface DeadlineView {
  caseTag: string;
  caseTitle: string;
  recordId: string;
  text: string;
  due: number;
  overdue: boolean;
}

/** Open, dated tasks across every case this keychain opens, soonest first
 * — the Cases panel's deadlines strip. */
export function upcomingDeadlines(s: Session, now: number = Date.now()): DeadlineView[] {
  const out: DeadlineView[] = [];
  for (const c of listCases(s)) {
    if (c.status === "archived") continue;
    for (const t of c.tasks) {
      if (t.meta["done"] === true || typeof t.meta["due"] !== "number" || t.text === null) continue;
      const due = t.meta["due"] as number;
      out.push({
        caseTag: c.caseTag,
        caseTitle: c.title,
        recordId: t.recordId,
        text: t.text,
        due,
        overdue: due < now,
      });
    }
  }
  return out.sort((a, b) => a.due - b.due);
}

function currentCaseKey(s: Session, caseTag: string): Uint8Array {
  const c = s.state.cases.get(caseTag);
  if (!c) throw new Error("unknown case");
  const key = keychain(s).get(caseTag)?.get(journal.currentEpoch(c));
  if (!key) throw new Error("no key for this case's current epoch (revoked?)");
  return key;
}

/** Workflow steps 3/5/8: write a note. New notes post a full-state Yjs
 * update; edits post only the incremental update produced by diffing the
 * new text against the note's local merge — so two clients editing
 * concurrently produce updates that merge instead of clobbering.
 * `baselineSeq` names the merge the writer's text was composed against:
 * when this client has already synced a newer remote update, diffing
 * against the baseline (not the current merge) keeps that remote edit —
 * otherwise the diff would read it as text the writer deleted. */
export async function writeNote(
  s: Session,
  caseTag: string,
  recordId: string | undefined,
  newText: string,
  baselineSeq?: number,
): Promise<string> {
  let plaintext: Uint8Array;
  if (recordId === undefined) {
    plaintext = notes.newNoteUpdate(newText);
  } else {
    const c = s.state.cases.get(caseTag);
    const note = c?.notes.get(recordId);
    if (!note) throw new Error("unknown record");
    const doc = openNoteDoc(
      s,
      caseTag,
      recordId,
      note,
      keychain(s).get(caseTag) ?? new Map(),
      baselineSeq,
    );
    if (!doc) throw new Error("no key for this case's current epoch (revoked?)");
    const atStamp = notes.metaUpdate(doc, { at: Date.now() });
    plaintext = notes.mergeUpdates([atStamp, notes.editUpdate(doc, newText)]);
  }
  const { envelope, recordId: rid } = journal.buildNoteUpdate(
    s.state,
    { userId: s.userId, sign: s.sign },
    { caseTag, caseKey: currentCaseKey(s, caseTag), recordId, plaintext },
  );
  await server.journalAppend(s.api, envelope);
  await sync(s);
  return rid;
}

/** Workflow step 4: share the case — wrap the current key for the recipient. */
export async function shareCase(s: Session, caseTag: string, recipient: string): Promise<void> {
  const env = journal.buildCaseGrant(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      caseTag,
      caseKey: currentCaseKey(s, caseTag),
      recipient,
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** Workflow step 7: revoke a user — new epoch, every note compacted to a
 * fresh snapshot under a new record key wrapped by the new case key.
 * Forward-looking only: it cannot erase what the revoked user already
 * copied. */
export async function revokeFromCase(s: Session, caseTag: string, revoked: string): Promise<void> {
  const c = s.state.cases.get(caseTag);
  if (!c) throw new Error("unknown case");
  const keys = keychain(s).get(caseTag) ?? new Map<number, Uint8Array>();
  // each snapshot is the note's full merged CRDT state as one Yjs update,
  // re-encrypted under the new epoch's fresh record key
  const noteSnapshots: Record<string, Uint8Array> = {};
  for (const [recordId, note] of c.notes) {
    const doc = openNoteDoc(s, caseTag, recordId, note, keys);
    if (!doc) throw new Error("cannot revoke: a note failed to decrypt");
    noteSnapshots[recordId] = notes.fullState(doc);
  }
  const env = journal.buildCaseRevoke(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      caseTag,
      revoked,
      newCaseKey: crypto.newKey(),
      noteSnapshots,
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
}

// ---- recovery ceremonies ----------------
//
// D1 personal recovery packages: the head-package pattern generalized to
// every member — a printed high-entropy secret wrapping the SAME identity
// keys, so recovery preserves every grant, case, and attribution. The
// printed code is deliberately high-entropy (no short PINs: this server is
// untrusted, so a PIN-wrapped blob would be offline-brute-forceable).

const RECOVERY_AAD = (orgId: string, userId: string) =>
  ({ v: 1, org: orgId, user: userId, use: "idrec" }) as const;

async function postRecoveryPackage(
  api: Api,
  orgId: string,
  userId: string,
  secrets: Record<string, string>,
): Promise<string> {
  const secret = crypto.newKey();
  const ct = crypto.aeadSeal(
    crypto.hash(secret),
    crypto.canonicalize(secrets),
    RECOVERY_AAD(orgId, userId),
  );
  await server.recoveryBlobPost(api, crypto.toB64u(ct));
  return crypto.encodePrinted(secret);
}

function sessionSecrets(s: Session): Record<string, string> {
  const secrets: Record<string, string> = {
    enc_sk: crypto.toB64u(s.enc.privateKey),
    sign_sk: crypto.toB64u(s.sign.privateKey),
  };
  // the head's personal code therefore ALSO guards governance — the UI
  // must say so
  if (s.governance) secrets["gov_sk"] = crypto.toB64u(s.governance.privateKey);
  return secrets;
}

/** Mint (or replace) this session's personal recovery package; returns the
 * printed code. The previous code, if any, becomes dead paper. */
export async function createRecoveryPackage(s: Session): Promise<string> {
  return postRecoveryPackage(s.api, s.orgId, s.userId, sessionSecrets(s));
}

async function openRecoveryBlob(
  api: Api,
  orgId: string,
  userId: string,
  printedCode: string,
): Promise<Record<string, string>> {
  const secret = crypto.decodePrinted(printedCode); // throws ChecksumError on typo
  const { ciphertext } = await server.recoveryBlobGet(api, userId);
  if (!ciphertext) throw new Error("no recovery package exists for this account");
  return JSON.parse(
    new TextDecoder().decode(
      crypto.aeadOpen(
        crypto.hash(secret),
        crypto.fromB64u(ciphertext),
        RECOVERY_AAD(orgId, userId),
      ),
    ),
  ) as Record<string, string>;
}

/** Verify-only rehearsal: decrypt the package and discard (D5). */
export async function verifyRecoveryCode(
  api: Api,
  userId: string,
  printedCode: string,
): Promise<void> {
  const { orgId } = await server.org(api);
  if (!orgId) throw new Error("no organization on this server");
  await openRecoveryBlob(api, orgId, userId, printedCode);
}

/** Account recovery (pre-login): the printed code decrypts the SAME
 * identity keys; a signature over the server's challenge unlocks a
 * one-shot OPAQUE re-registration under a new passphrase. No journal
 * event — the roster, grants, and authorship are untouched. A fresh
 * recovery code is minted (the old paper is spent). */
export async function recoverAccount(
  api: Api,
  userId: string,
  printedCode: string,
  newPassphrase: string,
): Promise<{ session: Session; recoveryPrinted: string }> {
  const { orgId } = await server.org(api);
  if (!orgId) throw new Error("no organization on this server");
  const secrets = await openRecoveryBlob(api, orgId, userId, printedCode);
  const signSk = crypto.fromB64u(secrets["sign_sk"]!);
  const sign: crypto.SignKeyPair = { privateKey: signSk, publicKey: signSk.subarray(32) };

  // prove possession of the roster-pinned identity signing key;
  // each phase's proof also signs a `commit` hash of the EXACT replacement
  // material it authorizes, so a captured proof cannot be re-bound to
  // attacker-chosen credentials; the server consumes the nonce one-shot
  // at finish and challenges expire in minutes.
  const { nonce } = await server.recoveryChallenge(api, userId);
  const commitOf = (material: crypto.JsonValue): string =>
    crypto.toB64u(crypto.hash(crypto.canonicalize(material)));
  const proofFor = (commit: string): string =>
    crypto.signEvent(sign, { use: "account-recovery", org: orgId, user: userId, nonce, commit });

  // OPAQUE re-registration: same userId, same keys, new passphrase
  const salt = crypto.newSalt();
  const { kWrap, kAuth } = crypto.deriveFromPassphrase(newPassphrase, salt);
  const blob = crypto.aeadSeal(kWrap, crypto.canonicalize(secrets), {
    v: 1,
    org: orgId,
    user: userId,
    use: "idkeys",
  });
  const reg = crypto.opaqueRegister.start(kAuth);
  const { registrationResponse } = await server.registerStart(
    api,
    userId,
    reg.registrationRequest,
    undefined,
    { nonce, sig: proofFor(commitOf({ registrationRequest: reg.registrationRequest })) },
  );
  const { registrationRecord } = crypto.opaqueRegister.finish(
    kAuth,
    reg.state,
    registrationResponse,
  );
  const saltB64 = crypto.toB64u(salt);
  const blobB64 = crypto.toB64u(blob);
  await server.registerFinish(api, {
    userId,
    registrationRecord,
    salt: saltB64,
    kdf: KDF_PARAMS,
    wrappedIdentityKeys: blobB64,
    recoveryNonce: nonce,
    recoverySig: proofFor(
      commitOf({
        registrationRecord,
        salt: saltB64,
        kdf: KDF_PARAMS,
        wrappedIdentityKeys: blobB64,
      }),
    ),
  });

  const token = await pakeLogin(api, userId, kAuth);
  const encSk = crypto.fromB64u(secrets["enc_sk"]!);
  const session: Session = {
    api: { ...api, token },
    userId,
    orgId,
    enc: { privateKey: encSk, publicKey: crypto.boxPkFromSk(encSk) },
    sign,
    state: journal.emptyState(),
  };
  if (secrets["gov_sk"]) {
    const gov = crypto.fromB64u(secrets["gov_sk"]);
    session.governance = { privateKey: gov, publicKey: gov.subarray(32) };
  }
  await sync(session);
  const recoveryPrinted = await createRecoveryPackage(session);
  return { session, recoveryPrinted };
}

// ---- D2: the case-recovery ceremony and case_rekey ----------------------

/** Join two printed shares and check the result against the genesis-pinned
 * recovery public key — the "wrong paper" check happens HERE, before
 * anything is decrypted. */
export function joinRecoveryShares(
  state: journal.OrgState,
  printedA: string,
  printedB: string,
): crypto.BoxKeyPair {
  const sk = crypto.xorJoin(crypto.decodePrinted(printedA), crypto.decodePrinted(printedB));
  const pk = crypto.boxPkFromSk(sk);
  if (crypto.toB64u(pk) !== state.genesis?.recovery_pk) {
    throw new Error(
      "these shares do not reconstruct this organization's recovery key — wrong paper?",
    );
  }
  return { privateKey: sk, publicKey: pk };
}

/** Full epoch->key map for a case via its recovery envelopes. */
function recoveredCaseKeys(
  s: Session,
  caseTag: string,
  recoveryKp: crypto.BoxKeyPair,
): Map<number, Uint8Array> {
  const c = s.state.cases.get(caseTag);
  if (!c) throw new Error("unknown case");
  const keys = new Map<number, Uint8Array>();
  for (let e = 1; e <= journal.currentEpoch(c); e++) {
    keys.set(e, journal.recoverCaseKey(s.state, recoveryKp, caseTag, e));
  }
  return keys;
}

/** Read-only recovery (the explicit "without restoring" choice — this path
 * leaves no journal trace; recorded residual). */
export function recoverReadCase(
  s: Session,
  caseTag: string,
  recoveryKp: crypto.BoxKeyPair,
): { recordId: string; text: string }[] {
  const c = s.state.cases.get(caseTag);
  if (!c) throw new Error("unknown case");
  const keys = recoveredCaseKeys(s, caseTag, recoveryKp);
  const out: { recordId: string; text: string }[] = [];
  for (const [recordId, note] of c.notes) {
    const doc = openNoteDoc(s, caseTag, recordId, note, keys);
    if (!doc) throw new Error("a note failed to decrypt during recovery");
    out.push({ recordId, text: notes.textOf(doc) });
  }
  return out;
}

function recoverNoteSnapshots(
  s: Session,
  caseTag: string,
  recoveryKp: crypto.BoxKeyPair,
): Record<string, Uint8Array> {
  const c = s.state.cases.get(caseTag)!;
  const keys = recoveredCaseKeys(s, caseTag, recoveryKp);
  const out: Record<string, Uint8Array> = {};
  for (const [recordId, note] of c.notes) {
    const doc = openNoteDoc(s, caseTag, recordId, note, keys);
    if (!doc) throw new Error("a note failed to decrypt during recovery");
    out[recordId] = notes.fullState(doc);
  }
  return out;
}

/** The restore ceremony (D2): reconstruct the recovery key from both
 * printed shares, decrypt and compact every note, and mint a new epoch
 * for the designated holders. Solo mode commits directly (head); armed
 * mode journals a PROPOSAL a second admin must countersign. Returns the
 * rekey id (null when committed directly). */
export async function rekeyCase(
  s: Session,
  caseTag: string,
  holders: string[],
  printedShareA: string,
  printedShareB: string,
  now: number = Date.now(),
): Promise<string | null> {
  const kp = joinRecoveryShares(s.state, printedShareA, printedShareB);
  const noteSnapshots = recoverNoteSnapshots(s, caseTag, kp);
  const newCaseKey = crypto.newKey();
  if (!s.state.adminBarrierArmed) {
    if (!s.governance) throw new Error("solo rekey requires the head's governance key");
    const env = journal.buildCaseRekeySolo(s.state, s.governance, {
      caseTag,
      newCaseKey,
      holders,
      noteSnapshots,
      now,
    });
    await server.journalAppend(s.api, env);
    await sync(s);
    return null;
  }
  const { envelope, rekeyId } = journal.buildCaseRekeyPropose(
    s.state,
    { userId: s.userId, sign: s.sign },
    { caseTag, newCaseKey, holders, noteSnapshots, now },
  );
  await server.journalAppend(s.api, envelope);
  await sync(s);
  return rekeyId;
}

/** Second admin's countersign: consent, not key material — the shares were
 * already exercised at propose time by the co-present custodians. */
export async function approveRekey(
  s: Session,
  rekeyId: string,
  now: number = Date.now(),
): Promise<void> {
  const env = journal.buildCaseRekeyCountersign(
    s.state,
    { userId: s.userId, sign: s.sign },
    { rekeyId, now },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
}

// ---- D3: head succession and governance rotation ------------------------

async function rewrapIdentityBlob(s: Session, passphrase: string): Promise<void> {
  const params = await server.params(s.api, s.userId);
  const { kWrap } = crypto.deriveFromPassphrase(passphrase, crypto.fromB64u(params.salt));
  const current = await server.identity(s.api);
  if (!current.wrappedIdentityKeys) throw new Error("no identity blob for this user");
  // decrypting with the derived key doubles as the passphrase check
  crypto.aeadOpen(kWrap, crypto.fromB64u(current.wrappedIdentityKeys), {
    v: 1,
    org: s.orgId,
    user: s.userId,
    use: "idkeys",
  });
  const blob = crypto.aeadSeal(kWrap, crypto.canonicalize(sessionSecrets(s)), {
    v: 1,
    org: s.orgId,
    user: s.userId,
    use: "idkeys",
  });
  await server.identityUpdate(s.api, crypto.toB64u(blob));
}

/** Successor step 1: generate the NEW governance keypair (the old head
 * never holds its private half), stash it in this member's identity
 * blob, and hand back a SUCCESSION CODE for the current head: the public
 * key PLUS a proof-of-possession signature (v0.9.1), checksum-wrapped
 * like every other printed string — a typo now fails loudly at entry
 * instead of bricking governance at commit. */
export async function prepareSuccession(s: Session, passphrase: string): Promise<string> {
  const gov = crypto.newSignKeyPair();
  const pop = journal.buildSuccessionPop(s.orgId, s.userId, gov);
  s.governance = gov;
  await rewrapIdentityBlob(s, passphrase);
  const bundle = new Uint8Array(96); // pk(32) ‖ pop signature(64)
  bundle.set(gov.publicKey);
  bundle.set(crypto.fromB64u(pop), 32);
  return crypto.encodePrinted(bundle);
}

/** Parse a succession code back into its halves (throws ChecksumError on
 * a transcription typo — the cheap failure, before anything signs). */
export function parseSuccessionCode(printed: string): { newGovernancePk: string; pop: string } {
  const bytes = crypto.decodePrinted(printed);
  if (bytes.length !== 96) throw new crypto.EncodingError("not a succession code");
  return {
    newGovernancePk: crypto.toB64u(bytes.subarray(0, 32)),
    pop: crypto.toB64u(bytes.subarray(32)),
  };
}

/** Head step 2: sign the succession (successor must be an active admin;
 * the builder re-verifies the proof of possession before signing). */
export async function succeedHead(
  s: Session,
  newHeadUserId: string,
  successionCode: string,
): Promise<void> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const { newGovernancePk, pop } = parseSuccessionCode(successionCode);
  const env = journal.buildHeadSucceed(s.state, s.governance, {
    newHeadUserId,
    newGovernancePk,
    pop,
  });
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** New head package — bootstrap, succession, and rotation all end here.
 * Returns the printed secret AND the printed ciphertext (the fourth
 * bootstrap artifact: head recovery must survive server loss). */
export async function createHeadPackage(
  s: Session,
): Promise<{ headSecretPrinted: string; headPackageCtPrinted: string }> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const secret = crypto.newKey();
  const ct = crypto.aeadSeal(crypto.hash(secret), s.governance.privateKey, {
    v: 1,
    org: s.orgId,
    use: "headpkg",
  });
  await server.headPackagePost(s.api, crypto.toB64u(ct));
  return {
    headSecretPrinted: crypto.encodePrinted(secret),
    headPackageCtPrinted: crypto.encodePrinted(ct),
  };
}

/** Pure governance-key rotation (self-succession) — the remedy for a
 * suspected head-package theft: after this, the stolen paper is dead. */
export async function rotateGovernance(
  s: Session,
  passphrase: string,
): Promise<{ headSecretPrinted: string; headPackageCtPrinted: string }> {
  if (!s.governance) throw new Error("only the head holds the governance key");
  const gov = crypto.newSignKeyPair();
  const env = journal.buildHeadSucceed(s.state, s.governance, {
    newHeadUserId: s.userId,
    newGovernancePk: crypto.toB64u(gov.publicKey),
    pop: journal.buildSuccessionPop(s.orgId, s.userId, gov),
  });
  await server.journalAppend(s.api, env);
  s.governance = gov;
  await sync(s);
  await rewrapIdentityBlob(s, passphrase);
  return createHeadPackage(s);
}

/** Emergency succession: the printed head secret restores the OLD
 * governance key, which signs an ordinary head_succeed — custody of the
 * head package IS the succession authority.
 * Runs inside any admitted member's session (the append needs a token);
 * `packageCtPrinted` is the printed fourth artifact, used when the
 * server's ciphertext copy is gone. */
export async function emergencySucceedHead(
  s: Session,
  printedHeadSecret: string,
  newHeadUserId: string,
  successionCode: string,
  packageCtPrinted?: string,
): Promise<void> {
  const secret = crypto.decodePrinted(printedHeadSecret);
  const ctB64 = packageCtPrinted
    ? crypto.toB64u(crypto.decodePrinted(packageCtPrinted))
    : (await server.headPackageGet(s.api)).ciphertext;
  if (!ctB64) {
    throw new Error("no head package on the server — enter the printed ciphertext artifact");
  }
  const govSk = crypto.aeadOpen(crypto.hash(secret), crypto.fromB64u(ctB64), {
    v: 1,
    org: s.orgId,
    use: "headpkg",
  });
  const gov: crypto.SignKeyPair = { privateKey: govSk, publicKey: govSk.subarray(32) };
  const { newGovernancePk, pop } = parseSuccessionCode(successionCode);
  const env = journal.buildHeadSucceed(s.state, gov, { newHeadUserId, newGovernancePk, pop });
  await server.journalAppend(s.api, env);
  await sync(s);
}

// ---- D4: share custody --------------------------------------------------

/** The RECEIVER journals that they now hold printed share A or B. */
export async function ackShareCustody(s: Session, share: "A" | "B"): Promise<void> {
  const env = journal.buildShareCustodyAck(s.state, { userId: s.userId, sign: s.sign }, { share });
  await server.journalAppend(s.api, env);
  await sync(s);
}

// ---- org directory: display names ------
//
// Names travel ONLY inside sealed boxes fanned out per recipient; the
// merge is client-side: a claim about user X is SELF-AUTHORED when the
// share's actor IS X, and self-authored beats relayed (admitters relay
// the map to newcomers). Latest `at` wins within a class, seq tiebreak.
// Uniqueness is neither promised nor enforced — the UI disambiguates
// collisions by showing the ID beside the name.

interface DirectoryDerived {
  names: Record<string, string>;
  /** names appearing on more than one member — the UI's disambiguation set */
  collisions: Set<string>;
  /** members who have EVER self-authored a share about themselves (even a
   * clearing one) — gates the one-time auto-publish */
  selfDeclared: Set<string>;
}

const directoryCache = new WeakMap<Session, { seq: number; derived: DirectoryDerived }>();

function deriveDirectory(s: Session): DirectoryDerived {
  const cached = directoryCache.get(s);
  if (cached && cached.seq === s.state.chain.seq) return cached.derived;
  const best = new Map<string, { name: string; at: number; self: boolean; seq: number }>();
  const selfDeclared = new Set<string>();
  for (const share of s.state.directoryShares) {
    const box = share.envelopes[s.userId];
    if (!box) continue; // not addressed to this account
    let names: Record<string, unknown>;
    let at = 0;
    try {
      const opened = JSON.parse(
        new TextDecoder().decode(crypto.openSealed(s.enc, crypto.fromB64u(box))),
      ) as { names?: Record<string, unknown>; at?: number };
      names = opened.names ?? {};
      at = typeof opened.at === "number" ? opened.at : 0;
    } catch {
      continue; // undecryptable or malformed: fail open, skip
    }
    for (const [uid, raw] of Object.entries(names)) {
      if (typeof raw !== "string") continue;
      const self = share.actor === uid;
      if (self) selfDeclared.add(uid);
      const cur = best.get(uid);
      const wins =
        !cur ||
        (self && !cur.self) ||
        (self === cur.self && (at > cur.at || (at === cur.at && share.seq > cur.seq)));
      if (wins) best.set(uid, { name: raw.trim(), at, self, seq: share.seq });
    }
  }
  const namesOut: Record<string, string> = {};
  const seen = new Map<string, number>();
  for (const [uid, v] of best) {
    if (!v.name) continue; // empty = cleared
    namesOut[uid] = v.name;
    seen.set(v.name, (seen.get(v.name) ?? 0) + 1);
  }
  const collisions = new Set([...seen.entries()].filter(([, n]) => n > 1).map(([name]) => name));
  const derived = { names: namesOut, collisions, selfDeclared };
  directoryCache.set(s, { seq: s.state.chain.seq, derived });
  return derived;
}

/** userId -> display name, for everyone who published one. */
export function displayNames(s: Session): Record<string, string> {
  return deriveDirectory(s).names;
}

/** names shared by more than one member (UI shows the ID alongside). */
export function nameCollisions(s: Session): Set<string> {
  return deriveDirectory(s).collisions;
}

/** has this account ever self-published (or cleared) a name? */
export function hasPublishedName(s: Session): boolean {
  return deriveDirectory(s).selfDeclared.has(s.userId);
}

/** Publish (or clear, with "") this account's display name to every
 * current member. */
export async function publishDisplayName(s: Session, name: string): Promise<void> {
  const env = journal.buildDirectoryShare(
    s.state,
    { userId: s.userId, sign: s.sign },
    {
      names: { [s.userId]: name.trim() },
      recipients: [...s.state.members.keys()],
      at: Date.now(),
    },
  );
  await server.journalAppend(s.api, env);
  await sync(s);
}

/** Relay every name this session knows to a just-admitted member, sealed
 * to them alone — how newcomers learn names published before they could
 * read anything. Best-effort: admission never fails on a relay error. */
async function relayDirectory(s: Session, newUserId: string): Promise<void> {
  try {
    const names = displayNames(s);
    if (Object.keys(names).length === 0) return;
    const env = journal.buildDirectoryShare(
      s.state,
      { userId: s.userId, sign: s.sign },
      {
        names,
        recipients: [newUserId],
        at: Date.now(),
      },
    );
    await server.journalAppend(s.api, env);
    await sync(s);
  } catch {
    /* relay is a courtesy; the newcomer still works name-less */
  }
}

// ---- session persistence --------------
//
// Split custody: the device keeps a locked box (identity secrets under a
// random K_persist), the server keeps only K_persist bound to the bearer
// token. Neither half is a session alone; deleting the server's key is
// remote revocation. This module stays storage-free — the UI owns
// localStorage and passes the record in and out.

const PERSIST_AAD = (orgId: string, userId: string) =>
  ({ v: 1, org: orgId, user: userId, use: "sesspersist" }) as const;

/** What the UI writes to localStorage: a bearer token and ciphertext.
 * No unwrapped key material — the memory-only rule holds. */
export interface PersistedSession {
  token: string;
  userId: string;
  orgId: string;
  /** The API base this record was created against: the
   * token is bound to that origin and must never be sent anywhere else —
   * e.g. to a host injected through a crafted `?server=` link. */
  server: string;
  blob: string; // identity secrets sealed under the server-held K_persist
}

/** Park a random unlock key with the server and return the record the UI
 * should store. K_persist is forgotten the moment this returns. */
export async function persistSession(s: Session): Promise<PersistedSession> {
  const kPersist = crypto.newKey();
  const blob = crypto.aeadSeal(
    kPersist,
    crypto.canonicalize(sessionSecrets(s)),
    PERSIST_AAD(s.orgId, s.userId),
  );
  await server.sessionUnlockPut(s.api, crypto.toB64u(kPersist));
  return {
    token: s.api.token!,
    userId: s.userId,
    orgId: s.orgId,
    server: s.api.base,
    blob: crypto.toB64u(blob),
  };
}

/** Rebuild a live session from a stored record: fetch K_persist with the
 * bearer token, decrypt the blob IN MEMORY, resync. Throws when the
 * server refuses (revoked, expired, restarted) or the blob fails to
 * open — every failure lands the caller on the relock screen. */
export async function resumeSession(api: Api, rec: PersistedSession): Promise<Session> {
  // the record is origin-bound. Refuse BEFORE any request — the
  // bearer token must never travel to a server the record wasn't created
  // against. A legacy record with no `server` field fails this check too.
  if (rec.server !== api.base) {
    throw new Error("persisted session is bound to a different server");
  }
  const authed = { ...api, token: rec.token };
  const { key } = await server.sessionUnlockGet(authed);
  const secrets = JSON.parse(
    new TextDecoder().decode(
      crypto.aeadOpen(
        crypto.fromB64u(key),
        crypto.fromB64u(rec.blob),
        PERSIST_AAD(rec.orgId, rec.userId),
      ),
    ),
  ) as Record<string, string>;
  const encSk = crypto.fromB64u(secrets["enc_sk"]!);
  const signSk = crypto.fromB64u(secrets["sign_sk"]!);
  const session: Session = {
    api: authed,
    userId: rec.userId,
    orgId: rec.orgId,
    enc: { privateKey: encSk, publicKey: crypto.boxPkFromSk(encSk) },
    sign: { privateKey: signSk, publicKey: signSk.subarray(32) },
    state: journal.emptyState(),
  };
  if (secrets["gov_sk"]) {
    const gov = crypto.fromB64u(secrets["gov_sk"]);
    session.governance = { privateKey: gov, publicKey: gov.subarray(32) };
  }
  await sync(session);
  return session;
}

/** "Log out other devices": the server drops every OTHER session of this
 * user — bearer tokens and persistence keys — so a stolen or forgotten
 * device can neither sync nor resume. Returns how many were dropped. */
export async function logOutOtherDevices(s: Session): Promise<number> {
  const { dropped } = await server.sessionUnlockDeleteOthers(s.api);
  return dropped;
}

/** Kill this session server-side (logout, idle lock, or a revocation from
 * any device holding the token): the bearer token AND the unlock key die
 * together . After this, the stored blob can never be opened again
 * and the token can neither sync nor append. */
export async function dropPersistedSession(api: Api): Promise<void> {
  try {
    await server.sessionDelete(api);
  } catch {
    /* offline logout: the TTL backstops expire both server-side */
  }
}
