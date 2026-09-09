// The dumb journal server. Plain node:http, no
// framework. Its complete job: OPAQUE registration/login, append-with-seq,
// incremental journal sync, an SSE "new entries exist" signal, and wrapped
// identity-blob storage. It validates nothing about journal content and can
// decrypt nothing — clients verify (server untrusted for
// content confidentiality/integrity; trusted only for ordering).
//
// Access gates — ALL availability-tier: a
// server that skips them discloses metadata to outsiders but gains no
// authority, so the trust model is unchanged. Clients still verify
// everything.
//   - Journal access (read, append, stream) requires the session's user to
//     be an ADMITTED member, derived from public journal state via the
//     shared state machine. Exception: the genesis append on an empty
//     journal (no roster exists yet). Admin surfaces are role-gated beyond
//     admission: join-request listing needs admin/head, head-package
//     upload needs head.
//   - Registration and join requests require an outstanding journaled
//     invite_id (existence + unused only — expiry stays signer-clock at
//     use; the server never sees the code).
//   - Re-registering an existing userId is rejected: silently overwriting
//     the OPAQUE record was a lockout vector, and under roster gating it
//     would have been an identity-claim bypass.
//   - Fixed-window rate limits back-stop registration, join requests, and
//     appends (abuse control, not precision).
//
// This file imports @serenity-kit/opaque directly: it IS the server half of
// the PAKE. The "only the crypto module imports crypto libraries" boundary
// is a client-side rule.

import { createServer as httpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import * as opaque from "@serenity-kit/opaque";
import { crypto, journal } from "@tallystick/shared";
import { MemoryStore } from "./store.ts";

const MAX_BODY = 10 * 1024 * 1024;
/** Absolute lifetime of a session-persistence unlock key. */
const SESSION_UNLOCK_TTL_MS = 12 * 60 * 60 * 1000;
/** Absolute lifetime of a bearer token — matched to the unlock-key
 * TTL so a resumed session and its token expire together. */
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
/** A pending OPAQUE login handshake must finish within this window . */
const LOGIN_TTL_MS = 2 * 60 * 1000;
/** An account-recovery challenge must be used within this window —
 * the human is mid-flow at a screen; minutes, not hours. */
const RECOVERY_CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** Outstanding recovery challenges per user: enough for retries and
 * a concurrent rehearsal, small enough to bound memory. Oldest evicted. */
const RECOVERY_CHALLENGE_CAP = 5;

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "access-control-allow-origin": "*", // prototype; tighten at pilot
    "access-control-allow-headers": "authorization, content-type",
  });
  res.end(json);
}

export interface TallystickServer {
  store: MemoryStore;
  listen(port?: number): Promise<number>;
  /** host actually bound after listen() (test surface) */
  boundAddress(): string | null;
  /** force an immediate expired-record sweep (test surface) */
  sweep(): void;
  close(): Promise<void>;
}

/** resolve bind host + bootstrap-race posture from the environment.
 * Pure and exported so the refusal policy is unit-testable.
 * - default: loopback, no setup code — dev/e2e keep zero-friction bootstrap;
 * - TALLYSTICK_HOST=<non-loopback> alone: REFUSE to start (plain HTTP is
 * test-only; production needs TLS termination in front);
 * - TALLYSTICK_HOST=<non-loopback> + TALLYSTICK_REMOTE_OK=1: bind it, and
 * mint a one-time high-entropy setup code that the first (bootstrap-window)
 * registration must present — closes the fresh-server takeover race. */
export interface ListenPlan {
  host: string;
  setupCode?: string;
  refusal?: string;
}
export function planListenFromEnv(env: Record<string, string | undefined>): ListenPlan {
  const host = env["TALLYSTICK_HOST"] ?? "127.0.0.1";
  const loopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
  if (loopback) return { host };
  if (env["TALLYSTICK_REMOTE_OK"] !== "1") {
    return {
      host,
      refusal:
        `refusing to bind ${host}: this server speaks PLAIN HTTP and is test-only. ` +
        `Bearer tokens and recovery proofs would cross the network unencrypted. ` +
        `For a trusted network experiment set TALLYSTICK_REMOTE_OK=1 (a one-time ` +
        `setup code will gate the first account); production needs TLS termination in front.`,
    };
  }
  return { host, setupCode: randomBytes(32).toString("base64url") };
}

/** Fixed-window abuse backstops. Defaults are deliberately
 * generous — these stop scripted abuse, they do not meter real use. */
const DEFAULT_LIMITS = {
  windowMs: 10 * 60 * 1000,
  registerPerIp: 60,
  joinRequestPerIp: 60,
  appendPerUser: 600,
  loginPerIp: 60, // backstop against login-state churn
};

export interface TallystickServerOptions {
  limits?: Partial<typeof DEFAULT_LIMITS>;
  /** host to bind; defaults to loopback so a dev server is never
   * reachable from the network by accident. */
  host?: string;
  /** when set (remote binds only — see planListenFromEnv), the
   * bootstrap-window registration on an EMPTY journal must present this
   * one-time code, closing the first-account race. Never set for loopback
   * dev servers, so local/e2e bootstrap friction is unchanged. */
  setupCode?: string;
}

export function createTallystickServer(options: TallystickServerOptions = {}): TallystickServer {
  const store = new MemoryStore();
  const serverSetup = opaque.server.createSetup();

  const bearer = (req: IncomingMessage): string | null =>
    /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1] ?? null;
  const tokenHash = (t: string): string => createHash("sha256").update(t).digest("base64url");
  const authedUser = (req: IncomingMessage): string | null => {
    const token = bearer(req);
    if (!token) return null;
    const h = tokenHash(token);
    const rec = store.sessions.get(h);
    if (!rec) return null;
    if (Date.now() > rec.expiresAt) {
      // lazy expiry: the token and its unlock key die together
      store.sessions.delete(h);
      store.sessionUnlockKeys.delete(h);
      return null;
    }
    return rec.userId;
  };

  // ---- rate limiting (availability-tier backstop) ------------------------
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const buckets = new Map<string, { count: number; windowStart: number }>();
  const overLimit = (key: string, max: number): boolean => {
    const now = Date.now();
    const b = buckets.get(key);
    if (!b || now - b.windowStart >= limits.windowMs) {
      buckets.set(key, { count: 1, windowStart: now });
      return false;
    }
    b.count += 1;
    return b.count > max;
  };
  const ip = (req: IncomingMessage): string => req.socket.remoteAddress ?? "unknown";

  // ---- roster tracking ----------------------------------
  // The server folds appended entries through the SAME public state machine
  // clients run, purely to learn the admitted-member and outstanding-invite
  // sets — public journal state, already in the threat model CAN-see
  // table (opaque IDs and roles; no new rows). It holds no keys and gains
  // no authority: clients never rely on these gates. Mirrors client
  // fail-stop — an invalid entry freezes the roster at the last valid
  // state (availability-only consequence; clients halt at that seq anyway).
  let roster = journal.emptyState();
  let rosterHalted = false;
  const foldRoster = (entry: journal.SignedEntry): void => {
    if (rosterHalted) return;
    try {
      roster = journal.applyEntry(roster, entry);
    } catch {
      rosterHalted = true;
    }
  };
  const isAdmitted = (userId: string): boolean => roster.members.has(userId);

  /** Journaled and not yet consumed. Expiry is deliberately NOT checked:
   * it is signer-clock-at-use and the admission builders
   * refuse expired invites — this gate only keeps strangers out. */
  const inviteOutstanding = (inviteId: unknown): boolean =>
    typeof inviteId === "string" &&
    roster.invites.has(inviteId) &&
    !roster.usedInviteIds.has(inviteId);

  /** Account-recovery proof: a signature by the roster-pinned identity signing key over an
   * outstanding challenge nonce AND a `commit` hash of the exact
   * replacement material being authorized — a captured proof cannot be
   * re-bound to attacker-chosen credentials. Nonces are TTL'd; `consume`
   * (the finish phase) spends the nonce one-shot BEFORE verification, the
   * same posture as login attempts. Availability-tier like every gate
   * here — the printed recovery secret (which decrypted the key that
   * signs this) is the real authority. */
  const validRecoveryProof = (
    userId: string,
    nonce: unknown,
    sig: unknown,
    commit: string,
    consume: boolean,
  ): boolean => {
    if (typeof nonce !== "string" || typeof sig !== "string") return false;
    const slots = store.recoveryChallenges.get(userId);
    const rec = slots?.get(nonce);
    if (!slots || !rec) return false;
    if (consume) slots.delete(nonce); // one-shot: spent even on a bad proof
    if (slots.size === 0) store.recoveryChallenges.delete(userId);
    if (Date.now() > rec.expiresAt) {
      slots.delete(nonce);
      return false;
    }
    const signPk = roster.members.get(userId)?.signPk;
    if (!signPk) return false;
    try {
      crypto.verifyEvent(crypto.fromB64u(signPk), {
        use: "account-recovery",
        org: roster.orgId,
        user: userId,
        nonce,
        commit,
        sig,
      });
      // a start-phase proof RESERVES this slot: raw
      // challenge creation can no longer evict a recovery whose printed
      // secret has already been proven — only TTL or consumption ends it
      if (!consume) rec.proved = true;
      return true;
    } catch {
      return false;
    }
  };

  /** flips true at the founder registration; the setup code
   * admits exactly one account, matching its stated one-time property. */
  let setupCodeUsed = false;

  /** expired sessions, unlock keys, pending
   * logins, and recovery challenges are reaped on a time-gated sweep at
   * the top of every request — not only when their own identifier is
   * presented again. An abandoned session's K_persist now dies within
   * SWEEP_INTERVAL_MS of its promised TTL. */
  const SWEEP_INTERVAL_MS = 60 * 1000;
  let lastSweep = 0;
  const sweepExpired = (force = false): void => {
    const now = Date.now();
    if (!force && now - lastSweep < SWEEP_INTERVAL_MS) return;
    lastSweep = now;
    for (const [h, rec] of store.sessions) {
      if (now > rec.expiresAt) {
        store.sessions.delete(h);
        store.sessionUnlockKeys.delete(h);
      }
    }
    for (const [h, rec] of store.sessionUnlockKeys) {
      if (now > rec.expiresAt) store.sessionUnlockKeys.delete(h);
    }
    for (const [id, rec] of store.pendingLogins) {
      if (now > rec.expiresAt) store.pendingLogins.delete(id);
    }
    for (const [uid, slots] of store.recoveryChallenges) {
      for (const [n, rec] of slots) if (now > rec.expiresAt) slots.delete(n);
      if (slots.size === 0) store.recoveryChallenges.delete(uid);
    }
  };

  /** Registration gate: duplicates rejected (silent OPAQUE-record
   * overwrite was a lockout vector and, under roster gating, an
   * identity-claim bypass) with ONE exception — account recovery, proven
   * by the identity signing key; invite required once an org exists. */
  const registrationRefusal = (
    userId: string,
    inviteId: unknown,
    recovery: { nonce?: unknown; sig?: unknown },
    setupCode: unknown,
    /** hash of the replacement material this phase presents; the
     * recovery proof must have signed exactly this value */
    recoveryCommit: string,
    /** true only at register/finish — spends the nonce one-shot */
    consumeNonce: boolean,
  ): { status: number; error: string } | null => {
    if (store.users.has(userId)) {
      return validRecoveryProof(userId, recovery.nonce, recovery.sig, recoveryCommit, consumeNonce)
        ? null
        : { status: 409, error: "userId already registered" };
    }
    // on a fresh, remotely reachable server the bootstrap window is
    // gated by the one-time startup setup code — otherwise whoever reaches
    // the server first becomes the permanent head. Loopback servers never
    // set options.setupCode, so dev/e2e bootstrap is unchanged.
    if (store.journal.length === 0 && options.setupCode) {
      if (setupCodeUsed) {
        return {
          status: 403,
          error: "setup code already used; restart the server to mint a new one",
        };
      }
      if (typeof setupCode !== "string" || setupCode !== options.setupCode) {
        return { status: 403, error: "fresh server: registration requires the startup setup code" };
      }
    }
    if (store.journal.length > 0 && !inviteOutstanding(inviteId)) {
      return { status: 403, error: "registration requires an outstanding invite" };
    }
    return null;
  };

  const server = httpServer(async (req, res) => {
    sweepExpired();
    const url = new URL(req.url ?? "/", "http://localhost");
    const route = `${req.method} ${url.pathname}`;
    try {
      // ---- OPAQUE registration (unauthenticated: admission authority is
      // journal-level — two admin signatures — not a server login gate) ----
      if (route === "POST /auth/register/start") {
        if (overLimit(`reg:${ip(req)}`, limits.registerPerIp)) {
          return send(res, 429, { error: "too many registrations; try again later" });
        }
        const b = await readJson(req);
        // the start-phase proof commits to the exact OPAQUE request
        const startCommit = crypto.toB64u(
          crypto.hash(crypto.canonicalize({ registrationRequest: String(b.registrationRequest) })),
        );
        const refusal = registrationRefusal(
          String(b.userId),
          b.inviteId,
          { nonce: b.recoveryNonce, sig: b.recoverySig },
          b.setupCode,
          startCommit,
          false,
        );
        if (refusal) return send(res, refusal.status, { error: refusal.error });
        const { registrationResponse } = opaque.server.createRegistrationResponse({
          serverSetup,
          userIdentifier: String(b.userId),
          registrationRequest: String(b.registrationRequest),
        });
        return send(res, 200, { registrationResponse });
      }
      if (route === "POST /auth/register/finish") {
        const b = await readJson(req);
        const userId = String(b.userId);
        const isRecovery = store.users.has(userId);
        // the finish-phase proof commits to the exact stored
        // replacement credentials, and its nonce is consumed one-shot —
        // a captured proof authorizes only this record/salt/kdf/blob
        const finishCommit = crypto.toB64u(
          crypto.hash(
            crypto.canonicalize({
              registrationRecord: String(b.registrationRecord),
              salt: String(b.salt),
              kdf: (b.kdf ?? null) as crypto.JsonValue,
              wrappedIdentityKeys: String(b.wrappedIdentityKeys),
            }),
          ),
        );
        const refusal = registrationRefusal(
          userId,
          b.inviteId,
          { nonce: b.recoveryNonce, sig: b.recoverySig },
          b.setupCode,
          finishCommit,
          true,
        );
        if (refusal) return send(res, refusal.status, { error: refusal.error });
        store.users.set(userId, {
          registrationRecord: String(b.registrationRecord),
          salt: String(b.salt),
          kdf: b.kdf,
          wrappedIdentityKeys: String(b.wrappedIdentityKeys),
        });
        if (isRecovery) {
          // recovery is a credential-replacement boundary —
          // every pre-recovery session, unlock key, and pending login of
          // this user dies before the recovered client logs in fresh
          for (const [h, rec] of [...store.sessions.entries()]) {
            if (rec.userId === userId) {
              store.sessions.delete(h);
              store.sessionUnlockKeys.delete(h);
            }
          }
          for (const [id, rec] of [...store.pendingLogins.entries()]) {
            if (rec.userId === userId) store.pendingLogins.delete(id);
          }
        }
        // the setup code is genuinely one-time — it admits
        // exactly the founder registration, then dies
        if (store.journal.length === 0 && options.setupCode) setupCodeUsed = true;
        return send(res, 200, { ok: true });
      }

      // ---- login: params (public salt) → start → finish → bearer token ----
      if (route === "GET /auth/params") {
        const user = store.users.get(String(url.searchParams.get("user")));
        if (!user) return send(res, 404, { error: "unknown user" });
        return send(res, 200, { salt: user.salt, kdf: user.kdf });
      }
      if (route === "POST /auth/login/start") {
        if (overLimit(`login:${ip(req)}`, limits.loginPerIp)) {
          return send(res, 429, { error: "login rate limit; try again later" });
        }
        const b = await readJson(req);
        const userId = String(b.userId);
        const user = store.users.get(userId);
        if (!user) return send(res, 404, { error: "unknown user" });
        const { serverLoginState, loginResponse } = opaque.server.startLogin({
          serverSetup,
          userIdentifier: userId,
          registrationRecord: user.registrationRecord,
          startLoginRequest: String(b.startLoginRequest),
        });
        // state keyed by a random single-use attempt id, not userId —
        // strangers can no longer stomp a user's in-progress login, and two
        // legitimate concurrent logins no longer break each other
        const loginId = randomBytes(16).toString("base64url");
        store.pendingLogins.set(loginId, {
          userId,
          state: serverLoginState,
          expiresAt: Date.now() + LOGIN_TTL_MS,
        });
        return send(res, 200, { loginResponse, loginId });
      }
      if (route === "POST /auth/login/finish") {
        const b = await readJson(req);
        const loginId = String(b.loginId);
        const pending = store.pendingLogins.get(loginId);
        store.pendingLogins.delete(loginId);
        if (!pending || Date.now() > pending.expiresAt) {
          return send(res, 400, { error: "no login in progress" });
        }
        try {
          opaque.server.finishLogin({
            serverLoginState: pending.state,
            finishLoginRequest: String(b.finishLoginRequest),
          });
        } catch {
          return send(res, 401, { error: "login failed" });
        }
        const token = randomBytes(32).toString("base64url");
        store.sessions.set(tokenHash(token), {
          userId: pending.userId,
          expiresAt: Date.now() + SESSION_TTL_MS,
        });
        // the token authorizes SYNC ONLY; it gates no decryption
        return send(res, 200, { sessionToken: token });
      }

      // ---- identity blob (authenticated) ----
      if (route === "GET /identity") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        const user = store.users.get(userId);
        return send(res, 200, { wrappedIdentityKeys: user?.wrappedIdentityKeys ?? null });
      }

      // ---- journal (authenticated + roster-gated.10: the session
      // token alone is not enough — the session's user must be an admitted
      // member of the org, except for the genesis append that creates it) --
      if (route === "POST /journal") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        const b = await readJson(req);
        const env = b.envelope as journal.Envelope;
        if (store.journal.length === 0) {
          // bootstrap window: only the founding genesis, by its own author
          if (env?.type !== "org_genesis" || env.actor !== userId) {
            return send(res, 403, {
              error: "first entry must be org_genesis by this session's user",
            });
          }
        } else if (!isAdmitted(userId)) {
          return send(res, 403, { error: "not an admitted member" });
        }
        if (overLimit(`append:${userId}`, limits.appendPerUser)) {
          return send(res, 429, { error: "append rate limit; try again later" });
        }
        const entry = store.append(env);
        foldRoster(entry);
        return send(res, 200, { seq: entry.seq });
      }
      if (route === "GET /journal") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        if (!isAdmitted(userId)) return send(res, 403, { error: "not an admitted member" });
        const since = Number(url.searchParams.get("since") ?? 0);
        return send(res, 200, { entries: store.since(since) });
      }
      if (route === "GET /journal/stream") {
        const streamUser = authedUser(req);
        if (!streamUser) return send(res, 401, { error: "unauthorized" });
        if (!isAdmitted(streamUser)) return send(res, 403, { error: "not an admitted member" });
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          "access-control-allow-origin": "*",
        });
        res.write(`data: ${store.journal.length}\n\n`);
        const unsubscribe = store.onAppend((seq) => res.write(`data: ${seq}\n\n`));
        req.on("close", unsubscribe);
        return;
      }

      // ---- org discovery (public: org_id is an opaque routing handle) ----
      if (route === "GET /org") {
        const genesis = store.journal[0];
        return send(res, 200, {
          orgId: genesis ? genesis.envelope.org_id : null,
          // tells the bootstrap screen to ask for the startup setup
          // code — true only on a fresh server that was started with one
          setupRequired: !genesis && !!options.setupCode,
        });
      }

      // ---- pre-admission join mailbox (POST is unauthenticated: the
      // joiner has no journal identity yet; admission authority is the
      // approvers' signatures, not this channel. The mailbox is
      // invite-gated — a post must reference an outstanding journaled
      // invite, which the server can check without ever seeing the code) --
      if (route === "POST /join-request") {
        if (overLimit(`join:${ip(req)}`, limits.joinRequestPerIp)) {
          return send(res, 429, { error: "too many join requests; try again later" });
        }
        const b = await readJson(req);
        if (!inviteOutstanding(b.invite_id)) {
          return send(res, 403, { error: "join request requires an outstanding invite" });
        }
        store.joinRequests.push({
          user_id: String(b.user_id),
          enc_pk: String(b.enc_pk),
          sign_pk: String(b.sign_pk),
          invite_id: String(b.invite_id),
          binding_tag: String(b.binding_tag),
        });
        return send(res, 200, { ok: true });
      }
      if (route === "GET /join-requests") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        // an admin workflow — pre-admission identities and invite
        // relationships are not ordinary-member data
        const role = roster.members.get(userId)?.role;
        if (role !== "admin" && role !== "head") {
          return send(res, 403, { error: "admins only" });
        }
        return send(res, 200, { requests: store.joinRequests });
      }

      // ---- personal recovery packages:
      // ciphertext only, same posture as the head package — GET and the
      // challenge are unauthenticated BY DESIGN (the recovery scenario is
      // a member who cannot log in; the printed secret is the real gate),
      // rate-limited as an abuse backstop ----
      if (route === "POST /identity-recovery") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        const b = await readJson(req);
        store.recoveryBlobs.set(userId, String(b.ciphertext));
        return send(res, 200, { ok: true });
      }
      if (route === "GET /identity-recovery") {
        if (overLimit(`recover:${ip(req)}`, limits.registerPerIp)) {
          return send(res, 429, { error: "too many recovery attempts; try again later" });
        }
        const user = String(url.searchParams.get("user"));
        return send(res, 200, { ciphertext: store.recoveryBlobs.get(user) ?? null });
      }
      if (route === "POST /recover/challenge") {
        if (overLimit(`recover:${ip(req)}`, limits.registerPerIp)) {
          return send(res, 429, { error: "too many recovery attempts; try again later" });
        }
        const b = await readJson(req);
        const userId = String(b.userId);
        const nonce = randomBytes(32).toString("base64url");
        // multi-slot — a new challenge no longer overwrites a
        // legitimate recovery already in flight; expired slots are reaped
        // here and the oldest evicted at the cap
        let slots = store.recoveryChallenges.get(userId);
        if (!slots) {
          slots = new Map();
          store.recoveryChallenges.set(userId, slots);
        }
        for (const [n, rec] of slots) if (Date.now() > rec.expiresAt) slots.delete(n);
        // eviction may only claim UNPROVED slots — five cheap requests can
        // no longer flush a recovery whose start proof already verified
        while (slots.size >= RECOVERY_CHALLENGE_CAP) {
          const evictable = [...slots.entries()].find(([, rec]) => !rec.proved);
          if (!evictable) {
            return send(res, 429, { error: "recovery challenges exhausted; try again later" });
          }
          slots.delete(evictable[0]);
        }
        slots.set(nonce, { expiresAt: Date.now() + RECOVERY_CHALLENGE_TTL_MS });
        return send(res, 200, { nonce });
      }

      // ---- session persistence: the
      // client parks its random unlock key here, bound to the bearer
      // token. Availability-tier: the server holds a key to a blob it
      // never sees. Absolute TTL backstops clients that never lock;
      // DELETE is logout / idle lock / remote revocation. ----
      if (route === "POST /session-unlock") {
        const token = bearer(req);
        if (!token || !authedUser(req)) return send(res, 401, { error: "unauthorized" });
        const b = await readJson(req);
        if (typeof b.key !== "string" || b.key.length === 0 || b.key.length > 128) {
          return send(res, 400, { error: "malformed key" });
        }
        store.sessionUnlockKeys.set(tokenHash(token), {
          key: b.key,
          expiresAt: Date.now() + SESSION_UNLOCK_TTL_MS,
        });
        return send(res, 200, { ok: true });
      }
      if (route === "GET /session-unlock") {
        const token = bearer(req);
        const rec = token ? store.sessionUnlockKeys.get(tokenHash(token)) : undefined;
        if (!token || !authedUser(req) || !rec) {
          return send(res, 404, { error: "no unlock key for this session" });
        }
        if (Date.now() > rec.expiresAt) {
          store.sessionUnlockKeys.delete(tokenHash(token));
          return send(res, 404, { error: "unlock key expired" });
        }
        return send(res, 200, { key: rec.key });
      }
      if (route === "DELETE /session-unlock-others") {
        // "log out other devices":
        // kill every OTHER session of this user — bearer tokens AND their
        // persistence unlock keys — so stolen or forgotten devices can
        // neither sync nor resume. The caller's own session survives.
        const token = bearer(req);
        const userId = authedUser(req);
        if (!token || !userId) return send(res, 401, { error: "unauthorized" });
        const mine = tokenHash(token);
        let dropped = 0;
        for (const [h, rec] of [...store.sessions.entries()]) {
          if (rec.userId === userId && h !== mine) {
            store.sessions.delete(h);
            store.sessionUnlockKeys.delete(h);
            dropped++;
          }
        }
        return send(res, 200, { dropped });
      }
      if (route === "DELETE /session") {
        // real logout — the bearer token and its unlock key die
        // together, atomically, so "Lock & log out" leaves nothing usable
        const token = bearer(req);
        if (!token) return send(res, 401, { error: "unauthorized" });
        const h = tokenHash(token);
        store.sessions.delete(h);
        store.sessionUnlockKeys.delete(h);
        return send(res, 200, { ok: true });
      }
      if (route === "DELETE /session-unlock") {
        const token = bearer(req);
        if (token) store.sessionUnlockKeys.delete(tokenHash(token));
        return send(res, 200, { ok: true });
      }

      // ---- identity blob replacement (succession: the successor re-wraps
      // their blob to include the new governance key) ----
      if (route === "POST /identity") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        const user = store.users.get(userId);
        if (!user) return send(res, 404, { error: "unknown user" });
        const b = await readJson(req);
        user.wrappedIdentityKeys = String(b.wrappedIdentityKeys);
        return send(res, 200, { ok: true });
      }

      // ---- head recovery package: ciphertext duplicate only. GET is
      // unauthenticated BY DESIGN — the recovery scenario is a head who
      // cannot log in; the printed secret is the real gate ----
      if (route === "POST /head-package") {
        const userId = authedUser(req);
        if (!userId) return send(res, 401, { error: "unauthorized" });
        // only the head may replace the server's copy — any member
        // could otherwise vandalize it into uselessness (it's authenticated
        // ciphertext, so forging a usable one was never possible)
        if (roster.members.get(userId)?.role !== "head") {
          return send(res, 403, { error: "head only" });
        }
        const b = await readJson(req);
        store.headPackage = String(b.ciphertext);
        return send(res, 200, { ok: true });
      }
      if (route === "GET /head-package") {
        return send(res, 200, { ciphertext: store.headPackage });
      }

      if (req.method === "OPTIONS") return send(res, 204, {});
      return send(res, 404, { error: "not found" });
    } catch (e) {
      return send(res, 400, { error: String(e) });
    }
  });

  return {
    store,
    sweep: () => sweepExpired(true),
    listen: (port = 0) => {
      // the refusal policy lives in the FACTORY, not only
      // the CLI — a direct caller cannot bind non-loopback plaintext HTTP
      // without the setup-code gate that closes the fresh-server race
      const host = options.host ?? "127.0.0.1";
      const loopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
      if (!loopback && !options.setupCode) {
        throw new Error(
          `refusing to bind ${host}: non-loopback plaintext HTTP requires a setupCode ` +
            `(use planListenFromEnv, which mints one under TALLYSTICK_REMOTE_OK=1)`,
        );
      }
      return new Promise((resolve) =>
        server.listen(port, host, () => {
          const addr = server.address();
          resolve(typeof addr === "object" && addr ? addr.port : port);
        }),
      );
    },
    boundAddress: () => {
      const addr = server.address();
      return typeof addr === "object" && addr ? addr.address : null;
    },
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
