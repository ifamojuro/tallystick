// In-memory storage for the dumb journal server.
// Persists exactly the server-side column: OPAQUE registration
// records, KDF salts/params, wrapped identity-key blobs, and the journal
// (ciphertext + envelopes + public keys). Nothing here can decrypt anything.

import { journal } from "@tallystick/shared";

export interface StoredUser {
  registrationRecord: string;
  salt: string; // b64u KDF salt — public, needed by the client before login
  kdf: unknown; // KDF params as registered; opaque to the server
  wrappedIdentityKeys: string; // ciphertext blob under the user's K_wrap
}

/** Pre-admission mailbox entry: a joining client's public keys + invite
 * binding tag, waiting for approver signatures. Public-key material only —
 * this is already in the threat model CAN-see table. */
export interface JoinRequest {
  user_id: string;
  enc_pk: string;
  sign_pk: string;
  invite_id: string;
  binding_tag: string;
}

export class MemoryStore {
  journal: journal.SignedEntry[] = [];
  users = new Map<string, StoredUser>();
  /** keyed by SHA-256(bearer token) — hashed so a stolen store
   * snapshot holds nothing replayable, with an absolute expiry so tokens
   * die on their own. Sync-only authority either way. */
  sessions = new Map<string, { userId: string; expiresAt: number }>();
  /** keyed by a random single-use login-attempt id — keying by
   * userId let anyone stomp a user's in-progress login. */
  pendingLogins = new Map<string, { userId: string; state: string; expiresAt: number }>();
  joinRequests: JoinRequest[] = [];
  headPackage: string | null = null; // ciphertext duplicate only
  /** userId -> identity blob re-wrapped under BLAKE2b(printed personal
   * recovery secret). Ciphertext only; the
   * printed secret is the gate, exactly like headPackage. */
  recoveryBlobs = new Map<string, string>();
  /** userId -> outstanding account-recovery challenges (nonce -> slot).
   * MULTIPLE capped, TTL'd slots per user, each nonce consumed
   * one-shot at register/finish. A slot whose start-phase proof verified
   * is marked `proved` and can no longer be evicted by unauthenticated
   * challenge creation — only its TTL or consumption removes it. */
  recoveryChallenges = new Map<string, Map<string, { expiresAt: number; proved?: boolean }>>();
  /** SHA-256(bearer token) -> session-persistence unlock key
   *: ONE random client-generated key per
   * session, attached to the existing token record. The server never sees
   * the blob this unlocks — deleting the key is the remote-revocation
   * handle. */
  sessionUnlockKeys = new Map<string, { key: string; expiresAt: number }>();
  private listeners = new Set<(seq: number) => void>();

  /** The server's ONLY journal job: assign the next seq and
   * prev_hash, store, notify. No validation — clients verify everything;
   * a stale/hostile entry halting clients is the accepted tension. */
  append(envelope: journal.Envelope): journal.SignedEntry {
    const prev = this.journal[this.journal.length - 1];
    const entry: journal.SignedEntry = {
      seq: this.journal.length + 1,
      prev_hash: prev ? journal.entryHash(prev) : journal.ZERO_HASH,
      envelope,
    };
    this.journal.push(entry);
    for (const l of this.listeners) l(entry.seq);
    return entry;
  }

  /** Incremental sync: everything after the client's cursor. */
  since(cursor: number): journal.SignedEntry[] {
    return this.journal.slice(cursor);
  }

  onAppend(listener: (seq: number) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
