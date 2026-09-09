# Tallystick

**End-to-end encrypted case management for small advocacy organizations** — immigration legal aid, domestic-violence services, and other groups whose case files could endanger people if exposed.

> **Status: research prototype · not audited · synthetic data only.**
> Tallystick is not ready for real constituent data. This is a prototype: it has not been independently audited.

## Why "Tallystick"

A medieval tally stick recorded a debt by notching a piece of wood, then splitting it lengthwise. Each party kept a half. Neither half could be altered without the notches failing to match, and the record could be proved only by bringing the halves together. Tallystick borrows the whole idea: an append-only record that everyone can verify, secrets split between custodians, and recovery that requires matching the halves.

## Three ideas carry the design

1. **One append-only journal is the entire database.** There are no user, permission, or case tables. Every change — admission, promotion, case creation, note edit, revocation, succession — is a signed, hash-chained event. Every client replays the journal from the start and derives the organization's state itself. The server stores and orders entries; it never decides what is true. Because every fact about the organization arrives as a signed event, membership, roles, and access are verifiable by any member rather than asserted by the server, every change is attributable to whoever had the authority to make it, and any device — new, stale, or recovered — reaches the identical state by running the same verifier over the same log.

2. **Access is key possession, not a permission row.** Every case has its own random encryption key. Sharing a case seals that key to a colleague's public key and journals the sealed copy. Revoking rotates the case to a fresh key sealed to everyone *except* the removed member. Nothing checks a permission — either your keys open the box or they don't.

3. **Everything the server holds is ciphertext or deliberately public.** Case content is encrypted in the browser before it leaves. The server stores content only as ciphertext it cannot read, so an operator cannot produce case content in cleartext — and what it *can* produce (opaque identifiers, event types, timing, sizes) is enumerated in the [threat model](docs/threat_model.md)'s **CAN-see table**, which is kept in sync with the implementation as a standing contract.

Encryption is standard and boring by intent: libsodium (XChaCha20-Poly1305, X25519 sealed boxes, Ed25519, Argon2id) and OPAQUE for password login, composed into a signed log. No novel primitives.

## What it does today

- Bootstrap an organization with a printed **Emergency Bundle**: split case-recovery shares, a governance backup, and a personal account-recovery code.
- Invite and admit members (solo head at first; a two-admin safeguard arms automatically once two admins exist), promote to admin, hand off leadership with proof-of-possession succession.
- Create cases with a bio, tasks, notes, and a contact log — all encrypted, collaboratively edited (CRDT), with a per-note audit trail.
- Share and revoke case access per person; recover a lost account or an orphaned case through paper ceremonies; stay signed in across refreshes without keys touching disk in the clear.
- Search locally over everything you can decrypt. The index never leaves your browser.

## Quickstart

```bash
npm install
cd server && npm start          # http://127.0.0.1:8787 — loopback only by default
cd client && npm run dev        # or: npm run build && npx vite preview --port 4173
```

Open the client and create an organization. If the client and server run on different ports, pass the API base explicitly: `http://localhost:4173/?server=http://localhost:8787`.

The server is **in-memory** — restarting it erases everything, which is the intended behavior for a synthetic-data prototype. It refuses to bind a non-loopback address: plain HTTP is test-only. For a trusted-network experiment set `TALLYSTICK_HOST=<addr> TALLYSTICK_REMOTE_OK=1`; the server then prints a one-time setup code that the founding registration must present.

### Tests

```bash
npm test --workspaces                 # unit + integration (shared, server, client)
cd client && npm run e2e              # needs a FRESH server on :8787 and vite preview on :4173
```

The five browser suites (`e2e`, `e2e:full`, `e2e:collab`, `e2e:recovery`, `e2e:casework`) fetch the matching Chromium build on first run, and each bootstraps its own organization — so restart the server between suites.

## Documentation

- [`docs/threat_model.md`](docs/threat_model.md) — what the server can and cannot see, who the adversaries are, and what the design does not claim. Read this before anything else.

## Repository layout

```
client/   browser app — TypeScript, no framework, all crypto client-side
server/   the "dumb journal server" — node:http, in-memory, decrypts nothing
shared/   the crypto wrapper and the journal state machine every client runs
```

## License

AGPL-3.0. Tallystick is meant to be run *for* vulnerable organizations, sometimes *by* them; the network-copyleft license guarantees that any hosted version — modified or not — must publish its source, so the people depending on it can audit exactly what is running.
