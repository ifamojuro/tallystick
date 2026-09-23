# Tallystick — agent instructions

End-to-end encrypted case management for small advocacy orgs. Research prototype, synthetic data only. Read `docs/threat_model.md` before changing anything security-relevant.

## Layout
- `shared/` — crypto wrapper (libsodium, OPAQUE) and the journal state machine every client runs
- `server/` — the "dumb journal server": node:http, in-memory, decrypts nothing
- `client/` — browser app, TypeScript, no framework, all crypto client-side (`src/ui.ts` is the UI, `src/flows.ts` the protocol flows)

## Running
- Server: `cd server && npm start` → http://127.0.0.1:8787 (loopback only). It is in-memory: restarting erases every org.
- Client: `cd client && npm run dev` (Vite hot-reloads client changes), or `npm run build && npx vite preview --port 4173`.
- Keep the server and client running in the background during a session. After changing `server/` or `shared/`, restart the server yourself and say that state was reset. Don't ask me to restart it.

## Testing
- Unit and integration: `npm test --workspaces`. Typecheck: `npm run typecheck --workspaces`.
- Browser suites (`client/`): `npm run e2e`, `e2e:full`, `e2e:collab`, `e2e:recovery`, `e2e:casework`. Each needs a fresh server on :8787 and `vite preview` on :4173, so restart the server between suites.
- Run the e2e suites that cover a flow before calling a change to it done.

## Design rules
- **The journal is the source of truth.** New state defaults to a signed journal event, and secrets travel as sealed boxes to the owner's key. Side-state (localStorage, server-only tables) needs a written justification.
- **Safeguards switch on as an org grows.** Orgs start with one person. Multi-person controls must work solo, switch on automatically from journal state (never configuration), and stay on once armed. Show the current mode plainly in the UI.
- **The server stays dumb.** It stores and orders entries; it never decides what is true, never serves per-record reads and never searches plaintext.
- No novel cryptography. Compose the existing primitives in `shared/src/crypto/`.

## Threat model contract (`docs/threat_model.md`)
- §6 (what the server sees) must match `server/src/store.ts` and everything the server receives or logs. Update it in the same change as the code.
- Every new feature answers: *what does this add to the CAN-see table?*
- §10 lists decisions that must not be quietly reversed. Flag any change that touches one.
- §11 gaps are removed only when fixed with a test.
- Bump the version and date at the top of the threat model when its content changes.

## Public repo hygiene
This repository is public. Commits, comments and docs must not reference files or documents outside this repository.
