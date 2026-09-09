# Threat Model

**Status: research prototype. Not independently audited. Synthetic data only — never real constituent data.**

**Version 0.1 — 2026-09-08.** First public edition. This is the project's honesty document. It states exactly what Tallystick protects, against whom, and what it does not. Any pitch, README, or UI copy that claims more than this document does is a bug.

---

## 1. What this system is, and the claim it makes

Tallystick is case-management software for organizations whose case files could endanger people if exposed — immigration legal aid, domestic-violence services, and similar. Case content is encrypted in the caseworker's browser before it reaches any server, and the organization's structure (who is a member, who may open which case) is a signed, append-only journal that every client verifies for itself.

### The claim, stated precisely

> **The server stores case content only as ciphertext it cannot read, so its operator cannot produce case content in cleartext. What the operator *can* produce — the metadata enumerated in §6 — is listed there in full and kept in sync with the implementation.**

### Scope

This document covers the prototype as built: one organization per server; a head, promoted admins, and ordinary members; a web client; a local-first journal (every client holds the full ciphertext journal); encrypted case records (bio, tasks, notes, contact log); case-by-case access grants and revocation; local per-user search; printed recovery ceremonies for governance, cases, and accounts; and split-custody session persistence. Attachments, multi-org sharing, mobile clients, constituent-facing surfaces, and configurable recovery thresholds are not built and are marked *future* where they appear.

---

## 2. The untrusted server, by design

The phrase recurs throughout this document, so here is its exact meaning.

**Untrusted server, by design** means the server is architecturally unable — not merely forbidden by policy — to read case content or to define the organization's structure. It is trusted for exactly two things:

- **Availability.** It stores ciphertext and serves it back. It can refuse (denial of service), and no design here prevents that.
- **Ordering.** It assigns each journal entry its sequence number and links it to the previous entry's hash. Clients verify the chain they are shown; what they cannot yet verify is that *everyone was shown the same chain* (§11, gap 1).

Everything else — authorship, authorization, membership, roles, grants, revocations, successions — is verified by every client from signatures in the journal. The server folds the same public journal through the same verifier, purely to gate access to itself (which accounts are admitted, which may list join requests); those gates are **availability-tier**: a server that skips them discloses metadata to strangers but gains no authority, because clients never rely on them.

**The adversarial server.** When this document needs to name a server that *acts* rather than merely observes — one under compulsion or compromise that tries to inject a key, equivocate about history, serve a poisoned client, or withhold entries — it says **adversarial server**. Passive disclosure yields only what already exists; an adversarial server can target future grants and future page loads, which is why §8 treats it separately.

---

## 3. Actors

| Actor | Role in the system | Trust posture |
|---|---|---|
| **Constituent** | The person a case is about. Not a user; the system exists for their safety. | Trusts the organization, not us. No constituent-facing surface exists. |
| **Member (caseworker)** | Org staff. Holds an identity keypair and a keychain of case keys granted to them. | Trusted with the cases in their keychain. Their device is *not* trusted (§7.5). |
| **Org admin** | A member promoted by the head. Once two exist, admissions and org-authority re-keys need two admin signatures. | Trusted jointly, not singly. |
| **Head** | The governance root: holds the governance signing key pinned at genesis. Promotes and demotes admins, hands off leadership. | Single governance root by design. Cannot decrypt cases by virtue of the role. |
| **Recovery custodians** | Whoever physically holds each printed tally half. Typically admins, but custody is physical and role-independent. | Trusted separately; the two halves must never be co-located. |
| **Server operator** | Us (hosted) or the org (self-hosted). | **Untrusted for confidentiality and integrity of content and structure; trusted only for availability and ordering (§2).** |
| **Client-code publisher** | Whoever serves the JavaScript. Today, the same party as the server operator. | A distinct trust role: poisoned client code defeats every cryptographic control (§7.6). |
| **Printer / print path** | The OS spooler, printer, or print service that renders the Emergency Bundle. | Not trusted (§7.7). |
| **Outsider** | Anyone with the server's address and no invite. | Untrusted. May abuse public endpoints (§7.8). |

---

## 4. Assumptions

The security of the system rests on these. Where an assumption is known to be shaky, it says so.

**About people**
- The founding head acts in good faith during bootstrap. There is no defense against a hostile founder.
- Recovery custodians store their halves apart, as the printed instructions say. Software cannot verify paper; custody acknowledgments are self-attested claims.
- A member does not deliberately exfiltrate plaintext they are authorized to read. Encryption cannot prevent copying by an authorized reader (§9).

**About the organization**
- It runs the printed ceremonies on a printer it trusts, or hand-copies. A shared, office, or cloud print queue can retain a complete copy of every recovery secret (§7.7).
- It does not enter real constituent data before the pilot gates in §11 are met.

**About cryptography**
- libsodium's primitives (XChaCha20-Poly1305, X25519 sealed boxes, Ed25519, BLAKE2b, Argon2id) and the OPAQUE PAKE are sound as implemented in the pinned libraries. We compose established primitives and invent none — but the *composition* is a protocol and has not been externally reviewed.
- The browser's random number generator is sound.

**About the environment**
- The caseworker's browser, operating system, and hardware are not compromised. A compromised endpoint sees what the caseworker sees (§9).
- Any deployment reachable beyond the local machine terminates TLS in front of the server. The prototype server speaks plain HTTP, binds only to loopback by default, and refuses to bind elsewhere without an explicit test-only override.

**About the server**
- It is untrusted by design (§2). Where the prototype *does* still trust it — for a single consistent journal order — that is recorded as an open gap, not an assumption we intend to keep.

---

## 5. Assets

In priority order.

| # | Asset | Examples | Why it matters |
|---|---|---|---|
| A1 | **Case content** | Bio, notes, tasks, contact-log entries | Can directly endanger a constituent |
| A2 | **Constituent identity** | Names and identifiers inside records | Links a person to the existence of a case |
| A3 | **The link between A1 and A2** | "This note is about this person" | Often more dangerous than either alone |
| A4 | **Organizational structure** | Who is a member, who is an admin, who holds which case, activity timing | Reveals operations, volume, and whom to pressure |
| A5 | **Cryptographic secrets** | Identity keys, case keys, the governance key, the recovery key and its halves, account-recovery codes | Instrumental: their compromise converts to A1–A4 |
| A6 | **Journal integrity** | The one consistent history every client derives state from | Forged or forked history silently changes who can do what |

The prototype holds no billing records and no attachments; neither appears in §6 because neither exists. Both will be added to that table if built.

---

## 6. What the server sees

This section is a contract. It was rebuilt on 2026-09-08 from the server's actual storage — every persistent map in `server/src/store.ts` plus the server's in-memory transient state — and it must be kept in sync with the implementation. A discrepancy in either direction is a security bug. (The server is in-memory for the prototype; "stores" below means "holds while running and would hold durably once storage exists.")

### The server CANNOT see (ciphertext only, or never sent)

- Case content and record structure: every note, bio, task, contact-log entry, and their field values — all encrypted per record under keys wrapped by the case key.
- Constituent identity fields, which live only inside encrypted records.
- Members' display names, which travel only inside per-recipient sealed boxes.
- Which records a member reads or searches. Sync is whole-journal; the search index is built locally and never uploaded.
- Passphrases. Login uses OPAQUE, so the passphrase never leaves the client.
- Case keys and record keys, which appear only inside sealed envelopes addressed to members' public keys.
- Invite codes. The journal carries each code sealed to its issuer's own key; the joiner's binding tag proves knowledge of the code without revealing it.
- The printed secrets: both tally halves, the governance recovery secret, and every member's account-recovery code.

### The server CAN see (and could be compelled to produce)

| Visible | Why the server holds it | Sensitivity, and what is chosen vs. structural |
|---|---|---|
| **Opaque member identifiers, roles, and public keys** | Signed journal envelopes are plaintext so every client can verify them | Structure: head/admin/member roster, membership count, when each joined. Structural — verification requires it. |
| **The type of every journal event, as a stream** | Same | The org's full activity rhythm: admissions, promotions, invites, case creation, grants, revocations (the revoked member's ID is a plaintext field), note-update cadence, re-keys and their designated holders, successions and the new head, custody acknowledgments, directory fan-outs. Content of none of it; the shape of all of it. Hiding types without size padding is ineffective, so type-hiding and padding are one future work item. |
| **Stable random case tags and which member writes to each** | Clients need a routing handle to find a case's entries without trying every key | An opaque per-case activity graph. Cannot be mapped to a constituent from the protocol. Structural until a private-routing design exists. |
| **Case-key envelope recipients** | Envelopes are labeled with the recipient's opaque ID so verifiers can check grants | Who holds which opaque case. Chosen: unlabeled envelopes with trial decryption would hide it at a compute cost. |
| **Invite issuances**: opaque invite ID, issuer, expiry, and a sealed blob only the issuer can open | Invites are journal state | That an invite is outstanding signals imminent growth. The code itself is never visible. |
| **The join-request mailbox**: pre-admission user IDs, public keys, invite IDs, and binding tags, in plaintext | Admitters must read them before signing | Pre-admission identity and invite linkage. Chosen: these could be sealed to the org's admins with existing machinery. An honest server shows the list only to admins; a hostile one need not. |
| **Ciphertext lengths** | Storage and transport | Distinguishes kinds of writes; small structured updates make activity patterns legible. Padding is future work. |
| **Login material per account**: the OPAQUE registration record, the KDF salt and parameters, and **the identity-key blob encrypted under a passphrase-derived key** | Log in from any device | **Recorded open finding (§11, gap 2):** because the wrapping key derives from the passphrase with a public salt, a stolen copy of this material is an offline passphrase-guessing target. Argon2id makes each guess expensive; it does not make guessing impossible. The OPAQUE server secret, also held in memory, is what makes the login record itself guessable offline. |
| **Recovery material**: each member's identity blob re-wrapped under their printed code; the head package ciphertext; and outstanding recovery challenges | Recovery must work for someone who cannot log in, so these are fetched before authentication | Existence oracle: whether a given opaque ID has a recovery package. Challenge traffic reveals a recovery in progress. The printed secret is the real gate. |
| **Session records**: SHA-256 hashes of bearer tokens with expiry, per-session unlock keys (12-hour TTL, deletable), and pending login attempts | Sync authorization and split-custody "stay signed in" | Timing of logins, persistence, resume, and revocation. Tokens are hashed at rest, so a stolen store yields nothing replayable. **Recorded delta:** an adversary holding both a device's disk and the server's memory can reconstruct that session's keys within the TTL. |
| **Which member synced, and when** | Sync requests carry the account's token and its cursor | Coarse staff-activity rhythm — not what they read. Observed per request; not stored beyond the request. |
| **Connection metadata**: IP addresses and exact request timing | Connections exist; rate-limit buckets are keyed by IP | The prototype writes no logs. IPs live in in-memory rate-limit buckets whose counters reset every ten minutes but whose entries are never pruned, so an IP that connected once remains in memory until the server restarts. A prospective order could compel logging. |
| **Journal size and entry count** | Storage | Rough caseload volume and growth. Structural. |
| **Share-custody acknowledgments**: which opaque member claims each tally half | Custody must be findable when a recovery is needed | Coercion-targeting metadata — whom to pressure. Chosen: these are self-attested and could be sealed fan-outs with existing machinery. |
| **Directory fan-out shape**: who sealed a name-map to whom, and when | Display names are sealed per recipient | Clusters around admissions and renames. Names themselves are never visible. |
| **The remote-mode setup code** | The server mints it when deliberately started reachable, to gate the first registration | Known to the server by construction; one-time; not used on loopback. |

**Structurally not hideable, stated plainly:** that an organization exists on the server, its rough data volume, and its member count. Self-hosting removes the hosted vendor from the data path; the same operational metadata still exists at the org's own server.

**Chosen disclosures.** Four rows above are marked *chosen*: the server sees them because the current implementation sends them in the clear, not because the protocol requires it. Each could be minimized with machinery the codebase already has. They are recorded here as deliberate prototype simplifications, not oversights.

### Standing rule

Every new feature must answer, in its design, *what does this add to the CAN-see table?* Server-side convenience — server search, analytics, funder reports — is the standing temptation; each moves a row from CANNOT to CAN. If a hybrid model is ever adopted (plaintext reporting fields for funder mandates), those fields move to this table explicitly and visibly in the organization's own admin UI, never silently.

---

## 7. Adversaries

Adversaries are listed first by position, then examined one at a time. Each examination uses the same three labels: **Can do** (with a foothold, what they achieve), **Stopped by** (what the design denies them), and **Not stopped by** (what the design does not prevent — stated plainly).

### 7.0 Summary by position

| Adversary | Where they sit | Primary answer |
|---|---|---|
| **The server operator** — compromised, insider, or hostile (§7.1) | Holds the server's memory; controls its behavior | Untrusted server by design: what the server holds is §6 plus ciphertext; what it can *do* is §8 |
| **Physical seizure** (§7.2) | Takes servers, devices, papers, or people | Self-hosting where the org chooses; split custody; nothing protects an unlocked screen |
| **Network position** (§7.3) | Between browser and server | End-to-end encryption under TLS; traffic analysis remains |
| **Compromised or coerced insider** (§7.4) | Holds a member's, admin's, or head's legitimate powers | Powers are split and journaled; one insider is bounded, two admins are not |
| **Someone with access to a device** (§7.5) | Reaches a caseworker's or constituent's device | Idle lock, split-custody persistence, remote log-out; an unlocked screen defeats everything |
| **The client-code channel** (§7.6) | Serves the JavaScript | CSP today; reproducible signed artifact and blocking verification are the pilot gate |
| **The print path** (§7.7) | Renders the Emergency Bundle | Warnings today; separation of authority is open |
| **An outsider at the public endpoints** (§7.8) | Has the server's address and no invite | Invite gating, rate limits, single-use attempt IDs, loopback default |

### 7.1 The server operator — compromised, insider, or hostile

*Whoever holds the server's memory or controls its behavior: a breach, a rogue employee, an acquirer, or an operator acting under a lawful order. The design does not distinguish why — every case produces an operator who wants what the server holds and may be made to act.*

- **Can do:** obtain everything in §6 and all ciphertext. Act against clients — withhold, equivocate, inject, or serve poisoned code (§8).
- **Stopped by:** the untrusted server, by design. No keys live server-side and no vendor recovery path exists, so what any such operator obtains is metadata plus ciphertext. This holds because of architecture, not policy: a policy can be overridden or abandoned; an inability to decrypt cannot.
- **Not stopped by:** anything that would hide the §6 metadata — that surface is real, and its remedy is minimization, not encryption. And not fully stopped when the operator *acts*: the fork problem is open (§11, gap 1).

### 7.2 Physical seizure

*Whoever takes hardware, paper, or people: a server, a laptop, the printed halves, or a custodian. The design answers the seizure, not the seizer.*

- **Can do:** take a server, a device, or the papers; coerce a custodian.
- **Stopped by:** a seized server yields §6 plus ciphertext (§7.1). A seized *locked* device yields a sealed blob whose key is server-side, and the org revokes that key remotely. Split custody means one seized half is useless alone. Self-hosting lets an organization place its server wherever it judges seizure least likely, preserved as a first-class deployment mode and made real by open source.
- **Not stopped by:** an unlocked device; both halves seized together; a coerced custodian. Self-hosting does not guarantee notice of a seizure elsewhere — infrastructure providers, network operators, and the client-code publisher remain third parties, and deployment guidance must say which of them still observe metadata.
- **Note:** emergency features (remote wipe, duress codes) are appropriate against seizure and dangerous in the presence of legal process. If ever built, they ship jurisdiction-aware, documented for seizure only, with counsel review. Not in the prototype.

### 7.3 Network position

- **Can do:** observe traffic; on plaintext HTTP, capture bearer tokens and recovery proofs.
- **Stopped by:** end-to-end encryption of content — a TLS break yields ciphertext. Recovery proofs are bound to the exact replacement material and consumed once, so a captured proof authorizes nothing else.
- **Not stopped by:** traffic analysis — exact timing, sizes, and opaque case tags remain observable (size bucketing and sync jitter are future work). And not stopped at all on plain HTTP: the prototype server has no TLS, binds to loopback by default, and refuses non-loopback binds without an explicit test-only override. Any real deployment terminates TLS in front of it.

### 7.4 Compromised or coerced insider

*One named person is a cheaper target than the cryptography. Powers are deliberately different by role.*

- **A member can:** read and copy every case in their keychain. **Cannot:** open cases not granted to them, admit anyone, or affect governance. **Not stopped by** encryption: copying plaintext one is authorized to read.
- **One admin can:** everything a member can; propose an admission or an org-authority re-key. **Cannot:** complete either alone once two admins exist. Note: an admin cannot suspend another member's sessions — only self-service "log out my other devices" exists.
- **Two admins together can:** admit a ghost member; re-key any case to holders of their choosing (journaled and conspicuous; prior epochs' recovery envelopes survive). **Cannot:** reconstruct the recovery key without the paper.
- **The head can:** promote and demote admins unilaterally; hand off leadership; below two admins, admit members alone (solo mode). **Cannot:** decrypt cases by virtue of the role — the governance key signs, it does not decrypt. **Not stopped by:** the two-admin barrier, if the head is compromised: a hostile head can promote two accomplices. The head is a single governance root by design, trading resistance to head compromise for recoverable governance.
- **Any two custodians of the tally halves can:** reconstruct the recovery key and decrypt every case's recovery envelope, in a client, with no guaranteed audit record if they work from downloaded ciphertext. Removing an admin role does not retrieve their paper.
- **Recorded residuals:** the reconstructed recovery key exists briefly in one browser and that client could retain it; read-only recovery leaves no journal event; re-key signers cannot prove they hold the shares; losing either half stops recovery.

### 7.5 Someone with access to a device

*Often the most immediate adversary for domestic-violence constituents: an abusive partner, a family member, a housemate (NNEDV Safety Net literature).*

- **Can do:** target the constituent's device, or a caseworker's.
- **Stopped by (constituent side):** there is no constituent-facing surface — no portal, email, or SMS — so there is nothing on a constituent's device to find. **Stopped by (caseworker side):** idle auto-lock wipes memory and revokes the server-side unlock key, so a walk-up refresh cannot resume; "stay signed in" is split custody — the disk holds only a sealed blob whose key lives server-side, so device access alone yields no content; "log out my other devices" kills a lost device's sessions remotely; the idle interval is configurable per device (a per-device opt-out of "stay signed in" is not built). The printed account-recovery code is a second credential inside this adversary's reach, and guidance says store it away from home.
- **Not stopped by:** an unlocked screen. If the abuser can read the caseworker's screen, no architecture helps. Stated plainly in org-facing guidance.

### 7.6 Compelled or compromised client code

*The subtle form of §7.1: an order to, or compromise of, whoever serves the JavaScript. One poisoned page, served to one org, once, and the encryption is moot for everything that org touches afterward.*

- **Can do:** serve a client that waits for login and uploads keys and plaintext. The server that supplies the page can replace both the application and its security headers in the same response.
- **Stopped by, today:** a Content Security Policy that blocks external scripts and styles (defense in depth against injection, not against page replacement); an open-source client, which is the minimum for the claim to be verifiable at all; and no update mechanism at all for crypto-bearing code, so a new release is always a new, visible hash. A warrant canary is planned for the public release (it only works if it predates any order) and does not yet exist.
- **Stopped by, at the pilot gate:** the client becomes a single reproducible static artifact with its hash published under a signed tag, so releases exist again. Then, cheapest first: public monitors that hash the live app (detection only — a server can serve a monitor different bytes); an out-of-band local copy an org verifies once and opens from disk (attack eliminated for that install); a companion verifier extension that blocks on hash mismatch; and WEBCAT enrollment when production-ready. Subresource-integrity tags do *not* solve this — they live in the HTML the same adversary serves; the verification anchor must sit outside the channel being verified.
- **Not stopped by:** anything, for a caseworker who types the URL into a fresh browser without blocking verification. Monitors may detect a poisoned bundle; they cannot prevent it. The prototype may run as a plain web app; the artifact pipeline and a blocking verification path are a pilot gate (§11, gap 4).

### 7.7 The print path

*The Emergency Bundle prints both tally halves, the governance secret and its encrypted backup, and the head's login ID and account-recovery code as one print job.*

- **Can do:** a compromised spooler, a network or cloud printer, a print server, a printer's disk, or a support technician with access to a retained job obtains every recovery authority at once. Cutting the paper afterward does not retract the digital job already delivered.
- **Stopped by, today:** prominent warnings on screen and on the printed bundle to use only a directly connected, trusted printer, and to treat a bundle printed on a shared or cloud queue as exposed.
- **Not stopped by:** the warnings, which are procedure rather than separation of authority. The typed confirmation proves the operator can type "Confirm," not that anything was printed, transcribed correctly, or stored with the intended custodians. Separating the jobs by custody destination and verifying each paper by type-back are open design work (§11, gap 6).

### 7.8 Outsider at the public endpoints

*Anyone who can reach the server and holds no invite.*

- **Can do:** attempt registration, login, recovery, and join-request calls.
- **Stopped by:** registration and join requests require an outstanding journaled invite once an organization exists; a fresh, remotely reachable server requires a one-time setup code minted at startup, consumed at the founder's registration; login attempts are keyed by random single-use IDs with a two-minute lifetime, so one user's in-progress login cannot be stomped; recovery challenges are per-user multi-slot with a proved slot immune to eviction; every endpoint is rate-limited by IP; and the default bind is loopback only.
- **Not stopped by:** account-existence probing — the login and recovery endpoints reveal whether an opaque ID exists. Accepted because IDs are random and unguessable; recorded here as a choice. Resource exhaustion by an *admitted* account (large bodies, whole-tail reads) is also only partly bounded (§11, gap 7).

---

## 8. Implications of compromise

The same adversaries, re-sliced by foothold: *if an attacker holds X, what do they get?* This is the section to read when something has gone wrong.

**A copy of the server's memory or database.** Everything in §6. All ciphertext, useful for future cryptanalysis and for offline passphrase guessing against every identity blob (§11, gap 2). Hashed session tokens — nothing replayable. No case content.

**The adversarial server (operator acting under compulsion or compromise).** Cannot forge a membership, a grant, a revocation, or a succession — every one is signed by a key the server does not hold, and clients verify. *Can:* withhold entries (denial of service); show different members different valid journals or roll a member back to an older prefix (§11, gap 1 — the open fork problem); accept a malformed entry that halts every honest client at that sequence number (gap 3); serve a poisoned client (§7.6); and attempt a ghost key, which the invite-code binding defeats because the verification anchor never crosses the server.

**A network position.** Under TLS: timing, sizes, tags. Without TLS: bearer tokens and recovery proofs in transit — the reason the prototype refuses to bind beyond loopback.

**A member's locked device.** A sealed session blob whose key is server-side, ciphertext, and a breadcrumb of which screen was open. No content. The org revokes the blob's key remotely.

**A member's unlocked device.** Everything in that member's keychain, in plaintext, for as long as it stays unlocked. The idle lock bounds this window; nothing shrinks it to zero.

**A member's identity keys** (via device, passphrase, or printed code). Every case the member ever held keys for, at every epoch they held — the full history, because keys that keep working are the archive requirement itself. Revocation at epoch N bounds exposure to epochs ≤ N. The governance key, if the member is the head.

**One admin.** A member's powers plus the ability to propose. Nothing completes alone.

**Two admins.** Ghost admissions and re-keys of any case to any holders — conspicuous in the journal, but complete.

**The head's governance key, or the governance paper.** Control of the roster: promote accomplices, defeat the two-admin barrier, hand leadership anywhere. Not a single case key. Rotating governance retires the old key by construction; a stolen paper dies the moment a rotation commits.

**Both tally halves.** The recovery private key, and with it every case's recovery envelope. Total case-recovery authority, with no audit record if used outside the application.

**The client-code channel.** Everything, silently, for every org served the poisoned page (§7.6).

**The print path.** Every recovery authority at once (§7.7).

---

## 9. Out of scope

Explicitly not defended, so that no one assumes otherwise.

- **A compromised endpoint** beyond the damage-limiting in §7.5: malware, a compromised browser or operating system, hardware attacks, or side channels within the browser. A compromised endpoint sees what the caseworker sees.
- **A malicious insider with legitimate access** copying or disclosing plaintext they are authorized to read.
- **Availability attacks** as a class. The server can always refuse service; the open fork and poison-pill gaps are recorded because they are integrity and availability failures a *member* can trigger, not because denial of service is defended.
- **Constituent-side devices** entirely: no constituent-facing surface exists.
- **Physical custody failures:** halves stored together, papers photographed, a printed code left at home.
- **Post-quantum adversaries:** stored X25519 envelopes are harvest-now, decrypt-later targets if large-scale quantum decryption becomes practical.
- **Deletion and retention.** An append-only, replicated journal has no erasure story yet; no crypto-shredding claim is made.

---

## 10. Decisions that must not be quietly reversed

Where the tempting option would falsify the claim in §1.

1. **No vendor key recovery, ever.** "Forgot password → vendor restores your data" reintroduces vendor access. Governance recovery is an org-held paper; case recovery is two org-held halves; account recovery is a member-held code. No vendor holds any secret.
2. **Search is local, per-user, client-side.** No shared search key, no uploaded index, no server-side search over plaintext.
3. **Any hybrid is explicit, org-visible, and field-level.** If plaintext reporting fields ever ship, the admin UI shows exactly which fields the server can read.
4. **Open source (AGPL-3.0), building in public.** The confidentiality claim is unverifiable closed-source, and the intermediaries who gate adoption recommend only auditable tools. This document ships with the code.
5. **Synthetic data only until external review.** The real risk of this project is not wasted effort; it is a real organization putting real constituent data into an unaudited prototype.
6. **Sync is journal-based; the server never serves per-record reads.** Per-case fetch APIs are prohibited because they would expose reads.
7. **No long-term IP retention, and the logging posture is public.**
8. **No identity enters the org without out-of-band binding and the required signatures.** Roles and membership come from the signed journal, never from a server-side table.
9. **Case access is case-by-case; no organization content key exists.** Revocation rotates future state and never claims to erase copies already received.
10. **The head is a governance root, not a data master key.** The governance key signs; it never decrypts.
11. **Everyone enters as an ordinary member.** Admin is a promoted title, never an invited one, so the roster grows through exactly one vetting path.

---

## 11. Known gaps

Findings the project already knows about, ordered by severity. A reviewer should expect this list to be defended, not hidden.

1. **The journal is tamper-evident, not globally consistent.** Authors sign envelopes but not their sequence numbers, and clients neither persist nor cross-compare trusted heads, so an adversarial server can show different members different valid histories or roll them back. Membership, grants, and revocations all rest on one consistent history, so this is a prerequisite for the design's other guarantees. *Pilot gate: signed heads compared through a channel the server cannot isolate — client gossip, an independent witness, or a transparency log.* 
2. **Server-stored identity blobs are offline passphrase-guessing targets.** The key that wraps a member's identity blob derives from their passphrase with a public salt, so a stolen store lets an attacker test passphrases at leisure; a hit yields every key that member ever held. Argon2id raises the cost per guess; it does not remove the oracle. *Endgame options under design: wrap under a secret that never touches the server — a printed second secret or device-bound keys — composed with OPAQUE's export key.* 
3. **One malformed entry halts every honest client, permanently.** The server appends before validating, and honest clients fail-stop at the first invalid entry by design. *Candidate fix: server pre-validation as an availability filter — never a trust root.* 
4. **Client code delivery is unverified.** See §7.6. A CSP exists; the reproducible signed artifact and blocking verification do not. *Pilot gate.* 
5. **Transport is plain HTTP.** Loopback-only by default with an explicit refusal to bind elsewhere; TLS is a deployment concern outside the repository.
6. **The Emergency Bundle is one print job.** See §7.7. Warnings exist; separation of authority and type-back verification do not.
7. **Resource limits are unfit for an adversarial member.** Large request bodies, generous append rates, uncapped streams, whole-tail reads, and incomplete runtime schema validation let one admitted account amplify cost across the whole organization.
8. **Retention, deletion, backup, and export are undesigned.**
9. **No member removal.** Demotion changes a title; it does not evict an identity or rotate every affected case. Containment is per-case re-key.
10. **Four chosen disclosures** in §6 could be minimized with existing machinery and have not been.

---

## 12. Maintenance

- §6 is a contract: any change to what the server stores, receives, or logs updates that table in the same change.
- §11 is a ledger: gaps are removed when fixed with a test, never when merely mitigated. "Repaired exploit" and "closed residual" are different states and are recorded as such.
- Terminology: *untrusted server, by design* for the standing posture; *adversarial server* for the active variant;