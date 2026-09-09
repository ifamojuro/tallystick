// UI: a thin vanilla-TS skin over flows.ts. Screens: landing,
// bootstrap ceremony wizard, join, login, home (roster + admin panels).
// Secrets and sessions live in module memory only; localStorage holds only
// login IDs and device-local nicknames (never sent anywhere).

import { crypto, journal } from "@tallystick/shared";
import * as flows from "./flows.ts";
import { server as api } from "./api.ts";

const API = { base: new URLSearchParams(location.search).get("server") ?? "http://localhost:8787" };

// ---- module state (memory only) ----------------------------------------
let session: flows.Session | null = null;
// pending invites derive from verified JOURNAL state: the
// code is sealed to the issuer's own identity key inside the invite_issue
// event, so any device that unlocks this identity recovers them after
// sync. No local store; consumed invites disappear because the journal
// says so.
let issuedInvites: Array<{ invite: flows.Invite; label: string; expiresAt: number }> = [];
let pollTimer: ReturnType<typeof setInterval> | null = null;

function reloadInvites() {
  issuedInvites = session
    ? flows.myPendingInvites(session).map(({ invite, expiresAt }) => ({
        invite,
        expiresAt,
        label: "member",
      }))
    : [];
}

async function addInvite(): Promise<void> {
  await flows.issueInvite(session!);
  reloadInvites();
}

// localStorage: PUBLIC login handles + local-only nicknames. The server is
// the single source of truth for which accounts exist (one server = one
// org); this list is just a convenience cache, so it must self-prune:
// after an in-memory server restart the server knows none of these
// handles, and validate() drops whatever the server doesn't recognize.
interface SavedAccount {
  userId: string;
  nickname: string;
}
const accounts = {
  all: (): SavedAccount[] => JSON.parse(localStorage.getItem("tallystick.accounts") ?? "[]"),
  add(userId: string, nickname: string) {
    const list = accounts.all().filter((a) => a.userId !== userId);
    list.push({ userId, nickname });
    localStorage.setItem("tallystick.accounts", JSON.stringify(list));
  },
  nick: (userId: string) => accounts.all().find((a) => a.userId === userId)?.nickname,
  /** Keep only handles this server actually has registration records for. */
  async validate(): Promise<SavedAccount[]> {
    const all = accounts.all();
    const valid: SavedAccount[] = [];
    for (const a of all) {
      try {
        await api.params(API, a.userId);
        valid.push(a);
      } catch {
        /* unknown to this server (e.g. restarted): drop */
      }
    }
    if (valid.length !== all.length) {
      localStorage.setItem("tallystick.accounts", JSON.stringify(valid));
    }
    return valid;
  },
};

// ---- tiny DOM helpers ---------------------------------------------------
const app = () => document.getElementById("app")!;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const $ = (id: string) => document.getElementById(id) as HTMLInputElement;

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

/** per-screen teardown (event listeners etc.), run on navigation */
let pageCleanup: (() => void) | null = null;

function go(screen: () => void) {
  stopPolling();
  pageCleanup?.();
  pageCleanup = null;
  screen();
}

function showError(e: unknown) {
  const box = document.getElementById("err");
  if (box) {
    box.innerHTML = `<div class="error">${esc(String((e as Error).message ?? e))}</div>`;
  } else {
    alert(String((e as Error).message ?? e));
  }
}

function showOk(msg: string) {
  const box = document.getElementById("err");
  if (box) box.innerHTML = `<p class="ok">${esc(msg)}</p>`;
}

// ---- change narration (cleanup backlog item 5) --------------------------
// Everything here derives from verified journal state already on the
// client — no presence channel, zero new server visibility (threat model). The "last looked" map is per-session display memory, deliberately
// unpersisted: it resets at login rather than becoming journal-external
// side state.

/** last seen journal seq per note, keyed `${caseTag}/${recordId}` */
const seenNoteSeqs = new WeakMap<flows.Session, Map<string, number>>();
function seenMap(s: flows.Session): Map<string, number> {
  let m = seenNoteSeqs.get(s);
  if (!m) {
    m = new Map();
    seenNoteSeqs.set(s, m);
  }
  return m;
}

/** display name for an event author: the org directory first
 * then this device's local nickname, else a
 * truncated ID. Colliding names carry the ID alongside (display-based
 * disambiguation, no uniqueness). */
const who = (id: string): string => {
  if (id === "(snapshot)") return id;
  if (session) {
    const dir = flows.displayNames(session);
    const name = dir[id];
    if (name) {
      return flows.nameCollisions(session).has(name) ? `${name} (${id.slice(0, 6)}…)` : name;
    }
  }
  return accounts.nick(id) ?? `${id.slice(0, 8)}…`;
};

/** name + ID together — for rosters and pickers, where identity precision
 * matters regardless of collisions. */
const whoFull = (id: string) => {
  const dirName = session ? flows.displayNames(session)[id] : undefined;
  const label = dirName ?? accounts.nick(id);
  return label ? `${label} (${id.slice(0, 8)}…)` : `${id.slice(0, 8)}…`;
};

/** transient corner notification; lives outside #app so re-renders keep it */
function toast(msg: string) {
  let box = document.getElementById("toasts");
  if (!box) {
    box = document.createElement("div");
    box.id = "toasts";
    document.body.appendChild(box);
  }
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

/** A background-sync re-render replaces #app wholesale, which would eat
 * typed-but-unsubmitted input. Snapshot every <input>/<select> value plus
 * focus/caret before the rebuild; the returned function puts them back
 * (re-firing "input" so live listeners, e.g. search, catch up). Note
 * textareas are NOT handled here — their drafts need merge semantics and
 * live in caseScreen. */
function snapshotInputs(): () => void {
  const saved = [
    ...app().querySelectorAll<HTMLInputElement | HTMLSelectElement>("input[id], select[id]"),
  ].map((el) => ({
    id: el.id,
    value: el.value,
    focused: document.activeElement === el,
    sel:
      el instanceof HTMLInputElement && el.selectionStart !== null
        ? ([el.selectionStart, el.selectionEnd ?? el.selectionStart] as const)
        : null,
  }));
  return () => {
    for (const snap of saved) {
      const el = document.getElementById(snap.id) as HTMLInputElement | HTMLSelectElement | null;
      if (!el) continue;
      if (el.value !== snap.value) {
        el.value = snap.value;
        el.dispatchEvent(new Event("input"));
      }
      if (snap.focused) {
        el.focus();
        if (snap.sel && el instanceof HTMLInputElement)
          el.setSelectionRange(snap.sel[0], snap.sel[1]);
      }
    }
  };
}

/** The printed page must be self-explanatory YEARS later, found in a
 * drawer by someone who has never seen this app: what the secret is for,
 * which org it belongs to, when it was printed, and how to use it. */
function printBlock(title: string, body: string, note = "") {
  const slot = document.getElementById("print-slot")!;
  const orgLine = session ? ` · organization ${session.orgId}` : "";
  slot.innerHTML = `<h1>Tallystick — ${esc(title)}</h1>
    <p>Tallystick PROTOTYPE — synthetic data only${esc(orgLine)} · printed ${new Date().toISOString().slice(0, 10)}</p>
    ${note ? `<p>${esc(note)}</p>` : ""}
    <div class="code-block">${esc(body)}</div>
    <p>Store on paper, offline. Anyone holding this page gains the capability described above.</p>`;
  document.body.classList.add("print-mode");
  window.print();
  document.body.classList.remove("print-mode");
}

/** A ceremony paper (Tier-1 regroup): one
 * PURPOSE per sheet. `cut` marks the tally sheet — printed to be cut in
 * half between its two codes, the paper itself becoming a tally stick. */
interface CeremonyPaper {
  title: string;
  /** One bold line answering "who is this for" — the contrast between the
   * papers lives here (org / org-without-you / you). */
  who: string;
  note: string;
  sub: Array<{ label: string; code: string; note: string }>;
  cut?: boolean;
}

function paperSectionsHtml(p: CeremonyPaper, pairCode: string): string {
  return p.sub
    .map(
      (s, i) => `${
        p.cut && i === 1
          ? `<p style="margin:1.1em 0;letter-spacing:0.15em">✂ ${"—".repeat(12)} CUT HERE ${"—".repeat(12)}<br>
             <span style="font-size:0.85em">pair code ${esc(pairCode)} — printed on BOTH halves so they can be matched at a recovery ceremony. The halves must never be STORED together.</span></p>`
          : ""
      }
      <h3>${esc(s.label)}${p.cut ? ` <span style="font-weight:400">· pair code ${esc(pairCode)}</span>` : ""}</h3>
      <p>${esc(s.note)}</p>
      <div class="code-block">${esc(s.code)}</div>`,
    )
    .join("");
}

/** The whole Emergency Bundle as ONE print job — one physical trip to
 * the printer. Gated by ONE typed "Confirm" acknowledgement — not custody
 * evidence (type-back verification stays deferred). */
function printPacket(papers: CeremonyPaper[], pairCode: string) {
  const slot = document.getElementById("print-slot")!;
  const orgLine = session ? ` · organization ${session.orgId}` : "";
  slot.innerHTML = `<h1>Tallystick — EMERGENCY BUNDLE (${papers.length} papers)</h1>
    <p>Tallystick PROTOTYPE — synthetic data only${esc(orgLine)} · printed ${new Date().toISOString().slice(0, 10)}</p>
    <p>Each paper prints on its own page — store each one as its own instructions say.
    If this was printed on a shared, office, or cloud printer, treat the bundle as exposed:
    finish setup, then rotate what you can and reprint on a trusted device.</p>
    ${papers
      .map(
        // every paper on its own printed page; paper 1 shares page 1 with
        // the bundle header so no page is wasted
        (
          p,
          i,
        ) => `<section style="${i > 0 ? "break-before:page;page-break-before:always;" : ""}margin-top:1.2em">
        <h2>Paper ${i + 1} of ${papers.length} — ${esc(p.title)}</h2>
        <p><b>${esc(p.who)}</b></p>
        <p>${esc(p.note)}</p>
        ${paperSectionsHtml(p, pairCode)}</section>`,
      )
      .join("")}`;
  document.body.classList.add("print-mode");
  window.print();
  document.body.classList.remove("print-mode");
}

// ---- session persistence + relock -------------

// The UI owns localStorage: it stores ONLY the flows.PersistedSession
// record (bearer token + ciphertext blob) and a non-secret breadcrumb
// (which nav surface was open). Unwrapped keys never touch storage.

const persisted = {
  save(rec: flows.PersistedSession) {
    localStorage.setItem("tallystick.session", JSON.stringify(rec));
  },
  load(): flows.PersistedSession | null {
    try {
      return JSON.parse(localStorage.getItem("tallystick.session") ?? "null");
    } catch {
      return null;
    }
  },
  clear() {
    localStorage.removeItem("tallystick.session");
  },
};

/** Non-secret return-to-where-you-were hint: nav surface + case tag only —
 * NEVER note text (design rule). */
const breadcrumb = {
  set(view: string, caseTag?: string) {
    sessionStorage.setItem("tallystick.breadcrumb", JSON.stringify({ view, caseTag }));
  },
  load(): { view: string; caseTag?: string } | null {
    try {
      return JSON.parse(sessionStorage.getItem("tallystick.breadcrumb") ?? "null");
    } catch {
      return null;
    }
  },
};

/** One-time auto-publish of the display name typed at join, at the first
 * unlock AFTER admission. Best-effort and
 * self-clearing; never re-fires once the account has self-published. */
async function maybePublishName(): Promise<void> {
  const s = session;
  if (!s) return;
  try {
    const key = `tallystick.wantName.${s.userId}`;
    const wanted = localStorage.getItem(key);
    if (!wanted) return;
    if (!flows.role(s)) return; // not admitted yet: keep waiting
    if (flows.hasPublishedName(s)) {
      localStorage.removeItem(key); // already self-published elsewhere
      return;
    }
    await flows.publishDisplayName(s, wanted);
    localStorage.removeItem(key);
    toast(`Display name "${wanted}" shared with your organization.`);
  } catch {
    /* retry at the next unlock */
  }
}

/** Persist the just-unlocked session (best-effort: a failure only means a
 * refresh needs the passphrase again — the relock screen covers it). */
async function persistCurrentSession(): Promise<void> {
  if (!session) return;
  try {
    persisted.save(await flows.persistSession(session));
  } catch {
    persisted.clear();
  }
}

/** Full lock: wipe memory, revoke the server-side unlock key, drop the
 * local blob. Used by logout and the idle timer. */
async function lockSession(): Promise<void> {
  const api = session?.api;
  session = null;
  issuedInvites = [];
  persisted.clear();
  if (api) await flows.dropPersistedSession(api);
}

/** Return to the breadcrumbed surface after a resume or relock. */
function goToBreadcrumb(): void {
  const b = breadcrumb.load();
  if (b?.view === "case" && b.caseTag && session?.state.cases.has(b.caseTag)) {
    return go(() => caseScreen(b.caseTag!));
  }
  if (b?.view === "org") return go(orgScreen);
  if (b?.view === "help") return go(helpScreen);
  if (b?.view === "cases") return go(casesScreen);
  go(homeScreen);
}

// ---- idle auto-lock --------------------------------------------
// timeout is a DEVICE-LOCAL setting (device-local for now; org policy can supersede later)
const IDLE_CHOICES_MIN = [5, 15, 30, 60];
function idleLockMs(): number {
  const m = Number(localStorage.getItem("tallystick.idleMinutes"));
  return (IDLE_CHOICES_MIN.includes(m) ? m : 15) * 60 * 1000;
}
let idleTimer: ReturnType<typeof setTimeout> | null = null;
function armIdleLock(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    if (!session) return;
    const userId = session.userId;
    await lockSession(); // invalidates the SERVER key — refresh cannot bypass
    go(() => relockScreen(userId, "Locked after inactivity."));
  }, idleLockMs());
}
for (const ev of ["pointerdown", "keydown"]) {
  document.addEventListener(ev, () => {
    if (session) armIdleLock();
  });
}

// ---- app shell (design canvas "Tallystick Home Panels", Fir): dark sidebar -----
// nav on top (amber count = items awaiting YOU), identity + personal
// actions pinned at the bottom. Members get no Organization item at all.

/** join requests seen by the latest poll — feeds the sidebar count */
let pendingReqCount = 0;

function pendingOrgCount(s: flows.Session): number {
  let n = pendingReqCount;
  if (flows.role(s) === "admin") {
    n += [...s.state.proposals.values()].filter((p) => p.proposedBy !== s.userId).length;
    n += [...s.state.pendingRekeys.values()].filter((p) => p.proposedBy !== s.userId).length;
  }
  return n;
}

function sidebarHtml(s: flows.Session, active: "cases" | "org" | "help"): string {
  const myRole = flows.role(s);
  const showOrg = myRole === "head" || myRole === "admin";
  const count = showOrg ? pendingOrgCount(s) : 0;
  return `<div class="sidebar">
    <div class="side-head">
      <div class="wordmark">Tallystick</div>
      <div class="orgline">org ${esc(s.orgId.slice(0, 8))}… · seq ${s.state.chain.seq}</div>
    </div>
    <div class="side-nav">
      <div class="nav-item${active === "cases" ? " active" : ""}" id="nav-cases">Cases</div>
      ${showOrg ? `<div class="nav-item${active === "org" ? " active" : ""}" id="nav-org"><span>Organization</span>${count ? `<span class="count">${count}</span>` : ""}</div>` : ""}
      <div class="nav-item${active === "help" ? " active" : ""}" id="nav-help">Help</div>
    </div>
    <div class="side-foot">
      <div><span class="name">${esc(accounts.nick(s.userId) ?? "account")}</span><span class="badge" id="role-badge">${esc(myRole ?? "?")}</span></div>
      <div class="side-link" id="mk-recovery">Recovery code</div>
      <div class="side-link" id="nav-session">Device &amp; session</div>
      <div class="side-link" id="logout">Lock &amp; log out</div>
    </div>
  </div>`;
}

function wireSidebar(): void {
  document.getElementById("nav-cases")?.addEventListener("click", () => go(casesScreen));
  document.getElementById("nav-org")?.addEventListener("click", () => go(orgScreen));
  document.getElementById("nav-help")?.addEventListener("click", () => go(helpScreen));
  document.getElementById("logout")?.addEventListener("click", async () => {
    // discard memory-only state; JS cannot guarantee zeroing.
    // Also revokes the server-side unlock key and drops the local blob.
    await lockSession();
    go(landing);
  });
  document.getElementById("nav-session")?.addEventListener("click", () => go(sessionScreen));
  document.getElementById("mk-recovery")?.addEventListener("click", async () => {
    try {
      if (!confirm("Print a NEW account recovery code? Any previous code becomes useless.")) return;
      printBlock(
        "ACCOUNT RECOVERY CODE",
        await flows.createRecoveryPackage(session!),
        `Restores this account under a NEW passphrase if yours is forgotten — use "Recover account" on the front page, which needs this code AND the login ID: ${session!.userId}. Any previously printed recovery code is now useless.`,
      );
    } catch (e) {
      showError(e);
    }
  });
}

/** Bootstrap step rail: the SAME geometry as the app sidebar, carrying
 * ceremony steps instead of nav — after Finish, the rail "becomes" the
 * real sidebar. During step 2 the five papers show as a sub-checklist. */
function bootRailHtml(step: number): string {
  const check = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="margin-right:8px"><path d="M3 8.5l3.2 3.2L13 5" stroke="#57b184" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg>`;
  const row = (n: number, label: string) =>
    step > n
      ? `<div class="nav-item step-done"><span style="display:flex;align-items:center">${check}${esc(label)}</span></div>`
      : step === n
        ? `<div class="nav-item active">${n} · ${esc(label)}</div>`
        : `<div class="nav-item">${n} · ${esc(label)}</div>`;
  return `<div class="sidebar">
    <div class="side-head">
      <div class="wordmark">Tallystick</div>
      <div class="orgline">new organization</div>
    </div>
    <div class="side-nav">
      ${row(1, "Passphrase")}
      ${row(2, "Save your emergency bundle")}
      ${row(3, "First members (optional)")}
      ${row(4, "Your organization")}
    </div>
    <div class="side-note">${
      step === 1
        ? "Have a printer, or pen and paper, ready before step 2."
        : step === 2
          ? "Your bundle is shown ONCE. It is not stored on this device or the server."
          : "Admins are made later, by promoting members from the Organization panel."
    }</div>
  </div>`;
}

// ---- screens ------------------------------------------------------------

export async function landing() {
  // a persisted session resumes silently; ANY failure falls
  // through — to the relock screen when we know who was here, else here.
  // a record bound to a DIFFERENT server (this page was opened with
  // a foreign ?server=) is treated as absent — no resume, no token sent,
  // and the record is kept so the real server still resumes next visit.
  const rec = persisted.load();
  if (rec && !session && rec.server === API.base) {
    try {
      session = await flows.resumeSession(API, rec);
      await persistCurrentSession(); // fresh blob + key for the new page
      armIdleLock();
      void maybePublishName();
      return goToBreadcrumb();
    } catch {
      persisted.clear();
      return relockScreen(rec.userId, "Session locked — unlock to continue.");
    }
  }
  const { orgId } = await api.org(API);
  app().innerHTML = `
    <div class="narrow">
    <h1>Tallystick case management</h1>
    <p class="muted">Server: ${esc(API.base)} · in-memory prototype — restarting the server erases everything.</p>
    <div id="err"></div>
    <p style="line-height:1.55">Tallystick is case management for small organizations that handle sensitive
    records. Case notes are encrypted <b>on your device</b> before anything is sent — the server
    stores only ciphertext it cannot read. Access is granted person by person, per case; every
    change lands in a tamper-evident journal your members verify themselves.</p>
    <p style="line-height:1.55">Named for the medieval <b>tally stick</b> — one record, split
    between holders, tamper-evident, provable when the halves are matched. Tallystick keeps your
    organization's records the same way: split custody, matched proofs, an append-only tally.</p>
    <p style="line-height:1.55">Nobody can reset your passphrase <b>for</b> you — no email link, no
    vendor, no admin override. If you ever lose it, the way back is a <b>printed recovery code you
    physically hold</b>, made once, during setup.</p>
    ${
      orgId
        ? `<div class="card"><p>Organization <span class="mono">${esc(orgId)}</span> exists on this server.</p>
           <button id="b-login" class="btn-primary">Log in</button>
           <button id="b-join">Join with an invite code</button>
           <button id="b-recover">Recover account</button></div>`
        : `<div class="card"><p>No organization exists on this server yet. Creating one makes you the
           <b>head</b> — the governance root — and walks you through printing the papers that make
           recovery possible.</p>
           <button id="b-boot" class="btn-primary">Create a new organization</button>
           <p class="muted">You'll need a passphrase you can remember, and a printer (or pen and
           paper) for three recovery papers. Ten minutes, once.</p></div>`
    }
    </div>`;
  document.getElementById("b-boot")?.addEventListener("click", () => go(bootstrapScreen));
  document.getElementById("b-login")?.addEventListener("click", () => go(loginScreen));
  document.getElementById("b-join")?.addEventListener("click", () => go(joinScreen));
  document.getElementById("b-recover")?.addEventListener("click", () => go(recoverScreen));
}

// -- relock: cheap re-entry ------------

function relockScreen(userId: string, reason: string) {
  const nick = accounts.nick(userId);
  app().innerHTML = `
    <div class="narrow">
    <h1>Unlock</h1>
    <p class="muted">${esc(reason)}</p>
    <div id="err"></div>
    <div class="card">
      <p>${nick ? `<b>${esc(nick)}</b> · ` : ""}<span class="mono">${esc(userId.slice(0, 16))}…</span></p>
      <label>Passphrase</label>
      <input id="pw" type="password" autocomplete="current-password" autofocus />
      <button id="go" class="btn-primary">Unlock</button>
      <button id="switch">Different account</button>
      <p class="muted">Unlocking derives your keys locally and replays the signed journal.
      Your passphrase never leaves this device.</p>
    </div>
    </div>`;
  const unlock = async () => {
    try {
      session = await flows.login(API, userId, $("pw").value);
      await persistCurrentSession();
      armIdleLock();
      void maybePublishName();
      goToBreadcrumb();
    } catch (e) {
      showError(e);
    }
  };
  document.getElementById("go")!.addEventListener("click", unlock);
  $("pw").addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") void unlock();
  });
  document.getElementById("switch")!.addEventListener("click", () => {
    persisted.clear();
    go(landing);
  });
}

// -- account recovery --

function recoverScreen() {
  app().innerHTML = `
    <div class="narrow">
    <h1>Recover your account</h1>
    <div id="err"></div>
    <div class="card">
      <p>Your printed <b>account recovery code</b> restores this account — same identity,
      same cases — under a NEW passphrase. There is no other way back from a lost passphrase.</p>
      <label>Your login ID</label>
      <input id="uid" class="mono" placeholder="login ID" />
      <label>Printed recovery code</label>
      <input id="code" class="mono" placeholder="XXXX-XXXX-…" />
      <button id="verify">Verify the code only</button>
      <label>New passphrase</label>
      <input id="pw1" type="password" autocomplete="new-password" />
      <label>Repeat new passphrase</label>
      <input id="pw2" type="password" autocomplete="new-password" />
      <button id="go" class="btn-primary">Recover account</button>
      <button id="back">← Back</button>
      <p class="muted">Recovering prints a FRESH recovery code — the paper you just used becomes
      useless. Verification only checks the paper and changes nothing.</p>
    </div>
    </div>`;
  document.getElementById("back")!.addEventListener("click", () => go(landing));
  document.getElementById("verify")!.addEventListener("click", async () => {
    try {
      await flows.verifyRecoveryCode(API, $("uid").value.trim(), $("code").value.trim());
      showOk("This code is valid for that account. Nothing was changed.");
    } catch (e) {
      showError(e);
    }
  });
  document.getElementById("go")!.addEventListener("click", async () => {
    try {
      if (!$("pw1").value || $("pw1").value !== $("pw2").value)
        throw new Error("passphrases are empty or do not match");
      const userId = $("uid").value.trim();
      const { session: s, recoveryPrinted } = await flows.recoverAccount(
        API,
        userId,
        $("code").value.trim(),
        $("pw1").value,
      );
      session = s;
      if (!accounts.nick(userId)) accounts.add(userId, "recovered");
      await persistCurrentSession();
      armIdleLock();
      void maybePublishName();
      app().innerHTML = `
        <div class="narrow">
        <h1>Account recovered</h1>
        <div class="card">
          <h2>YOUR NEW ACCOUNT RECOVERY CODE</h2>
          <div class="code-block">${esc(recoveryPrinted)}</div>
          <p>The old code is now useless. Print or hand-copy this replacement and store it
          safely${s.governance ? " — as the head, it also guards the governance key" : ""}.</p>
          <button id="print">Print</button>
          <label><input type="checkbox" id="confirm" style="width:auto"/> I have printed or hand-copied this</label>
          <button id="next" class="btn-primary" disabled>Continue to my cases</button>
        </div>
        </div>`;
      document
        .getElementById("print")!
        .addEventListener("click", () =>
          printBlock(
            "ACCOUNT RECOVERY CODE",
            recoveryPrinted,
            `Restores this account under a NEW passphrase if yours is forgotten — use "Recover account" on the front page, which needs this code AND the login ID: ${userId}. The code used for this recovery is now useless.`,
          ),
        );
      $("confirm").addEventListener("change", () => {
        (document.getElementById("next") as HTMLButtonElement).disabled = !$("confirm").checked;
      });
      document.getElementById("next")!.addEventListener("click", () => go(homeScreen));
    } catch (e) {
      showError(e);
    }
  });
}

// -- bootstrap ceremony (workflow step 1) --

function bootstrapScreen() {
  app().innerHTML = `
    <div class="shell">
    ${bootRailHtml(1)}
    <div class="content"><div class="content-narrow">
    <h1>Choose your passphrase</h1>
    <div id="err"></div>
    <div class="card">
      <label>Passphrase — the only thing that unlocks your account</label>
      <input id="pw1" type="password" autocomplete="new-password" />
      <label>Repeat passphrase</label>
      <input id="pw2" type="password" autocomplete="new-password" />
      <div id="setup-row" style="display:none">
        <label>Server setup code — printed in the server's startup log (type it in;
        sending it in a link would leave it in browser history)</label>
        <input id="setup-code" autocomplete="off" />
        <p class="muted">This server is reachable from the network, so creating the first account
        requires the one-time code shown where the server was started.</p>
      </div>
      <button id="go" class="btn-primary">Create organization</button>
      <p class="muted">There is no "forgot passphrase" email — recovery is the printed papers you're
      about to make. If you lose the passphrase before printing them, the account is gone.</p>
    </div>
    </div></div></div>`;
  // only a fresh, remotely reachable server asks for a setup code —
  // local dev servers never set setupRequired, so this row stays hidden
  void api
    .org(API)
    .then(({ setupRequired }) => {
      if (setupRequired) document.getElementById("setup-row")!.style.display = "";
    })
    .catch(() => {});
  document.getElementById("go")!.addEventListener("click", async () => {
    try {
      if (!$("pw1").value || $("pw1").value !== $("pw2").value)
        throw new Error("passphrases are empty or do not match");
      showOk("Deriving keys and creating the organization…");
      const result = await flows.bootstrapOrg(
        API,
        $("pw1").value,
        $("setup-code").value.trim() || undefined,
      );
      session = result.session;
      accounts.add(session.userId, "head");
      await persistCurrentSession();
      armIdleLock();
      void maybePublishName();
      ceremonyScreen(result);
    } catch (e) {
      showError(e);
    }
  });
}

function ceremonyScreen(result: flows.BootstrapResult) {
  // Tier-1 regroup: five artifacts, three PURPOSES, three
  // papers — cases / governance / you. Same secrets, same custody rules.
  const pairCode = result.session.orgId.slice(0, 6).toUpperCase();
  const papers: CeremonyPaper[] = [
    {
      title: "CASE RECOVERY TALLY (cut this sheet in half)",
      who: "For the organization — opens cases when no one else can.",
      note: "One key, split into two halves. Cut along the line, keep one half, and give the other to someone you trust (an org admin, once you have one). Either half alone is useless; both together can open every case. Never store the two halves in the same place.",
      cut: true,
      sub: [
        {
          label: "SHARE 1 of 2 — keep this half",
          code: result.recoveryShareAPrinted,
          note: "If a half changes hands later, the receiver records it on their home screen.",
        },
        {
          label: "SHARE 2 of 2 — give this half away",
          code: result.recoveryShareBPrinted,
          note: "Recovering a case means typing both halves into one screen.",
        },
      ],
    },
    {
      title: "GOVERNANCE BACKUP",
      who: "For the organization, without you — keeps leadership going if you're gone.",
      note: "If you are ever unreachable, or lose your passphrase, an admin can use this paper to take over as head. It cannot read cases and cannot restore your account. Whoever holds it can claim leadership — store it offline, somewhere safe, away from your computer.",
      sub: [
        {
          label: "HEAD RECOVERY SECRET",
          code: result.headRecoverySecretPrinted,
          note: "Useless without the encrypted backup below.",
        },
        {
          label: "ENCRYPTED BACKUP",
          code: result.headPackageCtPrinted,
          note: "Locked — only the secret above opens it. Works even if the server's copy is lost.",
        },
      ],
    },
    {
      title: "YOUR ACCOUNT RECOVERY CODE",
      who: "For you — gets you back in if you forget your passphrase.",
      note: `Use "Recover account" on the front page with the login ID and code below. You keep your account and everything in it — you just choose a new passphrase. Because you are the head, this code can also restore leadership: guard it like the Governance backup, away from your computer, ideally not at home.`,
      sub: [
        {
          label: "YOUR LOGIN ID",
          code: result.session.userId,
          note: "Needed together with the code below.",
        },
        {
          label: "ACCOUNT RECOVERY CODE",
          code: result.accountRecoveryPrinted,
          note: "You can print a replacement any time from your home screen; the old code then stops working.",
        },
      ],
    },
  ];
  // Single-screen Emergency Bundle: all three
  // papers on one page, one print action, 1Password Emergency Kit shape.
  // Continue is gated on ONE typed "Confirm" — an acknowledgement, not
  // custody evidence (type-back verification stays deferred).
  const paperCard = (p: CeremonyPaper, idx: number) => `
      <div class="card">
        <h2>Paper ${idx + 1} — ${esc(p.title)}</h2>
        <p style="font-weight:600;color:#2e6b4f">${esc(p.who)}</p>
        <p>${esc(p.note)}</p>
        ${p.sub
          .map(
            (s, i) => `${
              p.cut && i === 1
                ? `<p class="muted" style="text-align:center;border-top:2px dashed #7d9a8c;padding-top:0.5rem;margin-top:1.1rem">✂ cut line on the printed sheet — pair code ${esc(pairCode)} appears on both halves</p>`
                : ""
            }
            <label>${esc(s.label)}</label>
            <div class="code-block">${esc(s.code)}</div>`,
          )
          .join("")}
      </div>`;
  app().innerHTML = `
      <div class="shell">
      ${bootRailHtml(2)}
      <div class="content"><div class="content-narrow">
      <h1>Your Emergency Bundle</h1>
      <div id="err"></div>
      <div class="card">
        <p>These three papers are your organization's <b>Emergency Bundle</b> — everything that
        can recover <b>cases</b>, <b>governance</b>, and <b>your account</b> if passphrases or
        devices are lost. Read each paper's storage instructions, then print the bundle at the
        bottom (careful hand copies work too).</p>
        <p class="muted">Shown ONCE. Nothing on this screen is stored on this device or the server.</p>
        <p class="muted"><b>Print only on a printer you trust</b> — one connected directly to this
        computer. Office and cloud print services can keep copies of every print job, and a copy
        of this bundle is a copy of every recovery power at once.</p>
      </div>
      ${papers.map(paperCard).join("")}
      <div class="card">
        <button id="print-all" class="btn-primary">Print your Emergency Bundle</button>
        <label>Type <b>Confirm</b> once you have printed (or hand-copied) your Emergency Bundle and stored each paper as instructed</label>
        <input id="confirm-word" autocomplete="off" placeholder="Confirm" />
        <button id="next" class="btn-primary" disabled>Continue</button>
        <p class="muted">Continue stays off until you confirm — this screen cannot be shown again.</p>
      </div>
      </div></div></div>`;
  document
    .getElementById("print-all")!
    .addEventListener("click", () => printPacket(papers, pairCode));
  $("confirm-word").addEventListener("input", () => {
    (document.getElementById("next") as HTMLButtonElement).disabled =
      $("confirm-word").value.trim().toLowerCase() !== "confirm";
  });
  document.getElementById("next")!.addEventListener("click", () => adminInvitesScreen());
}

function adminInvitesScreen() {
  app().innerHTML = `
    <div class="shell">
    ${bootRailHtml(3)}
    <div class="content"><div class="content-narrow">
    <h1>Invite your first members — now or later</h1>
    <div id="err"></div>
    <div class="card">
      <p>Generate an invite and share it <b>outside this system</b> — in person, by phone, or
      on paper. Your colleague opens this site, chooses "Join with an invite code", and their
      request appears below for you to approve.</p>
      <p>Everyone starts as a regular member. Later, promote the people you trust to admin from
      the Organization panel — once you've promoted two, admitting anyone new takes two admins
      instead of just you.</p>
      <button id="mk-member">Generate member invite</button>
      <div id="invites"></div>
      <p class="muted">Invites are single-use and saved to your account — come back and approve
      requests any time, from any device.</p>
    </div>
    <div class="card"><h2>Join requests</h2><div id="requests" class="muted">Waiting…</div></div>
    <button id="done" class="btn-primary">Finish bootstrap</button>
    <p class="muted">Finishing before you've promoted two admins asks you to confirm you're
    running solo.</p>
    </div></div></div>`;
  reloadInvites();
  const refreshInvites = () => {
    reloadInvites(); // re-derives from journal state; consumed ones vanish
    const el = document.getElementById("invites");
    if (el) el.innerHTML = inviteStatusHtml();
  };
  const mk = async () => {
    try {
      await addInvite();
      refreshInvites();
    } catch (e) {
      showError(e);
    }
  };
  document.getElementById("mk-member")!.addEventListener("click", () => mk());
  document.getElementById("done")!.addEventListener("click", async () => {
    await flows.sync(session!);
    const n = journal.activeAdmins(session!.state).length;
    if (
      n < 2 &&
      !confirm(
        `You have ${n} admin(s). Finish in SOLO GOVERNANCE mode?\n\nYou will admit members alone until two admins are appointed (you can do that any time from the head panel).`,
      )
    )
      return;
    go(homeScreen);
  });
  pollTimer = setInterval(() => {
    renderJoinRequests("requests", headActions());
    refreshInvites(); // invite pending→used chips update as approvals land
  }, 2000);
}

interface ReqAction {
  label: string;
  run: (req: flows.JoinRequest, printedInvite: string) => Promise<void>;
}

/** Render pending join requests with one button per available action. A
 * request is actionable only when its invite is in this tab's memory —
 * the lifecycle indicator (renderInviteStatus) is what keeps that true by
 * telling the issuer when reloading is safe. */
async function renderJoinRequests(targetId: string, actions: ReqAction[]) {
  if (!session) return;
  try {
    await flows.sync(session);
    const { requests } = await api.joinRequests(session.api);
    const pending = requests.filter((r) => !session!.state.members.has(r.user_id));
    pendingReqCount = pending.length; // feeds the sidebar's amber count
    const el = document.getElementById(targetId);
    if (!el) return;
    if (pending.length === 0) {
      el.innerHTML = `<span class="muted">No pending join requests.</span>`;
      delete el.dataset.rendered;
      return;
    }
    const html = pending
      .map((r, i) => {
        const m = matchInvite(r);
        return `<div style="margin-bottom:0.6rem">
          <span class="mono">${esc(r.user_id.slice(0, 16))}…</span>
          ${
            m
              ? `<span class="badge">invite: ${esc(m.label)}</span>`
              : `<span class="badge" style="background:#c0392b">invite not in this tab's memory</span>
                 <span class="muted">— issued in another tab or lost to a reload; issue a fresh invite for this person</span>`
          }
          ${actions.map((a, ai) => `<button class="req-act" data-i="${i}" data-ai="${ai}" ${m ? "" : "disabled"}>${esc(a.label)}</button>`).join("")}
        </div>`;
      })
      .join("");
    // don't clobber the DOM (and swallow in-flight clicks) when nothing
    // changed — the poll runs every 2s
    if (el.dataset.rendered === html) return;
    el.dataset.rendered = html;
    el.innerHTML = html;
    el.querySelectorAll("button.req-act").forEach((btn) =>
      btn.addEventListener("click", async () => {
        try {
          const req = pending[Number((btn as HTMLElement).dataset.i)]!;
          const m = matchInvite(req);
          if (!m) throw new Error("invite not in this tab's memory");
          await actions[Number((btn as HTMLElement).dataset.ai)]!.run(req, m.invite.printed);
        } catch (e) {
          showError(e);
        }
      }),
    );
  } catch {
    /* server unreachable between polls: retry next tick */
  }
}

/** Pending invites, derived from journal state: fully
 * asynchronous and device-independent — reload, log out, switch devices. */
function inviteStatusHtml(): string {
  if (issuedInvites.length === 0) return "";
  return (
    `<p class="muted">Pending invites — single-use, recorded in the journal with the code sealed to your
     identity — available on any device you unlock (they leave this list once used):</p>` +
    issuedInvites
      .map(
        (x) =>
          `<h2>Invite — ${esc(x.label)} <span class="badge" style="background:#b8860b">expires in ${Math.max(1, Math.round((x.expiresAt - Date.now()) / 3_600_000))}h</span></h2>
           <div class="code-block">${esc(x.invite.printed)}</div>`,
      )
      .join("")
  );
}

const matchInvite = (r: flows.JoinRequest) =>
  issuedInvites.find((x) => x.invite.inviteId === r.invite_id);

/** Head's actions on a join request: appoint as admin, or (until the
 * two-admin barrier arms) solo-admit as an ordinary member. */
function headActions(): ReqAction[] {
  // no admin appointment — everyone enters as a member. Below the
  // barrier the head admits solo; once armed, admissions are admin work
  // and the head's request list is watch-only.
  return session!.state.adminBarrierArmed
    ? []
    : [
        {
          label: "Admit as member (solo)",
          run: (r: flows.JoinRequest, p: string) => flows.admitMemberSolo(session!, r, p),
        },
      ];
}

// -- join (admin candidate or member) --

function joinScreen() {
  app().innerHTML = `
    <div class="narrow">
    <h1>Join this organization</h1>
    <div id="err"></div>
    <div class="card">
      <label>Invite code (received in person / by phone — never by email through this system)</label>
      <input id="invite" class="mono" placeholder="XXXX-XXXX-XXXX-…" />
      <label>Choose a passphrase</label>
      <input id="pw" type="password" autocomplete="new-password" />
      <label>Display name — shared with your organization once you're admitted (optional)</label>
      <input id="nick" placeholder="e.g. Maria" />
      <button id="go" class="btn-primary">Request to join</button>
    </div>
    </div>`;
  document.getElementById("go")!.addEventListener("click", async () => {
    try {
      const joined = await flows.joinWithInvite(API, $("pw").value, $("invite").value);
      const typedName = $("nick").value.trim();
      accounts.add(joined.userId, typedName || "me");
      // auto-published at first login AFTER admission — only a name the person actually typed
      if (typedName) localStorage.setItem(`tallystick.wantName.${joined.userId}`, typedName);
      app().innerHTML = `
        <div class="narrow">
        <h1>Request sent</h1>
        <div class="card">
          <p>Your login ID (public, random — <b>save it; you need it to log in</b>):</p>
          <div class="code-block">${esc(joined.userId)}</div>
          <p class="muted">Saved to this browser as "${esc($("nick").value || "me")}".</p>
          <p id="status">Waiting for approval…</p>
          <button id="to-login" disabled>Log in</button>
        </div>
        <div class="card">
          <h2>YOUR ACCOUNT RECOVERY CODE</h2>
          <div class="code-block">${esc(joined.recoveryPrinted)}</div>
          <p>Shown ONCE. If you ever forget your passphrase, this printed code (plus your login
          ID) restores your account — there is no other way back. Store it away from your
          computer, ideally not at home.</p>
          <button id="print-rec">Print</button>
        </div>
        </div>`;
      document
        .getElementById("print-rec")!
        .addEventListener("click", () =>
          printBlock(
            "ACCOUNT RECOVERY CODE",
            joined.recoveryPrinted,
            `Restores this account under a NEW passphrase if yours is forgotten — use "Recover account" on the front page, which needs this code AND the login ID: ${joined.userId}. Store it away from your computer, ideally not at home.`,
          ),
        );
      pollTimer = setInterval(async () => {
        const { entries } = await api.journalSince(joined.api, 0);
        try {
          const state = journal.replay(entries);
          const me = state.members.get(joined.userId);
          if (me) {
            document.getElementById("status")!.innerHTML =
              `<span class="ok">Approved as <b>${esc(me.role)}</b>.</span>`;
            (document.getElementById("to-login") as HTMLButtonElement).disabled = false;
          }
        } catch {
          /* halted journal surfaces at login */
        }
      }, 2000);
      document.getElementById("to-login")!.addEventListener("click", () => go(loginScreen));
    } catch (e) {
      showError(e);
    }
  });
}

// -- login --

async function loginScreen() {
  // validate cached handles against the server — a restarted (in-memory)
  // server has no accounts, so stale handles are pruned here
  const saved = await accounts.validate();
  app().innerHTML = `
    <div class="narrow">
    <h1>Log in</h1>
    <div id="err"></div>
    <div class="card">
      ${
        saved.length
          ? `<label>Account</label><select id="acct">
             ${saved.map((a) => `<option value="${esc(a.userId)}">${esc(a.nickname)} (${esc(a.userId.slice(0, 8))}…)</option>`).join("")}
             <option value="">— enter a login ID manually —</option></select>`
          : ""
      }
      <label>Login ID</label>
      <input id="uid" class="mono" value="${esc(saved[0]?.userId ?? "")}" />
      <label>Passphrase</label>
      <input id="pw" type="password" autocomplete="current-password" />
      <button id="go" class="btn-primary">Unlock</button>
      <p class="muted">Unlocking derives your keys locally and replays the signed journal.
      Your passphrase never leaves this device.</p>
    </div>
    </div>`;
  document.getElementById("acct")?.addEventListener("change", () => {
    $("uid").value = ($("acct") as unknown as HTMLSelectElement).value;
  });
  document.getElementById("go")!.addEventListener("click", async () => {
    try {
      app().insertAdjacentHTML("beforeend", `<p class="muted">Deriving keys…</p>`);
      session = await flows.login(API, $("uid").value.trim(), $("pw").value);
      await persistCurrentSession();
      armIdleLock();
      void maybePublishName();
      go(homeScreen);
    } catch (e) {
      showError(e);
    }
  });
}

// -- home --

// -- recovery panels: custody, succession, case rekey --

function custodyLineHtml(s: flows.Session): string {
  const c = s.state.shareCustody;
  const label = (h?: string) =>
    h ? `<span class="mono">${esc(who(h))}</span>${h === s.userId ? " (you)" : ""}` : "unrecorded";
  return `Share 1 — ${label(c.A)} · Share 2 — ${label(c.B)}`;
}

/** Governance & custody card (head and admins). */
function governanceCardHtml(s: flows.Session, myRole: journal.Role): string {
  const admins = journal.activeAdmins(s.state);
  const adminOptions = admins
    .map((id) => `<option value="${esc(id)}">${esc(who(id))}</option>`)
    .join("");
  return `<div class="card"><h2>Recovery custody &amp; succession</h2>
    <p class="muted">Printed-share custody (journaled): ${custodyLineHtml(s)}</p>
    <button class="ack-share" data-share="A">I now hold share 1</button>
    <button class="ack-share" data-share="B">I now hold share 2</button>
    <p class="muted">Acknowledge only after physically receiving the printed paper — the journal
    records who to ask when a case must be recovered.</p>
    ${
      myRole === "head"
        ? `<details class="section" data-dkey="succ"><summary id="open-succ">Succession <span class="muted">— hand governance to an active admin</span></summary>
           <p class="muted">They first use "Prepare to become head" on THEIR account and give you
           the key string it shows. You drop to ordinary member; their admin seat empties
           (promote a replacement afterwards).</p>
           ${
             admins.length
               ? `<label>Successor (an active admin)</label><select id="succ-to">${adminOptions}</select>
                  <label>Successor's succession code</label>
                  <input id="succ-pk" class="mono" placeholder="from their Prepare step (checksum-protected)" />
                  <button id="succ-go" class="btn-primary">Sign succession</button>`
               : `<p class="muted">No active admins yet — succession needs one.</p>`
           }
           </details>
           <details class="section" data-dkey="gov"><summary id="open-gov">Governance key <span class="muted">— rotate, or print a fresh head package</span></summary>
           <label>Rotate the governance key (suspected head-package theft) — your passphrase</label>
           <input id="rot-pw" type="password" />
           <button id="rot-go">Rotate &amp; show new package</button>
           <button id="new-package">Print a fresh head recovery package</button>
           <p class="muted">Rotation makes every previous head-package paper dead. Either action
           shows the new secret and encrypted backup to print.</p>
           </details>`
        : `<details class="section" data-dkey="prep"><summary id="open-prep">Prepare to become head <span class="muted">— generate the key you hand to the current head</span></summary>
           <label>Your passphrase</label>
           <input id="prep-pw" type="password" />
           <button id="prep-go" class="btn-primary">Prepare</button>
           <div id="prep-out"></div>
           </details>
           <details class="section" data-dkey="em"><summary id="open-em">Emergency succession <span class="muted">— the current head is gone</span></summary>
             <p class="muted">Whoever holds the printed head package can sign succession — that
             custody IS the authority. First "Prepare" above, then enter the papers.</p>
             <label>Printed HEAD RECOVERY SECRET</label><input id="em-secret" class="mono" />
             <label>Printed HEAD PACKAGE BACKUP (only if the server copy is gone)</label>
             <input id="em-ct" class="mono" />
             <label>New head (an active admin)</label><select id="em-to">${adminOptions}</select>
             <label>Their succession code (from the Prepare step)</label>
             <input id="em-pk" class="mono" />
             <button id="em-go" class="btn-primary">Sign emergency succession</button>
           </details>`
    }
  </div>`;
}

/** Case restore/re-key ceremony card (head and admins). Lists ALL cases
 * from public journal state — tags and counts only; content stays sealed
 * until both shares are entered. */
function caseRecoveryCardHtml(s: flows.Session): string {
  const cases = [...s.state.cases.entries()];
  const armed = s.state.adminBarrierArmed;
  const memberOptions = [...s.state.members.keys()]
    .map(
      (id) =>
        `<option value="${esc(id)}">${esc(who(id))} (${esc(s.state.members.get(id)!.role)})</option>`,
    )
    .join("");
  const pending = [...s.state.pendingRekeys.entries()];
  return `<div class="card"><h2>Case recovery — restore or re-key</h2>
    <p class="muted">For a case nobody can open (creator gone or locked out) or one that must be
    rotated away from a compromised account. Needs BOTH printed shares — bring the two
    custodians to this screen.${armed ? " A second admin must countersign before anything changes." : ""}</p>
    ${
      cases.length === 0
        ? `<p class="muted">No cases exist yet.</p>`
        : `<label>Case (public metadata only)</label>
           <select id="rk-case">${cases
             .map(
               ([tag, c]) =>
                 `<option value="${esc(tag)}">${esc(tag.slice(0, 12))}… · created by ${esc(who(c.creatorId))} · epoch ${c.epochs.length} · ${c.notes.size} note(s)</option>`,
             )
             .join("")}</select>
           <label>Recovery share 1</label><input id="rk-a" class="mono" placeholder="XXXX-XXXX-…" />
           <label>Recovery share 2</label><input id="rk-b" class="mono" placeholder="XXXX-XXXX-…" />
           <label>Restore access to (hold ctrl/cmd to pick several)</label>
           <select id="rk-holders" multiple>${memberOptions}</select>
           <button id="rk-go" class="btn-primary">${armed ? "Propose restore" : "Restore"}</button>
           <button id="rk-read">Read only — no restore, leaves no journal record</button>
           <div id="rk-out"></div>`
    }
    ${
      pending.length
        ? `<h2>Pending re-key proposals</h2>` +
          pending
            .map(
              ([id, p]) =>
                `<div><span class="mono">${esc(p.payload.case_tag.slice(0, 12))}…</span>
                 proposed by <span class="mono">${esc(who(p.proposedBy))}</span>
                 ${
                   p.proposedBy !== s.userId
                     ? `<button class="rk-approve" data-id="${esc(id)}">Countersign</button>`
                     : `<span class="muted">awaiting the other admin</span>`
                 }</div>`,
            )
            .join("")
        : ""
    }
  </div>`;
}

function wireRecoveryPanels(s: flows.Session, render: () => void): void {
  const val = (id: string) => ($(id) as HTMLInputElement | null)?.value.trim() ?? "";
  const run = (fn: () => Promise<void>) => async () => {
    try {
      await fn();
    } catch (e) {
      showError(e);
    }
  };
  app()
    .querySelectorAll("button.ack-share")
    .forEach((b) =>
      b.addEventListener(
        "click",
        run(async () => {
          const share = (b as HTMLElement).dataset.share as "A" | "B";
          if (
            !confirm(
              `Record in the journal that YOU physically hold printed share ${share === "A" ? 1 : 2}?`,
            )
          )
            return;
          await flows.ackShareCustody(s, share);
          render();
        }),
      ),
    );
  document.getElementById("succ-go")?.addEventListener(
    "click",
    run(async () => {
      const to = ($("succ-to") as unknown as HTMLSelectElement).value;
      if (!val("succ-pk")) throw new Error("enter the successor's succession code");
      if (!confirm("Sign the succession? You become an ordinary member; their admin seat empties."))
        return;
      await flows.succeedHead(s, to, val("succ-pk"));
      render();
    }),
  );
  const showPackage = (pkg: { headSecretPrinted: string; headPackageCtPrinted: string }) => {
    app().innerHTML = `
      <div class="narrow">
      <h1>New head recovery package</h1>
      <div class="card">
        <h2>HEAD RECOVERY SECRET (new)</h2>
        <div class="code-block">${esc(pkg.headSecretPrinted)}</div>
        <h2>HEAD PACKAGE BACKUP (new, encrypted)</h2>
        <div class="code-block">${esc(pkg.headPackageCtPrinted)}</div>
        <p>Print BOTH and destroy any previous head-package papers — they are now dead.</p>
        <button id="print">Print</button>
        <label style="display:flex;gap:0.5rem;align-items:center;font-weight:400"><input type="checkbox" id="confirm" style="width:auto;margin:0"/> I have printed or hand-copied both</label>
        <button id="next" class="btn-primary" disabled>Done</button>
      </div>
      </div>`;
    document
      .getElementById("print")!
      .addEventListener("click", () =>
        printBlock(
          "HEAD RECOVERY PACKAGE",
          `SECRET:\n${pkg.headSecretPrinted}\n\nENCRYPTED BACKUP:\n${pkg.headPackageCtPrinted}`,
          "Restores the head governance key: the SECRET decrypts the ENCRYPTED BACKUP (kept on the " +
            "server too — the backup here covers server loss). Whoever holds this page can sign " +
            "governance actions and succession — its custody IS the succession authority. Every " +
            "previously printed head package is now dead paper.",
        ),
      );
    $("confirm").addEventListener("change", () => {
      (document.getElementById("next") as HTMLButtonElement).disabled = !$("confirm").checked;
    });
    document.getElementById("next")!.addEventListener("click", render);
  };
  document.getElementById("rot-go")?.addEventListener(
    "click",
    run(async () => {
      if (!val("rot-pw")) throw new Error("enter your passphrase");
      if (!confirm("Rotate the governance key? Every existing head-package paper becomes dead."))
        return;
      showPackage(await flows.rotateGovernance(s, val("rot-pw")));
    }),
  );
  document.getElementById("new-package")?.addEventListener(
    "click",
    run(async () => {
      showPackage(await flows.createHeadPackage(s));
    }),
  );
  document.getElementById("prep-go")?.addEventListener(
    "click",
    run(async () => {
      if (!val("prep-pw")) throw new Error("enter your passphrase");
      const code = await flows.prepareSuccession(s, val("prep-pw"));
      document.getElementById("prep-out")!.innerHTML = `
        <p>Give this SUCCESSION CODE to the current head (or use it below for emergency
        succession). It carries the new governance public key plus proof that this account
        holds its private half — and a checksum, so a typo fails loudly instead of
        bricking governance:</p>
        <div class="code-block">${esc(code)}</div>`;
    }),
  );
  document.getElementById("em-go")?.addEventListener(
    "click",
    run(async () => {
      const to = ($("em-to") as unknown as HTMLSelectElement).value;
      if (!confirm("Sign the emergency succession with the printed head package?")) return;
      await flows.emergencySucceedHead(
        s,
        val("em-secret"),
        to,
        val("em-pk"),
        val("em-ct") || undefined,
      );
      render();
    }),
  );
  const rekeyInputs = () => {
    const holders = [
      ...(($("rk-holders") as unknown as HTMLSelectElement)?.selectedOptions ?? []),
    ].map((o) => o.value);
    return { caseTag: ($("rk-case") as unknown as HTMLSelectElement).value, holders };
  };
  document.getElementById("rk-go")?.addEventListener(
    "click",
    run(async () => {
      const { caseTag, holders } = rekeyInputs();
      if (holders.length === 0) throw new Error("pick at least one member to restore access to");
      const rekeyId = await flows.rekeyCase(s, caseTag, holders, val("rk-a"), val("rk-b"));
      render();
      if (rekeyId)
        alert("Restore proposed — a second admin must countersign it from their home screen.");
    }),
  );
  document.getElementById("rk-read")?.addEventListener(
    "click",
    run(async () => {
      const { caseTag } = rekeyInputs();
      const kp = flows.joinRecoveryShares(s.state, val("rk-a"), val("rk-b"));
      const notes = flows.recoverReadCase(s, caseTag, kp);
      document.getElementById("rk-out")!.innerHTML =
        `<p class="muted">Recovered read-only view (nothing was changed or recorded):</p>` +
        notes
          .filter((n) => n.text.trim().length > 0) // header/meta-only records have no body
          .map((n) => `<pre class="mono" style="white-space:pre-wrap">${esc(n.text)}</pre>`)
          .join("");
    }),
  );
  app()
    .querySelectorAll("button.rk-approve")
    .forEach((b) =>
      b.addEventListener(
        "click",
        run(async () => {
          if (
            !confirm("Countersign this re-key? The case is re-encrypted for the proposed holders.")
          )
            return;
          await flows.approveRekey(s, (b as HTMLElement).dataset.id!);
          render();
        }),
      ),
    );
}

/** Post-login landing: org people land on Organization (pending work
 * first); members land on Cases. */
function homeScreen() {
  if (!session) return go(landing);
  const r = flows.role(session);
  return r === "head" || r === "admin" ? orgScreen() : casesScreen();
}

const haltedBanner = (s: flows.Session) =>
  s.halted
    ? `<div class="halted">JOURNAL HALTED at seq ${s.halted.seq}: ${esc(s.halted.reason)} — this client will not process further entries. Contact your admins.</div>`
    : "";

// -- Cases panel --

let casesFilter: "open" | "closed" | "archived" = "open";

function casesScreen() {
  if (!session) return go(landing);
  breadcrumb.set("cases");
  const s = session;
  const render = () => {
    const seen = seenMap(s);
    const allCases = flows.listCases(s);
    const deadlines = flows.upcomingDeadlines(s).slice(0, 5);
    const count = (st: string) => allCases.filter((c) => c.status === st).length;
    const cases = allCases.filter((c) => c.status === casesFilter);
    const changedSinceLook = (c: flows.CaseView) =>
      c.records.some((n) => {
        const at = seen.get(`${c.caseTag}/${n.recordId}`);
        return at !== undefined && n.lastSeq > at;
      });
    app().innerHTML = `
      ${haltedBanner(s)}
      <div class="shell">
      ${sidebarHtml(s, "cases")}
      <div class="content"><div class="content-narrow">
        <div id="err"></div>
        <div class="card">
          <input id="search" placeholder="Search notes… (only cases your keys open; the index never leaves this tab)" style="max-width:100%" />
          <div id="search-results"></div>
        </div>
        ${
          deadlines.length
            ? `<div class="card"><h2>Upcoming deadlines</h2>
               ${deadlines
                 .map(
                   (d) => `<div class="case-row"><div style="flex-grow:1">
                     <b>${esc(d.text)}</b> <span class="muted">— ${esc(d.caseTitle)}</span>
                     <span class="badge" style="background:${d.overdue ? "#c0392b" : "#55665c"}">${d.overdue ? "overdue · " : "due "}${esc(fmtWhen(d.due))}</span>
                   </div><button data-tag="${esc(d.caseTag)}" class="open-case">Open</button></div>`,
                 )
                 .join("")}</div>`
            : ""
        }
        <div class="card">
          <h2>Cases</h2>
          <p class="muted">Your keychain — what your keys open. Nothing else exists here.</p>
          <div style="display:flex;gap:0.4rem;margin:0.4rem 0 0.6rem 0">
            ${(["open", "closed", "archived"] as const)
              .map(
                (st) =>
                  `<button class="case-filter${casesFilter === st ? " btn-primary" : ""}" data-st="${st}">${st} (${count(st)})</button>`,
              )
              .join("")}
          </div>
          <div id="cases">${
            cases.length === 0
              ? `<span class="muted">No ${casesFilter} cases.</span>`
              : cases
                  .map(
                    (c) => `<div class="case-row">
                      <div style="flex-grow:1">
                        <div class="case-label">${esc(c.title)}
                          ${changedSinceLook(c) ? `<span class="badge updated">updated</span>` : ""}
                          ${c.records.some((n) => n.locked) ? `<span class="badge" style="background:#c0392b">locked</span>` : ""}
                        </div>
                        <div class="muted">epoch ${c.epoch} · ${c.notes.length} note(s) · ${c.contacts.length} contact(s) · ${c.tasks.filter((t) => t.meta["done"] !== true).length} open task(s) · ${c.holders.length} member(s)</div>
                      </div>
                      <button data-tag="${esc(c.caseTag)}" class="open-case">Open</button>
                    </div>`,
                  )
                  .join("")
          }</div>
        </div>
        <div class="card">
          <h2>Create a case</h2>
          <label>Case title</label>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <input id="new-case" placeholder="Synthetic intake #…" style="flex-grow:1;max-width:none" />
            <button id="mk-case" class="btn-primary">Create case</button>
          </div>
          <p class="muted">Synthetic data only. Case content is encrypted in this tab; the server
          stores ciphertext and an opaque case tag.</p>
        </div>
      </div></div></div>`;
    // "updated" = changed since this session last looked; first sight seeds
    // silently (pre-login history is not "new")
    for (const c of allCases)
      for (const n of c.records) {
        const k = `${c.caseTag}/${n.recordId}`;
        if (!seen.has(k)) seen.set(k, n.lastSeq);
      }
    app()
      .querySelectorAll("button.open-case")
      .forEach((b) =>
        b.addEventListener("click", () => go(() => caseScreen((b as HTMLElement).dataset.tag!))),
      );
    document.getElementById("search")!.addEventListener("input", () => {
      const q = $("search").value;
      const out = document.getElementById("search-results")!;
      if (!q.trim()) return void (out.innerHTML = "");
      const hits = flows.searchNotes(s, q);
      out.innerHTML =
        hits.length === 0
          ? `<p class="muted">No matches in your cases.</p>`
          : hits
              .map(
                (
                  h,
                ) => `<div><b>${esc(h.caseLabel)}</b> — <span class="muted">${esc(h.snippet)}</span>
                 <button class="open-hit" data-tag="${esc(h.caseTag)}">Open</button></div>`,
              )
              .join("");
      out
        .querySelectorAll("button.open-hit")
        .forEach((b) =>
          b.addEventListener("click", () => go(() => caseScreen((b as HTMLElement).dataset.tag!))),
        );
    });
    app()
      .querySelectorAll("button.case-filter")
      .forEach((b) =>
        b.addEventListener("click", () => {
          casesFilter = (b as HTMLElement).dataset.st as typeof casesFilter;
          render();
        }),
      );
    document.getElementById("mk-case")!.addEventListener("click", async () => {
      try {
        if (!$("new-case").value.trim()) throw new Error("give the case a title");
        await flows.createCase(s, "", $("new-case").value.trim());
        render();
      } catch (e) {
        showError(e);
      }
    });
    wireSidebar();
  };
  render();
  pollTimer = setInterval(async () => {
    const before = s.state.chain.seq;
    await flows.sync(s);
    if (s.state.chain.seq !== before || s.halted) {
      const restore = snapshotInputs(); // background render must not eat typing
      render();
      restore();
    }
  }, 2000);
}

// -- Organization panel (head and admins) --

function headJoinCardHtml(s: flows.Session): string {
  const admins = journal.activeAdmins(s.state).length;
  return `<div class="card"><h2>Join requests &amp; invites</h2>
    ${
      !s.state.adminBarrierArmed
        ? `<p><b>Solo governance</b> (${admins}/2 admins): you admit members alone
           and the two-person admission safeguard is OFF. Promote members to admin from the
           roster — the second promotion turns it on permanently.</p>
           <button id="mk-head-member-invite">Generate member invite (solo)</button>`
        : `<p class="muted">The two-admin safeguard is armed${admins < 2 ? ` — but only ${admins} admin(s) are active, so admissions are stuck until you promote a member from the roster to restore the pair` : " — admissions require both admins"}. Solo admission stays permanently off.</p>`
    }
    <div id="invites">${inviteStatusHtml()}</div>
    <h2>Join requests</h2><div id="requests" class="muted">Waiting…</div></div>`;
}

function rosterCardHtml(s: flows.Session, myRole: journal.Role): string {
  const roster = [...s.state.members.entries()];
  const headActionsCol = myRole === "head";
  return `<div class="card"><h2>Roster${headActionsCol ? "" : ` <span class="muted" style="font-weight:400">read-only</span>`}</h2>
    <p class="muted">Derived from the signed journal — not a server list.${headActionsCol ? "" : " Titles are granted and removed by the head."}</p>
    <table><tr><th>ID</th><th>role</th><th>admitted at seq</th>${headActionsCol ? "<th></th>" : ""}</tr>
    ${roster
      .map(
        ([
          id,
          m,
        ]) => `<tr><td class="mono">${esc(whoFull(id))}${id === s.userId ? ` <span class="muted" style="font-family:system-ui,sans-serif">(you)</span>` : ""}</td><td>${esc(m.role)}</td><td>${m.admittedAtSeq}</td>
         ${
           headActionsCol
             ? `<td>${
                 m.role === "member" && journal.activeAdmins(s.state).length < 2
                   ? `<button class="promote" data-uid="${esc(id)}">Make admin</button>`
                   : m.role === "admin"
                     ? `<button class="demote" data-uid="${esc(id)}">Remove admin</button>`
                     : ""
               }</td>`
             : ""
         }</tr>`,
      )
      .join("")}
    </table>
    ${headActionsCol ? `<p class="muted">Admin is a title: you can grant and remove it. Removing an admin does NOT retrieve a printed recovery share they hold, and once two admins have ever existed, solo admission stays off.</p>` : ""}</div>`;
}

function adminAdmissionsCardHtml(s: flows.Session): string {
  const proposals = [...s.state.proposals.entries()].filter(([, p]) => p.proposedBy !== s.userId);
  return `<div class="card"><h2>Admissions</h2>
    <p class="muted">Admissions take BOTH admins: one proposes, the other verifies the invite code
    independently.</p>
    ${
      proposals.length === 0
        ? `<p class="muted">No proposals awaiting your approval.</p>`
        : proposals
            .map(
              ([pid, p]) => `<div><span class="mono">${esc(p.payload.user_id.slice(0, 16))}…</span>
               <label>Enter the invite code you received for this person</label>
               <div style="display:flex;gap:0.5rem;align-items:center">
                 <input class="mono" id="code-${esc(pid)}" placeholder="XXXX-XXXX-…" style="flex-grow:1;max-width:none" />
                 <button data-pid="${esc(pid)}" class="approve btn-primary">Verify &amp; approve</button>
               </div></div>`,
            )
            .join("")
    }
    <h2>Join requests</h2><div id="requests" class="muted">Waiting…</div>
    <button id="mk-invite">Generate member invite</button>
    <div id="invites">${inviteStatusHtml()}</div>
    <p class="muted">Deliver the invite out of band to the joining person AND to the other admin
    (they need it to verify).</p></div>`;
}

function orgScreen() {
  if (!session) return go(landing);
  breadcrumb.set("org");
  const s = session;
  reloadInvites(); // journal state → memory; consumed invites already gone
  const render = () => {
    const myRole = flows.role(s);
    if (myRole !== "head" && myRole !== "admin") return go(casesScreen); // role moved on
    // keep ceremony sections open across the rebuild
    const openDetails = new Set(
      [...app().querySelectorAll<HTMLElement>("details[open][data-dkey]")].map(
        (d) => d.dataset.dkey!,
      ),
    );
    app().innerHTML = `
      ${haltedBanner(s)}
      <div class="shell">
      ${sidebarHtml(s, "org")}
      <div class="content"><div class="content-wide">
        <div id="err"></div>
        <div class="grid2">
          ${myRole === "head" ? rosterCardHtml(s, myRole) + headJoinCardHtml(s) : adminAdmissionsCardHtml(s) + rosterCardHtml(s, myRole)}
          ${governanceCardHtml(s, myRole)}
          ${caseRecoveryCardHtml(s)}
        </div>
      </div></div></div>`;
    app()
      .querySelectorAll<HTMLDetailsElement>("details[data-dkey]")
      .forEach((d) => {
        if (openDetails.has(d.dataset.dkey!)) d.open = true;
      });
    wireSidebar();
    const mkHeadInvite = async () => {
      try {
        await addInvite(); // journaled: recoverable on any device after sync
        render();
      } catch (e) {
        showError(e);
      }
    };
    document
      .getElementById("mk-head-member-invite")
      ?.addEventListener("click", () => mkHeadInvite());
    document.getElementById("mk-invite")?.addEventListener("click", async () => {
      try {
        await addInvite();
        render();
      } catch (e) {
        showError(e);
      }
    });
    app()
      .querySelectorAll("button.promote")
      .forEach((b) =>
        b.addEventListener("click", async () => {
          try {
            await flows.promoteToAdmin(s, (b as HTMLElement).dataset.uid!);
            render();
          } catch (e) {
            showError(e);
          }
        }),
      );
    app()
      .querySelectorAll("button.demote")
      .forEach((b) =>
        b.addEventListener("click", async () => {
          try {
            const uid = (b as HTMLElement).dataset.uid!;
            if (
              !confirm(
                "Remove this admin? Their printed recovery share (if any) stays with them, and solo admission does NOT come back.",
              )
            )
              return;
            await flows.demoteAdmin(s, uid);
            render();
          } catch (e) {
            showError(e);
          }
        }),
      );
    app()
      .querySelectorAll("button.approve")
      .forEach((btn) =>
        btn.addEventListener("click", async () => {
          try {
            const pid = (btn as HTMLElement).dataset.pid!;
            const code = ($(`code-${pid}`) as HTMLInputElement).value;
            await flows.approveMember(s, pid, code, Date.now());
            render();
          } catch (e) {
            showError(e);
          }
        }),
      );
    wireRecoveryPanels(s, render);
  };
  render();
  pollTimer = setInterval(async () => {
    const before = s.state.chain.seq;
    await flows.sync(s);
    if (s.state.chain.seq !== before || s.halted) {
      reloadInvites(); // new journal state may have consumed invites
      const restore = snapshotInputs(); // background render must not eat typing
      render();
      restore();
    }
    const liveRole = flows.role(s); // may have changed over sync
    if (liveRole === "admin")
      renderJoinRequests("requests", [
        {
          label: "Propose member",
          run: async (req, printed) => {
            await flows.proposeMember(s, req, printed, Date.now());
            render();
          },
        },
      ]);
    if (liveRole === "head")
      renderJoinRequests(
        "requests",
        // wrap: actions sync internally, so the seq-change poll check won't
        // fire afterwards — re-render explicitly on success
        headActions().map((a) => ({
          ...a,
          run: async (r: flows.JoinRequest, p: string) => {
            await a.run(r, p);
            reloadInvites();
            render();
          },
        })),
      );
  }, 2000);
}

// -- Device & session --------

function sessionScreen() {
  if (!session) return go(landing);
  const s = session;
  const render = () => {
    const idleMin = idleLockMs() / 60000;
    app().innerHTML = `
      ${haltedBanner(s)}
      <div class="shell">
      ${sidebarHtml(s, "help")}
      <div class="content"><div class="content-narrow">
        <h1 style="margin-top:0.2rem">Device &amp; session</h1>
        <div id="err"></div>
        <div class="card"><h2>Display name</h2>
          <p class="muted">Shown to everyone in your organization instead of your random ID —
          delivered inside sealed boxes; the server never sees it. Leave it blank to stay
          ID-only. If two people pick the same name, IDs are shown alongside.</p>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <input id="disp-name" value="${esc(flows.displayNames(s)[s.userId] ?? "")}" placeholder="e.g. Maria" style="flex-grow:1;max-width:none" />
            <button id="save-disp" class="btn-primary">Publish</button>
          </div>
        </div>
        <div class="card"><h2>Auto-lock</h2>
          <p class="muted">This device locks after inactivity — memory is wiped and the
          server-side unlock key is revoked, so a walk-up refresh cannot get back in.</p>
          <label>Lock after</label>
          <select id="idle-select" style="max-width:12rem">
            ${IDLE_CHOICES_MIN.map((m) => `<option value="${m}"${m === idleMin ? " selected" : ""}>${m} minutes</option>`).join("")}
          </select>
        </div>
        <div class="card"><h2>Other devices</h2>
          <p class="muted">Ends every other logged-in session of YOUR account — their stay-unlocked
          keys are revoked and their sync tokens die. Use it for a lost laptop or a shared
          computer you forgot to lock.</p>
          <button id="logout-others" class="btn-primary">Log out my other devices</button>
          <span id="others-result" class="muted"></span>
        </div>
      </div></div></div>`;
    wireSidebar();
    document.getElementById("idle-select")?.addEventListener("change", () => {
      localStorage.setItem(
        "tallystick.idleMinutes",
        ($("idle-select") as unknown as HTMLSelectElement).value,
      );
      armIdleLock();
      showOk("Auto-lock updated for this device.");
    });
    document.getElementById("save-disp")?.addEventListener("click", async () => {
      try {
        await flows.publishDisplayName(s, $("disp-name").value);
        showOk("Published — colleagues see it after their next sync.");
      } catch (e) {
        showError(e);
      }
    });
    document.getElementById("logout-others")?.addEventListener("click", async () => {
      try {
        if (!confirm("End every other logged-in session of your account?")) return;
        const n = await flows.logOutOtherDevices(s);
        document.getElementById("others-result")!.textContent =
          n === 0 ? "No other sessions were active." : `${n} other session(s) logged out.`;
      } catch (e) {
        showError(e);
      }
    });
  };
  render();
  pollTimer = setInterval(async () => {
    await flows.sync(s);
  }, 2000);
}

// -- Help (role-filtered; the design's per-card ⓘ marks link here) --

function helpScreen() {
  if (!session) return go(landing);
  breadcrumb.set("help");
  const s = session;
  const myRole = flows.role(s);
  const org = myRole === "head" || myRole === "admin";
  const entry = (q: string, a: string, tag?: string) =>
    `<details class="card" style="padding:0.9rem 1rem;margin:0.6rem 0"><summary style="cursor:pointer;font-weight:600">${esc(q)}${tag ? `<span class="badge">${esc(tag)}</span>` : ""}</summary>
     <p style="margin:0.5rem 0 0 0;line-height:1.5">${a}</p></details>`;
  app().innerHTML = `
    ${haltedBanner(s)}
    <div class="shell">
    ${sidebarHtml(s, "help")}
    <div class="content"><div class="content-narrow">
      <h1 style="margin-top:0.2rem">Help</h1>
      <p class="muted">What you see here is filtered to your role. Answers live in this tab — no
      external links, nothing leaves this device.</p>
      ${entry(
        "Who can read a case?",
        `Only the people on the case's member list. Everything in a case is encrypted in your
         browser before it leaves; the server stores ciphertext and an opaque tag and cannot read
         content. A case you were never granted does not appear anywhere on your screen — that is
         by design, not a bug.`,
      )}
      ${entry(
        "What goes where in a case?",
        `<b>Case Bio</b> — a quick orientation paragraph, the first thing shown when a case is
         opened (the other sections start collapsed). <b>Tasks</b> — next steps with due
         dates; open dated tasks across all your cases feed the "Upcoming deadlines" list on the
         Cases panel. <b>Notes</b> — the working narrative. <b>Contact log</b> — one dated entry
         per session, call, or court date, each attributed to whoever logged it and provable
         against the org's records. Saved text shows read-only; Edit reopens it.`,
      )}
      ${entry(
        "What do the badges mean?",
        `<span class="badge updated" style="margin-left:0">updated</span> — a colleague changed the
         case since you last looked. <span class="badge" style="background:#c0392b;margin-left:0">locked</span>
         — your key no longer opens it; access was rotated away from this account (what you saw
         before stays seen; nothing new is readable).
         <span class="badge" style="background:#55665c;margin-left:0">due</span> /
         <span class="badge" style="background:#c0392b;margin-left:0">overdue</span> — a dated
         task's deadline.`,
      )}
      ${entry(
        "What happens to a note while I'm typing?",
        `Your unsaved text is never overwritten: if a colleague's change arrives mid-edit you'll
         see a notice, and Save merges your edit with theirs. The History button on every note
         shows who changed what, when.`,
      )}
      ${entry(
        "Display names",
        `Optional. Your name travels only inside sealed boxes addressed to each colleague — the
         server never sees it; leave it blank to stay ID-only. If two people pick the same name,
         IDs are shown alongside. Set or change yours under "Device &amp; session" in the sidebar.`,
      )}
      ${entry(
        "Staying unlocked, auto-lock, and lost devices",
        `Refreshing the page keeps you signed in: your device holds only a locked copy of your
         keys, and the server holds the key to that lock — neither works alone. Walk away and this
         device locks itself after the timeout you choose (Device &amp; session), wiping memory and
         revoking the server-side key, so a refresh can't get past it. Lost a laptop? "Log out my
         other devices" ends every other session of your account remotely.`,
      )}
      ${entry(
        "I forgot my passphrase",
        `Your printed <b>account recovery code</b> is the only way back — nobody can reset the
         passphrase for you. Log out, choose "Recover account" on the front page, and enter your
         login ID plus the printed code; you'll set a new passphrase and print a fresh code. If you
         have lost BOTH the passphrase and the code, this account cannot be recovered — ask for a
         new invite, and the org can restore cases you created through the recovery ceremony.`,
      )}
      ${entry(
        "How do invites and admins work?",
        `Everyone joins the same way: one printed invite string, delivered out of band — in
         person, by phone, on paper, never through this system — single-use, expiring after 72
         hours. Everyone enters as an ordinary member; admins are made by the head promoting
         members from the roster. Once two admins exist, every admission needs one admin to
         propose and the other to independently re-type the invite code — that re-entry IS the
         verification.`,
      )}
      ${entry(
        "Can I attach files?",
        `Not yet — a decision, not an oversight. Attachments will be encrypted like everything
         else, but the design work they need (hiding file-size fingerprints from the server,
         storage, retention rules) is real and is planned for after the prototype. Until then,
         keep documents in your organization's existing secure storage and reference them from a
         note.`,
      )}
      ${
        org
          ? entry(
              "Restore a case nobody can open",
              `Organization → Case recovery. Bring BOTH halves of the recovery tally sheet to one
               screen — their custodians together — pick the case, enter the two codes (the pair
               code printed on each half confirms they belong together), and choose who gets
               access. Below two admins the head restores alone; once the safeguard is armed a
               second admin must countersign. "Read only" decrypts without changing anything — and
               leaves no journal record.`,
              "head · admin",
            )
          : ""
      }
      ${
        org
          ? entry(
              "Printed papers and who holds them",
              `Three papers exist from setup: the <b>recovery tally sheet</b> (cut in half — the
               two halves must never live together), the <b>governance backup</b>, and each
               member's personal <b>recovery code</b>. The journal records who claims each tally
               half — when one physically changes hands, the RECEIVER records it ("I now hold
               share…"); that record is an honor-system claim, useful for knowing whom to ask.
               Handing over the head role uses a succession code from the successor's "Prepare"
               step; succession or key rotation makes every older governance-backup paper dead.`,
              "head · admin",
            )
          : ""
      }
      ${myRole === "member" ? `<p class="muted">Organization management (roster, invites, recovery ceremonies) is head/admin work — an Organization panel appears if you're ever promoted.</p>` : ""}
    </div></div></div>`;
  wireSidebar();
  pollTimer = setInterval(async () => {
    await flows.sync(s); // keep verifying; badges refresh on next screen
  }, 2000);
}

// -- case view (workflow steps 3–9) --

/** display formatting for the encrypted client timestamps (legibility only — journal seq stays the cryptographic ordering) */
const fmtWhen = (ms: number | null) =>
  ms === null
    ? ""
    : new Date(ms).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
const fmtWhenFull = (ms: number | null) =>
  ms === null
    ? ""
    : new Date(ms).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      });

const CHANNEL_LABELS: Record<string, string> = {
  call: "Call",
  visit: "Visit",
  court: "Court",
  accompaniment: "Accompaniment",
  message: "Message",
  other: "Other",
};

function caseScreen(caseTag: string) {
  breadcrumb.set("case", caseTag);
  const s = session!;
  const td = new TextDecoder();
  const seen = seenMap(s);
  // Unsaved textarea edits, keyed by record id, carried across re-renders
  // (a background sync must never eat typing). baselineSeq is the note's
  // lastSeq when typing began: Save hands it to writeNote, so a draft typed
  // against an older view merges with remote updates that landed meanwhile
  // instead of diffing them away.
  const drafts = new Map<
    string,
    { text: string; baselineSeq: number; selStart: number; selEnd: number; focused: boolean }
  >();
  // notes remotely changed during this visit — badge sticks until you leave
  const changedThisVisit = new Set<string>();
  // record ids whose history panel is open (survives re-renders)
  const openHistories = new Set<string>();
  // collapsible section open/closed state: only the Case Bio starts open —
  // the orientation paragraph greets whoever opens the case; the rest wait
  const sectionState = new Map<string, boolean>([
    ["bio", true],
    ["tasks", false],
    ["notes", false],
    ["contacts", false],
    ["access", false],
  ]);
  const secAttr = (k: string) => (sectionState.get(k) ? " open" : "");
  // saved content renders READ-ONLY; Edit swaps a record into a textarea.
  // A live draft forces edit mode (so background renders never demote a
  // note someone is typing in back to the read view).
  const editing = new Set<string>();
  let bioEditing = false;
  let titleEditing = false; // inline header rename (option A)
  const BIO_NEW = "bio-new"; // draft key for a first bio (no record yet)

  const trunc = (t: string) => (t.length > 80 ? `${t.slice(0, 80)}…` : t);
  // per-note audit trail from the journal (flows.noteHistory), newest
  // first; each step expands to the full text as of that seq
  const historyHtml = (rid: string) => {
    const steps = flows.noteHistory(s, caseTag, rid);
    if (!steps) return `<p class="muted">History unavailable for this account.</p>`;
    return `<div class="history-panel">${[...steps]
      .reverse()
      .map(
        (st) => `<details data-hkey="${esc(`${rid}:${st.seq}`)}">
          <summary>seq ${st.seq} · epoch ${st.epoch} · ${
            st.author === null
              ? `<em>pre-rotation history, compacted at a revocation</em>`
              : `<span class="mono">${esc(who(st.author))}</span>`
          }${st.added ? ` <ins>${esc(trunc(st.added))}</ins>` : ""}${
            st.removed ? ` <del>${esc(trunc(st.removed))}</del>` : ""
          }</summary>
          <pre>${esc(st.text)}</pre>
        </details>`,
      )
      .join("")}</div>`;
  };

  // read the OLD DOM (called before innerHTML replaces it)
  const captureDrafts = () => {
    app()
      .querySelectorAll<HTMLTextAreaElement>("textarea[data-rid]")
      .forEach((ta) => {
        const rid = ta.dataset.rid!;
        if (ta.value === ta.defaultValue) {
          drafts.delete(rid); // matches the rendered merge: nothing unsaved
          return;
        }
        const prev = drafts.get(rid);
        drafts.set(rid, {
          text: ta.value,
          baselineSeq: prev?.baselineSeq ?? Number(ta.dataset.seq),
          selStart: ta.selectionStart,
          selEnd: ta.selectionEnd,
          focused: document.activeElement === ta,
        });
      });
  };
  const restoreDrafts = () => {
    app()
      .querySelectorAll<HTMLTextAreaElement>("textarea[data-rid]")
      .forEach((ta) => {
        const d = drafts.get(ta.dataset.rid!);
        if (!d) return;
        ta.value = d.text;
        const dot = app().querySelector<HTMLElement>(
          `button.save[data-rid="${CSS.escape(ta.dataset.rid!)}"] .dirty-dot`,
        );
        if (dot) dot.style.display = "inline";
        if (d.focused) {
          ta.focus();
          ta.setSelectionRange(d.selStart, d.selEnd);
        }
      });
  };
  // drafts are in-memory only — a reload resumes the session but drops
  // them; warn before letting a dirty tab go
  const unloadGuard = (e: BeforeUnloadEvent) => {
    captureDrafts();
    if (drafts.size > 0) e.preventDefault();
  };
  window.addEventListener("beforeunload", unloadGuard);
  pageCleanup = () => window.removeEventListener("beforeunload", unloadGuard);

  const render = () => {
    captureDrafts();
    // expanded history steps survive the rebuild
    const openDetails = new Set(
      [
        ...app().querySelectorAll<HTMLElement>(
          "details[open][data-hkey], details[open][data-dkey]",
        ),
      ].map((d) => d.dataset.hkey ?? d.dataset.dkey!),
    );
    app()
      .querySelectorAll<HTMLDetailsElement>("details[data-sec]")
      .forEach((d) => {
        sectionState.set((d as HTMLElement).dataset.sec!, d.open);
      });
    const c = flows.readCase(s, caseTag);
    if (!c) return go(casesScreen);
    for (const rid of drafts.keys()) if (rid !== BIO_NEW) editing.add(rid);
    // narrate remote changes: toast now, badge for the rest of the visit
    for (const n of c.notes) {
      const k = `${caseTag}/${n.recordId}`;
      const at = seen.get(k);
      seen.set(k, n.lastSeq);
      if (at !== undefined && n.lastSeq > at && n.lastAuthor !== s.userId) {
        changedThisVisit.add(n.recordId);
        toast(`Note updated by ${who(n.lastAuthor)} (seq ${n.lastSeq})`);
      }
    }
    const others = [...s.state.members.keys()].filter((id) => !c.holders.includes(id));
    app().innerHTML = `
      ${haltedBanner(s)}
      <div class="shell">
      ${sidebarHtml(s, "cases")}
      <div class="content"><div class="content-narrow">
      <button id="back">← Cases</button>
      <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap">
        ${
          titleEditing && c.header
            ? `<input id="case-title" value="${esc(c.title)}" style="flex-grow:1;max-width:none;font-size:1.25rem;font-weight:700" />
               <button id="save-title" class="btn-primary">Save</button>
               <button id="cancel-title">Cancel</button>`
            : `<h1 style="margin:0.4rem 0">${esc(c.title)}</h1>
               ${c.header ? `<button id="edit-title" class="ghost-btn" title="Rename this case">✎</button>` : ""}`
        }
        ${
          c.header
            ? `<select id="case-status" style="max-width:9rem;margin-left:auto">
                 ${["open", "closed", "archived"].map((st) => `<option value="${st}"${c.status === st ? " selected" : ""}>${st}</option>`).join("")}
               </select>`
            : c.status !== "open"
              ? `<span class="badge" style="background:#777">${esc(c.status)}</span>`
              : ""
        }
      </div>
      <p class="muted">tag <span class="mono">${esc(caseTag.slice(0, 12))}…</span> · epoch ${c.epoch}
        · created by <span class="mono">${esc(c.creatorId.slice(0, 8))}…${c.amCreator ? " (you)" : ""}</span></p>
      <div id="err"></div>
      ${
        c.records.every((n) => n.locked)
          ? `<div class="halted">You no longer hold the current key for this case. Content written
             after your access was revoked cannot be decrypted by this account.</div>`
          : ""
      }
      ${
        c.header
          ? `<details class="card sec" data-sec="bio"${secAttr("bio")}><summary><h2>Case Bio</h2></summary>
               ${
                 bioEditing || drafts.has(c.profile?.recordId ?? BIO_NEW)
                   ? `<textarea class="mono" style="width:100%;min-height:5rem" data-rid="${esc(c.profile?.recordId ?? BIO_NEW)}" data-seq="${c.profile?.lastSeq ?? 0}" placeholder="A quick orientation for anyone opening this case…">${esc(c.profile?.text ?? "")}</textarea>
                      <button id="save-bio" class="btn-primary">Save bio</button>
                      <button id="cancel-bio">Cancel</button>`
                   : (c.profile?.text ?? "").trim()
                     ? `<div class="note-view">${esc(c.profile!.text!)}</div>
                        <p class="muted">last update by <span class="mono">${esc(who(c.profile!.lastAuthor))}</span>${flows.recordAt(c.profile!) !== null ? ` · ${esc(fmtWhenFull(flows.recordAt(c.profile!)))}` : ""}</p>
                        <button id="edit-bio">Edit</button>`
                     : `<p class="muted">No bio yet.</p><button id="edit-bio">Write bio</button>`
               }
             </details>`
          : ""
      }
      <details class="card sec" data-sec="tasks"${secAttr("tasks")}><summary><h2>Tasks</h2>${(() => {
        const open = c.tasks.filter((t) => t.meta["done"] !== true).length;
        return open ? ` <span class="count-pill">${open}</span>` : "";
      })()}</summary>
        <div style="display:flex;gap:0.5rem;align-items:flex-start">
          <input id="task-text" placeholder="Next step…" style="flex-grow:1;max-width:none" />
          <input id="task-due" type="date" style="max-width:11rem" />
          <button id="add-task" class="btn-primary">Add task</button>
        </div>
        ${c.tasks
          .map((r) => {
            if (r.locked) return "";
            const done = r.meta["done"] === true;
            const due = typeof r.meta["due"] === "number" ? (r.meta["due"] as number) : null;
            const overdue = !done && due !== null && due < Date.now();
            return `<div class="case-row"><label style="display:flex;gap:0.6rem;align-items:center;font-weight:400;margin:0;flex-grow:1">
              <input type="checkbox" class="task-toggle" data-rid="${esc(r.recordId)}" style="width:auto;margin:0" ${done ? "checked" : ""} />
              <span style="${done ? "text-decoration:line-through;color:#777" : ""}">${esc(r.text ?? "")}</span>
              ${due !== null ? `<span class="badge" style="background:${overdue ? "#c0392b" : "#55665c"}">${overdue ? "overdue · " : "due "}${esc(fmtWhen(due))}</span>` : ""}
            </label></div>`;
          })
          .join("")}
        ${c.tasks.length === 0 ? `<p class="muted">No tasks yet.</p>` : ""}
      </details>
      <details class="card sec" data-sec="notes"${secAttr("notes")}><summary><h2>Notes</h2>${c.notes.length ? ` <span class="count-pill">${c.notes.length}</span>` : ""}</summary>
        ${c.notes
          .map((n) => {
            const d = drafts.get(n.recordId);
            const conflict = d !== undefined && n.lastSeq > d.baselineSeq;
            const byline = `<p class="muted">last update seq ${n.lastSeq} by <span class="mono">${esc(who(n.lastAuthor))}</span>
                     ${flows.recordAt(n) !== null ? ` · ${esc(fmtWhenFull(flows.recordAt(n)))}` : ""}
                     ${changedThisVisit.has(n.recordId) ? `<span class="badge updated">updated</span>` : ""}`;
            if (n.locked) {
              return `<div><p class="muted">🔒 note <span class="mono">${esc(n.recordId.slice(0, 8))}…</span> — not decryptable at the current epoch</p></div>`;
            }
            if (editing.has(n.recordId)) {
              return `<div>
                <textarea class="mono" style="width:100%;min-height:4rem" data-rid="${esc(n.recordId)}" data-seq="${n.lastSeq}">${esc(n.text!)}</textarea>
                ${
                  conflict
                    ? `<p class="merge-note">Changed by <span class="mono">${esc(who(n.lastAuthor))}</span> while you were editing — your unsaved text is shown; Save merges your edit with theirs.</p>`
                    : ""
                }
                ${byline}
                <button class="save btn-primary" data-rid="${esc(n.recordId)}">Save<span class="dirty-dot" style="display:none"> •</span></button>
                <button class="cancel-edit" data-rid="${esc(n.recordId)}">Cancel</button></p>
              </div>`;
            }
            return `<div>
              <div class="note-view" data-rid="${esc(n.recordId)}">${esc(n.text!)}</div>
              ${byline}
              <button class="edit-note" data-rid="${esc(n.recordId)}">Edit</button>
              <button class="history" data-rid="${esc(n.recordId)}">${openHistories.has(n.recordId) ? "Hide history" : "History"}</button></p>
              ${openHistories.has(n.recordId) ? historyHtml(n.recordId) : ""}</div>`;
          })
          .join("")}
        <label>New note</label><input id="new-note" placeholder="Note text…" />
        <button id="add-note">Add note</button>
      </details>
      <details class="card sec" data-sec="contacts"${secAttr("contacts")}><summary><h2>Contact log</h2>${c.contacts.length ? ` <span class="count-pill">${c.contacts.length}</span>` : ""}</summary>
        <p class="muted">One entry per session or contact — dated, attributed, and provable
        against the journal.</p>
        <div style="display:flex;gap:0.5rem;align-items:flex-start">
          <select id="contact-channel" style="max-width:10rem">
            ${Object.entries(CHANNEL_LABELS)
              .map(([v, l]) => `<option value="${v}">${l}</option>`)
              .join("")}
          </select>
          <input id="contact-text" placeholder="What happened…" style="flex-grow:1;max-width:none" />
          <button id="add-contact" class="btn-primary">Log contact</button>
        </div>
        ${c.contacts
          .map((r) =>
            r.locked
              ? ""
              : `<div class="case-row"><div style="flex-grow:1">
                 <div><span class="badge" style="margin-left:0;background:#55665c">${esc(CHANNEL_LABELS[String(r.meta["channel"])] ?? "Contact")}</span>
                 <b>${esc(fmtWhenFull(flows.recordAt(r)))}</b>
                 <span class="muted">· <span class="mono">${esc(who(r.lastAuthor))}</span></span></div>
                 <div>${esc(r.text ?? "")}</div>
                 </div></div>`,
          )
          .join("")}
        ${c.contacts.length === 0 ? `<p class="muted">No contacts logged yet.</p>` : ""}
      </details>
      ${
        c.amCreator
          ? `<details class="card sec" data-sec="access"${secAttr("access")}><summary><h2>Access</h2></summary>
             <p>Current members: ${c.holders.map((h) => `<span class="mono">${esc(whoFull(h))}</span>${h !== c.creatorId ? `<button class="revoke" data-uid="${esc(h)}">Revoke</button>` : " (creator)"}`).join(" · ")}</p>
             ${
               others.length
                 ? `<label>Share with</label><select id="share-with">${others.map((id) => `<option value="${esc(id)}">${esc(whoFull(id))} — ${esc(s.state.members.get(id)!.role)}</option>`).join("")}</select>
                    <button id="share">Share case</button>`
                 : `<span class="muted">Every member already has access.</span>`
             }
             <p class="muted">Revoking rotates the case key so the removed account cannot read anything
             written afterwards. It does NOT erase what they already saw or copied.</p></details>`
          : ""
      }
      </div></div></div>`;
    restoreDrafts();
    app()
      .querySelectorAll<HTMLDetailsElement>("details[data-hkey], details[data-dkey]")
      .forEach((d) => {
        const k = (d as HTMLElement).dataset.hkey ?? (d as HTMLElement).dataset.dkey!;
        if (openDetails.has(k)) d.open = true;
      });
    app()
      .querySelectorAll("button.history")
      .forEach((b) =>
        b.addEventListener("click", () => {
          const rid = (b as HTMLElement).dataset.rid!;
          if (!openHistories.delete(rid)) openHistories.add(rid);
          render();
        }),
      );
    wireSidebar();
    document.getElementById("back")!.addEventListener("click", () => go(casesScreen));
    const act = (fn: () => Promise<void>) => async () => {
      try {
        await fn();
        render();
      } catch (e) {
        showError(e);
      }
    };
    document.getElementById("edit-title")?.addEventListener("click", () => {
      titleEditing = true;
      render();
    });
    document.getElementById("cancel-title")?.addEventListener("click", () => {
      titleEditing = false;
      render();
    });
    document.getElementById("save-title")?.addEventListener(
      "click",
      act(async () => {
        const t = $("case-title").value.trim();
        if (!t) throw new Error("title cannot be empty");
        await flows.setRecordMeta(s, caseTag, c.header!.recordId, { title: t });
        titleEditing = false;
      }),
    );
    document.getElementById("case-status")?.addEventListener(
      "change",
      act(async () => {
        const st = ($("case-status") as unknown as HTMLSelectElement).value as flows.CaseStatus;
        await flows.setRecordMeta(s, caseTag, c.header!.recordId, { status: st });
      }),
    );
    document.getElementById("edit-bio")?.addEventListener("click", () => {
      bioEditing = true;
      render();
    });
    document.getElementById("cancel-bio")?.addEventListener("click", () => {
      bioEditing = false;
      drafts.delete(c.profile?.recordId ?? BIO_NEW);
      render();
    });
    document.getElementById("save-bio")?.addEventListener(
      "click",
      act(async () => {
        const rid = c.profile?.recordId ?? BIO_NEW;
        const ta = app().querySelector<HTMLTextAreaElement>(
          `textarea[data-rid="${CSS.escape(rid)}"]`,
        )!;
        const text = ta.value;
        if (c.profile) {
          // baseline-aware like any note edit: a stale bio save merges
          await flows.writeNote(s, caseTag, c.profile.recordId, text, drafts.get(rid)?.baselineSeq);
        } else {
          await flows.createRecord(s, caseTag, { kind: "profile" }, text);
        }
        drafts.delete(rid);
        bioEditing = false;
        if (ta.value === text) ta.defaultValue = text; // don't resurrect as draft
      }),
    );
    app()
      .querySelectorAll("button.edit-note")
      .forEach((b) =>
        b.addEventListener("click", () => {
          editing.add((b as HTMLElement).dataset.rid!);
          render();
        }),
      );
    app()
      .querySelectorAll("button.cancel-edit")
      .forEach((b) =>
        b.addEventListener("click", () => {
          const rid = (b as HTMLElement).dataset.rid!;
          editing.delete(rid);
          drafts.delete(rid);
          render();
        }),
      );
    document.getElementById("add-contact")?.addEventListener(
      "click",
      act(async () => {
        const text = $("contact-text").value.trim();
        if (!text) throw new Error("describe the contact first");
        const channel = ($("contact-channel") as unknown as HTMLSelectElement).value;
        await flows.createRecord(s, caseTag, { kind: "contact", channel }, text);
        $("contact-text").value = "";
      }),
    );
    document.getElementById("add-task")?.addEventListener(
      "click",
      act(async () => {
        const text = $("task-text").value.trim();
        if (!text) throw new Error("describe the task first");
        const dueStr = $("task-due").value;
        const due = dueStr ? new Date(`${dueStr}T17:00:00`).getTime() : null;
        await flows.createRecord(s, caseTag, { kind: "task", done: false, due }, text);
        $("task-text").value = "";
      }),
    );
    app()
      .querySelectorAll("input.task-toggle")
      .forEach((b) =>
        b.addEventListener(
          "change",
          act(async () => {
            await flows.setRecordMeta(s, caseTag, (b as HTMLElement).dataset.rid!, {
              done: (b as HTMLInputElement).checked,
            });
          }),
        ),
      );
    // unsaved-changes indicator
    app()
      .querySelectorAll<HTMLTextAreaElement>("textarea[data-rid]")
      .forEach((ta) =>
        ta.addEventListener("input", () => {
          const dot = app().querySelector<HTMLElement>(
            `button.save[data-rid="${CSS.escape(ta.dataset.rid!)}"] .dirty-dot`,
          );
          if (dot) dot.style.display = ta.value === ta.defaultValue ? "none" : "inline";
        }),
      );
    app()
      .querySelectorAll("button.save")
      .forEach((b) =>
        b.addEventListener("click", async () => {
          try {
            const rid = (b as HTMLElement).dataset.rid!;
            const ta = app().querySelector(
              `textarea[data-rid="${CSS.escape(rid)}"]`,
            ) as HTMLTextAreaElement;
            const text = ta.value;
            // diff against what the drafting began from, not the latest merge
            await flows.writeNote(s, caseTag, rid, text, drafts.get(rid)?.baselineSeq);
            drafts.delete(rid);
            editing.delete(rid); // back to the read view
            // mark the textarea clean so render's captureDrafts doesn't
            // resurrect the just-saved text as a draft over the fresh merge
            if (ta.value === text) ta.defaultValue = text;
            render();
          } catch (e) {
            showError(e);
          }
        }),
      );
    document.getElementById("add-note")!.addEventListener("click", async () => {
      try {
        await flows.writeNote(s, caseTag, undefined, $("new-note").value);
        render();
      } catch (e) {
        showError(e);
      }
    });
    document.getElementById("share")?.addEventListener("click", async () => {
      try {
        await flows.shareCase(s, caseTag, ($("share-with") as unknown as HTMLSelectElement).value);
        render();
      } catch (e) {
        showError(e);
      }
    });
    app()
      .querySelectorAll("button.revoke")
      .forEach((b) =>
        b.addEventListener("click", async () => {
          try {
            const uid = (b as HTMLElement).dataset.uid!;
            if (!confirm("Rotate the case key and revoke this account's future access?")) return;
            await flows.revokeFromCase(s, caseTag, uid);
            render();
          } catch (e) {
            showError(e);
          }
        }),
      );
  };
  render();
  pollTimer = setInterval(async () => {
    const before = s.state.chain.seq;
    await flows.sync(s);
    if (s.state.chain.seq !== before) {
      const restore = snapshotInputs(); // e.g. a half-typed #new-note
      render();
      restore();
    }
  }, 2000);
}
