// FULL user-flow e2e: bootstrap → admin appointment → two-admin admission →
// cases (create/edit/share/revoke/search) → logout/login → armed re-key
// (propose + countersign) → succession → promote → custody ack.
// Prereqs: fresh server on :8787, vite preview on :4173. Run from client/.
import { chromium } from "playwright";

const APP = "http://localhost:4173/?server=http://localhost:8787";
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(` ${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) throw new Error(`FAILED: ${name}`);
};
const T = { timeout: 30_000 };

// sections start collapsed by default; open them all so the
// suite can interact with their contents directly
const openSecs = async (p) => {
  await p.waitForSelector("details[data-sec]", { state: "attached", timeout: 15_000 });
  await p.$$eval("details[data-sec]", (ds) => ds.forEach((d) => (d.open = true)));
};

const browser = await chromium.launch();
const page = async () => {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  p.on("dialog", (d) => d.accept());
  return p;
};
/** newest invite string in the head/admin panel not seen before */
const newInvite = async (p, seen) => {
  await p.waitForFunction(
    (known) =>
      [...document.querySelectorAll("#invites .code-block")].some(
        (el) => !known.includes(el.textContent?.trim() ?? ""),
      ),
    [...seen],
    T,
  );
  const all = (await p.locator("#invites .code-block").allTextContents()).map((t) => t.trim());
  const fresh = all.find((t) => !seen.has(t));
  fresh && seen.add(fresh);
  return fresh;
};
/** join with an invite; returns login id (recovery code also shown) */
const join = async (p, invite, pw, nick) => {
  await p.goto(APP);
  await p.click("#b-join");
  await p.fill("#invite", invite);
  await p.fill("#pw", pw);
  await p.fill("#nick", nick);
  await p.click("#go");
  await p.waitForSelector("#status", T);
  return ((await p.locator(".code-block").first().textContent()) ?? "").trim();
};
const loginAfterApproval = async (p, pw) => {
  await p.locator("#status", { hasText: "Approved" }).waitFor(T);
  await p.click("#to-login");
  await p.waitForSelector("#uid", T);
  await p.fill("#pw", pw);
  await p.click("#go");
  await p.waitForSelector("#logout", T);
};
const badge = async (p) => ((await p.textContent("#role-badge")) ?? "").trim();

try {
  // ---------- 1. bootstrap (five artifacts) ----------
  const head = await page();
  await head.goto(APP);
  await head.click("#b-boot");
  await head.fill("#pw1", "head pw");
  await head.fill("#pw2", "head pw");
  await head.click("#go");
  await head.waitForSelector("#confirm-word", T);
  const artifacts = (await head.locator(".code-block").allTextContents()).map((t) => t.trim());
  await head.fill("#confirm-word", "Confirm");
  await head.click("#next");
  const [shareA, shareB] = artifacts; // paper 1 = the tally cut-sheet
  await head.waitForSelector("#done");
  await head.click("#done");
  await head.waitForSelector("#mk-head-member-invite", T);
  check("1. bootstrap → solo head home", (await badge(head)) === "head");

  // ---------- 2. admin designation: member admit, then PROMOTE ----
  const seenInvites = new Set();
  const admitSoloAndPromote = async (p, pw, nick) => {
    await head.click("#mk-head-member-invite");
    const inv = await newInvite(head, seenInvites);
    const id = await join(p, inv, pw, nick);
    const admit = head.locator("#requests button.req-act", { hasText: "Admit as member (solo)" });
    await admit.waitFor(T);
    await admit.click();
    await loginAfterApproval(p, pw);
    // the head promotes from the roster — the ONLY path to admin
    const promote = head.locator(`button.promote[data-uid="${id}"]`);
    await promote.waitFor(T);
    await promote.click();
    await p.waitForFunction(
      () => document.querySelector("#role-badge")?.textContent === "admin",
      null,
      T,
    );
    await p.click("#nav-org"); // newly promoted: move to the org panel
    return id;
  };
  const adminA = await page();
  const adminAId = await admitSoloAndPromote(adminA, "adminA pw", "admin-a");
  check("2a. admin A admitted as member, promoted, sees admin badge live", true);
  const adminB = await page();
  const adminBId = await admitSoloAndPromote(adminB, "adminB pw", "admin-b");
  check("2b. admin B promoted; barrier arms on the second grant", true);
  await head.waitForSelector("text=safeguard is armed", T);
  check("2c. head panel reports the armed two-admin safeguard", true);

  // ---------- 2d. org directory: auto-publish + rename ----------
  // the join-form name auto-published at first login; the head's roster
  // shows it (sealed fan-out — the server never saw the name)
  await head.waitForSelector("table >> text=admin-a (", T);
  check("2d. join-form display name auto-published; roster shows name + id", true);
  await adminA.click("#nav-session");
  await adminA.waitForSelector("#disp-name", T);
  check(
    "2e. Device & session shows the current name",
    (await adminA.inputValue("#disp-name")) === "admin-a",
  );
  await adminA.fill("#disp-name", "Ana");
  await adminA.click("#save-disp");
  await head.waitForSelector("table >> text=Ana (", T);
  check("2f. rename propagates to colleagues' rosters", true);
  await adminA.click("#nav-org");
  await adminA.waitForSelector("#mk-invite", T);

  // ---------- 3. two-admin member admission ----------
  await adminA.waitForSelector("#mk-invite", T);
  await adminA.click("#mk-invite");
  const invM = await newInvite(adminA, new Set());
  const carol = await page();
  await join(carol, invM, "carol pw", "carol");
  const propose = adminA.locator("#requests button.req-act", { hasText: "Propose member" });
  await propose.waitFor(T);
  await propose.click();
  await adminB.waitForSelector('input[id^="code-"]', T);
  await adminB.fill('input[id^="code-"]', invM);
  await adminB.click("button.approve");
  await loginAfterApproval(carol, "carol pw");
  check(
    "3. two-admin admission: propose + code-verified approve",
    (await badge(carol)) === "member",
  );

  // ---------- 4. case flows: create, note, edit, share ----------
  await carol.fill("#new-case", "Full e2e case");
  await carol.click("#mk-case");
  await carol.waitForSelector("button.open-case", T);
  await carol.click("button.open-case");
  await openSecs(carol);
  await carol.waitForSelector("#new-note", T);
  await carol.fill("#new-note", "Full e2e case");
  await carol.click("#add-note");
  await carol.waitForSelector(".note-view[data-rid]", T);
  await carol.fill("#new-note", "second note body");
  await carol.click("#add-note");
  await carol.waitForFunction(
    () => document.querySelectorAll(".note-view[data-rid]").length === 2,
    null,
    T,
  );
  await carol.locator("button.edit-note").first().click();
  const ta = carol.locator("textarea[data-rid]").first();
  await ta.fill("Full e2e case — edited");
  await carol.locator("button.save").first().click();
  await carol.waitForSelector(".note-view[data-rid] >> text=Full e2e case — edited", T);
  check("4a. case created, note added, edit saved", true);

  await carol.waitForSelector("#share-with", T);
  await carol.locator("#share-with").selectOption(adminAId);
  await carol.click("#share");
  await adminA.click("#nav-cases");
  await adminA.waitForSelector("#cases >> text=Full e2e case", T);
  await adminA.locator("button.open-case").click();
  await openSecs(adminA);
  await adminA.waitForSelector("text=Full e2e case — edited", T);
  check("4b. shared case readable by admin A", true);

  // ---------- 5. revoke: admin A locked out, live ----------
  const revoke = carol.locator(`button.revoke[data-uid="${adminAId}"]`);
  await revoke.waitFor(T);
  await revoke.click();
  await adminA.waitForSelector("text=no longer hold the current key", T);
  check("5. revocation locks admin A's open case screen", true);
  await adminA.click("#back");

  // ---------- 6. search ----------
  await carol.click("#back");
  await carol.waitForSelector("#search", T);
  await carol.fill("#search", "edited");
  await carol.waitForSelector("#search-results >> text=Full e2e case", T);
  check("6. local search finds the note", true);

  // ---------- 7. logout / login ----------
  await carol.click("#logout");
  await carol.waitForSelector("#b-login", T);
  await carol.click("#b-login");
  await carol.waitForSelector("#uid", T);
  await carol.fill("#pw", "carol pw");
  await carol.click("#go");
  await carol.waitForSelector("#logout", T);
  await carol.waitForSelector("#cases >> text=Full e2e case", T);
  check("7. logout → login round-trip keeps the keychain", true);

  // ---------- 8. armed re-key: propose (shares) + countersign ----------
  await adminA.click("#nav-org");
  await adminA.waitForSelector("#rk-case", T);
  await adminA.fill("#rk-a", shareA);
  await adminA.fill("#rk-b", shareB);
  await adminA.locator("#rk-holders").selectOption(adminBId);
  await adminA.click("#rk-go"); // alert: proposed — auto-accepted
  await adminB.waitForSelector("button.rk-approve", T);
  await adminB.click("button.rk-approve");
  await adminB.click("#nav-cases");
  await adminB.waitForSelector("#cases >> text=Full e2e case", T);
  check("8a. propose + countersign restores the case to admin B", true);
  await adminB.click("#nav-org"); // back for the succession steps
  // the creator was not designated: her copy is now locked (forward-only)
  await carol.waitForSelector('#cases .badge:has-text("locked")', T);
  check("8b. non-designated creator sees the case locked", true);

  // ---------- 9. succession: prepare → sign → roles follow live ----------
  await adminB.click("#open-prep");
  await adminB.fill("#prep-pw", "adminB pw");
  await adminB.click("#prep-go");
  await adminB.waitForSelector("#prep-out .code-block", T);
  const newGovPk = ((await adminB.textContent("#prep-out .code-block")) ?? "").trim();
  await head.click("#open-succ");
  await head.locator("#succ-to").selectOption(adminBId);
  await head.fill("#succ-pk", newGovPk);
  await head.click("#succ-go");
  await head.waitForFunction(
    () => document.querySelector("#role-badge")?.textContent === "member",
    null,
    T,
  );
  check("9a. old head's screen drops to member, live", true);
  await adminB.waitForFunction(
    () => document.querySelector("#role-badge")?.textContent === "head",
    null,
    T,
  );
  await adminB.waitForSelector("button.promote", T); // head-only roster controls
  check("9b. successor's screen becomes head with head panel, live", true);

  // ---------- 10. new head promotes the old head from the roster ----------
  const promote = adminB.locator("button.promote").first();
  await promote.waitFor(T);
  await promote.click();
  await head.waitForFunction(
    () => document.querySelector("#role-badge")?.textContent === "admin",
    null,
    T,
  );
  check("10. roster promotion: old head is an admin again", true);

  // ---------- 11. new head package + custody ack ----------
  await adminB.click("#open-gov");
  await adminB.click("#new-package");
  await adminB.waitForSelector("text=HEAD RECOVERY SECRET (new)", T);
  await adminB.check("#confirm");
  await adminB.click("#next");
  await adminB.waitForSelector("#logout", T);
  check("11a. new head prints a fresh head package", true);

  await adminA.locator('button.ack-share[data-share="A"]').click();
  await adminA.waitForFunction(
    () =>
      document.body.textContent?.includes("Share 1 — ") &&
      /Share 1 — [^·]*\(you\)/.test(document.body.textContent ?? ""),
    null,
    T,
  );
  check("11b. custody ack: share 1 recorded to admin A", true);

  console.log(`\nFULL E2E PASSED — ${results.length}/${results.length} checks green`);
} finally {
  await browser.close();
}
