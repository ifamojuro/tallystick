// Recovery e2e: account recovery and case restore through the REAL UI.
// Prereqs: fresh server on :8787, vite preview on :4173. Run from client/.
import { chromium } from "playwright";

const APP = "http://localhost:4173/?server=http://localhost:8787";
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(` ${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) throw new Error(`FAILED: ${name}`);
};

// sections start collapsed by default; open them all so the
// suite can interact with their contents directly
const openSecs = async (p) => {
  await p.waitForSelector("details[data-sec]", { state: "attached", timeout: 15_000 });
  await p.$$eval("details[data-sec]", (ds) => ds.forEach((d) => (d.open = true)));
};

const browser = await chromium.launch();
try {
  // ---------- HEAD: bootstrap, capturing all five artifacts ----------
  const headCtx = await browser.newContext();
  const head = await headCtx.newPage();
  head.on("dialog", (d) => d.accept());
  await head.goto(APP);
  await head.click("#b-boot");
  await head.fill("#pw1", "head smoke pw");
  await head.fill("#pw2", "head smoke pw");
  await head.click("#go");
  await head.waitForSelector("#confirm-word", { timeout: 30_000 });
  const artifacts = (await head.locator(".code-block").allTextContents()).map((t) => t.trim());
  await head.fill("#confirm-word", "Confirm");
  await head.click("#next");
  const [shareA, shareB] = artifacts; // paper 1 = the tally cut-sheet
  const secretCodes = artifacts.filter((a) => /^[0-9A-Z-]+$/.test(a) && a.length > 40);
  check("five distinct secret codes across the three papers", new Set(secretCodes).size === 5);
  await head.waitForSelector("#done");
  await head.click("#done");
  await head.waitForSelector("#mk-head-member-invite", { timeout: 15_000 });

  // custody journaled at genesis: both shares with the head
  await head.waitForSelector("text=Share 1 —", { timeout: 15_000 });
  const custody = (await head.textContent(".card:has-text('Recovery custody')")) ?? "";
  check("genesis custody journaled to the head", custody.includes("(you)"));

  // ---------- MEMBER: join (capture recovery code), solo-admit, login ----
  await head.click("#mk-head-member-invite");
  await head.waitForSelector("#invites .code-block", { timeout: 15_000 });
  const invite = ((await head.textContent("#invites .code-block")) ?? "").trim();

  const memCtx = await browser.newContext();
  const mem = await memCtx.newPage();
  mem.on("dialog", (d) => d.accept());
  await mem.goto(APP);
  await mem.click("#b-join");
  await mem.fill("#invite", invite);
  await mem.fill("#pw", "member old pw");
  await mem.fill("#nick", "smoke-member");
  await mem.click("#go");
  await mem.waitForSelector("#status", { timeout: 30_000 });
  const blocks = await mem.locator(".code-block").allTextContents();
  const memberId = blocks[0].trim();
  const memberRecovery = blocks[1].trim();
  check("join screen shows the personal recovery code", memberRecovery.length > 40);

  const admitBtn = head.locator("#requests button.req-act", { hasText: "Admit as member (solo)" });
  await admitBtn.waitFor({ timeout: 20_000 });
  await admitBtn.click();
  await mem.locator("#status", { hasText: "Approved" }).waitFor({ timeout: 30_000 });
  await mem.click("#to-login");
  await mem.waitForSelector("#uid");
  await mem.fill("#pw", "member old pw");
  await mem.click("#go");
  await mem.waitForSelector("#logout", { timeout: 30_000 });

  // member creates a case nobody else holds, then "forgets" the passphrase
  await mem.fill("#new-case", "Orphan case smoke");
  await mem.click("#mk-case");
  await mem.waitForSelector("button.open-case", { timeout: 15_000 });
  await mem.click("button.open-case");
  await openSecs(mem);
  await mem.waitForSelector("#new-note", { timeout: 15_000 });
  await mem.fill("#new-note", "Orphan case smoke — narrative");
  await mem.click("#add-note");
  await mem.waitForSelector(".note-view[data-rid]", { timeout: 15_000 });
  await memCtx.close();

  // ---------- ACCOUNT RECOVERY through the UI (fresh "device") ----------
  const recCtx = await browser.newContext();
  const rec = await recCtx.newPage();
  rec.on("dialog", (d) => d.accept());
  await rec.goto(APP);
  await rec.click("#b-recover");
  await rec.fill("#uid", memberId);
  await rec.fill("#code", memberRecovery);
  await rec.click("#verify");
  await rec.waitForSelector("text=valid for that account", { timeout: 15_000 });
  check("verify-only mode confirms the code", true);
  await rec.fill("#pw1", "member NEW pw");
  await rec.fill("#pw2", "member NEW pw");
  await rec.click("#go");
  await rec.waitForSelector("text=Account recovered", { timeout: 30_000 });
  const newCode = ((await rec.textContent(".code-block")) ?? "").trim();
  check("recovery mints a fresh code", newCode.length > 40 && newCode !== memberRecovery);
  await rec.check("#confirm");
  await rec.click("#next");
  await rec.waitForSelector("#logout", { timeout: 30_000 });
  await rec.waitForSelector("text=Orphan case smoke", { timeout: 15_000 });
  check("recovered account still opens its case", true);
  await recCtx.close();

  // ---------- CASE RESTORE through the UI (solo head, both shares) -------
  // pretend the member is gone: the head restores their case to themself
  await head.waitForSelector("#rk-case", { timeout: 15_000 });
  const options = await head.locator("#rk-case option").allTextContents();
  const memberCase = options.findIndex((t) => !t.includes("head"));
  check(
    "case list shows the member's case by public metadata",
    memberCase >= 0,
    options.join(" | "),
  );
  await head.locator("#rk-case").selectOption({ index: memberCase });
  await head.fill("#rk-a", shareA);
  await head.fill("#rk-b", shareB);

  // read-only first: content appears, nothing changes
  await head.click("#rk-read");
  await head.waitForSelector("#rk-out pre", { timeout: 15_000 });
  check(
    "read-only ceremony decrypts the case",
    ((await head.textContent("#rk-out")) ?? "").includes("Orphan case smoke"),
  );

  // wrong paper: same share twice → refused with the wrong-paper message
  await head.fill("#rk-b", shareA);
  await head.click("#rk-read");
  await head.waitForSelector("text=wrong paper", { timeout: 15_000 });
  check("mismatched shares are refused before decrypting", true);
  await head.fill("#rk-b", shareB);

  // restore to the head; solo mode commits immediately
  const holderTexts = await head.locator("#rk-holders option").allTextContents();
  await head.locator("#rk-holders").selectOption({
    index: holderTexts.findIndex((t) => t.includes("head")),
  });
  await head.click("#rk-go");
  await head.click("#nav-cases");
  await head.waitForSelector("#cases >> text=Orphan case smoke", { timeout: 20_000 });
  check("restored case appears in the head's keychain", true);

  // ---------- custody handoff ack ----------
  await head.click("#nav-org");
  await head.waitForSelector("button.ack-share", { timeout: 15_000 });
  await head.click("button.ack-share >> nth=0");
  await head.waitForSelector("text=Share 1 — ", { timeout: 15_000 });
  check("custody ack round-trips", true);

  console.log(`\nRECOVERY SMOKE PASSED — ${results.length}/${results.length} checks green`);
} finally {
  await browser.close();
}
