// Live end-to-end: bootstrap an org and admit a member through the REAL UI.
// Two isolated browser contexts = two people on different machines.
// Prereqs: server on :8787 (fresh), client built + vite preview on :4173.
// Run: node e2e.mjs
import { chromium } from "playwright";

const APP = "http://localhost:4173/?server=http://localhost:8787";
const PASS = { head: "head e2e passphrase", member: "member e2e passphrase" };
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(` ${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) throw new Error(`FAILED: ${name}`);
};

const browser = await chromium.launch();
try {
  // ---------- HEAD: bootstrap ceremony ----------
  const headCtx = await browser.newContext();
  const head = await headCtx.newPage();
  head.on("dialog", (d) => d.accept()); // solo-governance confirm
  await head.goto(APP);
  console.log("HEAD: bootstrap");
  await head.click("#b-boot");
  await head.fill("#pw1", PASS.head);
  await head.fill("#pw2", PASS.head);
  await head.click("#go");

  // single-screen ceremony: the Emergency Bundle, gated by typing Confirm
  await head.waitForSelector("#confirm-word", { timeout: 30_000 });
  const artifacts = (await head.locator(".code-block").allTextContents()).map((t) => t.trim());
  const secrets = artifacts.filter((a) => /^[0-9A-Z-]+$/.test(a) && a.length > 40);
  check(
    "bundle shows login id + five printed codes on one screen",
    artifacts.length === 6 && secrets.length === 5,
  );
  check("continue stays disabled until Confirm is typed", await head.locator("#next").isDisabled());
  await head.fill("#confirm-word", "Confirm");
  await head.click("#next");

  // finish bootstrap solo (0 admins) — confirm dialog auto-accepted
  await head.waitForSelector("#done");
  await head.click("#done");
  await head.waitForSelector("#mk-head-member-invite", { timeout: 15_000 });
  check("home shows solo-governance head panel", true);

  // issue a member invite through the journal
  await head.click("#mk-head-member-invite");
  await head.waitForSelector("#invites .code-block", { timeout: 15_000 });
  const invite = (await head.textContent("#invites .code-block"))?.trim() ?? "";
  check("member invite issued and displayed", invite.length > 40, invite.slice(0, 24) + "…");

  // reload the head's page NOW — the session must RESUME silently
  // and invites must survive (journal)
  await head.reload();
  await head.waitForSelector("#invites .code-block", { timeout: 30_000 });
  const inviteAfterReload = (await head.textContent("#invites .code-block"))?.trim() ?? "";
  check(
    "refresh resumes the session; invite survives (split custody + journal)",
    inviteAfterReload === invite,
  );

  // logout revokes the persisted session: the next load stays logged out
  await head.click("#logout");
  await head.waitForSelector("#b-login", { timeout: 15_000 });
  await head.reload();
  await head.waitForSelector("#b-login", { timeout: 15_000 });
  check("logout revokes persistence — reload stays on the landing page", true);
  // log back in for the rest of the suite
  await head.click("#b-login");
  await head.waitForSelector("#uid");
  await head.fill("#pw", PASS.head);
  await head.click("#go");
  await head.waitForSelector("#invites .code-block", { timeout: 30_000 });

  // ---------- JOINER: request to join ----------
  const joinCtx = await browser.newContext();
  const joiner = await joinCtx.newPage();
  await joiner.goto(APP);
  console.log("JOINER: join with invite");
  await joiner.click("#b-join");
  await joiner.fill("#invite", invite);
  await joiner.fill("#pw", PASS.member);
  await joiner.fill("#nick", "e2e-member");
  await joiner.click("#go");
  await joiner.waitForSelector("#status", { timeout: 30_000 });
  check(
    "join request sent; login ID shown",
    ((await joiner.textContent(".code-block")) ?? "").trim().length > 10,
  );

  // ---------- HEAD: solo-admit from the join request ----------
  console.log("HEAD: approve join request");
  const admitBtn = head.locator("#requests button.req-act", { hasText: "Admit as member (solo)" });
  await admitBtn.waitFor({ timeout: 30_000 }); // 2s poll surfaces the request
  await admitBtn.click();
  try {
    await head.locator("table td", { hasText: /^member$/ }).waitFor({ timeout: 30_000 });
  } catch (e) {
    console.log(
      " [debug] page error box:",
      (await head
        .locator("#err")
        .textContent()
        .catch(() => "")) || "(empty)",
    );
    console.log(
      " [debug] requests area:",
      (await head
        .locator("#requests")
        .textContent()
        .catch(() => "")) || "(empty)",
    );
    throw e;
  }
  check("roster shows the admitted member on the head's screen", true);
  await head.locator("#invites .code-block").waitFor({ state: "detached", timeout: 30_000 });
  check("consumed invite left the pending list (journal truth)", true);

  // ---------- JOINER: sees approval, logs in ----------
  console.log("JOINER: login after approval");
  await joiner.locator("#status", { hasText: "Approved" }).waitFor({ timeout: 30_000 });
  check("joiner sees approval", true);
  await joiner.click("#to-login");
  await joiner.waitForSelector("#uid");
  await joiner.fill("#pw", PASS.member);
  await joiner.click("#go");
  await joiner.waitForSelector("#role-badge", { timeout: 30_000 });
  check(
    "member logged in with role badge",
    ((await joiner.textContent("#role-badge")) ?? "").includes("member"),
  );
  // sidebar redesign: members land on the Cases panel with NO Organization
  // item — the org surface (roster included) is head/admin chrome
  await joiner.waitForSelector("#cases", { timeout: 15_000 });
  const orgNav = await joiner.locator("#nav-org").count();
  check("member sees the Cases panel and no Organization nav", orgNav === 0);

  console.log(`\nE2E PASSED — ${results.length}/${results.length} checks green`);
} finally {
  await browser.close();
}
