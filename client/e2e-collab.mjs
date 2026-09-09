// Collaboration e2e (cleanup-backlog item 5): draft survival across
// background sync, conflict notice, toast, stale-draft CRDT merge.
// Prereqs: fresh server on :8787, vite preview on :4173. Run from client/.
import { chromium } from "playwright";

const APP = "http://localhost:4173/?server=http://localhost:8787";
const PASS = { head: "head smoke passphrase", member: "member smoke passphrase" };
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
  // ---------- HEAD: bootstrap ----------
  const headCtx = await browser.newContext();
  const head = await headCtx.newPage();
  head.on("dialog", (d) => d.accept());
  await head.goto(APP);
  await head.click("#b-boot");
  await head.fill("#pw1", PASS.head);
  await head.fill("#pw2", PASS.head);
  await head.click("#go");
  await head.waitForSelector("#confirm-word", { timeout: 30_000 });
  await head.fill("#confirm-word", "Confirm");
  await head.click("#next");
  await head.waitForSelector("#done");
  await head.click("#done");
  await head.waitForSelector("#mk-head-member-invite", { timeout: 15_000 });
  console.log("HEAD: bootstrapped");

  // ---------- HEAD: create a case (head lands on Organization) ----------
  await head.click("#nav-cases");
  await head.waitForSelector("#new-case", { timeout: 15_000 });
  await head.fill("#new-case", "Synthetic intake #1");
  await head.click("#mk-case");
  await head.waitForSelector("button.open-case", { timeout: 15_000 });
  await head.click("button.open-case");
  await openSecs(head);
  await head.waitForSelector("#new-note", { timeout: 15_000 });
  await head.fill("#new-note", "Synthetic intake #1");
  await head.click("#add-note");
  await head.waitForSelector(".note-view[data-rid]", { timeout: 15_000 });
  await head.click("#back");
  await head.waitForSelector("#cases", { timeout: 15_000 });
  console.log("HEAD: case + first note created");

  // ---------- HEAD: issue member invite (solo mode) ----------
  await head.click("#nav-org");
  await head.waitForSelector("#mk-head-member-invite", { timeout: 15_000 });
  await head.click("#mk-head-member-invite");
  await head.waitForSelector("#invites .code-block", { timeout: 15_000 });
  const invite = (await head.textContent("#invites .code-block"))?.trim() ?? "";

  // ---------- MEMBER: join ----------
  const memCtx = await browser.newContext();
  const mem = await memCtx.newPage();
  mem.on("dialog", (d) => d.accept());
  await mem.goto(APP);
  await mem.click("#b-join");
  await mem.fill("#invite", invite);
  await mem.fill("#pw", PASS.member);
  await mem.fill("#nick", "smoke-member");
  await mem.click("#go");
  await mem.waitForSelector("#status", { timeout: 30_000 });

  // ---------- HEAD: solo-admit ----------
  const admitBtn = head.locator("#requests button.req-act", { hasText: "Admit as member (solo)" });
  await admitBtn.waitFor({ timeout: 20_000 });
  await admitBtn.click();
  await mem.locator("#status", { hasText: "Approved" }).waitFor({ timeout: 30_000 });
  await mem.click("#to-login");
  await mem.waitForSelector("#uid");
  await mem.fill("#pw", PASS.member);
  await mem.click("#go");
  await mem.waitForSelector("#logout", { timeout: 30_000 });
  console.log("MEMBER: admitted and logged in");

  // ---------- HEAD: open case, share with member ----------
  await head.click("#nav-cases");
  await head.waitForSelector("button.open-case", { timeout: 15_000 });
  await head.click("button.open-case");
  await openSecs(head);
  await head.waitForSelector(".note-view[data-rid]", { timeout: 15_000 });
  await head.waitForSelector("#share", { timeout: 15_000 });
  await head.click("#share");
  await head.waitForSelector("text=Every member already has access", { timeout: 15_000 });
  console.log("HEAD: case shared");

  // ---------- MEMBER: home shows the case; open it ----------
  await mem.waitForSelector("button.open-case", { timeout: 20_000 });
  await mem.click("button.open-case");
  await openSecs(mem);
  await mem.waitForSelector(".note-view[data-rid]", { timeout: 15_000 });

  // ---------- HEAD types a draft (no save) ----------
  const base = "Synthetic intake #1";
  const headDraft = `HEAD PREFIX >> ${base}`;
  await head.click("button.edit-note");
  await head.waitForSelector("textarea[data-rid]", { timeout: 15_000 });
  await head.fill("textarea[data-rid]", headDraft);

  // ---------- MEMBER edits the same note and saves ----------
  await mem.click("button.edit-note");
  await mem.waitForSelector("textarea[data-rid]", { timeout: 15_000 });
  await mem.fill("textarea[data-rid]", `${base} << MEMBER SUFFIX`);
  await mem.click("button.save");
  await mem.waitForSelector(`.note-view[data-rid] >> text=MEMBER SUFFIX`, { timeout: 15_000 });
  console.log("MEMBER: edit saved");

  // ---------- HEAD: poll picks it up; draft must survive + be narrated ----
  await head.waitForSelector(".merge-note", { timeout: 15_000 });
  const headTa = await head.inputValue("textarea[data-rid]");
  check("head draft survived the background merge", headTa === headDraft, headTa);
  check(
    "conflict notice shown",
    ((await head.textContent(".merge-note")) ?? "").includes("while you were editing"),
  );
  const toastText =
    (await head
      .locator(".toast")
      .first()
      .textContent()
      .catch(() => "")) ?? "";
  check("toast attributes the remote edit", toastText.includes("Note updated by"), toastText);
  const badge = await head.locator(".badge.updated").count();
  check("sticky 'updated' badge shown on the note", badge >= 1);

  // ---------- HEAD saves the stale draft; both edits must survive --------
  await head.click("button.save");
  await head.waitForSelector(".note-view[data-rid] >> text=HEAD PREFIX", { timeout: 15_000 });
  const merged = ((await head.textContent(".note-view[data-rid]")) ?? "").trim();
  check(
    "stale save merged, not clobbered (head view)",
    merged.includes("HEAD PREFIX") && merged.includes("MEMBER SUFFIX") && merged.includes(base),
    merged,
  );
  await mem.waitForFunction(
    () => document.querySelector(".note-view[data-rid]")?.textContent?.includes("HEAD PREFIX"),
    { timeout: 15_000 },
  );
  const memMerged = ((await mem.textContent(".note-view[data-rid]")) ?? "").trim();
  check("identical merge on the member's client", memMerged === merged, memMerged);

  // ---------- HEAD: history panel ----------
  await head.click("button.history");
  await head.waitForSelector(".history-panel", { timeout: 15_000 });
  const rows = await head.locator(".history-panel details").count();
  check("history shows one step per journal event", rows === 3, `${rows} rows`);
  const insTexts = await head.locator(".history-panel ins").allTextContents();
  check(
    "history diffs attribute both edits",
    insTexts.some((t) => t.includes("MEMBER SUFFIX")) &&
      insTexts.some((t) => t.includes("HEAD PREFIX")),
    insTexts.join(" | "),
  );
  await head.locator(".history-panel details summary").first().click();
  const asOf = (await head.locator(".history-panel details pre").first().textContent()) ?? "";
  check("expanded step shows full text as of that seq", asOf === merged, asOf);

  // ---------- MEMBER back home: head edits again -> 'updated' case badge --
  await mem.click("#back");
  await mem.waitForSelector("button.open-case", { timeout: 15_000 });
  await head.click("button.edit-note");
  await head.waitForSelector("textarea[data-rid]", { timeout: 15_000 });
  await head.fill("textarea[data-rid]", `${merged}\nsecond head edit`);
  await head.click("button.save");
  await mem.waitForSelector("#cases .badge.updated", { timeout: 20_000 });
  check("home case list shows 'updated' badge after remote edit", true);
  await mem.click("button.open-case");
  await openSecs(mem);
  await mem.waitForSelector(".note-view[data-rid]", { timeout: 15_000 });
  await mem.click("#back");
  await mem.waitForSelector("button.open-case", { timeout: 15_000 });
  await mem.waitForTimeout(2500); // one poll cycle
  const badgeAfterLook = await mem.locator("#cases .badge.updated").count();
  check("badge clears after looking at the case", badgeAfterLook === 0);

  console.log(`\nSMOKE PASSED — ${results.length}/${results.length} checks green`);
} finally {
  await browser.close();
}
