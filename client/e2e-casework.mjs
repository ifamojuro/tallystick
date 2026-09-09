// Case-content v2 e2e: header/title/status,
// profile, contact log, tasks + deadlines strip, status filters, dirty dot.
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

// sections start collapsed by default — only the bio opens;
// openSecs opens them all so the suite can interact with their contents
const openSecs = async (p) => {
  await p.waitForSelector("details[data-sec]", { state: "attached", timeout: 15_000 });
  await p.$$eval("details[data-sec]", (ds) => ds.forEach((d) => (d.open = true)));
};

const browser = await chromium.launch();
try {
  const p = await (await browser.newContext()).newPage();
  p.on("dialog", (d) => d.accept());
  await p.goto(APP);
  await p.click("#b-boot");
  await p.fill("#pw1", "cw pw");
  await p.fill("#pw2", "cw pw");
  await p.click("#go");
  await p.waitForSelector("#confirm-word", T);
  await p.fill("#confirm-word", "Confirm");
  await p.click("#next");
  await p.waitForSelector("#done");
  await p.click("#done");
  await p.waitForSelector("#nav-cases", T);
  await p.click("#nav-cases");

  // ---------- create: title is first-class ----------
  await p.waitForSelector("#new-case", T);
  await p.fill("#new-case", "Maria R. — housing");
  await p.click("#mk-case");
  await p.waitForSelector("#cases >> text=Maria R. — housing", T);
  check("1. case created with explicit title", true);
  await p.click("button.open-case");
  await p.waitForSelector("#edit-title", T);
  await p.click("#edit-title");
  await p.waitForSelector("#case-title", T);
  check(
    "2. inline header rename prefills the current title",
    (await p.inputValue("#case-title")) === "Maria R. — housing",
  );
  await p.click("#cancel-title");
  await p.waitForSelector("#edit-title", T);

  // ---------- Case Bio (open by default; plain-text; read/edit views) ----
  const bioOpen = await p.locator("details[data-sec='bio'][open]").count();
  const othersOpen = await p
    .locator(
      "details[data-sec='tasks'][open], details[data-sec='notes'][open], details[data-sec='contacts'][open], details[data-sec='access'][open]",
    )
    .count();
  check("3. Case Bio open by default, other sections collapsed", bioOpen === 1 && othersOpen === 0);
  await openSecs(p);
  await p.click("#edit-bio"); // "Write bio" on an empty case
  await p.waitForSelector("#save-bio", T);
  await p
    .locator("details[data-sec='bio'] textarea")
    .fill("Maria R., Spanish-speaking; unsafe to leave voicemail. Code word: girasol.");
  await p.click("#save-bio");
  await p.waitForSelector("details[data-sec='bio'] .note-view", T);
  check(
    "4. bio saved and rendered read-only",
    ((await p.textContent("details[data-sec='bio'] .note-view")) ?? "").includes("girasol") &&
      (await p.locator("#save-bio").count()) === 0,
  );
  check(
    "4b. Case Bio stays open across re-render",
    (await p.locator("details[data-sec='bio'][open]").count()) === 1,
  );
  await p.click("#edit-bio");
  await p.waitForSelector("#save-bio", T);
  check(
    "4c. Edit repopulates the editable view with the saved bio",
    (await p.inputValue("details[data-sec='bio'] textarea")).includes("girasol"),
  );
  await p.click("#cancel-bio");
  await p.waitForSelector("details[data-sec='bio'] .note-view", T);

  // ---------- contact log ----------
  await p.locator("#contact-channel").selectOption("court");
  await p.fill("#contact-text", "accompanied to protective-order hearing");
  await p.click("#add-contact");
  try {
    await p.waitForSelector("text=accompanied to protective-order hearing", T);
  } catch (e) {
    console.log(" [debug] err box:", (await p.textContent("#err").catch(() => "")) || "(empty)");
    console.log(
      " [debug] contact-text value:",
      await p.inputValue("#contact-text").catch(() => "?"),
    );
    throw e;
  }
  const entry = (await p.textContent(".card:has-text('Contact log')")) ?? "";
  check(
    "5. contact entry logged with channel + date",
    entry.includes("Court") && /\d{4}/.test(entry),
  );

  // ---------- tasks + deadlines ----------
  await p.fill("#task-text", "file continuance");
  const y = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
  await p.fill("#task-due", y);
  await p.click("#add-task");
  await p.waitForSelector("text=file continuance", T);
  check("6. dated task added", true);
  await p.click("#back");
  await p.waitForSelector("text=Upcoming deadlines", T);
  check(
    "7. deadlines strip shows the open dated task",
    ((await p.textContent("body")) ?? "").includes("file continuance"),
  );

  // toggle done → strip empties
  await p.click("button.open-case");
  await openSecs(p);
  await p.waitForSelector("input.task-toggle", T);
  await p.check("input.task-toggle");
  await p.waitForFunction(
    () => document.querySelector("input.task-toggle")?.["checked"] === true,
    null,
    T,
  );
  await p.click("#back");
  await p.waitForSelector("#cases", T);
  const stripGone = (await p.locator("text=Upcoming deadlines").count()) === 0;
  check("8. completing the task clears the deadlines strip", stripGone);

  // ---------- status + filters ----------
  await p.click("button.open-case");
  await p.waitForSelector("#case-status", T);
  await p.locator("#case-status").selectOption("closed");
  // the [selected] attribute only appears once the meta update round-trips
  // through the journal and the header re-renders from verified state
  await p.waitForSelector('#case-status option[value="closed"][selected]', {
    state: "attached",
    ...T,
  });
  check("9. status change renders in the header select", true);
  await p.click("#back");
  await p.waitForSelector("#cases", T);
  check(
    "10. closed case leaves the open filter",
    ((await p.textContent("#cases")) ?? "").includes("No open cases"),
  );
  await p.click("button.case-filter[data-st='closed']");
  await p.waitForSelector("#cases >> text=Maria R. — housing", T);
  check("11. closed filter shows it", true);

  // ---------- dirty dot on notes ----------
  await p.click("button.open-case");
  await openSecs(p);
  await p.waitForSelector("#new-note", T);
  await p.fill("#new-note", "working note");
  await p.click("#add-note");
  await p.waitForSelector(".note-view[data-rid]", T);
  check(
    "11b. saved note renders read-only (no textarea)",
    (await p.locator("textarea[data-rid]").count()) === 0,
  );
  await p.click("button.edit-note");
  await p.waitForSelector("textarea[data-rid]", T);
  await p.locator("textarea[data-rid]").first().fill("working note — edited");
  const dotVisible = await p
    .locator("button.save .dirty-dot")
    .first()
    .evaluate((el) => el.style.display !== "none");
  check("12. dirty dot appears on unsaved edit", dotVisible);
  await p.locator("button.save").first().click();
  await p.waitForSelector(".note-view[data-rid]", T);
  check(
    "13. save returns to the read view with the new text",
    ((await p.textContent(".note-view[data-rid]")) ?? "").includes("working note — edited"),
  );

  console.log(`\nCASEWORK E2E PASSED — ${results.length}/${results.length} checks green`);
} finally {
  await browser.close();
}
