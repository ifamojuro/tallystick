// Kill-criterion #2 benchmark (design_order.md layer 7): full-journal
// replay, note decryption, and search-index build at realistic synthetic
// volume. Run: npm run bench (in client/).
//
// BUDGET (stated before measuring, following the spike's convention —
// research_notes.md 2026-08-06 set login crypto ≈1.9s at 20x throttle
// against a 3s budget):
// - full replay of a ~2,000-case org: < 5s unthrottled (dev hardware)
// - one member's decrypt+index (their keychain slice): < 1s unthrottled
// - rough weak-hardware estimate = 20x those numbers (CPU-bound WASM/JS,
// same scaling the spike observed); replay > ~100s extrapolated =
// FAIL: journal snapshots/caching must move up the roadmap before any
// pilot. Real donated-laptop numbers still required before trusting
// kill-criterion #2 (CPU throttle cannot test memory pressure).

import { crypto, journal } from "@tallystick/shared";
import { TestOrg } from "@tallystick/shared/src/journal/fixtures.ts";
import { newNoteUpdate } from "./src/notes.ts";
import { buildIndex, search } from "./src/search.ts";
import type { CaseView, NoteView } from "./src/flows.ts";

const MEMBERS = Number(process.env.MEMBERS ?? 20);
const CASES_PER = Number(process.env.CASES_PER ?? 100);
const NOTES_PER = Number(process.env.NOTES_PER ?? 3);

const WORDS =
 "housing court hearing intake motion filing benefits appeal safety plan referral clinic interpreter continuance deadline evidence declaration".split(" ");
const noteText = (i: number, c: number, n: number) => {
 const w = () => WORDS[(i * 31 + c * 17 + n * 7 + Math.floor(pseudo() * WORDS.length)) % WORDS.length];
 let s = `synthetic note ${i}/${c}/${n}: `;
 for (let k = 0; k < 60; k++) s += w() + " ";
 return s;
};
// deterministic pseudo-random (Math.random is banned nowhere here, but
// deterministic content makes runs comparable)
let seed = 42;
const pseudo = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);

const ms = (t: number) => `${t.toFixed(0)} ms`;

await crypto.init();

console.log(`building synthetic org: ${MEMBERS} members × ${CASES_PER} cases × ${NOTES_PER} notes…`);
let t0 = performance.now();
const org = new TestOrg();
const actors = org.populate({
 members: MEMBERS,
 casesPerMember: CASES_PER,
 notesPerCase: NOTES_PER,
 notePlaintext: (i, c, n) => newNoteUpdate(noteText(i, c, n)),
});
const buildTime = performance.now() - t0;
const entries = org.entries;
console.log(` ${entries.length} journal entries, built in ${ms(buildTime)} (not the measurement)`);

// --- measurement 1: full replay (every client pays this at login) --------
t0 = performance.now();
const state = journal.replay(entries);
const replayTime = performance.now() - t0;

// --- measurement 2: one member's keychain + decrypt + index --------------
// (the "caseworker logs in" cost on top of replay)
const me = actors[0]!;
t0 = performance.now();
const keychain = journal.deriveKeychain(state, me.userId, me.enc);
const keychainTime = performance.now() - t0;

t0 = performance.now();
const td = new TextDecoder();
const cases: CaseView[] = [];
for (const [caseTag, keys] of keychain) {
 const c = state.cases.get(caseTag)!;
 const notes: NoteView[] = [];
 for (const [recordId, note] of c.notes) {
 const wrapEpoch = note.snapshot?.epoch ?? note.updates[0]!.epoch;
 const caseKey = keys.get(wrapEpoch)!;
 const recordKey = crypto.aeadOpen(
 caseKey,
 crypto.fromB64u(note.wrappedRecordKey),
 journal.recordKeyAad(state.orgId, caseTag, wrapEpoch)
 );
 // bench uses raw text extraction from single-update notes (Yjs decode
 // is exercised, matching the real read path)
 const { docFrom, textOf } = await import("./src/notes.ts");
 const doc = docFrom(
 note.updates.map((u) =>
 crypto.aeadOpen(recordKey, crypto.fromB64u(u.ct), journal.noteAad(state.orgId, caseTag, u.epoch, recordId))
 )
 );
 notes.push({ recordId, text: textOf(doc), locked: false, lastSeq: 1, lastAuthor: "" });
 }
 cases.push({
 caseTag,
 creatorId: me.userId,
 epoch: 1,
 amCreator: true,
 holders: [me.userId],
 notes,
 label: (notes[0]?.text ?? "").split("\n")[0] ?? "",
 });
}
const decryptTime = performance.now() - t0;

t0 = performance.now();
const index = buildIndex(cases);
const indexTime = performance.now() - t0;

t0 = performance.now();
const hits = search(index, "housing hearing");
const queryTime = performance.now() - t0;

const login = replayTime + keychainTime + decryptTime + indexTime;
console.log(`
=== kill-criterion #2 measurements ===
journal entries ${entries.length}
total cases ${state.cases.size}
replay (all clients) ${ms(replayTime)}
one member's keychain ${ms(keychainTime)} (${keychain.size} cases)
decrypt member's notes ${ms(decryptTime)} (${cases.reduce((s, c) => s + c.notes.length, 0)} notes)
build search index ${ms(indexTime)} (${index.notes.size} notes, ${index.postings.size} terms)
query "housing hearing" ${ms(queryTime)} (${hits.length} hits)
------------------------------------------
TOTAL login-path cost ${ms(login)}
20x weak-hardware estimate ${(login * 20 / 1000).toFixed(1)} s
budget: replay+index < 5s unthrottled → ${login < 5000 ? "PASS" : "FAIL"}
`);
