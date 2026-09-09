import { describe, expect, it } from "vitest";
import { buildIndex, search, tokenize } from "./search.ts";
import type { CaseView, NoteView } from "./flows.ts";

const note = (recordId: string, text: string | null): NoteView => ({
  recordId,
  text,
  locked: text === null,
  createdSeq: 1,
  lastSeq: 1,
  lastAuthor: "a",
  kind: "note",
  meta: {},
});
const cse = (caseTag: string, label: string, notes: NoteView[]): CaseView => ({
  caseTag,
  creatorId: "a",
  epoch: 1,
  amCreator: true,
  holders: ["a"],
  records: notes,
  notes,
  contacts: [],
  tasks: [],
  title: label,
  status: "open",
  label,
});

describe("local search index", () => {
  it("tokenizes unicode text, dropping single characters", () => {
    expect(tokenize("Housing hearing 3B — 14 días, café")).toEqual([
      "housing",
      "hearing",
      "3b",
      "14",
      "días",
      "café",
    ]);
  });

  it("ANDs terms, prefix-matches the final term, and snippets around hits", () => {
    const index = buildIndex([
      cse("c1", "Intake A", [note("n1", "housing court hearing on tuesday")]),
      cse("c2", "Intake B", [note("n2", "medical records for the hearing")]),
      cse("c3", "Intake C", [note("n3", "unrelated grocery list")]),
    ]);
    expect(search(index, "hearing").length).toBe(2);
    expect(search(index, "housing hearing").map((h) => h.caseTag)).toEqual(["c1"]);
    expect(search(index, "medical hear").map((h) => h.caseTag)).toEqual(["c2"]); // prefix
    expect(search(index, "grocery")[0]!.snippet).toContain("grocery");
    expect(search(index, "")).toEqual([]);
    expect(search(index, "zzz")).toEqual([]);
  });

  it("never indexes locked notes", () => {
    const index = buildIndex([cse("c1", "Locked", [note("n1", null)])]);
    expect(index.notes.size).toBe(0);
    expect(search(index, "anything")).toEqual([]);
  });
});
