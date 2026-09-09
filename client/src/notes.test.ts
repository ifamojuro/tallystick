import { describe, expect, it } from "vitest";
import { docFrom, editUpdate, fullState, newNoteUpdate, textOf } from "./notes.ts";

describe("CRDT note codec", () => {
  it("merges concurrent edits identically regardless of application order", () => {
    const base = newNoteUpdate("Hello world");
    // two clients diverge from the same base without seeing each other
    const a = docFrom([base]);
    const b = docFrom([base]);
    const updA = editUpdate(a, "PREFIX >> Hello world");
    const updB = editUpdate(b, "Hello world << SUFFIX");
    // journal order and reverse order converge to the same text
    const forward = textOf(docFrom([base, updA, updB]));
    const reverse = textOf(docFrom([base, updB, updA]));
    expect(forward).toBe(reverse);
    expect(forward).toContain("PREFIX");
    expect(forward).toContain("SUFFIX");
    expect(forward).toContain("Hello world");
  });

  it("edits are incremental, and a snapshot compacts to equal state", () => {
    const base = newNoteUpdate("line one\nline two");
    const doc = docFrom([base]);
    const upd = editUpdate(doc, "line one\nline two\nline three");
    expect(upd.length).toBeLessThan(fullState(doc).length); // truly incremental
    // snapshot (full state) replaces history: same text from one update
    const compacted = docFrom([fullState(doc)]);
    expect(textOf(compacted)).toBe(textOf(doc));
    // and future updates build on the snapshot
    const post = editUpdate(compacted, textOf(compacted) + "\nline four");
    expect(textOf(docFrom([fullState(doc), post]))).toContain("line four");
    expect(upd.length).toBeGreaterThan(0);
  });
});
