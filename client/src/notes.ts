// Note content is a Yjs CRDT document — one Y.Doc
// per note (record_id), text in getText("t"). Each note_update event's
// plaintext payload is ONE Yjs update; concurrent authorized edits merge
// deterministically, and correctness must not depend on journal order.
// Yjs 13.6.32, exact-pinned (the only permitted CRDT library).

import * as Y from "yjs";

/** Rebuild a note's document from its decrypted update payloads (the
 * revocation snapshot, if any, is itself a valid full-state update).
 * Application order does not affect the result — that's the CRDT claim,
 * and the layer-6 test asserts it. */
export function docFrom(updates: Uint8Array[]): Y.Doc {
  const doc = new Y.Doc();
  for (const u of updates) Y.applyUpdate(doc, u);
  return doc;
}

export function textOf(doc: Y.Doc): string {
  return doc.getText("t").toString();
}

/** First update of a brand-new note: full state of a fresh doc. */
export function newNoteUpdate(text: string): Uint8Array {
  const doc = new Y.Doc();
  doc.getText("t").insert(0, text);
  return Y.encodeStateAsUpdate(doc);
}

// ---- typed records ---------------------------
// Structure lives INSIDE the encrypted doc: a "meta" Y.Map (kind + fields)
// beside the "t" Y.Text body. The journal/protocol never sees any of it.
// Records without meta are plain notes (the legacy shape IS the fail-open
// path for unknown or malformed kinds).

export type MetaValue = string | number | boolean | null;

/** First update of a typed record: meta fields + optional body text. */
export function newRecordUpdate(meta: Record<string, MetaValue>, text = ""): Uint8Array {
  const doc = new Y.Doc();
  doc.transact(() => {
    const m = doc.getMap("meta");
    for (const [k, v] of Object.entries(meta)) m.set(k, v);
    if (text) doc.getText("t").insert(0, text);
  });
  return Y.encodeStateAsUpdate(doc);
}

/** Incremental update setting meta fields (status flip, task toggle,
 * title edit). Last-writer-wins per field — Y.Map semantics, which is
 * the right merge for scalar fields. */
export function metaUpdate(doc: Y.Doc, fields: Record<string, MetaValue>): Uint8Array {
  const before = Y.encodeStateVector(doc);
  doc.transact(() => {
    const m = doc.getMap("meta");
    for (const [k, v] of Object.entries(fields)) m.set(k, v);
  });
  return Y.encodeStateAsUpdate(doc, before);
}

/** Merge incremental updates into one payload (e.g. a meta stamp plus a
 * text diff posted as a single journal event). */
export function mergeUpdates(updates: Uint8Array[]): Uint8Array {
  return Y.mergeUpdates(updates);
}

/** The record's meta as a plain object — values are whatever the writing
 * client claimed; readers validate (fail-open to plain note). */
export function metaOf(doc: Y.Doc): Record<string, unknown> {
  return Object.fromEntries(doc.getMap("meta").entries());
}

/** Apply an edit as a minimal delete/insert (common prefix/suffix diff) and
 * return only the INCREMENTAL update since the doc's prior state. The
 * diff keeps concurrent edits to different regions mergeable instead of
 * clobbering the whole text. */
export function editUpdate(doc: Y.Doc, newText: string): Uint8Array {
  const before = Y.encodeStateVector(doc);
  const t = doc.getText("t");
  const old = t.toString();
  let prefix = 0;
  while (prefix < old.length && prefix < newText.length && old[prefix] === newText[prefix])
    prefix++;
  let suffix = 0;
  while (
    suffix < old.length - prefix &&
    suffix < newText.length - prefix &&
    old[old.length - 1 - suffix] === newText[newText.length - 1 - suffix]
  )
    suffix++;
  doc.transact(() => {
    const delLen = old.length - prefix - suffix;
    if (delLen > 0) t.delete(prefix, delLen);
    const ins = newText.slice(prefix, newText.length - suffix);
    if (ins) t.insert(prefix, ins);
  });
  return Y.encodeStateAsUpdate(doc, before);
}

/** Full current state as one update — the revocation snapshot payload:
 * the compacted note under the new epoch's fresh record key. */
export function fullState(doc: Y.Doc): Uint8Array {
  return Y.encodeStateAsUpdate(doc);
}

/** The note's text after each successive update, in order: index i is the
 * merged text once updates[0..i] have applied. Feeds the history panel —
 * one readable state per journal event. */
export function textTimeline(updates: Uint8Array[]): string[] {
  const doc = new Y.Doc();
  const out: string[] = [];
  for (const u of updates) {
    Y.applyUpdate(doc, u);
    out.push(textOf(doc));
  }
  return out;
}
