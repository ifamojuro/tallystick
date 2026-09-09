// Local search.
// An in-memory inverted index built ONLY from cases the session's keychain
// opens — keychain-scoped by construction, because the input is the already
// decrypted CaseView list. Memory-only lifecycle: rebuilt from verified
// state, discarded with the session, never serialized, never uploaded.

import type { CaseView } from "./flows.ts";

export interface SearchHit {
  caseTag: string;
  recordId: string;
  caseLabel: string;
  /** short plaintext excerpt around the first matched term */
  snippet: string;
}

interface NoteEntry {
  caseTag: string;
  recordId: string;
  caseLabel: string;
  text: string;
}

export interface SearchIndex {
  /** token -> set of note keys ("caseTag/recordId") */
  postings: Map<string, Set<string>>;
  notes: Map<string, NoteEntry>;
}

export function tokenize(text: string): string[] {
  return (text.toLowerCase().match(/[\p{L}\p{N}]{2,}/gu) ?? []) as string[];
}

export function buildIndex(cases: CaseView[]): SearchIndex {
  const postings = new Map<string, Set<string>>();
  const notes = new Map<string, NoteEntry>();
  for (const c of cases) {
    for (const n of c.records) {
      if (n.text === null) continue; // locked notes (e.g. revoked) are not indexed
      const key = `${c.caseTag}/${n.recordId}`;
      // meta string values are searchable too (profile name, contact
      // channel…) so "find the case by the client's name" works
      const metaText = Object.values(n.meta)
        .filter((v): v is string => typeof v === "string")
        .join(" ");
      const searchable = `${n.text} ${metaText}`.trim();
      notes.set(key, {
        caseTag: c.caseTag,
        recordId: n.recordId,
        caseLabel: c.label,
        text: searchable,
      });
      for (const tok of new Set(tokenize(searchable))) {
        let set = postings.get(tok);
        if (!set) postings.set(tok, (set = new Set()));
        set.add(key);
      }
    }
  }
  return { postings, notes };
}

/** AND across terms; the final term also matches as a prefix (search-as-you-type). */
export function search(index: SearchIndex, query: string, limit = 20): SearchHit[] {
  const terms = tokenize(query);
  if (terms.length === 0) return [];
  const candidatesPer = terms.map((term, i) => {
    if (i < terms.length - 1) return index.postings.get(term) ?? new Set<string>();
    // prefix match for the final term
    const acc = new Set<string>();
    for (const [tok, keys] of index.postings) {
      if (tok.startsWith(term)) for (const k of keys) acc.add(k);
    }
    return acc;
  });
  candidatesPer.sort((a, b) => a.size - b.size); // intersect smallest-first
  let result = [...candidatesPer[0]!];
  for (const set of candidatesPer.slice(1)) result = result.filter((k) => set.has(k));

  return result.slice(0, limit).map((key) => {
    const n = index.notes.get(key)!;
    const at = n.text.toLowerCase().indexOf(terms[0]!);
    const start = Math.max(0, at - 40);
    return {
      caseTag: n.caseTag,
      recordId: n.recordId,
      caseLabel: n.caseLabel,
      snippet:
        (start > 0 ? "…" : "") +
        n.text.slice(start, Math.min(n.text.length, (at < 0 ? 0 : at) + 60)).replace(/\n/g, " ") +
        "…",
    };
  });
}
