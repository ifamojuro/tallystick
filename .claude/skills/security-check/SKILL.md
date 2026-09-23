---
name: security-check
description: Independent check that Tallystick's code still matches its threat model. Use after changes to server/, shared/ or client flows, before opening a security-relevant PR, or when asked "do the security assertions still hold?" or "is the CAN-see table accurate?"
context: fork
agent: general-purpose
---

# Tallystick security check

You are reviewing code you did not write. Be skeptical: the job is to find where the code and `docs/threat_model.md` disagree, not to confirm they agree. Report findings only. Don't edit code or docs.

All paths below are relative to the repository root (the folder that contains this `.claude/` directory), not the session's working directory.

Scope: $ARGUMENTS (if empty, review the current branch's changes against `main`, plus a full pass over §6).

## Steps

1. **Read the contract.** Read `docs/threat_model.md` in full, especially §1 (the claim), §6 (what the server sees), §10 (decisions that must not be reversed) and §11 (known gaps).

2. **Rebuild the CAN-see table from the code.** Go through:
   - every field and Map in `server/src/store.ts`
   - every route in `server/src/server.ts`: what it receives, what it stores and what it keeps in memory (rate-limit buckets, challenges, sessions)
   - every plaintext field of journal envelopes in `shared/src/journal/`

   List everything the server can see. Compare it to §6, both ways: anything the server sees that §6 doesn't list, and anything §6 lists that no longer exists.

3. **Check the changes.** For each changed file in scope, ask:
   - What does this add to the CAN-see table?
   - Does it add side-state outside the journal? If so, is there a written reason?
   - Does it touch a §10 decision?
   - Does a multi-person safeguard now block a solo org, or switch off once armed?
   - Does it close a §11 gap? A gap only counts as closed with a test.

4. **Ask the minimization question.** Does the server see anything it doesn't need to? Look especially at the "chosen" rows in §6.

5. **Check the other claims.** Spot-check §1 and §7 against the code: keys never leave the client unencrypted, the server never decrypts, search stays local, no per-record read API exists.

6. **Run the tests.** Run `npm test --workspaces` and `npm run typecheck --workspaces`. If the change touches a user flow, also run the matching e2e suite. Each needs a fresh server on :8787 and `vite preview` on :4173 (see `AGENTS.md`). Report pass or fail with the failing output.

## Report

Lead with a verdict: **holds**, **holds with doc updates needed** or **broken**. Then:

- **CAN-see diff**: a table with the columns *Row*, *Change (added / removed / wrong)*, *Evidence (file:line)* and *Suggested §6 wording*. Write "no differences" if there are none.
- **Findings**: ranked by severity, each with file:line, what's wrong and a concrete fix.
- **Unneeded exposure**: anything the server sees that it doesn't need to.
- **Threat model edits**: sections to update, and whether the version needs a bump.
- **Tests**: what ran and the results.

