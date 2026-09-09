// Acceptance test: the complete governance bootstrap and two-admin
// admission ceremony, every actor running the real flows against the real
// server over HTTP. This is workflow steps 1–2 end to end.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { crypto, journal } from "@tallystick/shared";
import { createTallystickServer, type TallystickServer } from "@tallystick/server/src/server.ts";
import * as flows from "./flows.ts";
import { server as api } from "./api.ts";

let srv: TallystickServer;
let base: { base: string };
const NOW = 1_750_000_000_000;

beforeAll(async () => {
  await crypto.init();
  srv = createTallystickServer();
  base = { base: `http://localhost:${await srv.listen(0)}` };
});

afterAll(async () => {
  await srv.close();
});

describe("workflow steps 1–2 over HTTP", () => {
  let boot: flows.BootstrapResult;
  const passphrases = {
    head: "head passphrase long enough",
    adminA: "admin a passphrase",
    adminB: "admin b passphrase",
    member: "member passphrase",
  };
  let adminAJoin: flows.JoinResult;
  let adminBJoin: flows.JoinResult;
  let adminASession: flows.Session;
  let adminBSession: flows.Session;

  it("bootstraps governance and prints the ceremony artifacts", async () => {
    boot = await flows.bootstrapOrg(base, passphrases.head);
    expect(flows.role(boot.session)).toBe("head");
    // seq 1 genesis + two share_custody_acks (the head holds both shares
    // at genesis — journaled fact)
    expect(boot.session.state.chain.seq).toBe(3);
    expect(boot.session.state.shareCustody).toEqual({
      A: boot.session.userId,
      B: boot.session.userId,
    });
    // printed artifacts decode cleanly (transcription-checked)
    expect(crypto.decodePrinted(boot.headRecoverySecretPrinted).length).toBe(32);
    expect(crypto.decodePrinted(boot.recoveryShareAPrinted).length).toBe(32);
    expect(crypto.decodePrinted(boot.recoveryShareBPrinted).length).toBe(32);
    // fourth artifact: the head-package ciphertext, decodable print
    expect(crypto.decodePrinted(boot.headPackageCtPrinted).length).toBeGreaterThan(32);
    // the head's personal account-recovery code exists (D1)
    expect(boot.accountRecoveryPrinted.length).toBeGreaterThan(0);
    // a second bootstrap on the same server refuses
    await expect(flows.bootstrapOrg(base, "x")).rejects.toThrow(/already hosts/);
  });

  it("creates two admins by admitting members, then promoting them", async () => {
    // there is no admin invite and no direct admin admission —
    // everyone joins as an ordinary member and the head PROMOTES
    const inviteA = await flows.issueInvite(boot.session);
    const inviteB = await flows.issueInvite(boot.session);
    adminAJoin = await flows.joinWithInvite(base, passphrases.adminA, inviteA.printed);
    adminBJoin = await flows.joinWithInvite(base, passphrases.adminB, inviteB.printed);

    const { requests } = await api.joinRequests(boot.session.api);
    expect(requests.length).toBe(2);
    const reqA = requests.find((r) => r.user_id === adminAJoin.userId)!;
    const reqB = requests.find((r) => r.user_id === adminBJoin.userId)!;

    // wrong invite for a request → refused before anything is signed
    await expect(flows.admitMemberSolo(boot.session, reqA, inviteB.printed)).rejects.toThrow(
      /different invite/,
    );

    await flows.admitMemberSolo(boot.session, reqA, inviteA.printed);
    await flows.admitMemberSolo(boot.session, reqB, inviteB.printed);
    expect(boot.session.state.members.get(adminAJoin.userId)?.role).toBe("member");

    await flows.promoteToAdmin(boot.session, adminAJoin.userId);
    expect(boot.session.state.adminBarrierArmed).toBe(false); // one admin: still solo
    await flows.promoteToAdmin(boot.session, adminBJoin.userId);
    expect(journal.activeAdmins(boot.session.state).length).toBe(2);
    expect(boot.session.state.adminBarrierArmed).toBe(true); // second grant arms it

    // both admins can now log in with only their passphrase + login ID
    adminASession = await flows.login(base, adminAJoin.userId, passphrases.adminA);
    adminBSession = await flows.login(base, adminBJoin.userId, passphrases.adminB);
    expect(flows.role(adminASession)).toBe("admin");
    expect(flows.role(adminBSession)).toBe("admin");
  });

  it("admits an ordinary member only with both admins and the right code", async () => {
    const invite = await flows.issueInvite(adminASession);
    const joined = await flows.joinWithInvite(base, passphrases.member, invite.printed);
    const { requests } = await api.joinRequests(adminASession.api);
    const req = requests.find((r) => r.user_id === joined.userId)!;

    await flows.proposeMember(adminASession, req, invite.printed, NOW);
    await flows.sync(adminBSession);
    const proposalId = [...adminBSession.state.proposals.keys()][0]!;

    // admin B with a WRONG code: the binding check refuses (ghost defense)
    const wrongInvite = await flows.issueInvite(adminBSession);
    await expect(
      flows.approveMember(adminBSession, proposalId, wrongInvite.printed, NOW),
    ).rejects.toThrow(/binding tag mismatch/);

    // the proposing admin cannot self-approve
    await expect(
      flows.approveMember(adminASession, proposalId, invite.printed, NOW),
    ).rejects.toThrow(/other admin/);

    await flows.approveMember(adminBSession, proposalId, invite.printed, NOW);
    const member = await flows.login(base, joined.userId, passphrases.member);
    expect(flows.role(member)).toBe("member");
    expect(member.state.members.size).toBe(4); // head + 2 admins + member
  });

  it("rejects a mistyped invite and a wrong passphrase", async () => {
    const invite = await flows.issueInvite(adminASession);
    const typo = invite.printed.slice(0, -1) + (invite.printed.endsWith("2") ? "3" : "2");
    await expect(flows.joinWithInvite(base, "pw", typo)).rejects.toThrow(crypto.ChecksumError);
    await expect(flows.login(base, adminAJoin.userId, "not the passphrase")).rejects.toThrow(
      crypto.AuthFailed,
    );
  });

  it("head recovery package restores the governance key from the printed secret", async () => {
    // workflow step 11's core: passphrase treated as lost — only the
    // printed secret and the server's ciphertext duplicate
    const { ciphertext } = await api.headPackageGet(base);
    const secret = crypto.decodePrinted(boot.headRecoverySecretPrinted);
    const govSk = crypto.aeadOpen(crypto.hash(secret), crypto.fromB64u(ciphertext!), {
      v: 1,
      org: boot.session.orgId,
      use: "headpkg",
    });
    // restored key == pinned genesis key, and it can sign a valid new event
    expect(crypto.toB64u(govSk.subarray(32))).toBe(boot.session.state.genesis!.governance_pk);
    // ...and it still decrypts no case content: it is a signing key, not an
    // encryption key — there is no case envelope addressed to it (threat
    // model: head is a governance root, not a data master key)
  });

  it("case layer (workflow steps 3–9): create, share, revoke, lockout — over HTTP", async () => {
    // admit two more members through the real two-admin ceremony
    const admit = async (pw: string) => {
      const invite = await flows.issueInvite(adminASession);
      const j = await flows.joinWithInvite(base, pw, invite.printed);
      const { requests } = await api.joinRequests(adminASession.api);
      const req = requests.find((r) => r.user_id === j.userId)!;
      await flows.proposeMember(adminASession, req, invite.printed, NOW);
      await flows.sync(adminBSession);
      const pid = [...adminBSession.state.proposals.keys()].pop()!;
      await flows.approveMember(adminBSession, pid, invite.printed, NOW);
      return flows.login(base, j.userId, pw);
    };
    const alice = await admit("alice case pw");
    const bob = await admit("bob case pw");

    // step 3: Alice creates a case; label = first line of the first note
    const caseTag = await flows.createCase(alice, "Synthetic intake #1\nDetails follow.");
    const noteId = await flows.writeNote(
      alice,
      caseTag,
      undefined,
      "second note: synthetic narrative",
    );
    expect(flows.listCases(alice)[0]!.label).toBe("Synthetic intake #1");

    // a case outside the keychain does not exist for others (acceptance)
    await flows.sync(adminASession);
    expect(flows.listCases(adminASession).length).toBe(0);
    expect(flows.readCase(adminASession, caseTag)).toBeNull();

    // step 4: share with Bob; step 5: Bob reads AND writes
    await flows.shareCase(alice, caseTag, bob.userId);
    await flows.sync(bob);
    const bobView = flows.readCase(bob, caseTag)!;
    expect(bobView.notes.length).toBe(2);
    expect(bobView.notes[1]!.text).toContain("second note");
    await flows.writeNote(bob, caseTag, noteId, "bob's edit");
    await flows.sync(alice);
    expect(flows.readCase(alice, caseTag)!.notes[1]!.text).toBe("bob's edit");

    // step 5 proper: CONCURRENT edits to the same note merge
    // deterministically. Both clients start from the same synced state;
    // neither sees the other's update until after both have posted.
    await flows.sync(alice);
    await flows.sync(bob);
    const base_ = "bob's edit";
    await flows.writeNote(alice, caseTag, noteId, `ALICE PREFIX >> ${base_}`);
    // bob edits against his STALE view (he has not synced alice's update)
    await flows.writeNote(bob, caseTag, noteId, `${base_} << BOB SUFFIX`);
    await flows.sync(alice);
    await flows.sync(bob);
    const aliceMerged = flows.readCase(alice, caseTag)!.notes[1]!.text!;
    const bobMerged = flows.readCase(bob, caseTag)!.notes[1]!.text!;
    expect(aliceMerged).toBe(bobMerged); // identical on every client
    expect(aliceMerged).toContain("ALICE PREFIX");
    expect(aliceMerged).toContain("BOB SUFFIX");
    expect(aliceMerged).toContain(base_); // neither edit clobbered the other

    // stale-baseline save (cleanup backlog item 5): bob starts typing, his
    // client then SYNCS alice's newer update, and only then does he save.
    // Diffing his text against the current merge would read alice's
    // insertion as deleted text; passing the baseline seq he composed
    // against keeps both edits.
    const staleView = flows.readCase(bob, caseTag)!.notes[1]!;
    const bobDraft = `${staleView.text} + bob addendum`; // typed against staleView
    await flows.writeNote(alice, caseTag, noteId, `alice interim >> ${staleView.text}`);
    await flows.sync(bob); // alice's edit lands on bob's client mid-draft
    await flows.writeNote(bob, caseTag, noteId, bobDraft, staleView.lastSeq);
    await flows.sync(alice);
    await flows.sync(bob);
    const staleMergedA = flows.readCase(alice, caseTag)!.notes[1]!.text!;
    expect(staleMergedA).toBe(flows.readCase(bob, caseTag)!.notes[1]!.text!);
    expect(staleMergedA).toContain("alice interim");
    expect(staleMergedA).toContain("bob addendum");

    // note history (backlog item 5 idea 3): one step per journal event,
    // attributed, oldest first, ending at the current merge
    const preHist = flows.noteHistory(alice, caseTag, noteId)!;
    expect(preHist.length).toBe(6); // creation + 5 edits, nothing compacted yet
    const authors = new Set(preHist.map((h) => h.author));
    expect(authors.has(alice.userId)).toBe(true);
    expect(authors.has(bob.userId)).toBe(true);
    expect(preHist[0]!.added).toBe("second note: synthetic narrative");
    expect(preHist[preHist.length - 1]!.text).toBe(staleMergedA);

    // step 7: revoke Bob; step 8: Alice writes after the rotation
    await flows.revokeFromCase(alice, caseTag, bob.userId);
    await flows.writeNote(
      alice,
      caseTag,
      noteId,
      `${aliceMerged}\npost-revocation: bob must not read this`,
    );

    // step 9: Bob's honest client now shows the case locked — every note
    // undecryptable at the current epoch, and no epoch-2 key derivable
    await flows.sync(bob);
    const locked = flows.readCase(bob, caseTag)!;
    expect(locked.notes.every((n) => n.locked && n.text === null)).toBe(true);
    expect(flows.keychain(bob).get(caseTag)?.get(2)).toBeUndefined();
    await expect(flows.writeNote(bob, caseTag, noteId, "locked out")).rejects.toThrow(
      /no key|no grant/,
    );

    // Alice still reads everything: the pre-revocation merge survived the
    // snapshot compaction AND the post-revocation line is present
    const aliceView = flows.readCase(alice, caseTag)!;
    expect(aliceView.epoch).toBe(2);
    expect(aliceView.notes[1]!.text).toContain("ALICE PREFIX");
    expect(aliceView.notes[1]!.text).toContain("post-revocation");
    expect(aliceView.holders).not.toContain(bob.userId);

    // history after the rotation: pre-revoke work is ONE labeled
    // compaction step (author null), then the post-revocation edit
    const postHist = flows.noteHistory(alice, caseTag, noteId)!;
    expect(postHist.length).toBe(2);
    expect(postHist[0]!.author).toBeNull();
    expect(postHist[0]!.epoch).toBe(2);
    expect(postHist[0]!.text).toBe(staleMergedA); // compaction preserved the merge
    expect(postHist[1]!.author).toBe(alice.userId);
    expect(postHist[1]!.added).toContain("post-revocation");
    // the revoked account cannot read history at all
    expect(flows.noteHistory(bob, caseTag, noteId)).toBeNull();

    // non-creator cannot share or revoke
    await flows.sync(bob);
    await expect(flows.shareCase(bob, caseTag, adminAJoin.userId)).rejects.toThrow();
    await expect(flows.revokeFromCase(bob, caseTag, alice.userId)).rejects.toThrow();

    // ---- workflow step 6: search is local and keychain-scoped
    // Alice finds her own content, including the post-revocation line
    expect(flows.searchNotes(alice, "post-revocation").length).toBe(1);
    expect(flows.searchNotes(alice, "synthetic intake")[0]!.caseTag).toBe(caseTag);
    // Bob (revoked) gets NOTHING from this case: his locked notes are not
    // indexed, so post-revocation content is unsearchable for him
    expect(flows.searchNotes(bob, "post-revocation")).toEqual([]);
    expect(flows.searchNotes(bob, "synthetic intake")).toEqual([]);
    // an admin who was never granted the case: zero results ever existed
    await flows.sync(adminASession);
    expect(flows.searchNotes(adminASession, "synthetic")).toEqual([]);
  });

  it("solo-governance: one person bootstraps, admits, works — then the mode flips off", async () => {
    // fresh server: each hosts one org
    const solo = createTallystickServer();
    const soloBase = { base: `http://localhost:${await solo.listen(0)}` };
    try {
      // one person creates the whole org, no admins required
      const b = await flows.bootstrapOrg(soloBase, "solo head passphrase");
      expect(flows.role(b.session)).toBe("head");

      // head admits a member alone (same invite binding as ever)
      const invite = await flows.issueInvite(b.session);
      const joined = await flows.joinWithInvite(soloBase, "solo member pw", invite.printed);
      const { requests } = await api.joinRequests(b.session.api);
      const req = requests.find((r) => r.user_id === joined.userId)!;
      // ghost defense unchanged: a wrong code still hard-refuses
      const wrong = await flows.issueInvite(b.session);
      await expect(flows.admitMemberSolo(b.session, req, wrong.printed)).rejects.toThrow(
        /different invite/,
      );
      await flows.admitMemberSolo(b.session, req, invite.printed);

      // the solo-admitted member is a full member: cases work end to end
      const member = await flows.login(soloBase, joined.userId, "solo member pw");
      expect(flows.role(member)).toBe("member");
      const tag = await flows.createCase(member, "Solo-org case\nsynthetic");
      await flows.shareCase(member, tag, b.session.userId);
      await flows.sync(b.session);
      expect(flows.readCase(b.session, tag)!.notes[0]!.text).toContain("Solo-org case");

      // now the org grows the natural way: the head PROMOTES the existing
      // member to admin (title, not a new identity)…
      await flows.promoteToAdmin(b.session, joined.userId);
      expect(b.session.state.members.get(joined.userId)?.role).toBe("admin");
      expect(b.session.state.adminBarrierArmed).toBe(false); // one admin: still solo

      // …solo admission still works at one admin…
      const i2 = await flows.issueInvite(b.session);
      const j2 = await flows.joinWithInvite(soloBase, "second member pw", i2.printed);
      const r2 = (await api.joinRequests(b.session.api)).requests.find(
        (r) => r.user_id === j2.userId,
      )!;
      await flows.admitMemberSolo(b.session, r2, i2.printed);

      // …promote a second: the barrier arms permanently
      await flows.promoteToAdmin(b.session, j2.userId);
      expect(b.session.state.adminBarrierArmed).toBe(true);
      const late = await flows.issueInvite(b.session);
      const lateJoin = await flows.joinWithInvite(soloBase, "too late pw", late.printed);
      const lateReq = (await api.joinRequests(b.session.api)).requests.find(
        (r) => r.user_id === lateJoin.userId,
      )!;
      await expect(flows.admitMemberSolo(b.session, lateReq, late.printed)).rejects.toThrow(
        /two admins have existed/,
      );

      // demoting an admin does NOT bring solo admission back (one-way)
      await flows.demoteAdmin(b.session, j2.userId);
      expect(b.session.state.members.get(j2.userId)?.role).toBe("member");
      expect(b.session.state.adminBarrierArmed).toBe(true);
      await expect(flows.admitMemberSolo(b.session, lateReq, late.printed)).rejects.toThrow(
        /two admins have existed/,
      );
      // restore the pair by re-promoting; roster-title churn, same identity
      await flows.promoteToAdmin(b.session, j2.userId);
      expect(journal.activeAdmins(b.session.state).length).toBe(2);
    } finally {
      await solo.close();
    }
  });

  it("pending invites are journal state: another device recovers them and sees consumption", async () => {
    // "device 2" = a completely fresh login of the same identity — nothing
    // shared with device 1 except the passphrase and the journal
    const issued = await flows.issueInvite(adminASession);
    const device2 = await flows.login(base, adminAJoin.userId, passphrases.adminA);
    const pending = flows.myPendingInvites(device2);
    const found = pending.find((p) => p.invite.inviteId === issued.inviteId);
    expect(found).toBeDefined();
    expect(found!.invite.printed).toBe(issued.printed); // full code recovered

    // other identities see the issuance but can NEVER recover the code:
    // sealed to the issuer only (and the server stores only ciphertext)
    expect(
      flows.myPendingInvites(adminBSession).find((p) => p.invite.inviteId === issued.inviteId),
    ).toBeUndefined();

    // the invite is used via the normal two-admin ceremony…
    const joiner = await flows.joinWithInvite(base, "cross-device pw", issued.printed);
    const req = (await api.joinRequests(device2.api)).requests.find(
      (r) => r.user_id === joiner.userId,
    )!;
    await flows.proposeMember(device2, req, issued.printed, NOW);
    await flows.sync(adminBSession);
    const pid = [...adminBSession.state.proposals.keys()].pop()!;
    await flows.approveMember(adminBSession, pid, issued.printed, NOW);

    // …and BOTH devices see it leave the pending list — journal truth
    await flows.sync(adminASession);
    await flows.sync(device2);
    for (const s of [adminASession, device2]) {
      expect(
        flows.myPendingInvites(s).find((p) => p.invite.inviteId === issued.inviteId),
      ).toBeUndefined();
    }
  });

  it("invites expire by the signer's clock: unusable and gone from pending", async () => {
    const issued = await flows.issueInvite(adminASession, NOW);
    const LATER = NOW + 73 * 60 * 60 * 1000; // past the 72h TTL

    // still pending at issuance time, gone when viewed past expiry
    expect(
      flows.myPendingInvites(adminASession, NOW).some((p) => p.invite.inviteId === issued.inviteId),
    ).toBe(true);
    expect(
      flows
        .myPendingInvites(adminASession, LATER)
        .some((p) => p.invite.inviteId === issued.inviteId),
    ).toBe(false);

    // a joiner can still register with it (client-side parse only)…
    const j = await flows.joinWithInvite(base, "expired invite pw", issued.printed);
    const req = (await api.joinRequests(adminASession.api)).requests.find(
      (r) => r.user_id === j.userId,
    )!;
    // …but the signing admin's builder refuses past expiry
    await expect(flows.proposeMember(adminASession, req, issued.printed, LATER)).rejects.toThrow(
      /invite expired/,
    );
    // within the window it would have been fine (same invite, earlier clock)
    await flows.proposeMember(adminASession, req, issued.printed, NOW + 1000);
  });

  it("the two printed recovery shares reconstruct the pinned recovery key", async () => {
    const a = crypto.decodePrinted(boot.recoveryShareAPrinted);
    const b = crypto.decodePrinted(boot.recoveryShareBPrinted);
    const sk = crypto.xorJoin(a, b);
    expect(crypto.toB64u(crypto.boxPkFromSk(sk))).toBe(boot.session.state.genesis!.recovery_pk);
    // either share alone is not the key
    expect(crypto.toB64u(a)).not.toBe(crypto.toB64u(sk));
    expect(crypto.toB64u(b)).not.toBe(crypto.toB64u(sk));
  });

  it("case content v2: typed records, status, deadlines, fail-open", async () => {
    const srvC = createTallystickServer();
    const bC = { base: `http://localhost:${await srvC.listen(0)}` };
    try {
      const boot = await flows.bootstrapOrg(bC, "cc head pw");
      const s = boot.session;
      const tag = await flows.createCase(
        s,
        "Intake narrative\nfull text here",
        "Maria R. — housing",
      );

      // header: explicit title + status, replacing the first-line hack
      let c = flows.readCase(s, tag)!;
      expect(c.title).toBe("Maria R. — housing");
      expect(c.status).toBe("open");
      expect(c.notes.length).toBe(1); // header is NOT a note
      expect(c.notes[0]!.text).toContain("Intake narrative");
      expect(c.header).toBeDefined();

      // profile with the DV safe-contact block — encrypted like everything
      await flows.createRecord(s, tag, {
        kind: "profile",
        name: "Maria R.",
        language: "es",
        safeCall: false,
        safeVoicemail: false,
        codeWord: "girasol",
      });
      // contact-log entry and two tasks (one dated, one done)
      await flows.createRecord(s, tag, { kind: "contact", channel: "call" }, "intake call, 40 min");
      const due = Date.now() + 24 * 60 * 60 * 1000;
      const taskId = await flows.createRecord(
        s,
        tag,
        { kind: "task", done: false, due },
        "file I-589",
      );
      await flows.createRecord(s, tag, { kind: "task", done: true }, "safety plan reviewed");

      c = flows.readCase(s, tag)!;
      expect(c.profile?.meta["codeWord"]).toBe("girasol");
      expect(c.contacts.length).toBe(1);
      expect(c.contacts[0]!.meta["channel"]).toBe("call");
      expect(flows.recordAt(c.contacts[0]!)).toBeGreaterThan(0); // encrypted client timestamp
      expect(c.tasks.map((t) => t.meta["done"])).toEqual([false, true]); // open first

      // deadlines strip: the open dated task, and only that
      const dl = flows.upcomingDeadlines(s);
      expect(dl.length).toBe(1);
      expect(dl[0]!.text).toBe("file I-589");
      expect(dl[0]!.overdue).toBe(false);

      // meta edits: toggle the task done; close the case
      await flows.setRecordMeta(s, tag, taskId, { done: true });
      await flows.setRecordMeta(s, tag, c.header!.recordId, { status: "closed" });
      c = flows.readCase(s, tag)!;
      expect(c.status).toBe("closed");
      expect(flows.upcomingDeadlines(s).length).toBe(0);

      // search finds the case by PROFILE name (meta is indexed)
      expect(flows.searchNotes(s, "maria").length).toBeGreaterThan(0);

      // fail-open: a malformed header claim reads as a plain note and the
      // real header keeps authority
      await flows.createRecord(s, tag, { kind: "header", status: "bogus" }, "malformed");
      c = flows.readCase(s, tag)!;
      expect(c.title).toBe("Maria R. — housing");
      expect(c.notes.some((n) => n.text === "malformed")).toBe(true);

      // the whole structure round-trips through another device (journal
      // replay, no local state)
      const dev2 = await flows.login(bC, s.userId, "cc head pw");
      const c2 = flows.readCase(dev2, tag)!;
      expect(c2.title).toBe("Maria R. — housing");
      expect(c2.status).toBe("closed");
      expect(c2.profile?.meta["name"]).toBe("Maria R.");
      expect(c2.tasks.every((t) => t.meta["done"] === true)).toBe(true);
    } finally {
      await srvC.close();
    }
  });

  it("org directory: publish, relay to newcomers, self beats relay, collisions", async () => {
    const srvD = createTallystickServer();
    const bD = { base: `http://localhost:${await srvD.listen(0)}` };
    try {
      const boot = await flows.bootstrapOrg(bD, "dir head pw");
      const head = boot.session;
      await flows.publishDisplayName(head, "Rosa");
      expect(flows.displayNames(head)[head.userId]).toBe("Rosa");

      // newcomer: solo-admitted AFTER Rosa published — relay covers them
      const inv = await flows.issueInvite(head);
      const j = await flows.joinWithInvite(bD, "ana pw", inv.printed);
      const req = (await api.joinRequests(head.api)).requests.find((r) => r.user_id === j.userId)!;
      await flows.admitMemberSolo(head, req, inv.printed);
      const ana = await flows.login(bD, j.userId, "ana pw");
      expect(flows.displayNames(ana)[head.userId]).toBe("Rosa"); // via relay
      expect(flows.hasPublishedName(ana)).toBe(false);

      // ana publishes; head sees it after sync
      await flows.publishDisplayName(ana, "Ana");
      expect(flows.hasPublishedName(ana)).toBe(true);
      await flows.sync(head);
      expect(flows.displayNames(head)[ana.userId]).toBe("Ana");

      // a lying relay about the HEAD's name loses to the head's own claim
      const lie = journal.buildDirectoryShare(
        ana.state,
        { userId: ana.userId, sign: ana.sign },
        { names: { [head.userId]: "Impostor" }, recipients: [ana.userId], at: Date.now() + 10_000 },
      );
      await api.journalAppend(ana.api, lie);
      await flows.sync(ana);
      expect(flows.displayNames(ana)[head.userId]).toBe("Rosa"); // self-authored wins

      // collision: second member also named Rosa → both flagged
      const inv2 = await flows.issueInvite(head);
      const j2 = await flows.joinWithInvite(bD, "rosa2 pw", inv2.printed);
      const req2 = (await api.joinRequests(head.api)).requests.find(
        (r) => r.user_id === j2.userId,
      )!;
      await flows.admitMemberSolo(head, req2, inv2.printed);
      const rosa2 = await flows.login(bD, j2.userId, "rosa2 pw");
      await flows.publishDisplayName(rosa2, "Rosa");
      await flows.sync(head);
      expect(flows.nameCollisions(head).has("Rosa")).toBe(true);

      // clearing: empty string removes the name; hasPublishedName stays true
      await flows.publishDisplayName(rosa2, "");
      await flows.sync(head);
      expect(flows.displayNames(head)[rosa2.userId]).toBeUndefined();
      expect(flows.nameCollisions(head).has("Rosa")).toBe(false);
      expect(flows.hasPublishedName(rosa2)).toBe(true); // no auto-republish later
    } finally {
      await srvD.close();
    }
  });

  it("session persistence: persist → resume → revoke (split custody over HTTP)", async () => {
    const srvP = createTallystickServer();
    const bP = { base: `http://localhost:${await srvP.listen(0)}` };
    try {
      const boot = await flows.bootstrapOrg(bP, "persist head pw");
      const tag = await flows.createCase(boot.session, "Persisted case\nsynthetic");

      // persist: the record holds ONLY a token and ciphertext
      const rec = await flows.persistSession(boot.session);
      expect(rec.token).toBe(boot.session.api.token);
      expect(() => JSON.parse(rec.blob)).toThrow(); // not plaintext JSON

      // resume on a "fresh page": full session rebuilt from record + server key
      const resumed = await flows.resumeSession(bP, rec);
      expect(resumed.userId).toBe(boot.session.userId);
      expect(resumed.governance).toBeDefined(); // head blob carries gov_sk
      expect(flows.readCase(resumed, tag)!.notes[0]!.text).toContain("Persisted case");

      // a tampered blob fails closed
      const bad = { ...rec, blob: rec.blob.slice(0, -2) + "AA" };
      await expect(flows.resumeSession(bP, bad)).rejects.toThrow();

      // the record is origin-bound — resuming against a different
      // server base is refused BEFORE any request. The asserted message
      // proves it's our guard, not a connection failure (nothing listens
      // on the foreign base; contacting it would raise a fetch error).
      const foreign = { base: "http://127.0.0.1:9" };
      await expect(flows.resumeSession(foreign, rec)).rejects.toThrow(
        /bound to a different server/,
      );
      // a legacy record with no server field is refused the same way
      const legacy = { ...rec } as Record<string, unknown>;
      delete legacy["server"];
      await expect(
        flows.resumeSession(bP, legacy as unknown as flows.PersistedSession),
      ).rejects.toThrow(/bound to a different server/);

      // revocation: drop the server key — the record is dead forever
      await flows.dropPersistedSession(resumed.api);
      await expect(flows.resumeSession(bP, rec)).rejects.toThrow(/no unlock key/);
    } finally {
      await srvP.close();
    }
  });

  it("account recovery, case rekey, custody, succession — over HTTP", async () => {
    const srv8 = createTallystickServer();
    const b8 = { base: `http://localhost:${await srv8.listen(0)}` };
    try {
      const boot8 = await flows.bootstrapOrg(b8, "l8 head pw");
      const head = boot8.session;

      // ---- D1: account recovery preserves identity, grants, and cases ----
      const inv = await flows.issueInvite(head);
      const joined = await flows.joinWithInvite(b8, "member old pw", inv.printed);
      const req = (await api.joinRequests(head.api)).requests.find(
        (r) => r.user_id === joined.userId,
      )!;
      await flows.admitMemberSolo(head, req, inv.printed);
      const alice = await flows.login(b8, joined.userId, "member old pw");
      const tag = await flows.createCase(alice, "Recovery case\nsynthetic");

      // verify-only rehearsal; the wrong paper fails cleanly
      await flows.verifyRecoveryCode(b8, joined.userId, joined.recoveryPrinted);
      await expect(
        flows.verifyRecoveryCode(b8, joined.userId, boot8.accountRecoveryPrinted),
      ).rejects.toThrow();

      // passphrase forgotten: the printed code recovers the SAME identity
      const rec = await flows.recoverAccount(
        b8,
        joined.userId,
        joined.recoveryPrinted,
        "member NEW pw",
      );
      expect(rec.session.userId).toBe(joined.userId);
      expect(flows.readCase(rec.session, tag)!.notes[0]!.text).toContain("Recovery case");
      const aliceNew = await flows.login(b8, joined.userId, "member NEW pw");
      expect(flows.role(aliceNew)).toBe("member"); // roster untouched
      await expect(flows.login(b8, joined.userId, "member old pw")).rejects.toThrow();
      // the old code is spent; the freshly minted one verifies
      await expect(
        flows.verifyRecoveryCode(b8, joined.userId, joined.recoveryPrinted),
      ).rejects.toThrow();
      await flows.verifyRecoveryCode(b8, joined.userId, rec.recoveryPrinted);

      // ---- D2 solo: restore an inaccessible case to a new holder ----
      const inv2 = await flows.issueInvite(head);
      const j2 = await flows.joinWithInvite(b8, "bob pw", inv2.printed);
      const r2 = (await api.joinRequests(head.api)).requests.find((r) => r.user_id === j2.userId)!;
      await flows.admitMemberSolo(head, r2, inv2.printed);
      const bob = await flows.login(b8, j2.userId, "bob pw");

      expect(flows.readCase(head, tag)).toBeNull(); // head never held it
      // wrong paper is caught before anything decrypts
      expect(() =>
        flows.joinRecoveryShares(
          head.state,
          boot8.recoveryShareAPrinted,
          boot8.recoveryShareAPrinted,
        ),
      ).toThrow(/wrong paper/);
      // read-only ceremony (leaves no journal trace — recorded residual)
      const kp = flows.joinRecoveryShares(
        head.state,
        boot8.recoveryShareAPrinted,
        boot8.recoveryShareBPrinted,
      );
      expect(
        flows
          .recoverReadCase(head, tag, kp)
          .map((r) => r.text)
          .join("\n"),
      ).toContain("Recovery case");
      // restore: solo rekey commits directly and grants bob
      const soloRekey = await flows.rekeyCase(
        head,
        tag,
        [j2.userId],
        boot8.recoveryShareAPrinted,
        boot8.recoveryShareBPrinted,
      );
      expect(soloRekey).toBeNull(); // committed, no proposal
      await flows.sync(bob);
      const restored = flows.readCase(bob, tag)!;
      expect(restored.epoch).toBe(2);
      expect(restored.notes[0]!.text).toContain("Recovery case");

      // ---- D4: custody handoff journaled by the receiver ----
      expect(head.state.shareCustody).toEqual({ A: head.userId, B: head.userId });
      await flows.promoteToAdmin(head, j2.userId);
      await flows.sync(bob);
      await flows.ackShareCustody(bob, "A");
      await flows.sync(head);
      expect(head.state.shareCustody).toEqual({ A: j2.userId, B: head.userId });

      // ---- D2 armed: propose + countersign ----
      await flows.promoteToAdmin(head, joined.userId); // second admin: barrier arms
      expect(head.state.adminBarrierArmed).toBe(true);
      await flows.sync(aliceNew);
      const tag2 = await flows.createCase(aliceNew, "Second case\nsynthetic");
      await flows.sync(bob);
      const rekeyId = await flows.rekeyCase(
        bob,
        tag2,
        [j2.userId],
        boot8.recoveryShareAPrinted,
        boot8.recoveryShareBPrinted,
      );
      expect(rekeyId).not.toBeNull(); // a proposal, not a commit
      expect(flows.readCase(bob, tag2)).toBeNull(); // no access yet
      await flows.sync(aliceNew);
      expect(aliceNew.state.pendingRekeys.size).toBe(1);
      await flows.approveRekey(aliceNew, rekeyId!);
      await flows.sync(bob);
      expect(flows.readCase(bob, tag2)!.epoch).toBe(2);
      expect(flows.readCase(bob, tag2)!.notes[0]!.text).toContain("Second case");

      // ---- D3: succession to an admin; governance survives re-login ----
      const newGovPk = await flows.prepareSuccession(bob, "bob pw");
      await flows.succeedHead(head, j2.userId, newGovPk);
      await flows.sync(bob);
      expect(bob.state.currentHeadUserId).toBe(j2.userId);
      expect(flows.role(bob)).toBe("head");
      await flows.sync(head);
      expect(flows.role(head)).toBe("member"); // old head demoted

      // the new head's governance key came back from their identity blob
      const bob2 = await flows.login(b8, j2.userId, "bob pw");
      expect(bob2.governance).toBeDefined();
      // …and it governs: refill the admin seat bob vacated
      await flows.promoteToAdmin(bob2, head.userId);
      await flows.sync(head);
      expect(flows.role(head)).toBe("admin");

      // rotation (self-succession) mints a new package; the event verifies
      const rot = await flows.rotateGovernance(bob2, "bob pw");
      expect(crypto.decodePrinted(rot.headSecretPrinted).length).toBe(32);

      // ---- D3 emergency: printed package + prepared successor ----
      await flows.sync(aliceNew);
      const alicePk = await flows.prepareSuccession(aliceNew, "member NEW pw");
      await flows.emergencySucceedHead(aliceNew, rot.headSecretPrinted, joined.userId, alicePk);
      expect(aliceNew.state.currentHeadUserId).toBe(joined.userId);
      expect(flows.role(aliceNew)).toBe("head");
    } finally {
      await srv8.close();
    }
  });
});
