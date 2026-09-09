// The thin private layer over public verified state (the "public/private split"): walk state, unseal what's addressed to me.
// Memory-only; rebuilt at login, discarded at logout.

import * as crypto from "../crypto/index.ts";
import type { OrgState } from "./types.ts";

/** caseTag -> (epoch -> case key). Only epochs where the user holds a
 * grant appear; a revoked user keeps old epochs and lacks new ones. */
export type Keychain = Map<string, Map<number, Uint8Array>>;

export function deriveKeychain(
  state: OrgState,
  userId: string,
  boxKp: crypto.BoxKeyPair,
): Keychain {
  const keychain: Keychain = new Map();
  for (const [caseTag, c] of state.cases) {
    for (let i = 0; i < c.epochs.length; i++) {
      const sealed = c.epochs[i]!.holders.get(userId);
      if (sealed === undefined) continue;
      const caseKey = crypto.openSealed(boxKp, crypto.fromB64u(sealed));
      let perCase = keychain.get(caseTag);
      if (!perCase) {
        perCase = new Map();
        keychain.set(caseTag, perCase);
      }
      perCase.set(i + 1, caseKey);
    }
  }
  return keychain;
}

/** Recovery read-path (workflow step 10): open one epoch's recovery
 * envelope with the reconstructed recovery keypair. */
export function recoverCaseKey(
  state: OrgState,
  recoveryKp: crypto.BoxKeyPair,
  caseTag: string,
  epoch: number,
): Uint8Array {
  const c = state.cases.get(caseTag);
  if (!c) throw new Error("unknown case");
  const e = c.epochs[epoch - 1];
  if (!e) throw new Error("unknown epoch");
  return crypto.openSealed(recoveryKp, crypto.fromB64u(e.recoveryEnvelope));
}
