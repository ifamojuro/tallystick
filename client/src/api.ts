// Thin HTTP client for the dumb journal server.

import type { journal } from "@tallystick/shared";
import type { JoinRequest } from "./flows.ts";

export interface Api {
  base: string;
  token?: string;
}

async function request(
  api: Api,
  path: string,
  opts: { method?: string; body?: unknown } = {},
): Promise<any> {
  const res = await fetch(api.base + path, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers: {
      ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(api.token ? { authorization: `Bearer ${api.token}` } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${path}: ${body?.error ?? res.status}`);
  return body;
}

export const server = {
  org: (api: Api): Promise<{ orgId: string | null; setupRequired?: boolean }> =>
    request(api, "/org"),

  // inviteId: required by the server once an org exists
  // (invite-gated registration); omitted only during bootstrap.
  // setupCode: required by a FRESH server that was started
  // remotely reachable — printed in its startup log.
  registerStart: (
    api: Api,
    userId: string,
    registrationRequest: string,
    inviteId?: string,
    recovery?: { nonce: string; sig: string },
    setupCode?: string,
  ) =>
    request(api, "/auth/register/start", {
      body: {
        userId,
        registrationRequest,
        inviteId,
        recoveryNonce: recovery?.nonce,
        recoverySig: recovery?.sig,
        setupCode,
      },
    }),
  registerFinish: (
    api: Api,
    body: {
      userId: string;
      registrationRecord: string;
      salt: string;
      kdf: unknown;
      wrappedIdentityKeys: string;
      inviteId?: string;
      recoveryNonce?: string;
      recoverySig?: string;
      setupCode?: string;
    },
  ) => request(api, "/auth/register/finish", { body }),
  params: (api: Api, userId: string): Promise<{ salt: string; kdf: unknown }> =>
    request(api, `/auth/params?user=${encodeURIComponent(userId)}`),
  loginStart: (
    api: Api,
    userId: string,
    startLoginRequest: string,
  ): Promise<{ loginResponse: string; loginId: string }> =>
    request(api, "/auth/login/start", { body: { userId, startLoginRequest } }),
  // finish names the attempt, not the user — state is single-use
  loginFinish: (
    api: Api,
    loginId: string,
    finishLoginRequest: string,
  ): Promise<{ sessionToken: string }> =>
    request(api, "/auth/login/finish", { body: { loginId, finishLoginRequest } }),

  identity: (api: Api): Promise<{ wrappedIdentityKeys: string | null }> =>
    request(api, "/identity"),
  identityUpdate: (api: Api, wrappedIdentityKeys: string) =>
    request(api, "/identity", { body: { wrappedIdentityKeys } }),

  // personal recovery packages; GET and the
  // challenge are pre-login by design — the printed secret is the gate
  recoveryBlobPost: (api: Api, ciphertext: string) =>
    request(api, "/identity-recovery", { body: { ciphertext } }),
  recoveryBlobGet: (api: Api, userId: string): Promise<{ ciphertext: string | null }> =>
    request(api, `/identity-recovery?user=${encodeURIComponent(userId)}`),
  recoveryChallenge: (api: Api, userId: string): Promise<{ nonce: string }> =>
    request(api, "/recover/challenge", { body: { userId } }),

  journalSince: (api: Api, since: number): Promise<{ entries: journal.SignedEntry[] }> =>
    request(api, `/journal?since=${since}`),
  journalAppend: (api: Api, envelope: journal.Envelope): Promise<{ seq: number }> =>
    request(api, "/journal", { body: { envelope } }),

  joinRequestPost: (api: Api, body: JoinRequest) => request(api, "/join-request", { body }),
  joinRequests: (api: Api): Promise<{ requests: JoinRequest[] }> => request(api, "/join-requests"),

  // session persistence: the unlock key
  // parks with the server, bound to the bearer token
  sessionUnlockPut: (api: Api, key: string) => request(api, "/session-unlock", { body: { key } }),
  sessionUnlockGet: (api: Api): Promise<{ key: string }> => request(api, "/session-unlock"),
  sessionUnlockDelete: (api: Api) => request(api, "/session-unlock", { method: "DELETE" }),
  // real logout — token and unlock key die together
  sessionDelete: (api: Api) => request(api, "/session", { method: "DELETE" }),
  sessionUnlockDeleteOthers: (api: Api): Promise<{ dropped: number }> =>
    request(api, "/session-unlock-others", { method: "DELETE" }),

  headPackagePost: (api: Api, ciphertext: string) =>
    request(api, "/head-package", { body: { ciphertext } }),
  headPackageGet: (api: Api): Promise<{ ciphertext: string | null }> =>
    request(api, "/head-package"),
};
