// @tallystick/shared — the crypto module and the journal
// state machine. Used by client, server, and fixtures so all
// sides run the same verification code.
export * as crypto from "./crypto/index.ts";
export * as journal from "./journal/index.ts";
export const PROTOCOL_VERSION = 1 as const;
