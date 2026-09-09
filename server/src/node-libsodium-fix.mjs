// Node-only counterpart of the vite alias in shared/vitest.config.ts: libsodium-wrappers-sumo's ESM entry
// imports "./libsodium-sumo.mjs", which actually ships in the sibling
// `libsodium-sumo` package. Redirect exactly that specifier.
// Loaded via `node --import ./src/node-libsodium-fix.mjs` (see npm start).
import { registerHooks } from "node:module";

registerHooks({
 resolve(specifier, context, next) {
 if (
 specifier === "./libsodium-sumo.mjs" &&
 context.parentURL?.includes("/libsodium-wrappers-sumo/")
 ) {
 return {
 url: new URL(
 specifier,
 context.parentURL.replace("/libsodium-wrappers-sumo/", "/libsodium-sumo/")
 ).href,
 shortCircuit: true,
 };
 }
 return next(specifier, context);
 },
});
