import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Same libsodium ESM packaging quirk the browser spike hit (see
// spike/vite.config.ts and research_notes.md 2026-08-06): its entry imports
// "./libsodium-sumo.mjs", which actually ships in the sibling
// `libsodium-sumo` package behind an exports map.
export default defineConfig({
  test: {
    // vitest externalizes node_modules to Node's own resolver by default,
    // which bypasses the alias below — inline the package so it applies
    server: { deps: { inline: ["libsodium-wrappers-sumo"] } },
  },
  resolve: {
    alias: {
      "./libsodium-sumo.mjs": fileURLToPath(
        new URL(
          "../node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs",
          import.meta.url,
        ),
      ),
    },
  },
});
