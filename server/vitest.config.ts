import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Same libsodium ESM packaging workaround as shared/vitest.config.ts —
// the import chain reaches libsodium via @tallystick/shared's crypto module.
export default defineConfig({
  test: {
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
