import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Same libsodium ESM packaging workaround as shared/vitest.config.ts.
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
