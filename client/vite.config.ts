import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

// Same libsodium ESM workarounds as the spike (see research_notes.md
// 2026-08-06): alias the mispackaged import, es2022 for its top-level await.
export default defineConfig({
  build: { target: "es2022" },
  // dev server: esbuild pre-bundling bypasses resolve.alias, so libsodium's
  // broken internal import must be excluded from optimizeDeps and served
  // through vite's normal pipeline (where the alias below applies)
  optimizeDeps: { exclude: ["libsodium-wrappers-sumo", "libsodium-sumo"] },
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
