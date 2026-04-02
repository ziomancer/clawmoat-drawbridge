import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@vigil-harbor/clawmoat-drawbridge": fileURLToPath(
        new URL("../../src/index.ts", import.meta.url),
      ),
    },
  },
  test: {
    include: ["__tests__/**/*.test.ts"],
  },
});
