import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  resolve: {
    alias: {
      "@vigil-harbor/clawmoat-drawbridge": path.resolve(__dirname, "../../src/index.ts"),
    },
  },
  test: {
    include: ["__tests__/**/*.test.ts"],
  },
});
