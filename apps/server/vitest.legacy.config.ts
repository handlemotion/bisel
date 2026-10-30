import { defineConfig } from "vitest/config";

// Proves the migrations on a database built the way production looked before accounts (`pnpm test:legacy`).
export default defineConfig({
  test: {
    include: ["legacy-tests/**/*.test.ts"],
    globalSetup: ["legacy-tests/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
