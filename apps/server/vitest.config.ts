import { defineConfig } from "vitest/config";

// The flow tests share one `wrangler dev` (tests/support/global-setup.ts), so files run one after another.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    globalSetup: ["tests/support/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
