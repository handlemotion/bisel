import { defineConfig } from "@playwright/test";

const PORT = 8788;
export const TEST_BOOTSTRAP_TOKEN = "test-bootstrap-token";
const TEST_AUTH_SECRET = "test-only-better-auth-secret-9f2c1d7e5a3b4c6d8e0f1a2b3c4d5e6f";

// One real `wrangler dev` with a throwaway local D1 (separate from `pnpm dev`'s state and port).
// The flow is one serial story against a single database, because bootstrap happens exactly once.
export default defineConfig({
  testDir: "tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  timeout: 60_000,
  use: { baseURL: `http://localhost:${PORT}` },
  webServer: {
    command: [
      "rm -rf .wrangler/test-state",
      "pnpm exec wrangler d1 migrations apply bisel --local --persist-to .wrangler/test-state",
      `pnpm exec wrangler dev --port ${PORT} --persist-to .wrangler/test-state --var BOOTSTRAP_TOKEN:${TEST_BOOTSTRAP_TOKEN} --var AUTH_BACKOFF_MS:400 --var RECOVERY_ACTIVATION_DELAY_SECONDS:2 --var MAX_ITEMS_PER_BOX:40 --var MAX_BOX_BYTES:1000000 --var PUBLIC_ORIGIN:http://localhost:${PORT} --var BETTER_AUTH_SECRET:${TEST_AUTH_SECRET}`,
    ].join(" && "),
    port: PORT,
    reuseExistingServer: false,
    timeout: 120_000,
    // Set SERVER_LOGS=1 to stream the worker's request/auth-failure log lines into the test output.
    stdout: process.env.SERVER_LOGS ? "pipe" : "ignore",
    stderr: process.env.SERVER_LOGS ? "pipe" : "ignore",
  },
});
