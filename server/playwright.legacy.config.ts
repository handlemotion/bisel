import { defineConfig } from "@playwright/test";

const PORT = 8789;
export const LEGACY_STATE = ".wrangler/legacy-state";

// Proves migration 0004 on a database built by migrations 0001-0003 and seeded with a real-looking single box:
// build the old schema, seed it, apply the new migrations on top, then run the new Worker on it.
export default defineConfig({
  testDir: "legacy-tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  timeout: 60_000,
  use: { baseURL: `http://localhost:${PORT}` },
  webServer: {
    command: [
      `rm -rf ${LEGACY_STATE} .wrangler/pre`,
      "mkdir -p .wrangler/pre",
      "cp migrations/0001_init.sql migrations/0002_rotation.sql migrations/0003_admin_history.sql .wrangler/pre/",
      `pnpm exec wrangler d1 migrations apply bisel --local --persist-to ${LEGACY_STATE} -c wrangler.legacy.jsonc`,
      `pnpm exec wrangler d1 execute bisel --local --persist-to ${LEGACY_STATE} -c wrangler.legacy.jsonc --file legacy-tests/seed.sql`,
      `pnpm exec wrangler d1 migrations apply bisel --local --persist-to ${LEGACY_STATE}`,
      `pnpm exec wrangler dev --port ${PORT} --persist-to ${LEGACY_STATE} --var BOOTSTRAP_TOKEN:legacy-test-token --var AUTH_BACKOFF_MS:0`,
    ].join(" && "),
    port: PORT,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: process.env.SERVER_LOGS ? "pipe" : "ignore",
    stderr: process.env.SERVER_LOGS ? "pipe" : "ignore",
  },
});
