import { defineConfig } from "@playwright/test";

// Opt-in (`pnpm test:browser`, not part of `pnpm test`): the one thing vitest cannot cover, the dashboard's passkey ceremony in
// a real Chromium with a virtual WebAuthn authenticator. Needs `pnpm exec playwright install chromium` once.
export const PORT = 8788;

export default defineConfig({
  testDir: "tests/browser",
  testMatch: "**/*.spec.ts",
  workers: 1,
  reporter: "list",
  timeout: 60_000,
  globalSetup: "./tests/browser/global-setup.ts",
  use: { baseURL: `http://localhost:${PORT}` },
});
