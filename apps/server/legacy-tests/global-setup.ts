import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { TestProject } from "vitest/node";
import { migrate, SERVER_DIR, startServer } from "../tests/support/server";

const LEGACY_CONFIG = "wrangler.legacy.jsonc";

// Build the old schema (migrations 0001-0003), seed one real-looking box, then apply the current migrations on top and
// run the current Worker on it.
export default async function setup(project: TestProject) {
  const server = await startServer({
    vars: {
      BOOTSTRAP_TOKEN: "legacy-test-token",
      AUTH_BACKOFF_MS: "0",
      RECOVERY_ACTIVATION_DELAY_SECONDS: "0",
      MAX_ITEMS_PER_BOX: "5000",
      MAX_BOX_BYTES: "67108864",
    },
    prepare: (stateDir) => {
      const pre = join(SERVER_DIR, ".wrangler/pre");
      rmSync(pre, { recursive: true, force: true });
      mkdirSync(pre, { recursive: true });
      for (const m of ["0001_init", "0002_rotation", "0003_admin_history"])
        copyFileSync(join(SERVER_DIR, `migrations/${m}.sql`), join(pre, `${m}.sql`));
      migrate(stateDir, LEGACY_CONFIG);
      execFileSync(
        "pnpm",
        [
          "exec",
          "wrangler",
          "d1",
          "execute",
          "bisel",
          "--local",
          "--persist-to",
          stateDir,
          "-c",
          LEGACY_CONFIG,
          "--file",
          "legacy-tests/seed.sql",
        ],
        { cwd: SERVER_DIR, stdio: "ignore" },
      );
      migrate(stateDir);
    },
  });
  project.provide("server", { url: server.url, stateDir: server.stateDir });
  return server.stop;
}

declare module "vitest" {
  export interface ProvidedContext {
    server: { url: string; stateDir: string };
  }
}
