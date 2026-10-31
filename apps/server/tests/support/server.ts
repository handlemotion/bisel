// Starts the real Worker (`wrangler dev`, workerd) on a free port with a throwaway local D1. Nothing here can reach Cloudflare.
// Same idea as apps/mac/Packages/BiselCore/Sources/BiselTestSupport/TestServer.swift.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const SERVER_DIR = join(import.meta.dirname, "../..");
export const BOOTSTRAP_TOKEN = "test-bootstrap-token";
export const AUTH_SECRET = "test-only-better-auth-secret-9f2c1d7e5a3b4c6d8e0f1a2b3c4d5e6f";

export interface RunningServer {
  url: string;
  stateDir: string;
  stop(): Promise<void>;
}

export interface ServerOptions {
  /** Fixed port (the opt-in browser test needs one); default: any free port. */
  port?: number;
  /** Worker variables on top of the defaults below. */
  vars?: Record<string, string>;
  /** Builds the database before the Worker starts (default: apply every migration). */
  prepare?: (stateDir: string) => void;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });
}

const wrangler = (args: string[]) =>
  execFileSync("pnpm", ["exec", "wrangler", ...args], { cwd: SERVER_DIR, encoding: "utf8" });

export function migrate(stateDir: string, config?: string) {
  wrangler([
    "d1",
    "migrations",
    "apply",
    "bisel",
    "--local",
    "--persist-to",
    stateDir,
    ...(config ? ["-c", config] : []),
  ]);
}

/** Runs SQL against a server's local database, the way an operator (or a breach) could. Returns the first result set's rows. */
export function sql(stateDir: string, statement: string, config?: string): any[] {
  const out = wrangler([
    "d1",
    "execute",
    "bisel",
    "--local",
    "--persist-to",
    stateDir,
    "--json",
    "--command",
    statement,
    ...(config ? ["-c", config] : []),
  ]);
  // wrangler prints a banner before the JSON.
  return JSON.parse(out.slice(out.indexOf("[")))[0].results;
}

export async function startServer(options: ServerOptions = {}): Promise<RunningServer> {
  // `.dev.vars` is untracked; a fresh clone gets it from the example, as `pnpm dev` does.
  const devVars = join(SERVER_DIR, ".dev.vars");
  if (!existsSync(devVars)) copyFileSync(join(SERVER_DIR, ".dev.vars.example"), devVars);

  const stateDir = mkdtempSync(join(tmpdir(), "bisel-test-"));
  const port = options.port ?? (await freePort());
  const inspector = await freePort();
  const url = `http://localhost:${port}`;
  (options.prepare ?? ((dir) => migrate(dir)))(stateDir);

  const vars: Record<string, string> = {
    BOOTSTRAP_TOKEN,
    BETTER_AUTH_SECRET: AUTH_SECRET,
    PUBLIC_ORIGIN: url,
    // Large enough that a slow CI runner's normal latency (~1 s seen) never looks like a delay.
    AUTH_BACKOFF_MS: "2000",
    RECOVERY_ACTIVATION_DELAY_SECONDS: "2",
    MAX_ITEMS_PER_BOX: "40",
    MAX_BOX_BYTES: "1000000",
    ...options.vars,
  };
  const child: ChildProcess = spawn(
    "pnpm",
    [
      "exec",
      "wrangler",
      "dev",
      "--port",
      String(port),
      "--inspector-port",
      String(inspector),
      "--persist-to",
      stateDir,
      ...Object.entries(vars).flatMap(([k, v]) => ["--var", `${k}:${v}`]),
    ],
    // Its own process group, so stopping takes down pnpm, node and workerd together.
    { cwd: SERVER_DIR, detached: true, stdio: process.env.SERVER_LOGS ? "inherit" : "ignore" },
  );
  let exited = false;
  child.once("exit", () => (exited = true));

  const stop = async () => {
    if (!exited && child.pid) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
      for (let i = 0; i < 100 && !exited; i++) await new Promise((r) => setTimeout(r, 50));
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }
    rmSync(stateDir, { recursive: true, force: true });
  };

  for (let i = 0; i < 480; i++) {
    if (exited) break;
    try {
      if ((await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok)
        return { url, stateDir, stop };
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  await stop();
  throw new Error("wrangler dev did not start (rerun with SERVER_LOGS=1 to see why)");
}
