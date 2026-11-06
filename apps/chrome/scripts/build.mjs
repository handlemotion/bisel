import { cp, rm } from "node:fs/promises";
import { build } from "esbuild";

await rm("dist", { recursive: true, force: true });
await cp("public", "dist", { recursive: true });
await build({
  entryPoints: ["src/background.ts", "src/content.ts", "src/prompt.ts"],
  outdir: "dist",
  bundle: true,
  format: "iife",
  target: "chrome116",
  legalComments: "none",
});
