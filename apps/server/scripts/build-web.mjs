// Bundles the dashboard (web/app.ts) into public/app.js. public/ also holds the hand-written index.html, style.css and
// _headers; app.js is generated and git-ignored. No framework, one file, nothing loaded from another origin.
import { build } from "esbuild";

await build({
  entryPoints: ["web/app.ts"],
  outfile: "public/app.js",
  bundle: true,
  minify: true,
  format: "iife",
  target: "es2022",
  legalComments: "none",
  logLevel: "warning",
});
