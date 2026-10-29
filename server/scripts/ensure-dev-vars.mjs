import { appendFileSync, copyFileSync, existsSync, readFileSync } from "node:fs";

if (!existsSync(".dev.vars")) {
  copyFileSync(".dev.vars.example", ".dev.vars");
  console.log("created .dev.vars from .dev.vars.example (local dev secrets)");
} else {
  // A .dev.vars from before a secret existed: add what is missing, never touch what is there.
  const have = new Set(readFileSync(".dev.vars", "utf8").split("\n").map((l) => l.split("=")[0]));
  const missing = readFileSync(".dev.vars.example", "utf8")
    .split("\n")
    .filter((l) => l && !l.startsWith("#") && !have.has(l.split("=")[0]));
  if (missing.length) {
    appendFileSync(".dev.vars", "\n" + missing.join("\n") + "\n");
    console.log(`added to .dev.vars: ${missing.map((l) => l.split("=")[0]).join(", ")}`);
  }
}
