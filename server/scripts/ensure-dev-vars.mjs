import { copyFileSync, existsSync } from "node:fs";

if (!existsSync(".dev.vars")) {
  copyFileSync(".dev.vars.example", ".dev.vars");
  console.log("created .dev.vars from .dev.vars.example (local dev bootstrap token)");
}
