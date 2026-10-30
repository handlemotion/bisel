import type { TestProject } from "vitest/node";
import { startServer } from "./server";

// One real Worker on a local D1 for the whole run; the files talk to it over HTTP with plain fetch.
export default async function setup(project: TestProject) {
  const server = await startServer();
  project.provide("server", { url: server.url, stateDir: server.stateDir });
  return server.stop;
}

declare module "vitest" {
  export interface ProvidedContext {
    server: { url: string; stateDir: string };
  }
}
