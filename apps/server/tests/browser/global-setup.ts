import { PORT } from "../../playwright.config";
import { startServer } from "../support/server";

export default async function setup() {
  const server = await startServer({ port: PORT });
  process.env.BISEL_TEST_STATE = server.stateDir;
  return server.stop;
}
