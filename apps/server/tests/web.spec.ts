import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { TEST_BOOTSTRAP_TOKEN } from "../playwright.config";
import {
  b64u,
  Bisel,
  newAdminKey,
  newDevice,
  randomX25519Pub,
  recoveryKeyFromSeed,
} from "./support/client";

// The dashboard in a real browser with a virtual passkey authenticator (CDP WebAuthn), against the real Worker.
test.describe.configure({ mode: "serial" });

const sql = (command: string) =>
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
      ".wrangler/test-state",
      "--json",
      "--command",
      command,
    ],
    {
      encoding: "utf8",
    },
  );

async function virtualAuthenticator(page: Page, transport: "internal" | "usb" = "internal") {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

// One browser, one virtual authenticator, one story: the passkey made in the first test is what signs in later.
let context: BrowserContext;
let page: Page;
test.beforeAll(async ({ browser }) => {
  context = await browser.newContext({ baseURL: "http://localhost:8788" });
  page = await context.newPage();
  await virtualAuthenticator(page);
});
test.afterAll(async () => context.close());

let boxId: string;
let deviceName: string;
let deviceCreds: Awaited<ReturnType<typeof newDevice>>;

test("sign up with a passkey, sign out, sign in again", async () => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();

  // A name is required, and a failed attempt leaves nothing behind.
  await page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(page.getByText("Enter a name first.")).toBeVisible();

  await page.getByPlaceholder(/Your name/).fill("Rodrigo");
  await page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();
  await expect(page.getByText("No box yet")).toBeVisible();

  // The account row exists and carries a placeholder address, not anything the person typed.
  const users = JSON.parse(sql("SELECT name, email FROM user"))[0].results as {
    name: string;
    email: string;
  }[];
  expect(users.map((u) => u.name)).toContain("Rodrigo");
  expect(users.find((u) => u.name === "Rodrigo")!.email).toMatch(
    /^[0-9a-f]{32}@accounts\.bisel\.invalid$/,
  );

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();

  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();
});

test("the dashboard lists the account's devices once a box is linked, and nobody else's", async ({
  request,
}) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.7.0.1" });

  // Two boxes exist; only the first is linked to the account (linking by the connect flow is covered in connect.spec.ts).
  async function box(label: string) {
    const device = await newDevice(label);
    const res = await api.raw(
      "POST",
      "/v1/bootstrap",
      { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN },
      {
        device: device.registration(),
        recovery_pubkey: (await recoveryKeyFromSeed(randomBytes(32))).pub,
        recovery_enc_pubkey: await randomX25519Pub(),
        recovery_envelope: b64u(randomBytes(60)),
        admin_pubkey: (await newAdminKey()).pub,
      },
    );
    expect(res.status()).toBe(201);
    return { device, id: ((await res.json()) as any).box_id as string };
  }
  const mine = await box("Rodrigo's MacBook");
  const other = await box("Someone else's Mac");
  boxId = mine.id;
  deviceCreds = mine.device;
  deviceName = "Rodrigo's MacBook";
  sql(
    `UPDATE boxes SET owner_id = (SELECT id FROM user WHERE name = 'Rodrigo') WHERE id = '${mine.id}'`,
  );

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();
  await expect(page.getByText(deviceName)).toBeVisible();
  await expect(page.getByText("Someone else's Mac")).toHaveCount(0);
  expect(other.id).not.toBe(mine.id);

  // The page only ever shows public device columns: nothing from the box's secrets reaches the browser.
  const body = await page.evaluate(async () => (await fetch("/api/box")).text());
  for (const secret of ["envelope", "recovery", "admin_pubkey", "sig_pubkey", "enc_pubkey", "blob"])
    expect(body).not.toContain(secret);
});

test("passkeys: add a second, remove one, never the last", async () => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove" })).toBeDisabled();
  // The first authenticator already holds this account's passkey and refuses a duplicate, as a real device does; add a second one.
  await virtualAuthenticator(page, "usb");
  await page.getByRole("button", { name: "Add another passkey" }).click();
  await expect(page.getByRole("button", { name: "Remove" })).toHaveCount(2);
  await page.getByRole("button", { name: "Remove" }).first().click();
  await expect(page.getByRole("button", { name: "Remove" })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Remove" })).toBeDisabled();
});

test("account routes refuse the unauthenticated and the cross-site, and static pages carry the CSP", async ({
  request,
}) => {
  expect((await request.get("/api/box")).status()).toBe(401);
  expect((await request.delete("/api/box", { data: { confirm: "delete" } })).status()).toBe(403); // no CSRF header, no Origin
  const withHeader = await request.delete("/api/box", {
    headers: { "X-Bisel-CSRF": "1", Origin: "https://evil.example" },
    data: { confirm: "delete" },
  });
  expect(withHeader.status()).toBe(403);
  const same = await request.delete("/api/box", {
    headers: { "X-Bisel-CSRF": "1", Origin: "http://localhost:8788" },
    data: { confirm: "delete" },
  });
  expect(same.status()).toBe(401); // right origin and header, but no session

  const page = await request.get("/");
  expect(page.status()).toBe(200);
  const csp = page.headers()["content-security-policy"]!;
  expect(csp).toContain("script-src 'self'");
  expect(csp).not.toContain("unsafe-inline");
  expect(page.headers()["x-frame-options"]).toBe("DENY");
  // Deep links get the app shell; /v1 keeps its bare 404 for anything that is not a signed route.
  expect(await (await request.get("/connect")).text()).toContain('id="app"');
  const v1 = await request.get("/v1/nothing-here");
  expect(v1.status()).toBe(404);
  expect(await v1.text()).toBe("");
});

test("deleting the box needs a fresh passkey sign-in and removes the box from the server", async ({
  request,
}) => {
  await page.goto("/");
  await expect(page.getByText(deviceName)).toBeVisible();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete box from the server" }).click();
  await expect(page.getByText("No box yet")).toBeVisible();

  const api = new Bisel(request, { "CF-Connecting-IP": "10.7.0.2" });
  expect((await api.call(deviceCreds, "GET", "/v1/sync")).status()).toBe(404);
  const rows = JSON.parse(
    sql(
      `SELECT (SELECT COUNT(*) FROM boxes WHERE id = '${boxId}') AS b, (SELECT COUNT(*) FROM devices WHERE box_id = '${boxId}') AS d`,
    ),
  )[0].results[0];
  expect(rows).toEqual({ b: 0, d: 0 });
});
