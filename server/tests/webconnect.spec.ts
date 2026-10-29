import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { TEST_BOOTSTRAP_TOKEN } from "../playwright.config";
import { b64u, Bisel, newAdminKey, newDevice, randomX25519Pub, recoveryKeyFromSeed, type AdminKey, type TestDevice } from "./support/client";

// Device-code connect, end to end: a script plays the Mac, a real browser with a virtual passkey plays the person.
test.describe.configure({ mode: "serial" });

const ORIGIN = "http://localhost:8788";
const sql = (command: string) =>
  JSON.parse(
    execFileSync("pnpm", ["exec", "wrangler", "d1", "execute", "bisel", "--local", "--persist-to", ".wrangler/test-state", "--json", "--command", command], {
      encoding: "utf8",
    }),
  )[0].results as any[];

async function person(browser: import("@playwright/test").Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL: ORIGIN });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { context, page };
}

const bootstrapBody = async (device: TestDevice, admin?: AdminKey) => ({
  device: device.registration(),
  recovery_pubkey: (await recoveryKeyFromSeed(randomBytes(32))).pub,
  recovery_enc_pubkey: await randomX25519Pub(),
  recovery_envelope: b64u(randomBytes(60)),
  admin_pubkey: (admin ?? (await newAdminKey())).pub,
});

/** What the Mac does. */
const mac = (api: Bisel) => ({
  start: (name = "Test Mac") => api.raw("POST", "/v1/connect", {}, { device_name: name }),
  poll: async (device_code: string) => (await (await api.raw("POST", "/v1/connect/poll", {}, { device_code })).json()) as any,
  redeem: async (device_code: string, device: TestDevice) =>
    api.raw("POST", "/v1/bootstrap", { "X-Bisel-Connect": device_code }, await bootstrapBody(device)),
});

let ada: { context: BrowserContext; page: Page };
let adaDevice: TestDevice;
let adaBox: string;

test("a Mac with no credential gets approved by a new account and creates its box", async ({ browser, request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.6.0.1" });
  const m = mac(api);
  ada = await person(browser);

  const started = await m.start("Ada's MacBook");
  expect(started.status()).toBe(201);
  const code = (await started.json()) as any;
  expect(code.user_code).toMatch(/^[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}$/);
  expect(code.device_code).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(code.verification_uri).toBe(`${ORIGIN}/connect?code=${code.user_code}`);
  expect(code).toMatchObject({ expires_in: 600, interval: 3 });
  expect(await m.poll(code.device_code)).toEqual({ status: "pending" });
  expect(await m.poll("A".repeat(43))).toEqual({ status: "expired" }); // a guess looks like a timeout

  // Not approved yet: the secret redeems nothing, and neither does the code the person sees.
  adaDevice = await newDevice("Ada's MacBook");
  const early = await m.redeem(code.device_code, adaDevice);
  expect(early.status()).toBe(404);
  expect(await early.text()).toBe("");
  expect((await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Connect": code.user_code }, await bootstrapBody(adaDevice))).status()).toBe(404);

  // The person: the link lands on a sign-up (no account yet), then on the approval card.
  await ada.page.goto(`/connect?code=${code.user_code}`);
  await expect(ada.page.getByRole("heading", { name: "Connect your Mac" })).toBeVisible();
  await ada.page.getByPlaceholder(/Your name/).fill("Ada");
  await ada.page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(ada.page.getByRole("heading", { name: "Connect “Ada's MacBook”" })).toBeVisible();
  await expect(ada.page.getByText(code.user_code)).toBeVisible();
  await ada.page.getByRole("button", { name: "Approve" }).click();
  await expect(ada.page.getByText("Approved. Go back to bisel on your Mac")).toBeVisible();

  // The Mac's next poll sees it and redeems it, once.
  expect(await m.poll(code.device_code)).toEqual({ status: "approved", account_has_box: false });
  const created = await m.redeem(code.device_code, adaDevice);
  expect(created.status()).toBe(201);
  adaBox = ((await created.json()) as any).box_id;
  expect(await m.poll(code.device_code)).toEqual({ status: "consumed" });
  const again = await m.redeem(code.device_code, await newDevice("replay"));
  expect(again.status()).toBe(404);

  // The box is Ada's, the Mac syncs with its normal signed requests, and the dashboard lists it.
  expect(sql(`SELECT u.name FROM boxes b JOIN user u ON u.id = b.owner_id WHERE b.id = '${adaBox}'`)).toEqual([{ name: "Ada" }]);
  expect((await api.call(adaDevice, "GET", "/v1/sync")).status()).toBe(200);
  await ada.page.goto("/");
  await expect(ada.page.getByRole("heading", { name: "Ada" })).toBeVisible();
  await expect(ada.page.getByText("Ada's MacBook")).toBeVisible();
});

test("an account that already has a box cannot create another, and the Mac is told", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.6.0.2" });
  const m = mac(api);
  const code = (await (await m.start("Ada's second Mac")).json()) as any;
  await ada.page.goto(`/connect?code=${code.user_code}`);
  await expect(ada.page.getByText("This account already has a box")).toBeVisible();
  await ada.page.getByRole("button", { name: "Tell my Mac" }).click();
  await expect(ada.page.getByText("Your Mac has been told")).toBeVisible();
  expect(await m.poll(code.device_code)).toEqual({ status: "approved", account_has_box: true });
  const refused = await m.redeem(code.device_code, await newDevice("second"));
  expect(refused.status()).toBe(409);
  expect(await refused.json()).toEqual({ error: "box_exists" });
  expect(sql("SELECT COUNT(*) AS n FROM boxes b JOIN user u ON u.id = b.owner_id WHERE u.name = 'Ada'")).toEqual([{ n: 1 }]);
});

test("denying, expiry and the per-address cap leave nothing redeemable", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.6.0.3" });
  const m = mac(api);

  const denied = (await (await m.start()).json()) as any;
  await ada.page.goto(`/connect?code=${denied.user_code}`);
  await ada.page.getByRole("button", { name: "Tell my Mac" }).or(ada.page.getByRole("button", { name: "Not me" })).first().waitFor();
  await ada.page.getByRole("button", { name: "Not me" }).click();
  await expect(ada.page.getByText("Cancelled. Nothing was connected.")).toBeVisible();
  expect(await m.poll(denied.device_code)).toEqual({ status: "denied" });
  expect((await m.redeem(denied.device_code, await newDevice("x"))).status()).toBe(404);

  const stale = (await (await m.start()).json()) as any;
  sql(`UPDATE connect_requests SET expires_at = 1 WHERE user_code = '${stale.user_code}'`);
  expect(await m.poll(stale.device_code)).toEqual({ status: "expired" });
  await ada.page.goto(`/connect?code=${stale.user_code}`);
  await expect(ada.page.getByRole("heading", { name: "That code is not valid" })).toBeVisible();
  // An approved-then-expired code is dead too.
  const lapsed = (await (await m.start()).json()) as any;
  sql(`UPDATE connect_requests SET status = 'approved', account_id = (SELECT id FROM user WHERE name = 'Ada'), expires_at = 1 WHERE user_code = '${lapsed.user_code}'`);
  expect((await m.redeem(lapsed.device_code, await newDevice("late"))).status()).toBe(404);

  // Five open requests per address, then a bare 429; another address is unaffected.
  const flood = new Bisel(request, { "CF-Connecting-IP": "10.6.0.4" });
  for (let i = 0; i < 5; i++) expect((await mac(flood).start()).status()).toBe(201);
  const sixth = await mac(flood).start();
  expect(sixth.status()).toBe(429);
  expect(await sixth.text()).toBe("");
  expect((await mac(new Bisel(request, { "CF-Connecting-IP": "10.6.0.5" })).start()).status()).toBe(201);

  // Malformed input never reaches the database.
  expect((await api.raw("POST", "/v1/connect", {}, { device_name: "bad\u0000name" })).status()).toBe(400);
  expect((await api.raw("POST", "/v1/connect", {}, { device_name: "ok", extra: 1 })).status()).toBe(400);
  expect((await api.raw("POST", "/v1/connect/poll", {}, { device_code: "short" })).status()).toBe(400);
});

test("only a signed-in person can look at or answer a code", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.6.0.6" });
  const code = (await (await mac(api).start()).json()) as any;
  expect((await request.get(`/api/connect?code=${code.user_code}`)).status()).toBe(401);
  const csrf = { "X-Bisel-CSRF": "1", Origin: ORIGIN };
  expect((await request.post("/api/connect/approve", { headers: csrf, data: { code: code.user_code } })).status()).toBe(401);
  expect((await request.post("/api/connect/approve", { data: { code: code.user_code } })).status()).toBe(403);
  // Signed in, an unknown or malformed code is the same 404.
  for (const bad of ["ZZZZ-ZZZZ", "nope", ""]) {
    const res = await ada.page.evaluate(async (c) => (await fetch(`/api/connect?code=${encodeURIComponent(c)}`)).status, bad);
    expect(res).toBe(404);
  }
  expect(await mac(api).poll(code.device_code)).toEqual({ status: "pending" });
});

test("a Mac that already has a box links it to an account, with Touch ID (admin signature) on the Mac side", async ({ browser, request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.6.0.7" });
  const m = mac(api);
  // An unowned box, as the pre-accounts one is.
  const device = await newDevice("Legacy MacBook");
  const admin = await newAdminKey();
  const boot = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, await bootstrapBody(device, admin));
  expect(boot.status()).toBe(201);
  const boxId = ((await boot.json()) as any).box_id as string;

  // Signed by the device only: refused. The admin signature is what proves an unlocked vault.
  expect((await api.call(device, "POST", "/v1/box/claim", { admin: false })).status()).toBe(403);
  const claim = await api.call(device, "POST", "/v1/box/claim", { admin });
  expect(claim.status()).toBe(201);
  const code = (await claim.json()) as any;
  expect(await m.poll(code.device_code)).toEqual({ status: "pending" });

  // An account that already owns a box cannot take a second one, and the Mac learns it was refused.
  await ada.page.goto(`/connect?code=${code.user_code}`);
  await expect(ada.page.getByText("another cannot be linked")).toBeVisible();
  await expect(ada.page.getByRole("button", { name: "Link this box" })).toHaveCount(0);
  await ada.page.getByRole("button", { name: "Not me" }).click();
  expect(await m.poll(code.device_code)).toEqual({ status: "denied" });

  // A new account links it.
  const second = (await (await api.call(device, "POST", "/v1/box/claim", { admin })).json()) as any;
  const bob = await person(browser);
  await bob.page.goto(`/connect?code=${second.user_code}`);
  await bob.page.getByPlaceholder(/Your name/).fill("Bob");
  await bob.page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(bob.page.getByRole("heading", { name: "Link “Legacy MacBook” to your account" })).toBeVisible();
  await bob.page.getByRole("button", { name: "Link this box" }).click();
  await expect(bob.page.getByText("Linked. Your box now belongs to this account.")).toBeVisible();
  expect(await m.poll(second.device_code)).toEqual({ status: "consumed" });
  expect(sql(`SELECT u.name FROM boxes b JOIN user u ON u.id = b.owner_id WHERE b.id = '${boxId}'`)).toEqual([{ name: "Bob" }]);
  expect((await api.call(device, "GET", "/v1/sync")).status()).toBe(200); // unchanged for the device
  await bob.page.goto("/");
  await expect(bob.page.getByText("Legacy MacBook")).toBeVisible();

  // Linked boxes cannot be claimed again, and nobody else sees Bob's device.
  expect((await api.call(device, "POST", "/v1/box/claim", { admin })).status()).toBe(409);
  await ada.page.goto("/");
  await expect(ada.page.getByText("Legacy MacBook")).toHaveCount(0);
  await bob.context.close();
  await ada.context.close();
});
