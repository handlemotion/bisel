import { randomBytes } from "node:crypto";
import { expect, inject, test } from "vitest";
import { signUp, type Account } from "./support/accounts";
import { BOOTSTRAP_TOKEN, sql } from "./support/server";
import {
  b64u,
  clientAt,
  newAdminKey,
  newDevice,
  randomX25519Pub,
  recoveryKeyFromSeed,
  type AdminKey,
  type Bisel,
  type TestDevice,
} from "./support/client";

// The dashboard's account API and device-code connect, end to end against the real Worker. A signed-in person is a session row
// plus its signed cookie (tests/support/accounts.ts); the passkey ceremony itself is the opt-in browser test.

const json = async (res: Response) => (await res.json()) as any;
const rows = (statement: string) => sql(inject("server").stateDir, statement);

const bootstrapBody = async (device: TestDevice, admin?: AdminKey) => ({
  device: device.registration(),
  recovery_pubkey: (await recoveryKeyFromSeed(randomBytes(32))).pub,
  recovery_enc_pubkey: await randomX25519Pub(),
  recovery_envelope: b64u(randomBytes(60)),
  admin_pubkey: (admin ?? (await newAdminKey())).pub,
});

/** A box nobody owns yet, made with the operator's token (the pre-accounts way). */
async function unownedBox(api: Bisel, device: TestDevice, admin?: AdminKey) {
  const res = await api.raw(
    "POST",
    "/v1/bootstrap",
    { "X-Bisel-Bootstrap": BOOTSTRAP_TOKEN },
    await bootstrapBody(device, admin),
  );
  expect(res.status).toBe(201);
  return (await json(res)).box_id as string;
}

/** What the person's browser does. */
const person = (api: Bisel, who: Account) => ({
  look: (code: string) =>
    api.fetch(`/api/connect?code=${encodeURIComponent(code)}`, { headers: { Cookie: who.cookie } }),
  answer: (verb: "approve" | "deny", code: string) =>
    api.fetch(`/api/connect/${verb}`, {
      method: "POST",
      headers: { ...who.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }),
  box: () => api.fetch("/api/box", { headers: { Cookie: who.cookie } }),
});

/** What the Mac does. */
const mac = (api: Bisel) => ({
  start: (name = "Test Mac") => api.raw("POST", "/v1/connect", {}, { device_name: name }),
  poll: async (device_code: string) =>
    (await (await api.raw("POST", "/v1/connect/poll", {}, { device_code })).json()) as any,
  redeem: async (device_code: string, device: TestDevice) =>
    api.raw(
      "POST",
      "/v1/bootstrap",
      { "X-Bisel-Connect": device_code },
      await bootstrapBody(device),
    ),
});

let ada: Account;
const adaApi = () => clientAt("10.6.0.1");

test("dashboard routes refuse the unauthenticated and the cross-site, and the page carries a strict CSP", async () => {
  const api = clientAt("10.7.0.1");
  const origin = inject("server").url;
  expect((await api.fetch("/api/box")).status).toBe(401);
  const del = (headers: Record<string, string>) =>
    api.fetch("/api/box", {
      method: "DELETE",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: "delete" }),
    });
  expect((await del({})).status, "no CSRF header, no Origin").toBe(403);
  expect((await del({ "X-Bisel-CSRF": "1", Origin: "https://evil.example" })).status).toBe(403);
  expect(
    (await del({ "X-Bisel-CSRF": "1", Origin: origin })).status,
    "right origin, but no session",
  ).toBe(401);

  // Looking at or answering a connect code needs a session too, and a forged cookie is no session.
  const code = (await json(await mac(api).start())).user_code as string;
  expect((await api.fetch(`/api/connect?code=${code}`)).status).toBe(401);
  const post = (headers: Record<string, string>) =>
    api.fetch("/api/connect/approve", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
  expect((await post({ "X-Bisel-CSRF": "1", Origin: origin })).status).toBe(401);
  expect((await post({})).status).toBe(403);
  const forged = signUp("Mallory").cookie.replace(/.$/, (c) => (c === "A" ? "B" : "A"));
  expect((await api.fetch("/api/box", { headers: { Cookie: forged } })).status).toBe(401);

  const page = await api.fetch("/");
  expect(page.status).toBe(200);
  const csp = page.headers.get("content-security-policy")!;
  expect(csp).toContain("script-src 'self'");
  expect(csp).not.toContain("unsafe-inline");
  expect(page.headers.get("x-frame-options")).toBe("DENY");
});

test("the dashboard lists the account's own devices and nothing else, and none of the box's secrets", async () => {
  const api = clientAt("10.7.0.2");
  const rodrigo = signUp("Rodrigo");
  const mine = await unownedBox(api, await newDevice("Rodrigo's MacBook"));
  await unownedBox(api, await newDevice("Someone else's Mac"));
  rows(`UPDATE boxes SET owner_id = '${rodrigo.id}' WHERE id = '${mine}'`);

  const res = await person(api, rodrigo).box();
  expect(res.status).toBe(200);
  const text = await res.text();
  const view = JSON.parse(text);
  expect(view.box.id).toBe(mine);
  expect(view.devices.map((d: any) => d.name)).toEqual(["Rodrigo's MacBook"]);
  for (const secret of ["envelope", "recovery", "admin_pubkey", "sig_pubkey", "enc_pubkey", "blob"])
    expect(text).not.toContain(secret);
  expect((await json(await person(api, signUp("Nobody")).box())).box).toBeNull();
});

test("deleting the box needs a recent passkey sign-in and removes everything the server held", async () => {
  const api = clientAt("10.7.0.3");
  const del = (who: Account, body: unknown = { confirm: "delete" }) =>
    api.fetch("/api/box", {
      method: "DELETE",
      headers: { ...who.headers, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  async function ownedBox(who: Account) {
    const device = await newDevice(`${who.name}'s Mac`);
    const box = await unownedBox(api, device);
    rows(`UPDATE boxes SET owner_id = '${who.id}' WHERE id = '${box}'`);
    return { box, device };
  }

  // A session older than five minutes (a stolen cookie, an unattended browser) cannot delete.
  const stale = signUp("Stale", 600);
  const kept = await ownedBox(stale);
  const refused = await del(stale);
  expect(refused.status).toBe(403);
  expect(await json(refused)).toEqual({ error: "reauth_required" });
  expect((await api.call(kept.device, "GET", "/v1/sync")).status).toBe(200);

  const fresh = signUp("Fresh");
  const gone = await ownedBox(fresh);
  expect(
    (await del(fresh, { confirm: "yes" })).status,
    "the confirmation is part of the request",
  ).toBe(400);
  expect((await api.call(gone.device, "GET", "/v1/sync")).status).toBe(200);
  expect((await del(fresh)).status).toBe(200);
  expect((await api.call(gone.device, "GET", "/v1/sync")).status).toBe(404);
  expect(
    rows(
      `SELECT (SELECT COUNT(*) FROM boxes WHERE id = '${gone.box}') AS b, (SELECT COUNT(*) FROM devices WHERE box_id = '${gone.box}') AS d`,
    ),
  ).toEqual([{ b: 0, d: 0 }]);
  expect(rows(`SELECT COUNT(*) AS n FROM boxes WHERE id = '${kept.box}'`)).toEqual([{ n: 1 }]);
});

test("a Mac with no credential gets approved by an account and creates its box, once", async () => {
  const api = adaApi();
  const m = mac(api);
  ada = signUp("Ada");
  const ui = person(api, ada);

  const started = await m.start("Ada's MacBook");
  expect(started.status).toBe(201);
  const code = (await started.json()) as any;
  expect(await m.poll(code.device_code)).toEqual({ status: "pending" });
  expect(await m.poll("A".repeat(43))).toEqual({ status: "expired" }); // a guess looks like a timeout

  // Not approved yet: neither the secret nor the code the person sees redeems anything.
  const device = await newDevice("Ada's MacBook");
  const early = await m.redeem(code.device_code, device);
  expect(early.status).toBe(404);
  expect(await early.text()).toBe("");
  expect((await m.redeem(code.user_code, device)).status).toBe(404);

  // The person checks the name their Mac shows, then approves.
  expect(await json(await ui.look(code.user_code))).toMatchObject({
    kind: "create",
    device_name: "Ada's MacBook",
    account_has_box: false,
  });
  expect((await ui.answer("approve", code.user_code)).status).toBe(200);
  expect(await m.poll(code.device_code)).toEqual({ status: "approved", account_has_box: false });

  const created = await m.redeem(code.device_code, device);
  expect(created.status).toBe(201);
  const boxId = (await json(created)).box_id as string;
  expect(await m.poll(code.device_code)).toEqual({ status: "consumed" });
  expect((await m.redeem(code.device_code, await newDevice("replay"))).status, "single use").toBe(
    404,
  );

  // The box is Ada's, the Mac syncs with its normal signed requests, and the dashboard lists it.
  expect(rows(`SELECT owner_id FROM boxes WHERE id = '${boxId}'`)).toEqual([{ owner_id: ada.id }]);
  expect((await api.call(device, "GET", "/v1/sync")).status).toBe(200);
  expect((await json(await ui.box())).devices.map((d: any) => d.name)).toEqual(["Ada's MacBook"]);
});

test("an account that already has a box cannot create another, and the Mac is told", async () => {
  const api = clientAt("10.6.0.2");
  const m = mac(api);
  const code = await json(await m.start("Ada's second Mac"));
  expect((await person(api, ada).answer("approve", code.user_code)).status).toBe(200);
  expect(await m.poll(code.device_code)).toEqual({ status: "approved", account_has_box: true });
  const refused = await m.redeem(code.device_code, await newDevice("second"));
  expect(refused.status).toBe(409);
  expect(await refused.json()).toEqual({ error: "box_exists" });
  expect(rows(`SELECT COUNT(*) AS n FROM boxes WHERE owner_id = '${ada.id}'`)).toEqual([{ n: 1 }]);
});

test("denying, expiry and the per-address cap leave nothing redeemable", async () => {
  const api = clientAt("10.6.0.3");
  const m = mac(api);
  const ui = person(api, signUp("Grace"));

  const denied = await json(await m.start());
  expect((await ui.answer("deny", denied.user_code)).status).toBe(200);
  expect(await m.poll(denied.device_code)).toEqual({ status: "denied" });
  expect((await m.redeem(denied.device_code, await newDevice("x"))).status).toBe(404);

  const stale = await json(await m.start());
  rows(`UPDATE connect_requests SET expires_at = 1 WHERE user_code = '${stale.user_code}'`);
  expect(await m.poll(stale.device_code)).toEqual({ status: "expired" });
  expect((await ui.look(stale.user_code)).status, "the person cannot answer an expired code").toBe(
    404,
  );
  // An approved-then-expired code is dead too.
  const lapsed = await json(await m.start());
  rows(
    `UPDATE connect_requests SET status = 'approved', account_id = '${ada.id}', expires_at = 1 WHERE user_code = '${lapsed.user_code}'`,
  );
  expect((await m.redeem(lapsed.device_code, await newDevice("late"))).status).toBe(404);

  // Five open requests per address, then a bare 429; another address is unaffected.
  const flood = clientAt("10.6.0.4");
  for (let i = 0; i < 5; i++) expect((await mac(flood).start()).status).toBe(201);
  const sixth = await mac(flood).start();
  expect(sixth.status).toBe(429);
  expect(await sixth.text()).toBe("");
  expect((await mac(clientAt("10.6.0.5")).start()).status).toBe(201);
});

test("a Mac that already has a box links it to an account, with the vault-admin signature on the Mac side", async () => {
  const api = clientAt("10.6.0.7");
  const m = mac(api);
  const device = await newDevice("Legacy MacBook");
  const admin = await newAdminKey();
  const boxId = await unownedBox(api, device, admin);

  // Signed by the device only: refused. The admin signature is what proves an unlocked vault.
  expect((await api.call(device, "POST", "/v1/box/claim", { admin: false })).status).toBe(403);
  const claim = await json(await api.call(device, "POST", "/v1/box/claim", { admin }));
  expect(await m.poll(claim.device_code)).toEqual({ status: "pending" });

  // An account that already owns a box cannot take a second one, and the Mac learns it was refused.
  const refused = await person(api, ada).answer("approve", claim.user_code);
  expect(refused.status).toBe(409);
  expect(await m.poll(claim.device_code)).toEqual({ status: "denied" });

  // A new account links it.
  const second = await json(await api.call(device, "POST", "/v1/box/claim", { admin }));
  const bob = signUp("Bob");
  expect((await person(api, bob).answer("approve", second.user_code)).status).toBe(200);
  expect(await m.poll(second.device_code)).toEqual({ status: "consumed" });
  expect(rows(`SELECT owner_id FROM boxes WHERE id = '${boxId}'`)).toEqual([{ owner_id: bob.id }]);
  expect((await api.call(device, "GET", "/v1/sync")).status, "unchanged for the device").toBe(200);
  expect((await json(await person(api, bob).box())).devices.map((d: any) => d.name)).toEqual([
    "Legacy MacBook",
  ]);

  // Linked boxes cannot be claimed again, and nobody else sees Bob's device.
  expect((await api.call(device, "POST", "/v1/box/claim", { admin })).status).toBe(409);
  expect((await json(await person(api, ada).box())).devices.map((d: any) => d.name)).not.toContain(
    "Legacy MacBook",
  );
});
