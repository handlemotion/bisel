import { expect, test, type APIResponse } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { LEGACY_STATE } from "../playwright.legacy.config";
import { b64u, Bisel, boxState, recoveryKeyFromSeed, type Principal } from "../tests/support/client";

// The database was built by migrations 0001-0003, seeded with one box (legacy-tests/seed.sql), then migrated by 0004.
test.describe.configure({ mode: "serial" });

const json = async (res: APIResponse) => (await res.json()) as any;
const LEGACY_BOX = "legacy_box_00000000";

async function legacyDevice(): Promise<Principal> {
  const key = await webcrypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: "A-9d3lW-rA5cHomdKDFNWOZiZqRNwHFuJ03Yd7xwygY", y: "ZhAAyDEN120qI0AUAbQWGLg21QgD7h0Mt1s_6hoGiBQ", d: "KM7mYujgaK5MQYg9rBtq_fU5XKVL2RMXw7WzBWw2Ia0" },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return {
    id: "legacy-device-0000000001",
    sign: async (m) => new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(m))),
  };
}

const sql = (query: string) =>
  JSON.parse(
    execFileSync("pnpm", ["exec", "wrangler", "d1", "execute", "bisel", "--local", "--persist-to", LEGACY_STATE, "--json", "--command", query], {
      encoding: "utf8",
    }).replace(/^[^[]*/, ""),
  )[0].results as any[];

test("the old box moved to box legacy_box_00000000 with every row", async () => {
  expect(sql("SELECT id, owner_id, head_seq, epoch, item_count, disabled_at FROM boxes")).toEqual([
    { id: LEGACY_BOX, owner_id: null, head_seq: 3, epoch: 2, item_count: 2, disabled_at: null },
  ]);
  expect(sql("SELECT box_id, COUNT(*) AS n FROM devices GROUP BY box_id")).toEqual([{ box_id: LEGACY_BOX, n: 2 }]);
  expect(sql("SELECT box_id, COUNT(*) AS n FROM items GROUP BY box_id")).toEqual([{ box_id: LEGACY_BOX, n: 2 }]);
  expect(sql("SELECT box_id, COUNT(*) AS n FROM item_history GROUP BY box_id")).toEqual([{ box_id: LEGACY_BOX, n: 1 }]);
  expect(sql("SELECT box_id, COUNT(*) AS n FROM events GROUP BY box_id")).toEqual([{ box_id: LEGACY_BOX, n: 2 }]);
  // The item_count and stored_bytes triggers exist, and 0008 backfilled the byte count of the box's blobs.
  expect(sql("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name").map((r: any) => r.name)).toEqual([
    "items_bytes_delete", "items_bytes_insert", "items_bytes_update", "items_count_insert",
  ]);
  expect(sql("SELECT stored_bytes = (SELECT SUM(length(blob)) FROM items) AS ok, stored_bytes > 0 AS some FROM boxes")).toEqual([{ ok: 1, some: 1 }]);
});

test("the legacy device keeps working with no change to its requests", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.8.0.1" });
  const dev = await legacyDevice();

  const sync = await json(await api.call(dev, "GET", "/v1/sync"));
  expect(sync).toMatchObject({ head_seq: 3, epoch: 2, has_more: false });
  expect(sync.items.map((i: any) => [i.id, i.rev, i.seq, i.deleted])).toEqual([
    ["legacy-item-00000000002", 2, 2, true],
    ["legacy-item-00000000001", 2, 3, false],
  ]);
  expect(sync.devices.map((d: any) => [d.id, d.revoked_at])).toEqual([
    ["legacy-device-0000000001", null],
    ["legacy-device-0000000002", 1700000200],
  ]);
  expect(sync.events.map((e: any) => e.type)).toEqual(["bootstrap", "revoke"]);
  expect(sync.recovery.pubkey).toBe("yveNSL4xKJXKeM46BhJz7ugfaOE_wG0qtI9diFRHO3M");

  // Writes continue the same gapless log, and the history table keeps filling.
  const edit = await api.call(dev, "PUT", "/v1/items/legacy-item-00000000001", { json: { base_rev: 2, epoch: 2, blob: b64u(Buffer.alloc(100, 7))   /* sealed items are at least 88 bytes */ } });
  expect(edit.status()).toBe(200);
  expect((await json(edit)).item).toMatchObject({ rev: 3, seq: 4 });
  const fresh = await api.call(dev, "PUT", "/v1/items/legacy-item-00000000003", { json: { base_rev: 0, epoch: 2, blob: b64u(Buffer.alloc(100, 8)) } });
  expect((await json(fresh)).item).toMatchObject({ rev: 1, seq: 5 });
  // The edit's previous state is in history; the seeded 2023 row was older than the retention window and got pruned.
  expect((await json(await api.call(dev, "GET", "/v1/history"))).entries.map((e: any) => [e.item_id, e.rev])).toEqual([
    ["legacy-item-00000000001", 2],
  ]);
  // item_count follows new rows only, not edits.
  expect(sql("SELECT item_count, head_seq FROM boxes")).toEqual([{ item_count: 3, head_seq: 5 }]);

  // A revoked legacy device is still revoked.
  const old = await legacyDevice();
  expect((await api.call({ ...old, id: "legacy-device-0000000002" }, "GET", "/v1/sync")).status()).toBe(404);
});

test("a recovery request without X-Bisel-Box still reaches the legacy box", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.8.0.2" });
  const recovery = await recoveryKeyFromSeed(new Uint8Array(Buffer.from("XKfsWBcnjI5_rqPc65Zb90-HFm85SbfCVDg-6CAx9go", "base64url")));
  boxState.id = null;
  const res = await api.call(recovery, "POST", "/v1/recovery/session");
  expect(res.status()).toBe(200);
  expect(await json(res)).toMatchObject({ epoch: 2, head_seq: 5 });
  // Naming the box explicitly works too.
  boxState.id = LEGACY_BOX;
  expect((await api.call(recovery, "POST", "/v1/recovery/session")).status()).toBe(200);
  boxState.id = null;
});

test("a second box can be created beside it and never sees the legacy data", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.8.0.3" });
  const { newAdminKey, newDevice, randomX25519Pub } = await import("../tests/support/client");
  const device = await newDevice("newcomer");
  const created = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": "legacy-test-token" }, {
    device: device.registration(),
    recovery_pubkey: (await recoveryKeyFromSeed(new Uint8Array(32).fill(7))).pub,
    recovery_enc_pubkey: await randomX25519Pub(),
    recovery_envelope: b64u(Buffer.alloc(60, 1)),
    admin_pubkey: (await newAdminKey()).pub,
  });
  expect(created.status()).toBe(201);
  const sync = await json(await api.call(device, "GET", "/v1/sync"));
  expect(sync.items).toEqual([]);
  expect(sync.devices.map((d: any) => d.id)).toEqual([device.id]);
  expect(sql("SELECT COUNT(*) AS n FROM boxes")).toEqual([{ n: 2 }]);
});
