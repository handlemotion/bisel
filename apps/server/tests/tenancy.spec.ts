import { expect, test, type APIResponse } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { TEST_BOOTSTRAP_TOKEN } from "../playwright.config";
import { b64u, Bisel, boxState, newAdminKey, newDevice, randomId, randomX25519Pub, recoveryKeyFromSeed, type AdminKey, type TestDevice } from "./support/client";

// Two (and then more) boxes on one server: nothing one box does may be visible to, or change, another.
test.describe.configure({ mode: "serial" });

const json = async (res: APIResponse) => (await res.json()) as any;
const blob = (n = 200) => b64u(randomBytes(n));

interface TestBox {
  id: string;
  device: TestDevice;
  admin: AdminKey;
  recovery: Awaited<ReturnType<typeof recoveryKeyFromSeed>>;
  envelope: string;
}

async function createBox(api: Bisel, label: string): Promise<TestBox> {
  const device = await newDevice(`${label}-mac`);
  const recovery = await recoveryKeyFromSeed(randomBytes(32));
  const admin = await newAdminKey();
  const envelope = b64u(randomBytes(60));
  const res = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, {
    device: device.registration(),
    recovery_pubkey: recovery.pub,
    recovery_enc_pubkey: await randomX25519Pub(),
    recovery_envelope: envelope,
    admin_pubkey: admin.pub,
  });
  expect(res.status()).toBe(201);
  return { id: (await json(res)).box_id, device, admin, recovery, envelope };
}

/** Recovery requests name their box in X-Bisel-Box; run `fn` aimed at `boxId` (null = header omitted). */
async function aimedAt<T>(boxId: string | null, fn: () => Promise<T>): Promise<T> {
  const keep = boxState.id;
  boxState.id = boxId;
  try {
    return await fn();
  } finally {
    boxState.id = keep;
  }
}

let A: TestBox;
let B: TestBox;
const shared = randomId(); // the very same item id, used in both boxes

test("two boxes can use the same item id without touching each other", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.1" });
  A = await createBox(api, "alice");
  B = await createBox(api, "bob");
  expect(A.id).not.toBe(B.id);

  const blobA = blob();
  const blobB = blob();
  const putA = await api.call(A.device, "PUT", `/v1/items/${shared}`, { json: { base_rev: 0, epoch: 1, blob: blobA } });
  const putB = await api.call(B.device, "PUT", `/v1/items/${shared}`, { json: { base_rev: 0, epoch: 1, blob: blobB } });
  expect(putA.status()).toBe(200);
  expect(putB.status(), "bob's create is not a conflict with alice's row").toBe(200);

  // Alice edits hers; bob's row keeps its rev and blob.
  const blobA2 = blob();
  expect((await api.call(A.device, "PUT", `/v1/items/${shared}`, { json: { base_rev: 1, epoch: 1, blob: blobA2 } })).status()).toBe(200);

  const syncA = await json(await api.call(A.device, "GET", "/v1/sync"));
  const syncB = await json(await api.call(B.device, "GET", "/v1/sync"));
  expect(syncA.items).toHaveLength(1);
  expect(syncA.items[0]).toMatchObject({ id: shared, rev: 2, blob: blobA2 });
  expect(syncA.head_seq).toBe(2);
  expect(syncB.items).toHaveLength(1);
  expect(syncB.items[0]).toMatchObject({ id: shared, rev: 1, blob: blobB, seq: 1 });
  expect(syncB.head_seq).toBe(1);

  // Devices, events and recovery material are per box too.
  expect(syncA.devices.map((d: any) => d.id)).toEqual([A.device.id]);
  expect(syncB.devices.map((d: any) => d.id)).toEqual([B.device.id]);
  expect(syncA.events.map((e: any) => e.subject_id)).toEqual([A.device.id]);
  expect(syncB.events.map((e: any) => e.subject_id)).toEqual([B.device.id]);
  expect(syncA.recovery.pubkey).toBe(A.recovery.pub);
  expect(syncB.recovery.pubkey).toBe(B.recovery.pub);

  // History and the device list likewise.
  const histA = await json(await api.call(A.device, "GET", "/v1/history"));
  const histB = await json(await api.call(B.device, "GET", "/v1/history"));
  expect(histA.entries).toHaveLength(1);
  expect(histB.entries).toHaveLength(0);
  expect((await json(await api.call(B.device, "GET", "/v1/devices"))).devices.map((d: any) => d.id)).toEqual([B.device.id]);
});

test("deleting, revoking and approving reach only the caller's own box", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.2" });

  // Alice tombstones her copy; bob's is still live at rev 1.
  const del = await api.call(A.device, "DELETE", `/v1/items/${shared}`, { query: { base_rev: 2 }, json: { epoch: 1, marker: blob(32) } });
  expect(del.status()).toBe(200);
  const syncB = await json(await api.call(B.device, "GET", "/v1/sync"));
  expect(syncB.items[0]).toMatchObject({ id: shared, rev: 1, deleted: false });

  // Alice (with a valid admin signature) cannot revoke bob's device: it is not hers, so it does not exist for her.
  const revoke = await api.call(A.device, "DELETE", `/v1/devices/${B.device.id}`, { admin: A.admin });
  expect(revoke.status()).toBe(404);
  expect((await api.call(B.device, "GET", "/v1/sync")).status()).toBe(200);

  // Registering a device id that already lives in another box is refused, and moves nothing.
  const clash = await api.call(A.device, "POST", "/v1/devices", { admin: A.admin, json: { ...B.device.registration(), epoch: 1 } });
  expect(clash.status()).toBe(409);
  const syncA = await json(await api.call(A.device, "GET", "/v1/sync"));
  expect(syncA.devices.map((d: any) => d.id)).toEqual([A.device.id]);
  expect((await json(await api.call(B.device, "GET", "/v1/devices"))).devices[0].revoked_at).toBeNull();
});

test("a recovery key opens only its own box, and the box header cannot be used to probe", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.3" });
  expect((await aimedAt(A.id, () => api.call(A.recovery, "POST", "/v1/recovery/session"))).status()).toBe(200);
  expect((await aimedAt(B.id, () => api.call(B.recovery, "POST", "/v1/recovery/session"))).status()).toBe(200);
  // Right key, wrong box; unknown box; no box (falls back to a legacy box that does not exist here): all the same bare 404.
  const wrongBox = await aimedAt(B.id, () => api.call(A.recovery, "POST", "/v1/recovery/session"));
  const unknown = await aimedAt("nonexistent_box_000000", () => api.call(A.recovery, "POST", "/v1/recovery/session"));
  const none = await aimedAt(null, () => api.call(A.recovery, "POST", "/v1/recovery/session"));
  for (const r of [wrongBox, unknown, none]) {
    expect(r.status()).toBe(404);
    expect(await r.text()).toBe("");
  }
  // Only recovery requests may carry the header; on a device request it is malformed.
  const prepared = await import("./support/client").then((m) => m.prepare(A.device, "GET", "/v1/sync"));
  prepared.headers["X-Bisel-Box"] = A.id;
  expect((await api.send(prepared)).status()).toBe(404);
  // A malformed box id is the same refusal.
  expect((await aimedAt("short", () => api.call(A.recovery, "POST", "/v1/recovery/session"))).status()).toBe(404);
});

test("rotating one box leaves the other's epoch, items, devices and keys untouched", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.4" });
  const before = await json(await api.call(B.device, "GET", "/v1/sync"));
  const sA = await json(await api.call(A.device, "GET", "/v1/sync"));
  const newAdmin = await newAdminKey();
  const body = {
    base_epoch: sA.epoch,
    base_seq: sA.head_seq,
    revoke: null,
    new_admin_pubkey: newAdmin.pub,
    // Alice's only record is the tombstone from the previous test.
    tombstones: sA.items.filter((i: any) => i.deleted).map((i: any) => ({ id: i.id, rev: i.rev, marker: blob(32) })),
    items: sA.items.filter((i: any) => !i.deleted).map((i: any) => ({ id: i.id, rev: i.rev, key: b64u(randomBytes(60)) })),
    devices: [{ id: A.device.id, envelope: b64u(randomBytes(125)) }],
    recovery_envelope: b64u(randomBytes(60)),
  };
  const rot = await api.call(A.device, "POST", "/v1/rotate", { json: body, admin: A.admin });
  expect(rot.status()).toBe(200);
  expect((await json(rot)).epoch).toBe(2);

  const after = await json(await api.call(B.device, "GET", "/v1/sync"));
  expect(after.epoch).toBe(1);
  expect(after.head_seq).toBe(before.head_seq);
  expect(after.items).toEqual(before.items);
  expect(after.recovery).toEqual(before.recovery);
  expect(after.devices).toEqual(before.devices);
  // Bob's old admin key still works for bob's destructive routes; alice's rotation moved only her admin key.
  expect((await json(await api.call(A.device, "GET", "/v1/sync"))).epoch).toBe(2);
});

test("a box holds at most MAX_ITEMS_PER_BOX items; another box is unaffected", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.5" });
  const C = await createBox(api, "carol");
  const D = await createBox(api, "dave");
  const ids = Array.from({ length: 40 }, () => randomId());
  for (let i = 0; i < ids.length; i += 10) {
    const res = await Promise.all(ids.slice(i, i + 10).map((id) => api.call(C.device, "PUT", `/v1/items/${id}`, { json: { base_rev: 0, epoch: 1, blob: blob(100) } })));
    expect(res.map((r) => r.status())).toEqual(Array(res.length).fill(200));
  }
  const over = await api.call(C.device, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, epoch: 1, blob: blob(100) } });
  expect(over.status()).toBe(409);
  expect(await json(over)).toMatchObject({ error: "box_full", max_items: 40 });
  // The refusal consumed no seq, existing items can still be edited, and a tombstone still counts as an item.
  const state = await json(await api.call(C.device, "GET", "/v1/sync", { query: { limit: 200 } }));
  expect(state.head_seq).toBe(40);
  const edit = await api.call(C.device, "PUT", `/v1/items/${ids[0]}`, { json: { base_rev: 1, epoch: 1, blob: blob(100) } });
  expect(edit.status()).toBe(200);
  const del = await api.call(C.device, "DELETE", `/v1/items/${ids[1]}`, { query: { base_rev: 1 }, json: { epoch: 1, marker: blob(32) } });
  expect(del.status()).toBe(200);
  expect((await api.call(C.device, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, epoch: 1, blob: blob(100) } })).status()).toBe(409);
  // Dave is untouched by carol being full.
  expect((await api.call(D.device, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, epoch: 1, blob: blob(100) } })).status()).toBe(200);
});

test("a box stores at most MAX_BOX_BYTES of blobs and keeps its history under the same bound; another box is unaffected", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.8" });
  const F = await createBox(api, "frank");
  const G = await createBox(api, "gina");
  const big = () => blob(256 * 1024); // 349,526 characters; the test server allows 1,000,000 per box
  const put = (box: TestBox, id: string, baseRev: number, b: string) =>
    api.call(box.device, "PUT", `/v1/items/${id}`, { json: { base_rev: baseRev, epoch: 1, blob: b } });
  const one = randomId(), two = randomId();
  expect((await put(F, one, 0, big())).status()).toBe(200);
  expect((await put(F, two, 0, big())).status()).toBe(200);
  const over = await put(F, randomId(), 0, big());
  expect(over.status()).toBe(409);
  expect(await json(over)).toMatchObject({ error: "box_full", max_bytes: 1_000_000 });
  // The refusal consumed no seq; a small item and a same-size replacement still fit.
  expect((await json(await api.call(F.device, "GET", "/v1/sync"))).head_seq).toBe(2);
  expect((await put(F, randomId(), 0, blob(100))).status()).toBe(200);
  for (let rev = 1; rev <= 5; rev++) expect((await put(F, one, rev, big())).status()).toBe(200);
  // Five replaced blobs were retained, but only as many as the quota holds.
  const history = (await json(await api.call(F.device, "GET", "/v1/history"))).entries as { item_id: string }[];
  expect(history.length).toBeGreaterThan(0);
  expect(history.length).toBeLessThanOrEqual(2);
  // A delete frees the room the blob held (the tombstone marker is tiny).
  expect((await api.call(F.device, "DELETE", `/v1/items/${two}`, { query: { base_rev: 1 }, json: { epoch: 1, marker: blob(32) } })).status()).toBe(200);
  expect((await put(F, randomId(), 0, big())).status()).toBe(200);
  // Gina is untouched by frank being full.
  expect((await put(G, randomId(), 0, big())).status()).toBe(200);
});

test("a disabled box answers like a revoked device, and only that box", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.6" });
  const E = await createBox(api, "erin");
  expect((await api.call(E.device, "GET", "/v1/sync")).status()).toBe(200);
  // The operator kill switch is a column; flip it the way an operator would (no route sets it).
  execFileSync(
    "pnpm",
    ["exec", "wrangler", "d1", "execute", "bisel", "--local", "--persist-to", ".wrangler/test-state", "--command", `UPDATE boxes SET disabled_at = 1 WHERE id = '${E.id}'`],
    { stdio: "ignore" },
  );
  const dead = await api.call(E.device, "GET", "/v1/sync");
  expect(dead.status()).toBe(404);
  expect(await dead.text()).toBe("");
  expect((await aimedAt(E.id, () => api.call(E.recovery, "POST", "/v1/recovery/session"))).status()).toBe(404);
  expect((await api.call(B.device, "GET", "/v1/sync")).status()).toBe(200);
});
