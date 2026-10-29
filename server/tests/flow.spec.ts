import { expect, test, type APIResponse } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { TEST_BOOTSTRAP_TOKEN } from "../playwright.config";
import { b64u, Bisel, newDevice, prepare, randomId, recoveryKeyFromSeed, type TestDevice } from "./support/client";

// One story against one database. Each step depends on the state the previous ones left behind.
test.describe.configure({ mode: "serial" });

const blob = (n = 600) => b64u(randomBytes(n));
const recoveryEnvelope = b64u(randomBytes(60));

let a: TestDevice; // first device, created by bootstrap
let b: TestDevice; // second device, approved by a
let c: TestDevice; // replacement device registered through recovery
let recovery: Awaited<ReturnType<typeof recoveryKeyFromSeed>>;
let headSeq = 0;
const item1 = randomId();
const item2 = randomId();
const blob1 = blob();
const blob1b = blob();

const json = async (res: APIResponse) => (await res.json()) as any;

/** Everything a caller could use to tell two responses apart, except the clock. */
async function fingerprint(res: APIResponse) {
  const headers = Object.entries(res.headers())
    .filter(([k]) => k !== "date")
    .sort(([x], [y]) => x.localeCompare(y));
  return { status: res.status(), body: (await res.body()).toString("utf8"), headers };
}

test("bootstrap is one-time and guarded by the secret", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  a = await newDevice("test-mac");
  recovery = await recoveryKeyFromSeed(randomBytes(32));
  const body = { device: a.registration(), recovery_pubkey: recovery.pub, recovery_envelope: recoveryEnvelope };

  const wrong = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": "nope" }, body);
  expect(wrong.status()).toBe(404);
  expect(await wrong.text()).toBe("");
  expect((await api.raw("POST", "/v1/bootstrap", {}, body)).status()).toBe(404);

  // Not yet bootstrapped: the device that is about to exist cannot do anything.
  expect((await api.call(a, "GET", "/v1/sync")).status()).toBe(404);

  const ok = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, body);
  expect(ok.status()).toBe(201);

  // After success the endpoint always 404s, even with the right secret.
  const again = await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, {
    ...body,
    device: (await newDevice("intruder")).registration(),
  });
  expect(again.status()).toBe(404);
  expect(await again.text()).toBe("");
});

test("first device syncs an empty vault and reads back its own envelope", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const res = await api.call(a, "GET", "/v1/sync", { query: { since: 0 } });
  expect(res.status()).toBe(200);
  const sync = await json(res);
  expect(sync.items).toEqual([]);
  expect(sync.head_seq).toBe(0);
  expect(sync.devices.map((d: any) => d.id)).toEqual([a.id]);
  expect(sync.recovery.pubkey).toBe(recovery.pub);
  expect(sync.recovery.envelope).toBe(recoveryEnvelope);

  const env = await json(await api.call(a, "GET", "/v1/envelope"));
  expect(env.envelope).toBe(a.envelope);
});

test("create and edit an item; sync is incremental", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const created = await api.call(a, "PUT", `/v1/items/${item1}`, { json: { base_rev: 0, blob: blob1 } });
  expect(created.status()).toBe(200);
  expect((await json(created)).item).toMatchObject({ id: item1, rev: 1, seq: 1, deleted: false, blob: blob1 });

  const edited = await api.call(a, "PUT", `/v1/items/${item1}`, { json: { base_rev: 1, blob: blob1b } });
  expect(edited.status()).toBe(200);
  expect((await json(edited)).item).toMatchObject({ rev: 2, seq: 2, blob: blob1b });

  const full = await json(await api.call(a, "GET", "/v1/sync", { query: { since: 0 } }));
  expect(full.items).toHaveLength(1); // one record per item: the latest revision, at its newest seq
  expect(full.items[0]).toMatchObject({ id: item1, rev: 2, seq: 2, blob: blob1b });
  expect(full.head_seq).toBe(2);

  const none = await json(await api.call(a, "GET", "/v1/sync", { query: { since: 2 } }));
  expect(none.items).toEqual([]);
  headSeq = 2;
});

test("stale base_rev conflicts, returns the current record, and leaves no gap in seq", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const stale = await api.call(a, "PUT", `/v1/items/${item1}`, { json: { base_rev: 1, blob: blob() } });
  expect(stale.status()).toBe(409);
  expect((await json(stale)).current).toMatchObject({ id: item1, rev: 2, seq: 2, blob: blob1b });

  // Creating an id that already exists is the same conflict.
  const dup = await api.call(a, "PUT", `/v1/items/${item1}`, { json: { base_rev: 0, blob: blob() } });
  expect(dup.status()).toBe(409);

  // Editing something that never existed is a conflict too, with nothing to show.
  const ghost = await api.call(a, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 3, blob: blob() } });
  expect(ghost.status()).toBe(409);
  expect((await json(ghost)).current).toBeNull();

  // The three rejected writes consumed no seq: the next real write gets head+1.
  const next = await json(await api.call(a, "PUT", `/v1/items/${item2}`, { json: { base_rev: 0, blob: blob() } }));
  expect(next.item.seq).toBe(headSeq + 1);
  headSeq += 1;
});

test("delete leaves a tombstone that syncs, and is itself revision-checked", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const staleDel = await api.call(a, "DELETE", `/v1/items/${item2}`, { query: { base_rev: 5 } });
  expect(staleDel.status()).toBe(409);
  expect((await json(staleDel)).current).toMatchObject({ rev: 1, deleted: false });

  const del = await api.call(a, "DELETE", `/v1/items/${item2}`, { query: { base_rev: 1 } });
  expect(del.status()).toBe(200);
  expect((await json(del)).item).toMatchObject({ id: item2, rev: 2, seq: headSeq + 1, deleted: true, blob: "" });
  headSeq += 1;

  const sync = await json(await api.call(a, "GET", "/v1/sync", { query: { since: headSeq - 1 } }));
  expect(sync.items).toHaveLength(1);
  expect(sync.items[0]).toMatchObject({ id: item2, deleted: true, seq: headSeq });

  // Deleting twice does not mint another revision.
  const twice = await api.call(a, "DELETE", `/v1/items/${item2}`, { query: { base_rev: 2 } });
  expect(twice.status()).toBe(409);
  expect((await json(await api.call(a, "GET", "/v1/sync", { query: { since: 0 } }))).head_seq).toBe(headSeq);
});

test("concurrent writers still produce a gapless, duplicate-free seq log", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const before = headSeq;

  const distinct = await Promise.all(
    Array.from({ length: 12 }, () => api.call(a, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, blob: blob(100) } })),
  );
  expect(distinct.map((r) => r.status())).toEqual(Array(12).fill(200));

  // Six writers race to create the very same id: exactly one wins, five conflict and burn nothing.
  const same = randomId();
  const race = await Promise.all(
    Array.from({ length: 6 }, () => api.call(a, "PUT", `/v1/items/${same}`, { json: { base_rev: 0, blob: blob(100) } })),
  );
  expect(race.filter((r) => r.status() === 200)).toHaveLength(1);
  expect(race.filter((r) => r.status() === 409)).toHaveLength(5);

  headSeq = before + 13;
  const collected: number[] = [];
  let since = 0;
  for (let page = 0; page < 20; page++) {
    const s = await json(await api.call(a, "GET", "/v1/sync", { query: { since, limit: 4 } }));
    expect(s.head_seq).toBe(headSeq);
    collected.push(...s.items.map((i: any) => i.seq));
    since = s.next_since;
    if (!s.has_more) break;
  }
  // item1 (seq 2), the deleted item2 (seq 4) and the 13 new items: 15 records, strictly ascending,
  // and together with the superseded seqs 1 and 3 every number 1..head is accounted for exactly once.
  expect(collected).toHaveLength(15);
  expect([...collected].sort((x, y) => x - y)).toEqual(collected);
  expect(new Set(collected).size).toBe(collected.length);
  expect(collected.at(-1)).toBe(headSeq);
  expect(collected.slice(2)).toEqual(Array.from({ length: 13 }, (_, i) => before + 1 + i));
});

test("blob size limit: 256 KiB passes, one byte more is refused without consuming a seq", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  const big = randomId();
  const max = await api.call(a, "PUT", `/v1/items/${big}`, { json: { base_rev: 0, blob: blob(256 * 1024) } });
  expect(max.status()).toBe(200);
  headSeq += 1;
  expect((await json(max)).item.seq).toBe(headSeq);

  const over = await api.call(a, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, blob: blob(256 * 1024 + 1) } });
  expect(over.status()).toBe(413);
  const sync = await json(await api.call(a, "GET", "/v1/sync", { query: { since: headSeq } }));
  expect(sync.head_seq).toBe(headSeq);
});

test("an existing device approves a second one, which can then sync and write", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  b = await newDevice("test-iphone", "iphone");

  // Not registered yet: its (perfectly valid) signature means nothing.
  expect((await api.call(b, "GET", "/v1/sync")).status()).toBe(404);

  const badKey = await api.call(a, "POST", "/v1/devices", { json: { ...b.registration(), sig_pubkey: b64u(randomBytes(65)) } });
  expect(badKey.status()).toBe(400);

  const approve = await api.call(a, "POST", "/v1/devices", { json: b.registration() });
  expect(approve.status()).toBe(201);
  expect((await api.call(a, "POST", "/v1/devices", { json: b.registration() })).status()).toBe(409);

  const sync = await json(await api.call(b, "GET", "/v1/sync", { query: { since: 0, limit: 500 } }));
  expect(sync.head_seq).toBe(headSeq);
  expect(sync.devices.map((d: any) => d.id).sort()).toEqual([a.id, b.id].sort());
  expect((await json(await api.call(b, "GET", "/v1/envelope"))).envelope).toBe(b.envelope);

  const put = await api.call(b, "PUT", `/v1/items/${item1}`, { json: { base_rev: 2, blob: blob() } });
  expect(put.status()).toBe(200);
  headSeq += 1;
  expect((await json(put)).item).toMatchObject({ rev: 3, seq: headSeq });
});

test("revoking a device makes its very next request 404, and only its requests", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  expect((await api.call(b, "GET", "/v1/sync")).status()).toBe(200);

  const revoke = await api.call(a, "DELETE", `/v1/devices/${b.id}`);
  expect(revoke.status()).toBe(200);

  for (const [method, path] of [
    ["GET", "/v1/sync"],
    ["GET", "/v1/envelope"],
    ["GET", "/v1/devices"],
    ["PUT", `/v1/items/${item1}`],
  ] as const) {
    const res = await api.call(b, method, path, method === "PUT" ? { json: { base_rev: 3, blob: blob() } } : {});
    expect(res.status(), `${method} ${path}`).toBe(404);
    expect(await res.text()).toBe("");
  }
  // The rejected PUT must not have been applied.
  const sync = await json(await api.call(a, "GET", "/v1/sync", { query: { since: 0, limit: 500 } }));
  expect(sync.head_seq).toBe(headSeq);
  const dev = sync.devices.find((d: any) => d.id === b.id);
  expect(dev.revoked_at).toBeGreaterThan(0);
  expect(sync.devices.find((d: any) => d.id === a.id).revoked_at).toBeNull();
});

test("authentication failures are indistinguishable from an unknown route", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.9.0.1" });
  const now = Math.floor(Date.now() / 1000);
  const path = "/v1/sync";

  // Control: the same request, correctly signed, works.
  const control = await prepare(a, "GET", path, { query: { since: 0 } });
  expect((await api.send(control)).status()).toBe(200);

  const failures: Record<string, APIResponse> = {};

  // Replay: the exact same signed request again.
  failures.replay = await api.send(control);

  // Bad signature: signature made by a different key.
  const stranger = await newDevice("stranger");
  const forged = await prepare({ ...stranger, id: a.id }, "GET", path, { query: { since: 0 } });
  failures.badSignature = await api.send(forged);

  // Tampering after signing: query, body, method and path are all covered by the signature.
  const q = await prepare(a, "GET", path, { query: { since: 0 } });
  failures.tamperedQuery = await api.send({ ...q, query: { since: 1 } });
  const putReq = await prepare(a, "PUT", `/v1/items/${randomId()}`, { json: { base_rev: 0, blob: blob(50) } });
  failures.tamperedBody = await api.send({ ...putReq, body: Buffer.from(JSON.stringify({ base_rev: 0, blob: blob(50) })) });
  const getReq = await prepare(a, "GET", "/v1/devices");
  failures.tamperedPath = await api.send({ ...getReq, path: "/v1/envelope" });

  // Clock skew either way, with otherwise perfect signatures.
  failures.skewPast = await api.send(await prepare(a, "GET", path, { ts: now - 120 }));
  failures.skewFuture = await api.send(await prepare(a, "GET", path, { ts: now + 120 }));
  expect((await api.send(await prepare(a, "GET", path, { ts: now - 30 }))).status()).toBe(200); // inside the window

  // Unknown device, revoked device, missing headers, and the recovery id used by a device key.
  failures.unknownDevice = await api.send(await prepare({ ...stranger, id: randomId() }, "GET", path));
  failures.revokedDevice = await api.send(await prepare(b, "GET", path));
  failures.noHeaders = await api.api.fetch(path, { headers: { "CF-Connecting-IP": "10.9.0.1" } });
  failures.deviceKeyAsRecovery = await api.send(await prepare({ ...a, id: "recovery" }, "POST", "/v1/recovery/session"));

  // And what a plain unknown route looks like.
  failures.unknownRoute = await api.api.fetch("/v1/does-not-exist", { headers: { "CF-Connecting-IP": "10.9.0.1" } });

  const reference = await fingerprint(failures.unknownRoute!);
  expect(reference.status).toBe(404);
  expect(reference.body).toBe("");
  for (const [name, res] of Object.entries(failures)) {
    expect(await fingerprint(res), name).toEqual(reference);
  }

  // The tampered PUT must not have written anything, and the replay must not have either.
  const sync = await json(await api.call(a, "GET", "/v1/sync", { query: { since: headSeq } }));
  expect(sync.items).toEqual([]);
});

test("recovery key: fetch the envelope, register a replacement device, rotate", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.2.0.1" });

  // Wrong recovery key (Ed25519 verification really rejects).
  const impostor = await recoveryKeyFromSeed(randomBytes(32));
  expect((await api.call(impostor, "POST", "/v1/recovery/session")).status()).toBe(404);

  const s1 = await api.call(recovery, "POST", "/v1/recovery/session");
  expect(s1.status()).toBe(200);
  expect(await json(s1)).toMatchObject({ recovery_envelope: recoveryEnvelope, head_seq: headSeq });

  c = await newDevice("test-mac-restored");
  const s2 = await api.call(recovery, "POST", "/v1/recovery/session", { json: { device: c.registration() } });
  expect(s2.status()).toBe(200);

  // The replacement device is a normal device now and sees everything.
  const sync = await json(await api.call(c, "GET", "/v1/sync", { query: { since: 0, limit: 500 } }));
  expect(sync.head_seq).toBe(headSeq);
  expect(sync.items.some((i: any) => i.id === item1 && i.rev === 3)).toBe(true);

  // Rotate with a device signature; the old recovery key dies, the new one works.
  const next = await recoveryKeyFromSeed(randomBytes(32));
  const nextEnvelope = b64u(randomBytes(60));
  const rot = await api.call(c, "POST", "/v1/recovery/rotate", { json: { recovery_pubkey: next.pub, recovery_envelope: nextEnvelope } });
  expect(rot.status()).toBe(200);
  expect((await api.call(recovery, "POST", "/v1/recovery/session")).status()).toBe(404);
  const s3 = await api.call(next, "POST", "/v1/recovery/session");
  expect(s3.status()).toBe(200);
  expect((await json(s3)).recovery_envelope).toBe(nextEnvelope);
  expect((await json(await api.call(c, "GET", "/v1/sync"))).recovery.pubkey).toBe(next.pub);
});

test("repeated failed auth from one IP locks that IP out, and only that IP", async ({ request }) => {
  const attacker = new Bisel(request, { "CF-Connecting-IP": "10.66.0.1" });
  const elsewhere = new Bisel(request, { "CF-Connecting-IP": "10.66.0.2" });
  const stranger = await newDevice("stranger");

  // Below the limit, a valid request from this IP still works.
  expect((await attacker.call(a, "GET", "/v1/sync")).status()).toBe(200);

  // The default budget is 20 failures per window.
  for (let i = 0; i < 20; i++) {
    expect((await attacker.call({ ...stranger, id: a.id }, "GET", "/v1/sync")).status()).toBe(404);
  }

  // Now even a perfectly valid request from that IP is refused with the same bare 404 ...
  const locked = await attacker.call(a, "GET", "/v1/sync");
  expect(locked.status()).toBe(404);
  expect(await locked.text()).toBe("");
  // ... while the same device from another address is fine.
  expect((await elsewhere.call(a, "GET", "/v1/sync")).status()).toBe(200);
});
