import { expect, test, type APIResponse } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { TEST_BOOTSTRAP_TOKEN } from "../playwright.config";
import { b64u, Bisel, newDevice, prepare, randomId, randomX25519Pub, recoveryKeyFromSeed, type TestDevice } from "./support/client";

// One story against one database. Each step depends on the state the previous ones left behind.
test.describe.configure({ mode: "serial" });

const blob = (n = 600) => b64u(randomBytes(n));
const recoveryEnvelope = b64u(randomBytes(60));

let a: TestDevice; // first device, created by bootstrap
let b: TestDevice; // second device, approved by a
let c: TestDevice; // replacement device registered through recovery
let recovery: Awaited<ReturnType<typeof recoveryKeyFromSeed>>;
let recoveryEncPub: string;
let headSeq = 0;
/** Current vault-key epoch as the clients know it; moves with each rotation. */
let epoch = 1;
const item1 = randomId();
const item2 = randomId();
const blob1 = blob();
const blob1b = blob();

const json = async (res: APIResponse) => (await res.json()) as any;

/** PUT an item the way a current client does: base_rev + the epoch of the VK it wrapped the key under. */
const putBody = (base_rev: number, blobValue: string, e = epoch) => ({ base_rev, epoch: e, blob: blobValue });

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
  recoveryEncPub = await randomX25519Pub();
  const body = { device: a.registration(), recovery_pubkey: recovery.pub, recovery_enc_pubkey: recoveryEncPub, recovery_envelope: recoveryEnvelope };

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
  const created = await api.call(a, "PUT", `/v1/items/${item1}`, { json: putBody(0, blob1) });
  expect(created.status()).toBe(200);
  expect((await json(created)).item).toMatchObject({ id: item1, rev: 1, seq: 1, deleted: false, blob: blob1 });

  const edited = await api.call(a, "PUT", `/v1/items/${item1}`, { json: putBody(1, blob1b) });
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
  const stale = await api.call(a, "PUT", `/v1/items/${item1}`, { json: putBody(1, blob()) });
  expect(stale.status()).toBe(409);
  expect((await json(stale)).current).toMatchObject({ id: item1, rev: 2, seq: 2, blob: blob1b });

  // Creating an id that already exists is the same conflict.
  const dup = await api.call(a, "PUT", `/v1/items/${item1}`, { json: putBody(0, blob()) });
  expect(dup.status()).toBe(409);

  // Editing something that never existed is a conflict too, with nothing to show.
  const ghost = await api.call(a, "PUT", `/v1/items/${randomId()}`, { json: putBody(3, blob()) });
  expect(ghost.status()).toBe(409);
  expect((await json(ghost)).current).toBeNull();

  // The three rejected writes consumed no seq: the next real write gets head+1.
  const next = await json(await api.call(a, "PUT", `/v1/items/${item2}`, { json: putBody(0, blob()) }));
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
    Array.from({ length: 12 }, () => api.call(a, "PUT", `/v1/items/${randomId()}`, { json: putBody(0, blob(100)) })),
  );
  expect(distinct.map((r) => r.status())).toEqual(Array(12).fill(200));

  // Six writers race to create the very same id: exactly one wins, five conflict and burn nothing.
  const same = randomId();
  const race = await Promise.all(
    Array.from({ length: 6 }, () => api.call(a, "PUT", `/v1/items/${same}`, { json: putBody(0, blob(100)) })),
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
  const max = await api.call(a, "PUT", `/v1/items/${big}`, { json: putBody(0, blob(256 * 1024)) });
  expect(max.status()).toBe(200);
  headSeq += 1;
  expect((await json(max)).item.seq).toBe(headSeq);

  const over = await api.call(a, "PUT", `/v1/items/${randomId()}`, { json: putBody(0, blob(256 * 1024 + 1)) });
  expect(over.status()).toBe(413);
  const sync = await json(await api.call(a, "GET", "/v1/sync", { query: { since: headSeq } }));
  expect(sync.head_seq).toBe(headSeq);
});

test("an existing device approves a second one, which can then sync and write", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.1.0.1" });
  b = await newDevice("test-iphone", "iphone");

  // Not registered yet: its (perfectly valid) signature means nothing.
  expect((await api.call(b, "GET", "/v1/sync")).status()).toBe(404);

  const badKey = await api.call(a, "POST", "/v1/devices", { json: { ...b.registration(), epoch, sig_pubkey: b64u(randomBytes(65)) } });
  expect(badKey.status()).toBe(400);

  const approve = await api.call(a, "POST", "/v1/devices", { json: { ...b.registration(), epoch } });
  expect(approve.status()).toBe(201);
  expect((await api.call(a, "POST", "/v1/devices", { json: { ...b.registration(), epoch } })).status()).toBe(409);

  const sync = await json(await api.call(b, "GET", "/v1/sync", { query: { since: 0, limit: 500 } }));
  expect(sync.head_seq).toBe(headSeq);
  expect(sync.devices.map((d: any) => d.id).sort()).toEqual([a.id, b.id].sort());
  expect((await json(await api.call(b, "GET", "/v1/envelope"))).envelope).toBe(b.envelope);

  const put = await api.call(b, "PUT", `/v1/items/${item1}`, { json: putBody(2, blob()) });
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
    const res = await api.call(b, method, path, method === "PUT" ? { json: putBody(3, blob()) } : {});
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
  const putReq = await prepare(a, "PUT", `/v1/items/${randomId()}`, { json: putBody(0, blob(50)) });
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
  const s2 = await api.call(recovery, "POST", "/v1/recovery/session", { json: { device: c.registration(), epoch } });
  expect(s2.status()).toBe(200);

  // The replacement device is a normal device now and sees everything.
  const sync = await json(await api.call(c, "GET", "/v1/sync", { query: { since: 0, limit: 500 } }));
  expect(sync.head_seq).toBe(headSeq);
  expect(sync.items.some((i: any) => i.id === item1 && i.rev === 3)).toBe(true);

  // Rotate with a device signature; the old recovery key dies, the new one works.
  const next = await recoveryKeyFromSeed(randomBytes(32));
  const nextEnvelope = b64u(randomBytes(60));
  const nextEnc = await randomX25519Pub();
  const rot = await api.call(c, "POST", "/v1/recovery/rotate", {
    json: { recovery_pubkey: next.pub, recovery_enc_pubkey: nextEnc, recovery_envelope: nextEnvelope, epoch },
  });
  expect(rot.status()).toBe(200);
  expect((await api.call(recovery, "POST", "/v1/recovery/session")).status()).toBe(404);
  const s3 = await api.call(next, "POST", "/v1/recovery/session");
  expect(s3.status()).toBe(200);
  expect((await json(s3)).recovery_envelope).toBe(nextEnvelope);
  const after = (await json(await api.call(c, "GET", "/v1/sync"))).recovery;
  expect(after).toMatchObject({ pubkey: next.pub, enc_pubkey: nextEnc, envelope: nextEnvelope });
  recovery = next;
  recoveryEncPub = nextEnc;
});

// ---------------------------------------------------------------------------------------------
// vault-key rotation

/** What a client sees of the server: every live item, the active devices, epoch and head_seq. */
async function snapshot(api: Bisel, who: TestDevice) {
  const items: any[] = [];
  let since = 0;
  let last: any;
  for (;;) {
    last = await json(await api.call(who, "GET", "/v1/sync", { query: { since, limit: 500 } }));
    items.push(...last.items);
    since = last.next_since;
    if (!last.has_more) break;
  }
  return {
    items,
    live: items.filter((i) => !i.deleted),
    devices: (last.devices as any[]).filter((d) => d.revoked_at == null),
    allDevices: last.devices as any[],
    epoch: last.epoch as number,
    headSeq: last.head_seq as number,
    recovery: last.recovery,
  };
}

const newKey = () => b64u(randomBytes(60)); // a wrapped item key is nonce(12) + key(32) + tag(16)

/** Builds the POST /v1/rotate body a client would send for `snap`, with fresh keys/envelopes. */
function rotation(snap: Awaited<ReturnType<typeof snapshot>>, opts: { revoke?: string | null; keep?: string[] } = {}) {
  const keep = opts.keep ?? snap.devices.map((d) => d.id).filter((id) => id !== opts.revoke);
  const keys = new Map(snap.live.map((i) => [i.id as string, newKey()]));
  const envelopes = new Map(keep.map((id) => [id, b64u(randomBytes(125))]));
  const body = {
    base_epoch: snap.epoch,
    base_seq: snap.headSeq,
    revoke: opts.revoke ?? null,
    items: snap.live.map((i) => ({ id: i.id, rev: i.rev, key: keys.get(i.id)! })),
    devices: keep.map((id) => ({ id, envelope: envelopes.get(id)! })),
    recovery_envelope: b64u(randomBytes(60)),
  };
  return { body, keys, envelopes };
}

test("rotation without a revoke: wrapped keys are swapped, payload bytes, revs and tombstones are not", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.3.0.1" });
  const before = await snapshot(api, a);
  expect(before.epoch).toBe(1);
  const activeIds = before.devices.map((d) => d.id).sort();
  expect(activeIds).toEqual([a.id, c.id].sort());

  const rot = rotation(before);
  const res = await api.call(a, "POST", "/v1/rotate", { json: rot.body });
  expect(res.status()).toBe(200);
  expect(await json(res)).toMatchObject({ epoch: 2, rotated_items: before.live.length, revoked: null });

  const after = await snapshot(api, c);
  expect(after.epoch).toBe(2);
  expect(after.headSeq).toBe(before.headSeq + before.live.length);
  expect(after.live).toHaveLength(before.live.length);
  const oldById = new Map(before.live.map((i) => [i.id, i]));
  for (const item of after.live) {
    const old = oldById.get(item.id)!;
    expect(item.blob.slice(0, 80), "wrapped key replaced").toBe(rot.keys.get(item.id));
    expect(item.blob.slice(80), "payload ciphertext untouched").toBe(old.blob.slice(80));
    expect(item.rev, "rev unchanged: it is bound into the AAD").toBe(old.rev);
    expect(item.seq, "fresh seq so other devices re-pull it").toBeGreaterThan(before.headSeq);
  }
  // Tombstones were not touched, seqs stay unique and gapless at the top.
  expect(after.items.filter((i) => i.deleted).map((i) => [i.id, i.seq])).toEqual(
    before.items.filter((i) => i.deleted).map((i) => [i.id, i.seq]),
  );
  const seqs = after.live.map((i) => i.seq).sort((x, y) => x - y);
  expect(seqs.slice(-before.live.length)).toEqual(Array.from({ length: before.live.length }, (_, k) => before.headSeq + 1 + k));

  // Every active device got its new envelope at the new epoch; the recovery envelope moved too.
  for (const d of [a, c]) {
    const env = await json(await api.call(d, "GET", "/v1/envelope"));
    expect(env).toMatchObject({ envelope: rot.envelopes.get(d.id), epoch: 2 });
  }
  expect(after.recovery.envelope).toBe(rot.body.recovery_envelope);
  expect(after.recovery.pubkey, "same phrase: recovery keys are untouched").toBe(before.recovery.pubkey);
  expect((await json(await api.call(recovery, "POST", "/v1/recovery/session"))).epoch).toBe(2);
  epoch = 2;
  headSeq = after.headSeq;
});

test("after a rotation, anything built from the old vault key is refused", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.3.0.2" });
  const snap = await snapshot(api, a);
  const victim = snap.live[0]!;

  // A device that has not noticed the rotation writes an item key wrapped under the old VK.
  const stalePut = await api.call(a, "PUT", `/v1/items/${victim.id}`, { json: putBody(victim.rev, blob(), 1) });
  expect(stalePut.status()).toBe(409);
  expect(await json(stalePut)).toEqual({ error: "stale_epoch", epoch: 2 });
  // ... or approves a new device with an envelope holding the old VK ...
  const late = await newDevice("late");
  const staleApprove = await api.call(a, "POST", "/v1/devices", { json: { ...late.registration(), epoch: 1 } });
  expect(staleApprove.status()).toBe(409);
  expect((await json(staleApprove)).error).toBe("stale_epoch");
  expect((await api.call(late, "GET", "/v1/sync")).status(), "nothing was registered").toBe(404);
  // ... or replaces the recovery envelope with one derived from the old VK, or registers via recovery with it.
  const staleRecRotate = await api.call(a, "POST", "/v1/recovery/rotate", {
    json: { recovery_pubkey: recovery.pub, recovery_enc_pubkey: recoveryEncPub, recovery_envelope: b64u(randomBytes(60)), epoch: 1 },
  });
  expect(staleRecRotate.status()).toBe(409);
  const staleRecover = await api.call(recovery, "POST", "/v1/recovery/session", { json: { device: late.registration(), epoch: 1 } });
  expect(staleRecover.status()).toBe(409);
  expect((await snapshot(api, a)).headSeq, "nothing was written").toBe(snap.headSeq);

  // With the current epoch the very same writes go through.
  const ok = await api.call(a, "PUT", `/v1/items/${victim.id}`, { json: putBody(victim.rev, blob()) });
  expect(ok.status()).toBe(200);
  headSeq = (await json(ok)).item.seq;
});

test("rotation is refused, and changes nothing, when anything moved since the snapshot", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.3.0.3" });
  const base = await snapshot(api, a);
  const attempt = async (body: unknown, who: TestDevice = a) => api.call(who, "POST", "/v1/rotate", { json: body });
  const expectUnchanged = async (label: string) => {
    const now = await snapshot(api, a);
    expect(now.epoch, label).toBe(base.epoch);
    expect(now.headSeq, label).toBe(base.headSeq);
    expect(now.live.map((i) => [i.id, i.blob, i.seq]), label).toEqual(base.live.map((i) => [i.id, i.blob, i.seq]));
    expect(now.allDevices.map((d) => [d.id, d.revoked_at]), label).toEqual(base.allDevices.map((d) => [d.id, d.revoked_at]));
    expect((await json(await api.call(a, "GET", "/v1/envelope"))).envelope, label).toBe(
      (await json(await api.call(a, "GET", "/v1/envelope"))).envelope,
    );
  };
  const good = rotation(base);

  // A concurrent edit: another device wrote an item after the snapshot was taken.
  const edited = await api.call(c, "PUT", `/v1/items/${base.live[0]!.id}`, { json: putBody(base.live[0]!.rev, blob()) });
  expect(edited.status()).toBe(200);
  const racing = await attempt(good.body);
  expect(racing.status()).toBe(409);
  expect(await json(racing)).toMatchObject({ error: "conflict", epoch: 2 });

  // From here on use a fresh snapshot, and break one property of it at a time.
  const fresh = await snapshot(api, a);
  Object.assign(base, fresh);
  const clean = () => rotation(fresh);

  const wrongRev = clean();
  wrongRev.body.items[0]!.rev += 1;
  expect((await attempt(wrongRev.body)).status(), "item at another rev").toBe(409);

  const missingItem = clean();
  missingItem.body.items.pop();
  expect((await attempt(missingItem.body)).status(), "an item left out").toBe(409);

  const unknownItem = clean();
  unknownItem.body.items.push({ id: randomId(), rev: 1, key: newKey() });
  expect((await attempt(unknownItem.body)).status(), "an item that does not exist").toBe(409);

  const tombstoned = clean();
  const dead = fresh.items.find((i) => i.deleted)!;
  tombstoned.body.items.push({ id: dead.id, rev: dead.rev, key: newKey() });
  expect((await attempt(tombstoned.body)).status(), "a deleted item").toBe(409);

  const missingDevice = clean();
  missingDevice.body.devices = missingDevice.body.devices.filter((d) => d.id === a.id);
  expect((await attempt(missingDevice.body)).status(), "an active device without a new envelope").toBe(409);

  const strangerDevice = clean();
  strangerDevice.body.devices.push({ id: randomId(), envelope: b64u(randomBytes(125)) });
  expect((await attempt(strangerDevice.body)).status(), "an envelope for a device that does not exist").toBe(409);

  const revokedDevice = clean();
  revokedDevice.body.devices.push({ id: b.id, envelope: b64u(randomBytes(125)) });
  expect((await attempt(revokedDevice.body)).status(), "an envelope for an already revoked device").toBe(409);

  const staleEpoch = clean();
  staleEpoch.body.base_epoch = 1;
  expect((await attempt(staleEpoch.body)).status(), "stale epoch").toBe(409);

  const revokeRevoked = rotation(fresh, { revoke: b.id, keep: [a.id, c.id] });
  expect((await attempt(revokeRevoked.body)).status(), "revoking a device that is already revoked").toBe(409);
  const revokeUnknown = rotation(fresh, { revoke: randomId(), keep: [a.id, c.id] });
  expect((await attempt(revokeUnknown.body)).status(), "revoking a device that does not exist").toBe(409);

  // Malformed shapes never reach the database: 400, not 409.
  for (const [label, mutate] of [
    ["unknown field", (x: any) => (x.extra = 1)],
    ["short wrapped key", (x: any) => (x.items[0].key = x.items[0].key.slice(1))],
    ["padded base64", (x: any) => (x.items[0].key = x.items[0].key.slice(0, 78) + "==")],
    ["duplicate item", (x: any) => x.items.push({ ...x.items[0] })],
    ["duplicate device", (x: any) => x.devices.push({ ...x.devices[0] })],
    ["no devices", (x: any) => (x.devices = [])],
    ["caller not among the devices", (x: any) => (x.devices = x.devices.filter((d: any) => d.id !== a.id))],
    ["self revoke", (x: any) => (x.revoke = a.id)],
    ["revoked device also gets an envelope", (x: any) => (x.revoke = c.id)],
    ["fractional epoch", (x: any) => (x.base_epoch = 1.5)],
  ] as const) {
    const x = clean();
    mutate(x.body);
    expect((await attempt(x.body)).status(), label).toBe(400);
  }

  await expectUnchanged("no rejected rotation left a trace");
});

test("two rotations racing from the same snapshot: exactly one wins", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.3.0.4" });
  const snap = await snapshot(api, a);
  const attempts = [rotation(snap), rotation(snap), rotation(snap)];
  const results = await Promise.all(attempts.map((r, k) => api.call(k % 2 ? c : a, "POST", "/v1/rotate", { json: r.body })));
  expect(results.map((r) => r.status()).sort()).toEqual([200, 409, 409]);
  const winner = attempts[results.findIndex((r) => r.status() === 200)]!;

  const after = await snapshot(api, a);
  expect(after.epoch).toBe(snap.epoch + 1);
  expect(after.headSeq).toBe(snap.headSeq + snap.live.length);
  for (const item of after.live) expect(item.blob.slice(0, 80)).toBe(winner.keys.get(item.id));
  epoch = after.epoch;
  headSeq = after.headSeq;
});

test("rotating while revoking a device cuts it off in the same transaction", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.3.0.5" });
  const d = await newDevice("test-ipad", "ipad");
  const approve = await api.call(a, "POST", "/v1/devices", { json: { ...d.registration(), epoch } });
  expect(approve.status()).toBe(201);
  expect((await api.call(d, "GET", "/v1/sync")).status()).toBe(200);

  const snap = await snapshot(api, a);
  expect(snap.devices.map((x) => x.id).sort()).toEqual([a.id, c.id, d.id].sort());
  const rot = rotation(snap, { revoke: d.id });
  expect(rot.body.devices.map((x) => x.id)).not.toContain(d.id);
  const res = await api.call(a, "POST", "/v1/rotate", { json: rot.body });
  expect(res.status()).toBe(200);
  expect(await json(res)).toMatchObject({ epoch: epoch + 1, revoked: d.id });

  // The revoked device is out at once, every route, and sees nothing of the new material.
  for (const [method, path] of [["GET", "/v1/sync"], ["GET", "/v1/envelope"], ["GET", "/v1/devices"]] as const) {
    const r = await api.call(d, method, path);
    expect(r.status(), `${method} ${path}`).toBe(404);
    expect(await r.text()).toBe("");
  }
  expect((await api.call(d, "PUT", `/v1/items/${snap.live[0]!.id}`, { json: putBody(snap.live[0]!.rev, blob(), epoch + 1) })).status()).toBe(404);
  const after = await snapshot(api, a);
  const gone = after.allDevices.find((x) => x.id === d.id);
  expect(gone.revoked_at).toBeGreaterThan(0);
  expect(after.devices.map((x) => x.id).sort()).toEqual([a.id, c.id].sort());
  for (const survivor of [a, c]) {
    expect(await json(await api.call(survivor, "GET", "/v1/envelope"))).toMatchObject({ envelope: rot.envelopes.get(survivor.id), epoch: epoch + 1 });
  }
  epoch += 1;
  headSeq = after.headSeq;

  // A rotation can also be an empty vault's: zero items is a valid snapshot.
  // (Covered by the Swift flows; here the item set is non-empty.)
});

// ---------------------------------------------------------------------------------------------
// hardening

test("every body and query is validated strictly", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.4.0.1" });
  const id = randomId();
  const cases: [string, Promise<APIResponse>, number][] = [
    ["unknown field in PUT body", api.call(a, "PUT", `/v1/items/${id}`, { json: { ...putBody(0, blob()), admin: true } }), 400],
    ["missing epoch in PUT body", api.call(a, "PUT", `/v1/items/${id}`, { json: { base_rev: 0, blob: blob() } }), 400],
    ["negative base_rev", api.call(a, "PUT", `/v1/items/${id}`, { json: putBody(-1, blob()) }), 400],
    ["float epoch", api.call(a, "PUT", `/v1/items/${id}`, { json: putBody(0, blob(), 1.5) }), 400],
    ["padded blob", api.call(a, "PUT", `/v1/items/${id}`, { json: putBody(0, blob(50) + "==") }), 400],
    ["non-JSON body", api.call(a, "PUT", `/v1/items/${id}`, { rawBody: Buffer.from("not json") }), 400],
    ["JSON array body", api.call(a, "PUT", `/v1/items/${id}`, { json: [] }), 400],
    ["__proto__ key", api.call(a, "PUT", `/v1/items/${id}`, { rawBody: Buffer.from(`{"__proto__":{"x":1},"base_rev":0,"epoch":${epoch},"blob":"AAAA"}`) }), 400],
    ["bad item id", api.call(a, "PUT", "/v1/items/short", { json: putBody(0, blob()) }), 400],
    ["query on a PUT", api.call(a, "PUT", `/v1/items/${id}`, { query: { x: 1 }, json: putBody(0, blob()) }), 400],
    ["unknown sync param", api.call(a, "GET", "/v1/sync", { query: { since: 0, debug: 1 } }), 400],
    ["non-numeric since", api.call(a, "GET", "/v1/sync", { query: { since: "abc" } }), 400],
    ["limit 0", api.call(a, "GET", "/v1/sync", { query: { limit: 0 } }), 400],
    ["limit 501", api.call(a, "GET", "/v1/sync", { query: { limit: 501 } }), 400],
    ["body on GET", api.call(a, "GET", "/v1/sync", { json: {} }), 400],
    ["body on DELETE", api.call(a, "DELETE", `/v1/devices/${randomId()}`, { json: {} }), 400],
    ["delete without base_rev", api.call(a, "DELETE", `/v1/items/${id}`), 400],
    ["device with extra field", api.call(a, "POST", "/v1/devices", { json: { ...(await newDevice("x")).registration(), epoch, role: "admin" } }), 400],
    ["device name too long", api.call(a, "POST", "/v1/devices", { json: { ...(await newDevice("x".repeat(101))).registration(), epoch } }), 400],
  ];
  for (const [label, res, status] of cases) expect((await res).status(), label).toBe(status);

  // A repeated query parameter is ambiguous, so it is refused rather than guessed at.
  const dup = await prepare(a, "GET", "/v1/sync", { query: { since: 0 } });
  const dupRes = await api.api.fetch("/v1/sync?since=0&since=1", { headers: { ...dup.headers, "CF-Connecting-IP": "10.4.0.1" } });
  expect(dupRes.status()).toBe(404); // the signature covers one `since`; a smuggled second one fails authentication
});

test("body size limits: over 4 MiB is the bare 404; per-route limits answer the owner with 413", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.4.0.2" });
  const huge = await api.call(a, "PUT", `/v1/items/${randomId()}`, { rawBody: Buffer.alloc(4 * 1024 * 1024 + 1, 0x61) });
  expect(huge.status()).toBe(404);
  expect(await huge.text()).toBe("");

  const bigDevice = await api.call(a, "POST", "/v1/devices", { rawBody: Buffer.alloc(40 * 1024, 0x20) });
  expect(bigDevice.status()).toBe(413);
  const bigItem = await api.call(a, "PUT", `/v1/items/${randomId()}`, { rawBody: Buffer.alloc(401 * 1024, 0x20) });
  expect(bigItem.status()).toBe(413);
  expect(await json(bigItem)).toMatchObject({ error: "too_large" });
});

test("unknown routes, wrong methods and every kind of auth failure look identical, headers included", async ({ request }) => {
  const api = new Bisel(request, { "CF-Connecting-IP": "10.4.0.3" });
  const stranger = await newDevice("stranger");
  const responses: Record<string, APIResponse> = {
    unknownRoute: await api.api.fetch("/v1/nope", { headers: { "CF-Connecting-IP": "10.4.0.3" } }),
    root: await api.api.fetch("/", { headers: { "CF-Connecting-IP": "10.4.0.3" } }),
    wrongMethodOnRealRoute: await api.api.fetch("/v1/sync", { method: "POST", headers: { "CF-Connecting-IP": "10.4.0.3" } }),
    options: await api.api.fetch("/v1/items/" + randomId(), { method: "OPTIONS", headers: { "CF-Connecting-IP": "10.4.0.3" } }),
    badSignatureRealRoute: await api.call({ ...stranger, id: a.id }, "GET", "/v1/sync"),
    badSignatureUnknownRoute: await api.call({ ...stranger, id: a.id }, "GET", "/v1/nope"),
    validSignatureUnknownRoute: await api.call(a, "GET", "/v1/nope"),
    validSignatureWrongMethod: await api.call(a, "POST", "/v1/sync"),
    bootstrapGet: await api.api.fetch("/v1/bootstrap", { headers: { "CF-Connecting-IP": "10.4.0.3" } }),
    bootstrapWrongToken: await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": "wrong" }, {}),
    bootstrapRightTokenAlreadyDone: await api.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, {}),
    recoveryWrongKey: await api.call(await recoveryKeyFromSeed(randomBytes(32)), "POST", "/v1/recovery/session"),
  };
  const reference = await fingerprint(responses.unknownRoute!);
  expect(reference.status).toBe(404);
  expect(reference.body).toBe("");
  for (const [name, res] of Object.entries(responses)) {
    const fp = await fingerprint(res);
    expect(fp, name).toEqual(reference);
  }

  // HEAD has no body by definition, so it is compared with a HEAD to a route that does not exist.
  const headReal = await fingerprint(await api.api.fetch("/v1/sync", { method: "HEAD", headers: { "CF-Connecting-IP": "10.4.0.3" } }));
  const headFake = await fingerprint(await api.api.fetch("/v1/nope", { method: "HEAD", headers: { "CF-Connecting-IP": "10.4.0.3" } }));
  expect(headReal.status).toBe(404);
  expect(headReal).toEqual(headFake);

  // The hardening headers are on the 404 too, and the cache is told to keep nothing.
  const h = Object.fromEntries(reference.headers);
  expect(h["cache-control"]).toBe("no-store");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBe("no-referrer");
  expect(h["content-security-policy"]).toContain("default-src 'none'");
  expect(h["strict-transport-security"]).toContain("max-age=");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["cross-origin-resource-policy"]).toBe("same-origin");
  expect(h["server"], "no server banner").toBeUndefined();
  expect(h["x-powered-by"]).toBeUndefined();

  // Authenticated answers carry the same headers.
  const ok = await api.call(a, "GET", "/v1/sync");
  expect(ok.status()).toBe(200);
  expect(ok.headers()["cache-control"]).toBe("no-store");
  expect(ok.headers()["x-content-type-options"]).toBe("nosniff");
});

test("failed-auth backoff: it slows the offender, never locks out a valid signature", async ({ request }) => {
  const attacker = new Bisel(request, { "CF-Connecting-IP": "10.66.0.1" });
  const elsewhere = new Bisel(request, { "CF-Connecting-IP": "10.66.0.2" });
  const stranger = await newDevice("stranger");
  const timed = async (go: () => Promise<APIResponse>) => {
    const t0 = performance.now();
    const res = await go();
    return { status: res.status(), ms: performance.now() - t0 };
  };

  expect((await attacker.call(a, "GET", "/v1/sync")).status()).toBe(200);

  // The first 19 failures are answered at full speed.
  for (let i = 0; i < 19; i++) expect((await attacker.call({ ...stranger, id: a.id }, "GET", "/v1/sync")).status()).toBe(404);

  // From the 20th on, failing requests from this address are delayed (AUTH_BACKOFF_MS=400 in the test server) ...
  for (let i = 0; i < 3; i++) {
    const slow = await timed(() => attacker.call({ ...stranger, id: a.id }, "GET", "/v1/sync"));
    expect(slow.status).toBe(404);
    expect(slow.ms).toBeGreaterThan(350);
  }
  // ... for every kind of failure, unknown routes included, so the delay says nothing about what exists.
  const slowUnknown = await timed(() => attacker.call(stranger, "GET", "/v1/nope"));
  expect(slowUnknown.status).toBe(404);
  expect(slowUnknown.ms).toBeGreaterThan(350);

  // The owner's valid, signed requests from that very address are still served, promptly, however long the offender keeps going.
  for (let i = 0; i < 5; i++) {
    const good = await timed(() => attacker.call(a, "GET", "/v1/sync"));
    expect(good.status).toBe(200);
    expect(good.ms).toBeLessThan(350);
  }
  // Other addresses never noticed.
  const fine = await timed(() => elsewhere.call({ ...stranger, id: a.id }, "GET", "/v1/sync"));
  expect(fine.status).toBe(404);
  expect(fine.ms).toBeLessThan(350);
  expect((await elsewhere.call(a, "GET", "/v1/sync")).status()).toBe(200);

  // A correct bootstrap token is not delayed either (it is just refused: this vault exists).
  const refused = await timed(() => attacker.raw("POST", "/v1/bootstrap", { "X-Bisel-Bootstrap": TEST_BOOTSTRAP_TOKEN }, {}));
  expect(refused.status).toBe(404);
  expect(refused.ms).toBeLessThan(350);
});
