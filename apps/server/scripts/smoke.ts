// Manual end-to-end walk against a running `pnpm dev` (needs a fresh DB: `pnpm reset && pnpm migrate`).
//   node scripts/smoke.ts [baseUrl]
import {
  newDevice,
  prepare,
  randomId,
  randomX25519Pub,
  recoveryKeyFromSeed,
  b64u,
} from "../tests/support/client.ts";
import { randomBytes } from "node:crypto";

const base = process.argv[2] ?? "http://localhost:8787";

async function go(
  label: string,
  principal: Parameters<typeof prepare>[0],
  method: string,
  path: string,
  opts: Parameters<typeof prepare>[3] = {},
) {
  const p = await prepare(principal, method, path, opts);
  const qs = Object.keys(p.query).length
    ? "?" + new URLSearchParams(p.query as Record<string, string>)
    : "";
  const res = await fetch(base + path + qs, {
    method,
    headers: p.headers,
    body: p.body.length ? p.body : undefined,
  });
  const text = await res.text();
  console.log(`${label.padEnd(34)} ${res.status} ${text.slice(0, 150)}`);
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const a = await newDevice("smoke-mac");
const recovery = await recoveryKeyFromSeed(randomBytes(32));
let r = await fetch(base + "/v1/bootstrap", {
  method: "POST",
  headers: { "X-Bisel-Bootstrap": process.env.BOOTSTRAP_TOKEN ?? "dev-bootstrap-token" },
  body: JSON.stringify({
    device: a.registration(),
    recovery_pubkey: recovery.pub,
    recovery_enc_pubkey: await randomX25519Pub(),
    recovery_envelope: b64u(randomBytes(60)),
  }),
});
console.log("bootstrap".padEnd(34), r.status, await r.text());

const id = randomId();
const put1 = await go("put new item", a, "PUT", `/v1/items/${id}`, {
  json: { base_rev: 0, epoch: 1, blob: b64u(randomBytes(600)) },
});
await go("put stale (base_rev 0 again)", a, "PUT", `/v1/items/${id}`, {
  json: { base_rev: 0, epoch: 1, blob: b64u(randomBytes(600)) },
});
await go("put edit base_rev 1", a, "PUT", `/v1/items/${id}`, {
  json: { base_rev: 1, epoch: 1, blob: b64u(randomBytes(600)) },
});
await go("delete base_rev 2", a, "DELETE", `/v1/items/${id}`, { query: { base_rev: 2 } });
await go("sync since=0", a, "GET", "/v1/sync", { query: { since: 0 } });
await go("envelope", a, "GET", "/v1/envelope");
const b = await newDevice("smoke-iphone", "iphone");
await go("approve second device", a, "POST", "/v1/devices", {
  json: { ...b.registration(), epoch: 1 },
});
await go("second device syncs", b, "GET", "/v1/sync", { query: { since: 0, limit: 1 } });
const snap = await go("snapshot for rotation", a, "GET", "/v1/sync", {
  query: { since: 0, limit: 500 },
});
await go("rotate key + revoke second device", a, "POST", "/v1/rotate", {
  json: {
    base_epoch: snap.json.epoch,
    base_seq: snap.json.head_seq,
    revoke: b.id,
    items: snap.json.items
      .filter((i: any) => !i.deleted)
      .map((i: any) => ({ id: i.id, rev: i.rev, key: b64u(randomBytes(60)) })),
    devices: [{ id: a.id, envelope: b64u(randomBytes(125)) }],
    recovery_envelope: b64u(randomBytes(60)),
  },
});
await go("revoked device syncs (expect 404)", b, "GET", "/v1/sync");
await go("recovery session (ed25519)", recovery, "POST", "/v1/recovery/session");
void put1;

// Authenticated-but-invalid requests get JSON errors, not the bare 404.
await go("bad json body", a, "PUT", `/v1/items/${randomId()}`, { rawBody: Buffer.from("{nope") });
await go("padded base64 blob", a, "PUT", `/v1/items/${randomId()}`, {
  json: { base_rev: 0, epoch: 2, blob: "AAAA==" },
});
await go("sync since=abc", a, "GET", "/v1/sync", { query: { since: "abc" } });
await go("sync limit=0", a, "GET", "/v1/sync", { query: { limit: 0 } });
await go("item id too short", a, "PUT", "/v1/items/short", {
  json: { base_rev: 0, epoch: 2, blob: "AAAA" },
});
await go("delete unknown item", a, "DELETE", `/v1/items/${randomId()}`, { query: { base_rev: 1 } });
await go("revoke unknown device", a, "DELETE", `/v1/devices/${randomId()}`);
