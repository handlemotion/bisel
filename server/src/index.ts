import { Hono, type Context } from "hono";
import type { ZodType } from "zod";
import {
  authenticate,
  clientIp,
  deny,
  isBlocked,
  isBlockedStmt,
  readBodyCapped,
  recordFailure,
  type AppEnv,
} from "./auth";
import { b64urlByteLength, b64urlDecode } from "./encoding";
import {
  BootstrapSchema,
  DeleteQuerySchema,
  DeviceRegistrationSchema,
  IdSchema,
  MAX_BLOB_BYTES,
  PutItemSchema,
  RecoveryRotateSchema,
  RecoverySessionSchema,
  SyncQuerySchema,
  type DeviceRegistration,
} from "./schemas";

const app = new Hono<AppEnv>();

// Anything not matched (unknown path, wrong method, HEAD/OPTIONS) is indistinguishable from an auth failure.
app.notFound(() => deny());

app.onError((err, c) => {
  // Auth and bootstrap catch their own errors and answer 404; anything reaching here happened
  // after the caller was authenticated, so a JSON 500 is safe and useful.
  console.log(JSON.stringify({ evt: "error", path: c.req.path, message: String(err), stack: (err as Error).stack }));
  return c.json({ error: "internal" }, 500);
});

const deviceAuth = authenticate("device");
const recoveryAuth = authenticate("recovery");

// ---------------------------------------------------------------------------------------------
// helpers

type Ctx = Context<AppEnv>;

const bad = (c: Ctx, error = "invalid_request", detail?: unknown) =>
  c.json({ error, ...(detail ? { detail } : {}) }, 400);

/** Parse the already-read (and already-authenticated) body as JSON against a schema. */
function parseJson<T>(c: Ctx, schema: ZodType<T>): { ok: true; data: T } | { ok: false; res: Response } {
  const raw = c.get("body");
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw));
  } catch {
    return { ok: false, res: bad(c, "invalid_json") };
  }
  const r = schema.safeParse(json);
  if (!r.success) {
    return { ok: false, res: bad(c, "invalid_request", r.error.issues.map((i) => ({ path: i.path, message: i.message }))) };
  }
  return { ok: true, data: r.data };
}

/** Importing the key is what validates it: it must be a real point on the curve / valid Ed25519 key. */
async function validDeviceKeys(d: DeviceRegistration): Promise<boolean> {
  try {
    await crypto.subtle.importKey("raw", b64urlDecode(d.sig_pubkey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    // enc_pubkey is only ever used by clients (ECIES), but it must at least be a valid P-256 point.
    await crypto.subtle.importKey("raw", b64urlDecode(d.enc_pubkey), { name: "ECDH", namedCurve: "P-256" }, false, []);
    return true;
  } catch {
    return false;
  }
}

async function validRecoveryKey(pub: string): Promise<boolean> {
  try {
    if (b64urlDecode(pub).length !== 32) return false;
    await crypto.subtle.importKey("raw", b64urlDecode(pub), { name: "Ed25519" }, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

function insertDevice(db: D1Database, d: DeviceRegistration, now: number) {
  return db
    .prepare(
      `INSERT INTO devices (id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, created_at)
       VALUES (?1, ?2, ?3, 'p256', ?4, ?5, ?6, ?7)`,
    )
    .bind(d.id, d.name, d.kind, d.sig_pubkey, d.enc_pubkey, d.envelope, now);
}

function insertEvent(db: D1Database, now: number, deviceId: string | null, type: string, subject: string | null) {
  return db
    .prepare("INSERT INTO events (ts, device_id, type, subject_id) VALUES (?1, ?2, ?3, ?4)")
    .bind(now, deviceId, type, subject);
}

const isUnique = (err: unknown) => /UNIQUE|constraint/i.test(String(err));

interface ItemRow {
  id: string;
  rev: number;
  seq: number;
  deleted: number;
  blob: string;
  updated_at: number;
}
const itemJson = (r: ItemRow) => ({ ...r, deleted: r.deleted === 1 });
const ITEM_COLS = "id, rev, seq, deleted, blob, updated_at";

const DEVICE_PUBLIC_COLS = "id, name, kind, sig_pubkey, enc_pubkey, created_at, last_seen_at, revoked_at";

// ---------------------------------------------------------------------------------------------
// POST /v1/bootstrap  (one time; shared-secret auth, not signed)

app.post("/v1/bootstrap", async (c) => {
  const req = c.req.raw;
  const env = c.env;
  const now = Math.floor(Date.now() / 1000);
  let body: Uint8Array<ArrayBuffer> | null;
  try {
    const [blocked] = await env.DB.batch([isBlockedStmt(env, clientIp(req), now)]);
    if (isBlocked(env, blocked!.results[0] as { count: number } | undefined)) return deny();

    const supplied = req.headers.get("x-bisel-bootstrap") ?? "";
    const expected = env.BOOTSTRAP_TOKEN ?? "";
    const enc = new TextEncoder();
    // Hash both sides so the comparison is fixed-length, then compare in constant time.
    const [a, b] = await Promise.all([
      crypto.subtle.digest("SHA-256", enc.encode(supplied)),
      crypto.subtle.digest("SHA-256", enc.encode(expected)),
    ]);
    const tokenOk = expected.length > 0 && crypto.subtle.timingSafeEqual(a, b);
    if (!tokenOk) {
      await recordFailure(env, req, now, "bad_bootstrap_token");
      return deny();
    }

    const done = await env.DB.prepare("SELECT 1 AS x FROM meta WHERE id = 1").first();
    if (done) {
      console.log(JSON.stringify({ evt: "auth_fail", reason: "already_bootstrapped", ip: clientIp(req) }));
      return deny();
    }
    body = await readBodyCapped(req, 64 * 1024);
    if (!body) return deny();
  } catch (err) {
    console.log(JSON.stringify({ evt: "error", where: "bootstrap", message: String(err) }));
    return deny();
  }

  // The caller proved knowledge of the bootstrap secret, so informative errors are fine from here.
  c.set("body", body);
  const parsed = parseJson(c, BootstrapSchema);
  if (!parsed.ok) return parsed.res;
  const { device, recovery_pubkey, recovery_envelope } = parsed.data;
  if (!(await validDeviceKeys(device)) || !(await validRecoveryKey(recovery_pubkey))) return bad(c, "invalid_key");

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO meta (id, recovery_alg, recovery_pubkey, recovery_envelope, head_seq, created_at)
         VALUES (1, 'ed25519', ?1, ?2, 0, ?3)`,
      ).bind(recovery_pubkey, recovery_envelope, now),
      insertDevice(env.DB, device, now),
      insertEvent(env.DB, now, device.id, "bootstrap", device.id),
    ]);
  } catch (err) {
    // Lost a race with another bootstrap: meta.id is a CHECK(id=1) primary key.
    console.log(JSON.stringify({ evt: "auth_fail", reason: "bootstrap_conflict", message: String(err) }));
    return deny();
  }
  console.log(JSON.stringify({ evt: "bootstrap", device: device.id }));
  return c.json({ device_id: device.id, head_seq: 0 }, 201);
});

// ---------------------------------------------------------------------------------------------
// GET /v1/sync

app.get("/v1/sync", deviceAuth, async (c) => {
  const q = SyncQuerySchema.safeParse(Object.fromEntries(new URL(c.req.url).searchParams));
  if (!q.success) return bad(c, "invalid_query");
  const { since, limit } = q.data;
  const db = c.env.DB;

  // One batch = one transaction: items, head_seq and the device list are a consistent snapshot.
  const [itemsRes, metaRes, devicesRes] = await db.batch([
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2`).bind(since, limit + 1),
    db.prepare("SELECT head_seq, recovery_alg, recovery_pubkey, recovery_envelope FROM meta WHERE id = 1"),
    db.prepare(`SELECT ${DEVICE_PUBLIC_COLS} FROM devices ORDER BY created_at ASC, id ASC`),
  ]);
  const rows = itemsRes!.results as unknown as ItemRow[];
  const meta = metaRes!.results[0] as {
    head_seq: number;
    recovery_alg: string;
    recovery_pubkey: string;
    recovery_envelope: string;
  };
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  return c.json({
    items: page.map(itemJson),
    has_more: hasMore,
    next_since: page.length ? page[page.length - 1]!.seq : since,
    head_seq: meta.head_seq,
    devices: devicesRes!.results,
    recovery: { alg: meta.recovery_alg, pubkey: meta.recovery_pubkey, envelope: meta.recovery_envelope },
  });
});

// ---------------------------------------------------------------------------------------------
// PUT /v1/items/:id   DELETE /v1/items/:id?base_rev=
//
// Gapless seq: the head_seq bump and the item write carry the *same* guard (current rev == base_rev).
// If the guard fails, neither statement does anything, so a rejected write never consumes a seq.
// D1 runs a batch as a single transaction and serialises writers, so nothing can slip between them.

const REV_GUARD = "COALESCE((SELECT rev FROM items WHERE id = ?1), 0) = ?2";

app.put("/v1/items/:id", deviceAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const parsed = parseJson(c, PutItemSchema);
  if (!parsed.ok) return parsed.res;
  const { base_rev, blob } = parsed.data;
  if (b64urlByteLength(blob) > MAX_BLOB_BYTES) return c.json({ error: "too_large", max_bytes: MAX_BLOB_BYTES }, 413);

  const db = c.env.DB;
  const now = c.get("now");
  const [bump, , current] = await db.batch([
    db.prepare(`UPDATE meta SET head_seq = head_seq + 1 WHERE id = 1 AND ${REV_GUARD}`).bind(id, base_rev),
    db
      .prepare(
        `INSERT INTO items (id, rev, seq, deleted, blob, updated_at)
         SELECT ?1, ?2 + 1, head_seq, 0, ?3, ?4 FROM meta WHERE id = 1 AND ${REV_GUARD}
         ON CONFLICT(id) DO UPDATE SET
           rev = excluded.rev, seq = excluded.seq, deleted = 0, blob = excluded.blob, updated_at = excluded.updated_at`,
      )
      .bind(id, base_rev, blob, now),
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE id = ?1`).bind(id),
  ]);
  const row = current!.results[0] as ItemRow | undefined;
  if (bump!.meta.changes !== 1) {
    return c.json({ error: "conflict", current: row ? itemJson(row) : null }, 409);
  }
  return c.json({ item: itemJson(row!) });
});

app.delete("/v1/items/:id", deviceAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const q = DeleteQuerySchema.safeParse(Object.fromEntries(new URL(c.req.url).searchParams));
  if (!q.success) return bad(c, "invalid_query");
  const { base_rev } = q.data;

  const db = c.env.DB;
  const now = c.get("now");
  const guard = "EXISTS (SELECT 1 FROM items WHERE id = ?1 AND rev = ?2 AND deleted = 0)";
  const [bump, , current] = await db.batch([
    db.prepare(`UPDATE meta SET head_seq = head_seq + 1 WHERE id = 1 AND ${guard}`).bind(id, base_rev),
    db
      .prepare(
        `UPDATE items SET rev = rev + 1, seq = (SELECT head_seq FROM meta WHERE id = 1), deleted = 1, blob = '', updated_at = ?3
         WHERE id = ?1 AND rev = ?2 AND deleted = 0`,
      )
      .bind(id, base_rev, now),
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE id = ?1`).bind(id),
  ]);
  const row = current!.results[0] as ItemRow | undefined;
  if (!row) return c.json({ error: "not_found" }, 404);
  if (bump!.meta.changes !== 1) return c.json({ error: "conflict", current: itemJson(row) }, 409);
  return c.json({ item: itemJson(row) });
});

// ---------------------------------------------------------------------------------------------
// devices

app.get("/v1/devices", deviceAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT ${DEVICE_PUBLIC_COLS} FROM devices ORDER BY created_at ASC, id ASC`,
  ).all();
  return c.json({ devices: results });
});

app.post("/v1/devices", deviceAuth, async (c) => {
  const parsed = parseJson(c, DeviceRegistrationSchema);
  if (!parsed.ok) return parsed.res;
  const d = parsed.data;
  if (!(await validDeviceKeys(d))) return bad(c, "invalid_key");
  const p = c.get("principal");
  const now = c.get("now");
  try {
    await c.env.DB.batch([
      insertDevice(c.env.DB, d, now),
      insertEvent(c.env.DB, now, p.kind === "device" ? p.id : null, "approve", d.id),
    ]);
  } catch (err) {
    if (isUnique(err)) return c.json({ error: "exists" }, 409);
    throw err;
  }
  return c.json({ device: { id: d.id, name: d.name, kind: d.kind, created_at: now } }, 201);
});

app.delete("/v1/devices/:id", deviceAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const db = c.env.DB;
  const target = await db.prepare("SELECT id, revoked_at FROM devices WHERE id = ?1").bind(id).first<{
    id: string;
    revoked_at: number | null;
  }>();
  if (!target) return c.json({ error: "not_found" }, 404);
  if (target.revoked_at != null) return c.json({ id, revoked_at: target.revoked_at });
  const p = c.get("principal");
  const now = c.get("now");
  // Wipe the envelope too: a revoked device has no reason to keep a server-side copy of VK-to-it.
  await db.batch([
    db.prepare("UPDATE devices SET revoked_at = ?1, envelope = '' WHERE id = ?2 AND revoked_at IS NULL").bind(now, id),
    insertEvent(db, now, p.kind === "device" ? p.id : null, "revoke", id),
  ]);
  return c.json({ id, revoked_at: now });
});

app.get("/v1/envelope", deviceAuth, async (c) => {
  const p = c.get("principal");
  const row = await c.env.DB.prepare("SELECT envelope FROM devices WHERE id = ?1")
    .bind(p.kind === "device" ? p.id : "")
    .first<{ envelope: string }>();
  return c.json({ device_id: p.kind === "device" ? p.id : null, envelope: row?.envelope ?? "" });
});

// ---------------------------------------------------------------------------------------------
// recovery

app.post("/v1/recovery/session", recoveryAuth, async (c) => {
  const db = c.env.DB;
  const now = c.get("now");
  const raw = c.get("body");
  let device: DeviceRegistration | undefined;
  if (raw.length > 0) {
    const parsed = parseJson(c, RecoverySessionSchema);
    if (!parsed.ok) return parsed.res;
    device = parsed.data.device;
  }
  if (device) {
    if (!(await validDeviceKeys(device))) return bad(c, "invalid_key");
    try {
      await db.batch([insertDevice(db, device, now), insertEvent(db, now, null, "recovery", device.id)]);
    } catch (err) {
      if (isUnique(err)) return c.json({ error: "exists" }, 409);
      throw err;
    }
  } else {
    await insertEvent(db, now, null, "recovery", null).run();
  }
  const meta = await db
    .prepare("SELECT recovery_envelope, head_seq FROM meta WHERE id = 1")
    .first<{ recovery_envelope: string; head_seq: number }>();
  return c.json({
    recovery_envelope: meta!.recovery_envelope,
    head_seq: meta!.head_seq,
    ...(device ? { device: { id: device.id, name: device.name, kind: device.kind, created_at: now } } : {}),
  });
});

app.post("/v1/recovery/rotate", deviceAuth, async (c) => {
  const parsed = parseJson(c, RecoveryRotateSchema);
  if (!parsed.ok) return parsed.res;
  const { recovery_pubkey, recovery_envelope } = parsed.data;
  if (!(await validRecoveryKey(recovery_pubkey))) return bad(c, "invalid_key");
  const p = c.get("principal");
  const now = c.get("now");
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE meta SET recovery_pubkey = ?1, recovery_envelope = ?2 WHERE id = 1").bind(
      recovery_pubkey,
      recovery_envelope,
    ),
    insertEvent(c.env.DB, now, p.kind === "device" ? p.id : null, "recovery_rotate", null),
  ]);
  return c.json({ ok: true });
});

export default app;
