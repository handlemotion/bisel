import { Hono, type Context } from "hono";
import { secureHeaders } from "hono/secure-headers";
import type { ZodType } from "zod";
import {
  authenticate,
  clientIp,
  decoyVerify,
  deny,
  requireAdmin,
  readBodyCapped,
  recordFailure,
  shortHash,
  type AppEnv,
} from "./auth";
import { b64urlByteLength, b64urlDecode } from "./encoding";
import {
  BODY_LIMITS,
  BootstrapSchema,
  DeleteItemSchema,
  DeleteQuerySchema,
  DeviceApprovalSchema,
  EmptyQuerySchema,
  HistoryQuerySchema,
  IdSchema,
  MAX_BLOB_BYTES,
  PutItemSchema,
  RecoveryRotateSchema,
  RecoverySessionSchema,
  RotateSchema,
  SyncQuerySchema,
  WRAPPED_KEY_CHARS,
  type DeviceRegistration,
} from "./schemas";

const app = new Hono<AppEnv>();

// Every response, including the bare 404s, carries exactly the same hardening headers, so they
// cannot be used to tell an authentication failure from an unknown route.
app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
    crossOriginResourcePolicy: "same-origin",
    crossOriginOpenerPolicy: "same-origin",
    crossOriginEmbedderPolicy: false,
    referrerPolicy: "no-referrer",
    strictTransportSecurity: "max-age=63072000; includeSubDomains",
    xContentTypeOptions: "nosniff",
    xFrameOptions: "DENY",
    xDnsPrefetchControl: "off",
    xDownloadOptions: false,
    xPermittedCrossDomainPolicies: "none",
    xXssProtection: false,
    originAgentCluster: false,
    permissionsPolicy: {},
  }),
);
app.use("*", async (c, next) => {
  await next();
  c.header("Cache-Control", "no-store");
});

// Flood limit per client address: Cloudflare's Workers rate-limiting binding (wrangler.jsonc), checked before
// any D1 work. A request without CF-Connecting-IP never reaches a deployed Worker, so only local dev is exempt.
// The answer is the same empty 429 on every route and for every kind of caller, so it says nothing about auth.
// If the limiter itself errors the request is served: refusing the owner is worse than skipping a soft limit.
app.use("*", async (c, next) => {
  const ip = c.req.header("cf-connecting-ip");
  if (ip) {
    try {
      const { success } = await c.env.RATE_LIMITER.limit({ key: ip });
      if (!success) return c.body(null, 429, { "Retry-After": "10" });
    } catch (err) {
      console.log(JSON.stringify({ evt: "error", where: "rate_limiter", message: String(err) }));
    }
  }
  await next();
});

// Liveness for an uptime monitor: 200 with no body when D1 answers, 503 with no body when it does not.
// It carries no version, name, counts or setup state, and needs no signature.
app.get("/healthz", async (c) => {
  try {
    await c.env.DB.prepare("SELECT 1").first();
  } catch (err) {
    console.log(JSON.stringify({ evt: "error", where: "healthz", message: String(err) }));
    return c.body(null, 503);
  }
  return c.body(null, 200);
});

const deviceAuth = authenticate("device");
const recoveryAuth = authenticate("recovery");
/** Destructive routes: the device signature is not enough, the vault-admin signature (needs VK) must follow. */
const adminAuth = requireAdmin();

app.onError((err, c) => {
  // Auth and bootstrap catch their own errors and answer 404; anything reaching here happened
  // after the caller was authenticated, so a JSON 500 is safe and useful.
  console.log(JSON.stringify({ evt: "error", path: c.req.path, message: String(err), stack: (err as Error).stack }));
  return c.json({ error: "internal" }, 500);
});

// ---------------------------------------------------------------------------------------------
// helpers

type Ctx = Context<AppEnv>;

const bad = (c: Ctx, error = "invalid_request", detail?: unknown) =>
  c.json({ error, ...(detail ? { detail } : {}) }, 400);

type Parsed<T> = { ok: true; data: T } | { ok: false; res: Response };

/** Parse the already-read (and already-authenticated) body as JSON against a strict schema. */
function parseJson<T>(c: Ctx, schema: ZodType<T>, maxBytes: number): Parsed<T> {
  const raw = c.get("body");
  if (raw.length > maxBytes) return { ok: false, res: c.json({ error: "too_large", max_bytes: maxBytes }, 413) };
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

/** Query string against a strict schema; a repeated parameter is invalid (the signature covers both, the meaning would not be). */
function parseQuery<T>(c: Ctx, schema: ZodType<T>): Parsed<T> {
  const params = new URL(c.req.url).searchParams;
  const obj: Record<string, string> = {};
  for (const [k, v] of params) {
    if (Object.hasOwn(obj, k)) return { ok: false, res: bad(c, "invalid_query") };
    obj[k] = v;
  }
  const r = schema.safeParse(obj);
  return r.success ? { ok: true, data: r.data } : { ok: false, res: bad(c, "invalid_query") };
}

/** Requests that take no body: GET and DELETE with a body are malformed (400, after authentication). */
const noBody = (c: Ctx) => (c.get("body").length === 0 ? null : bad(c, "unexpected_body"));

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

async function validRecoveryKeys(sigPub: string, encPub: string): Promise<boolean> {
  try {
    const sig = b64urlDecode(sigPub);
    const enc = b64urlDecode(encPub);
    if (sig.length !== 32 || enc.length !== 32) return false;
    await crypto.subtle.importKey("raw", sig, { name: "Ed25519" }, false, ["verify"]);
    await crypto.subtle.importKey("raw", enc, { name: "X25519" }, false, []);
    return true;
  } catch {
    return false;
  }
}

function insertDevice(db: D1Database, d: DeviceRegistration, now: number, epoch: number, activatesAt: number | null = null) {
  return db
    .prepare(
      `INSERT INTO devices (id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, envelope_epoch, created_at, activates_at)
       VALUES (?1, ?2, ?3, 'p256', ?4, ?5, ?6, ?7, ?8, ?9)`,
    )
    .bind(d.id, d.name, d.kind, d.sig_pubkey, d.enc_pubkey, d.envelope, epoch, now, activatesAt);
}

const retentionSeconds = (env: Env) => (Number(env.HISTORY_RETENTION_DAYS) || 30) * 86400;

/** Previous state of an item, kept for the retention period. Same guard as the write it precedes (bound by the caller). */
function pruneHistory(env: Env, now: number) {
  return env.DB.prepare(
    "DELETE FROM item_history WHERE id IN (SELECT id FROM item_history WHERE replaced_at < ?1 LIMIT 100)",
  ).bind(now - retentionSeconds(env));
}

async function validAdminKey(pub: string): Promise<boolean> {
  try {
    const raw = b64urlDecode(pub);
    if (raw.length !== 32) return false;
    await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

function insertEvent(db: D1Database, now: number, deviceId: string | null, type: string, subject: string | null) {
  return db
    .prepare("INSERT INTO events (ts, device_id, type, subject_id) VALUES (?1, ?2, ?3, ?4)")
    .bind(now, deviceId, type, subject);
}

/**
 * A batch statement that aborts the whole D1 batch (a transaction) when `condition` is false, via the
 * CHECK on `assertions`. The condition is evaluated inside the transaction, so it cannot race.
 */
function assertThat(db: D1Database, condition: string, ...binds: unknown[]) {
  return db.prepare(`INSERT INTO assertions SELECT CASE WHEN ${condition} THEN 1 ELSE 0 END`).bind(...binds);
}
const clearAssertions = (db: D1Database) => db.prepare("DELETE FROM assertions");
const isAssertionFailure = (err: unknown) => /CHECK constraint/i.test(String(err));
const isUnique = (err: unknown) => /UNIQUE/i.test(String(err));

async function metaState(db: D1Database) {
  return (await db.prepare("SELECT epoch, head_seq FROM meta WHERE id = 1").first<{ epoch: number; head_seq: number }>())!;
}

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

const DEVICE_PUBLIC_COLS = "id, name, kind, sig_pubkey, enc_pubkey, created_at, last_seen_at, revoked_at, activates_at";

// ---------------------------------------------------------------------------------------------
// POST /v1/bootstrap  (one time; shared-secret auth, not signed)
//
// A request that fails here does the same work as one that fails in `authenticate` (one read, the
// digests, one signature verification against a decoy key, one counter write), and the secret is
// compared as two SHA-256 digests with timingSafeEqual, so neither the answer nor its timing says
// whether the route exists, whether the token was close, or whether the vault is already set up.

app.post("/v1/bootstrap", async (c) => {
  const req = c.req.raw;
  const env = c.env;
  const now = Math.floor(Date.now() / 1000);
  let body: Uint8Array<ArrayBuffer> | null;
  try {
    const supplied = req.headers.get("x-bisel-bootstrap") ?? "";
    const expected = env.BOOTSTRAP_TOKEN ?? "";
    const enc = new TextEncoder();
    const [a, b, done] = await Promise.all([
      crypto.subtle.digest("SHA-256", enc.encode(supplied)),
      crypto.subtle.digest("SHA-256", enc.encode(expected)),
      env.DB.prepare("SELECT 1 AS x FROM meta WHERE id = 1").first(),
    ]);
    const tokenOk = expected.length > 0 && crypto.subtle.timingSafeEqual(a, b);
    if (!tokenOk || done) {
      await decoyVerify("device", new Uint8Array(64), new Uint8Array(32));
      if (!tokenOk) await recordFailure(env, req, now, "bad_bootstrap_token");
      else console.log(JSON.stringify({ evt: "auth_fail", reason: "already_bootstrapped", ip: await shortHash(clientIp(req)) }));
      return deny();
    }
    body = await readBodyCapped(req, BODY_LIMITS.bootstrap);
    if (!body) return deny();
  } catch (err) {
    console.log(JSON.stringify({ evt: "error", where: "bootstrap", message: String(err) }));
    return deny();
  }

  // The caller proved knowledge of the bootstrap secret, so informative errors are fine from here.
  c.set("body", body);
  const parsed = parseJson(c, BootstrapSchema, BODY_LIMITS.bootstrap);
  if (!parsed.ok) return parsed.res;
  const { device, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey } = parsed.data;
  if (
    !(await validDeviceKeys(device)) ||
    !(await validRecoveryKeys(recovery_pubkey, recovery_enc_pubkey)) ||
    !(await validAdminKey(admin_pubkey))
  ) {
    return bad(c, "invalid_key");
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO meta (id, recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, head_seq, epoch, created_at)
         VALUES (1, 'ed25519', ?1, ?2, ?3, ?4, 0, 1, ?5)`,
      ).bind(recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, now),
      insertDevice(env.DB, device, now, 1),
      insertEvent(env.DB, now, device.id, "bootstrap", device.id),
    ]);
  } catch (err) {
    // Lost a race with another bootstrap: meta.id is a CHECK(id=1) primary key.
    console.log(JSON.stringify({ evt: "auth_fail", reason: "bootstrap_conflict", message: String(err) }));
    return deny();
  }
  console.log(JSON.stringify({ evt: "bootstrap", device: device.id }));
  return c.json({ device_id: device.id, head_seq: 0, epoch: 1 }, 201);
});

// ---------------------------------------------------------------------------------------------
// GET /v1/sync

app.get("/v1/sync", deviceAuth, async (c) => {
  const nb = noBody(c);
  if (nb) return nb;
  const q = parseQuery(c, SyncQuerySchema);
  if (!q.ok) return q.res;
  const { since, limit } = q.data;
  const db = c.env.DB;

  // One batch = one transaction: items, head_seq, epoch and the device list are a consistent snapshot.
  const { events_since } = q.data;
  const [itemsRes, metaRes, devicesRes, eventsRes] = await db.batch([
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2`).bind(since, limit + 1),
    db.prepare("SELECT head_seq, epoch, recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope FROM meta WHERE id = 1"),
    db.prepare(`SELECT ${DEVICE_PUBLIC_COLS} FROM devices ORDER BY created_at ASC, id ASC`),
    events_since === undefined
      ? db.prepare(
          "SELECT id, ts, device_id, type, subject_id FROM (SELECT id, ts, device_id, type, subject_id FROM events ORDER BY id DESC LIMIT 50) ORDER BY id ASC",
        )
      : db
          .prepare("SELECT id, ts, device_id, type, subject_id FROM events WHERE id > ?1 ORDER BY id ASC LIMIT 100")
          .bind(events_since),
  ]);
  const rows = itemsRes!.results as unknown as ItemRow[];
  const meta = metaRes!.results[0] as {
    head_seq: number;
    epoch: number;
    recovery_alg: string;
    recovery_pubkey: string;
    recovery_enc_pubkey: string;
    recovery_envelope: string;
  };
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  return c.json({
    items: page.map(itemJson),
    has_more: hasMore,
    next_since: page.length ? page[page.length - 1]!.seq : since,
    head_seq: meta.head_seq,
    epoch: meta.epoch,
    devices: devicesRes!.results,
    events: eventsRes!.results,
    recovery: {
      alg: meta.recovery_alg,
      pubkey: meta.recovery_pubkey,
      enc_pubkey: meta.recovery_enc_pubkey,
      envelope: meta.recovery_envelope,
    },
  });
});

// ---------------------------------------------------------------------------------------------
// PUT /v1/items/:id   DELETE /v1/items/:id?base_rev=
//
// Gapless seq: the head_seq bump and the item write carry the *same* guard (current rev == base_rev,
// and the caller's epoch is the current one). If the guard fails, neither statement does anything, so
// a rejected write never consumes a seq. D1 runs a batch as a single transaction and serialises
// writers, so nothing can slip between the statements.

app.put("/v1/items/:id", deviceAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const nq = parseQuery(c, EmptyQuerySchema);
  if (!nq.ok) return nq.res;
  const parsed = parseJson(c, PutItemSchema, BODY_LIMITS.item);
  if (!parsed.ok) return parsed.res;
  const { base_rev, blob, epoch } = parsed.data;
  if (b64urlByteLength(blob) > MAX_BLOB_BYTES) return c.json({ error: "too_large", max_bytes: MAX_BLOB_BYTES }, 413);

  const db = c.env.DB;
  const now = c.get("now");
  const REV_GUARD = "COALESCE((SELECT rev FROM items WHERE id = ?1), 0) = ?2";
  const [bump, , , current, state] = await db.batch([
    db.prepare(`UPDATE meta SET head_seq = head_seq + 1 WHERE id = 1 AND epoch = ?3 AND ${REV_GUARD}`).bind(id, base_rev, epoch),
    // The state being replaced stays recoverable for the retention period (same guard as the write).
    db
      .prepare(
        `INSERT INTO item_history (item_id, rev, kind, blob, deleted, epoch, replaced_at)
         SELECT id, rev, CASE deleted WHEN 1 THEN 'delete' ELSE 'overwrite' END, blob, deleted, ?3, ?4 FROM items
         WHERE id = ?1 AND rev = ?2 AND (SELECT epoch FROM meta WHERE id = 1) = ?3`,
      )
      .bind(id, base_rev, epoch, now),
    db
      .prepare(
        `INSERT INTO items (id, rev, seq, deleted, blob, updated_at)
         SELECT ?1, ?2 + 1, head_seq, 0, ?3, ?4 FROM meta WHERE id = 1 AND epoch = ?5 AND ${REV_GUARD}
         ON CONFLICT(id) DO UPDATE SET
           rev = excluded.rev, seq = excluded.seq, deleted = 0, blob = excluded.blob, updated_at = excluded.updated_at`,
      )
      .bind(id, base_rev, blob, now, epoch),
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE id = ?1`).bind(id),
    db.prepare("SELECT epoch FROM meta WHERE id = 1"),
  ]);
  await pruneHistory(c.env, now).run();
  const row = current!.results[0] as ItemRow | undefined;
  if (bump!.meta.changes !== 1) {
    const serverEpoch = (state!.results[0] as { epoch: number }).epoch;
    // The blob's item key is wrapped under a vault key that has since been rotated: refuse, the client re-wraps.
    if (serverEpoch !== epoch) return c.json({ error: "stale_epoch", epoch: serverEpoch }, 409);
    return c.json({ error: "conflict", current: row ? itemJson(row) : null }, 409);
  }
  return c.json({ item: itemJson(row!) });
});

app.delete("/v1/items/:id", deviceAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const q = parseQuery(c, DeleteQuerySchema);
  if (!q.ok) return q.res;
  const { base_rev } = q.data;
  const parsed = parseJson(c, DeleteItemSchema, BODY_LIMITS.small);
  if (!parsed.ok) return parsed.res;
  const { epoch, marker } = parsed.data;

  const db = c.env.DB;
  const now = c.get("now");
  const guard = "EXISTS (SELECT 1 FROM items WHERE id = ?1 AND rev = ?2 AND deleted = 0) AND (SELECT epoch FROM meta WHERE id = 1) = ?3";
  const [bump, , , current, state] = await db.batch([
    db.prepare(`UPDATE meta SET head_seq = head_seq + 1 WHERE id = 1 AND ${guard}`).bind(id, base_rev, epoch),
    db
      .prepare(
        `INSERT INTO item_history (item_id, rev, kind, blob, deleted, epoch, replaced_at)
         SELECT id, rev, 'overwrite', blob, deleted, ?3, ?4 FROM items
         WHERE id = ?1 AND rev = ?2 AND deleted = 0 AND (SELECT epoch FROM meta WHERE id = 1) = ?3`,
      )
      .bind(id, base_rev, epoch, now),
    // The tombstone keeps a sealed marker instead of an empty blob: other devices verify it before honouring the delete.
    db
      .prepare(
        `UPDATE items SET rev = rev + 1, seq = (SELECT head_seq FROM meta WHERE id = 1), deleted = 1, blob = ?4, updated_at = ?3
         WHERE id = ?1 AND rev = ?2 AND deleted = 0 AND (SELECT epoch FROM meta WHERE id = 1) = ?5`,
      )
      .bind(id, base_rev, now, marker, epoch),
    db.prepare(`SELECT ${ITEM_COLS} FROM items WHERE id = ?1`).bind(id),
    db.prepare("SELECT epoch FROM meta WHERE id = 1"),
  ]);
  await pruneHistory(c.env, now).run();
  const row = current!.results[0] as ItemRow | undefined;
  if (!row) return c.json({ error: "not_found" }, 404);
  if (bump!.meta.changes !== 1) {
    const serverEpoch = (state!.results[0] as { epoch: number }).epoch;
    if (serverEpoch !== epoch) return c.json({ error: "stale_epoch", epoch: serverEpoch }, 409);
    return c.json({ error: "conflict", current: itemJson(row) }, 409);
  }
  return c.json({ item: itemJson(row) });
});

// GET /v1/history[?id=][&after=][&limit=]: previous states of items, newest last. Ciphertext only; a client that
// holds VK opens them and re-saves the wanted one as a new revision (the AAD binds the old rev, so it cannot be
// pushed back verbatim). 'rotate' rows hold just the previous wrapped item key.
app.get("/v1/history", deviceAuth, async (c) => {
  const nb = noBody(c);
  if (nb) return nb;
  const q = parseQuery(c, HistoryQuerySchema);
  if (!q.ok) return q.res;
  const { id, after, limit } = q.data;
  const { results } = await c.env.DB.prepare(
    `SELECT id, item_id, rev, kind, blob, deleted, epoch, replaced_at FROM item_history
     WHERE id > ?1 AND (?2 IS NULL OR item_id = ?2) ORDER BY id ASC LIMIT ?3`,
  )
    .bind(after, id ?? null, limit)
    .all();
  return c.json({ entries: results });
});

// ---------------------------------------------------------------------------------------------
// devices

app.get("/v1/devices", deviceAuth, async (c) => {
  const nb = noBody(c);
  if (nb) return nb;
  const nq = parseQuery(c, EmptyQuerySchema);
  if (!nq.ok) return nq.res;
  const { results } = await c.env.DB.prepare(
    `SELECT ${DEVICE_PUBLIC_COLS} FROM devices ORDER BY created_at ASC, id ASC`,
  ).all();
  return c.json({ devices: results });
});

app.post("/v1/devices", deviceAuth, adminAuth, async (c) => {
  const parsed = parseJson(c, DeviceApprovalSchema, BODY_LIMITS.small);
  if (!parsed.ok) return parsed.res;
  const { epoch, ...d } = parsed.data;
  if (!(await validDeviceKeys(d))) return bad(c, "invalid_key");
  const p = c.get("principal");
  const now = c.get("now");
  const db = c.env.DB;
  try {
    await db.batch([
      assertThat(db, "EXISTS (SELECT 1 FROM meta WHERE id = 1 AND epoch = ?1)", epoch),
      insertDevice(db, d, now, epoch),
      insertEvent(db, now, p.kind === "device" ? p.id : null, "approve", d.id),
      clearAssertions(db),
    ]);
  } catch (err) {
    if (isAssertionFailure(err)) return c.json({ error: "stale_epoch", epoch: (await metaState(db)).epoch }, 409);
    if (isUnique(err)) return c.json({ error: "exists" }, 409);
    throw err;
  }
  return c.json({ device: { id: d.id, name: d.name, kind: d.kind, created_at: now } }, 201);
});

/**
 * Revokes without rotating the vault key. Emergency use only: the revoked device is cut off from the
 * server at once, but it still holds VK, which stays valid for everything it already copied and for
 * anything it can obtain from the server's storage. Clients revoke through POST /v1/rotate.
 */
app.delete("/v1/devices/:id", deviceAuth, adminAuth, async (c) => {
  const id = c.req.param("id");
  if (!IdSchema.safeParse(id).success) return bad(c, "invalid_id");
  const nb = noBody(c);
  if (nb) return nb;
  const nq = parseQuery(c, EmptyQuerySchema);
  if (!nq.ok) return nq.res;
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
  return c.json({ id, revoked_at: now, rotated: false });
});

app.get("/v1/envelope", deviceAuth, async (c) => {
  const nb = noBody(c);
  if (nb) return nb;
  const nq = parseQuery(c, EmptyQuerySchema);
  if (!nq.ok) return nq.res;
  const p = c.get("principal");
  const row = await c.env.DB.prepare(
    "SELECT d.envelope AS envelope, d.envelope_epoch AS epoch FROM devices d WHERE d.id = ?1",
  )
    .bind(p.kind === "device" ? p.id : "")
    .first<{ envelope: string; epoch: number }>();
  return c.json({ device_id: p.kind === "device" ? p.id : null, envelope: row?.envelope ?? "", epoch: row?.epoch ?? 0 });
});

// ---------------------------------------------------------------------------------------------
// POST /v1/rotate  (vault-key rotation, optionally revoking a device in the same transaction)
//
// The client has already built everything under the new VK; the server swaps it in atomically:
//   * the first 60 bytes (80 base64url chars) of every live item's blob, i.e. its wrapped item key.
//     The item payload, rev and AAD are untouched; the item gets a fresh seq so other devices re-pull it.
//   * the envelope of every active device (the set must match exactly), and the recovery envelope.
// It is applied only if nothing changed since the snapshot it was built from: same epoch, same
// head_seq (so no item was written), same live-item set at the same revs, same active-device set.
// Otherwise the whole D1 batch rolls back and the client gets 409 and retries from a fresh sync.

app.post("/v1/rotate", deviceAuth, adminAuth, async (c) => {
  const parsed = parseJson(c, RotateSchema, BODY_LIMITS.rotate);
  if (!parsed.ok) return parsed.res;
  const r = parsed.data;
  const p = c.get("principal");
  const callerId = p.kind === "device" ? p.id : "";
  if (r.revoke === callerId) return bad(c, "cannot_revoke_self");
  if (!r.devices.some((d) => d.id === callerId)) return bad(c, "caller_not_in_devices");
  if (r.revoke && r.devices.some((d) => d.id === r.revoke)) return bad(c, "revoked_device_in_devices");
  if (!(await validAdminKey(r.new_admin_pubkey))) return bad(c, "invalid_key");

  const db = c.env.DB;
  const now = c.get("now");
  const n = r.items.length;
  const t = r.tombstones.length;
  const m = r.devices.length;
  const newEpoch = r.base_epoch + 1;
  const keys = JSON.stringify(r.items.map((i) => ({ id: i.id, rev: i.rev, k: i.key })));
  const markers = JSON.stringify(r.tombstones.map((i) => ({ id: i.id, rev: i.rev, k: i.marker })));
  const envelopes = JSON.stringify(r.devices);

  try {
    await db.batch([
      assertThat(db, "EXISTS (SELECT 1 FROM meta WHERE id = 1 AND epoch = ?1 AND head_seq = ?2)", r.base_epoch, r.base_seq),
      ...(r.revoke
        ? [
            assertThat(db, "EXISTS (SELECT 1 FROM devices WHERE id = ?1 AND revoked_at IS NULL)", r.revoke),
            db.prepare("UPDATE devices SET revoked_at = ?1, envelope = '' WHERE id = ?2 AND revoked_at IS NULL").bind(now, r.revoke),
          ]
        : []),
      // The wrapped item keys being replaced stay recoverable for the retention period.
      db
        .prepare(
          `INSERT INTO item_history (item_id, rev, kind, blob, deleted, epoch, replaced_at)
           SELECT id, rev, 'rotate', substr(blob, 1, ${WRAPPED_KEY_CHARS}), 0, ?1, ?2 FROM items WHERE deleted = 0`,
        )
        .bind(r.base_epoch, now),
      // New wrapped item keys. `seq` is assigned in request order, base_seq + 1 .. base_seq + n, all above every existing seq.
      db
        .prepare(
          `WITH r AS (SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.rev') AS rev,
                             json_extract(value, '$.k') AS k, key AS pos FROM json_each(?1))
           UPDATE items SET blob = r.k || substr(items.blob, ${WRAPPED_KEY_CHARS + 1}), seq = ?2 + 1 + r.pos, updated_at = ?3
           FROM r
           WHERE items.id = r.id AND items.rev = r.rev AND items.deleted = 0 AND length(items.blob) > ${WRAPPED_KEY_CHARS}`,
        )
        .bind(keys, r.base_seq, now),
      // Tombstone markers are sealed under VK, so they are re-sealed too; seqs follow the items'.
      db
        .prepare(
          `WITH r AS (SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.rev') AS rev,
                             json_extract(value, '$.k') AS k, key AS pos FROM json_each(?1))
           UPDATE items SET blob = r.k, seq = ?2 + ?4 + 1 + r.pos, updated_at = ?3
           FROM r WHERE items.id = r.id AND items.rev = r.rev AND items.deleted = 1`,
        )
        .bind(markers, r.base_seq, now, n),
      db
        .prepare(
          `WITH r AS (SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.envelope') AS envelope FROM json_each(?1))
           UPDATE devices SET envelope = r.envelope, envelope_epoch = ?2 FROM r WHERE devices.id = r.id AND devices.revoked_at IS NULL`,
        )
        .bind(envelopes, newEpoch),
      // The admin key moves with VK; this request was authorised by the old one.
      db
        .prepare("UPDATE meta SET epoch = ?1, head_seq = head_seq + ?2, recovery_envelope = ?3, admin_pubkey = ?4 WHERE id = 1")
        .bind(newEpoch, n + t, r.recovery_envelope, r.new_admin_pubkey),
      // Every live item and tombstone was rotated (none omitted, none at another rev, none appeared) and every active device got its envelope.
      assertThat(
        db,
        `(SELECT COUNT(*) FROM items WHERE deleted = 0) = ?1 AND (SELECT COUNT(*) FROM items WHERE deleted = 0 AND seq > ?2) = ?1
         AND (SELECT COUNT(*) FROM items WHERE deleted = 1) = ?3 AND (SELECT COUNT(*) FROM items WHERE deleted = 1 AND seq > ?2) = ?3`,
        n,
        r.base_seq,
        t,
      ),
      assertThat(
        db,
        `(SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL) = ?1 AND (SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL AND envelope_epoch = ?2) = ?1`,
        m,
        newEpoch,
      ),
      insertEvent(db, now, callerId, "rotate", r.revoke),
      clearAssertions(db),
    ]);
  } catch (err) {
    if (!isAssertionFailure(err)) throw err;
    const state = await metaState(db);
    console.log(JSON.stringify({ evt: "rotate_conflict", device: callerId.slice(0, 8), base_epoch: r.base_epoch, epoch: state.epoch }));
    return c.json({ error: "conflict", epoch: state.epoch, head_seq: state.head_seq }, 409);
  }
  await pruneHistory(c.env, now).run();
  console.log(JSON.stringify({ evt: "rotate", device: callerId.slice(0, 8), epoch: newEpoch, items: n, tombstones: t, devices: m, revoked: !!r.revoke }));
  return c.json({ epoch: newEpoch, head_seq: r.base_seq + n + t, rotated_items: n, rotated_tombstones: t, revoked: r.revoke });
});

// ---------------------------------------------------------------------------------------------
// recovery

app.post("/v1/recovery/session", recoveryAuth, async (c) => {
  const db = c.env.DB;
  const now = c.get("now");
  const raw = c.get("body");
  let device: DeviceRegistration | undefined;
  let epoch = 0;
  if (raw.length > 0) {
    const parsed = parseJson(c, RecoverySessionSchema, BODY_LIMITS.small);
    if (!parsed.ok) return parsed.res;
    ({ device, epoch } = parsed.data);
  } else {
    const nq = parseQuery(c, EmptyQuerySchema);
    if (!nq.ok) return nq.res;
  }
  const delay = Math.max(0, Number(c.env.RECOVERY_ACTIVATION_DELAY_SECONDS) || 0);
  const activatesAt = delay > 0 ? now + delay : null;
  if (device) {
    if (!(await validDeviceKeys(device))) return bad(c, "invalid_key");
    try {
      await db.batch([
        assertThat(db, "EXISTS (SELECT 1 FROM meta WHERE id = 1 AND epoch = ?1)", epoch),
        insertDevice(db, device, now, epoch, activatesAt),
        insertEvent(db, now, null, "recovery", device.id),
        clearAssertions(db),
      ]);
    } catch (err) {
      if (isAssertionFailure(err)) return c.json({ error: "stale_epoch", epoch: (await metaState(db)).epoch }, 409);
      if (isUnique(err)) return c.json({ error: "exists" }, 409);
      throw err;
    }
  } else {
    await insertEvent(db, now, null, "recovery", null).run();
  }
  const meta = await db
    .prepare("SELECT recovery_envelope, head_seq, epoch FROM meta WHERE id = 1")
    .first<{ recovery_envelope: string; head_seq: number; epoch: number }>();
  return c.json({
    recovery_envelope: meta!.recovery_envelope,
    head_seq: meta!.head_seq,
    epoch: meta!.epoch,
    ...(device ? { device: { id: device.id, name: device.name, kind: device.kind, created_at: now, activates_at: activatesAt } } : {}),
  });
});

app.post("/v1/recovery/rotate", deviceAuth, adminAuth, async (c) => {
  const parsed = parseJson(c, RecoveryRotateSchema, BODY_LIMITS.small);
  if (!parsed.ok) return parsed.res;
  const { recovery_pubkey, recovery_enc_pubkey, recovery_envelope, epoch } = parsed.data;
  if (!(await validRecoveryKeys(recovery_pubkey, recovery_enc_pubkey))) return bad(c, "invalid_key");
  const p = c.get("principal");
  const now = c.get("now");
  const db = c.env.DB;
  try {
    await db.batch([
      assertThat(db, "EXISTS (SELECT 1 FROM meta WHERE id = 1 AND epoch = ?1)", epoch),
      db
        .prepare("UPDATE meta SET recovery_pubkey = ?1, recovery_enc_pubkey = ?2, recovery_envelope = ?3 WHERE id = 1")
        .bind(recovery_pubkey, recovery_enc_pubkey, recovery_envelope),
      insertEvent(db, now, p.kind === "device" ? p.id : null, "recovery_rotate", null),
      clearAssertions(db),
    ]);
  } catch (err) {
    if (isAssertionFailure(err)) return c.json({ error: "stale_epoch", epoch: (await metaState(db)).epoch }, 409);
    throw err;
  }
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------------------------
// Everything else (unknown path, wrong method, HEAD/OPTIONS on a POST route…) goes through the very
// same authentication as a real route and is then refused. A bad caller therefore cannot distinguish
// "this route exists" from "this route does not" by response or by cost.
app.all("*", deviceAuth, () => deny());
app.notFound(() => deny());

export default app;
