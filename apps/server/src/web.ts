import { Hono, type Context } from "hono";
import { createAuth } from "./accounts";
import { CONNECT_COLS, normalizeUserCode, type ConnectRow } from "./connect";

/**
 * The dashboard's API (DESIGN-accounts.md §6). Everything here is about the *account*: who is signed in, which box
 * they own, which devices that box lists. It reads the same public device columns GET /v1/devices exposes and never
 * touches an item blob, key or envelope.
 */
export const web = new Hono<{ Bindings: Env }>();

// Better Auth owns /api/auth/*: passkey ceremonies, sessions, sign-out. It does its own Origin check on cookie-bearing posts.
web.on(["GET", "POST"], "/auth/*", (c) => createAuth(c.env).handler(c.req.raw));

type Ctx = Context<{ Bindings: Env }>;

/** State-changing routes of ours: same-origin only, and a header a cross-site form or image cannot add. */
web.use("*", async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "HEAD" && !c.req.path.startsWith("/api/auth/")) {
    const origin = c.req.header("origin");
    if (origin !== new URL(c.env.PUBLIC_ORIGIN).origin || c.req.header("x-bisel-csrf") !== "1") {
      return c.json({ error: "forbidden" }, 403);
    }
  }
  await next();
});

async function session(c: Ctx) {
  return createAuth(c.env).api.getSession({ headers: c.req.raw.headers });
}

const REAUTH_WINDOW_SECONDS = 300;

web.get("/box", async (c) => {
  const s = await session(c);
  if (!s) return c.json({ error: "unauthenticated" }, 401);
  const box = await c.env.DB.prepare(
    "SELECT id, created_at, epoch, head_seq, item_count FROM boxes WHERE owner_id = ?1",
  )
    .bind(s.user.id)
    .first<{ id: string; created_at: number; epoch: number; head_seq: number; item_count: number }>();
  const devices = box
    ? (
        await c.env.DB.prepare(
          `SELECT id, name, kind, created_at, last_seen_at, revoked_at, activates_at FROM devices
           WHERE box_id = ?1 ORDER BY created_at ASC, id ASC`,
        )
          .bind(box.id)
          .all()
      ).results
    : [];
  return c.json({ user: { id: s.user.id, name: s.user.name }, box, devices });
});

/** Deleting a box removes its ciphertext from the server. Needs a passkey sign-in from the last few minutes. */
web.delete("/box", async (c) => {
  const s = await session(c);
  if (!s) return c.json({ error: "unauthenticated" }, 401);
  const signedInAt = new Date(s.session.createdAt).getTime() / 1000;
  if (Date.now() / 1000 - signedInAt > REAUTH_WINDOW_SECONDS) return c.json({ error: "reauth_required" }, 403);
  const body = (await c.req.json().catch(() => null)) as { confirm?: unknown } | null;
  if (body?.confirm !== "delete") return c.json({ error: "confirmation_required" }, 400);

  const db = c.env.DB;
  const box = await db.prepare("SELECT id FROM boxes WHERE owner_id = ?1").bind(s.user.id).first<{ id: string }>();
  if (!box) return c.json({ error: "no_box" }, 404);
  await db.batch([
    db.prepare("DELETE FROM items WHERE box_id = ?1").bind(box.id),
    db.prepare("DELETE FROM item_history WHERE box_id = ?1").bind(box.id),
    db.prepare("DELETE FROM events WHERE box_id = ?1").bind(box.id),
    db.prepare("DELETE FROM devices WHERE box_id = ?1").bind(box.id),
    db.prepare("DELETE FROM connect_requests WHERE box_id = ?1").bind(box.id),
    db.prepare("DELETE FROM boxes WHERE id = ?1").bind(box.id),
  ]);
  console.log(JSON.stringify({ evt: "box_deleted", box: box.id.slice(0, 8), by: "account" }));
  return c.json({ deleted: true });
});

// ---------------------------------------------------------------------------------------------------------------------
// Device-code connect, the browser half (DESIGN-accounts.md §6.3). The Mac asked for a code at POST /v1/connect; the
// person arrives here from /connect?code=… while signed in, checks that the code and device name are the ones their Mac
// shows, and approves. Everything is addressed by the short user code, which is useless without the Mac's secret.

async function pendingByCode(c: Ctx, raw: unknown): Promise<ConnectRow | null> {
  const code = typeof raw === "string" ? normalizeUserCode(raw) : null;
  if (!code) return null;
  return c.env.DB.prepare(`SELECT ${CONNECT_COLS} FROM connect_requests WHERE user_code = ?1 AND status = 'pending' AND expires_at > ?2`)
    .bind(code, Math.floor(Date.now() / 1000))
    .first<ConnectRow>();
}

const ownsBox = async (c: Ctx, userId: string) =>
  (await c.env.DB.prepare("SELECT id FROM boxes WHERE owner_id = ?1").bind(userId).first()) !== null;

web.get("/connect", async (c) => {
  const s = await session(c);
  if (!s) return c.json({ error: "unauthenticated" }, 401);
  const row = await pendingByCode(c, c.req.query("code"));
  if (!row) return c.json({ error: "not_found" }, 404);
  return c.json({
    kind: row.kind,
    device_name: row.device_name,
    country: row.country,
    created_at: row.created_at,
    expires_at: row.expires_at,
    account_has_box: await ownsBox(c, s.user.id),
  });
});

web.post("/connect/approve", async (c) => {
  const s = await session(c);
  if (!s) return c.json({ error: "unauthenticated" }, 401);
  const body = (await c.req.json().catch(() => null)) as { code?: unknown } | null;
  const row = await pendingByCode(c, body?.code);
  if (!row) return c.json({ error: "not_found" }, 404);
  const db = c.env.DB;
  const hasBox = await ownsBox(c, s.user.id);

  if (row.kind === "create") {
    // With a box already, approving only lets the Mac learn that (poll: account_has_box); it cannot create a second one.
    await db.prepare("UPDATE connect_requests SET status = 'approved', account_id = ?2 WHERE id = ?1 AND status = 'pending'").bind(row.id, s.user.id).run();
    return c.json({ ok: true, kind: "create", account_has_box: hasBox });
  }

  // claim: link the existing, unowned box to this account.
  if (hasBox) {
    await db.prepare("UPDATE connect_requests SET status = 'denied', account_id = ?2 WHERE id = ?1 AND status = 'pending'").bind(row.id, s.user.id).run();
    return c.json({ error: "box_exists" }, 409);
  }
  try {
    const [link] = await db.batch([
      db.prepare("UPDATE boxes SET owner_id = ?1 WHERE id = ?2 AND owner_id IS NULL").bind(s.user.id, row.box_id),
      db
        .prepare(
          `UPDATE connect_requests SET status = 'consumed', account_id = ?1
           WHERE id = ?2 AND status = 'pending' AND EXISTS (SELECT 1 FROM boxes WHERE id = ?3 AND owner_id = ?1)`,
        )
        .bind(s.user.id, row.id, row.box_id),
    ]);
    if (link!.meta.changes !== 1) return c.json({ error: "already_linked" }, 409);
  } catch (err) {
    if (/boxes\.owner_id/.test(String(err))) return c.json({ error: "box_exists" }, 409);
    throw err;
  }
  console.log(JSON.stringify({ evt: "box_linked", box: (row.box_id ?? "").slice(0, 8) }));
  return c.json({ ok: true, kind: "claim" });
});

web.post("/connect/deny", async (c) => {
  const s = await session(c);
  if (!s) return c.json({ error: "unauthenticated" }, 401);
  const body = (await c.req.json().catch(() => null)) as { code?: unknown } | null;
  const row = await pendingByCode(c, body?.code);
  if (!row) return c.json({ error: "not_found" }, 404);
  await c.env.DB.prepare("UPDATE connect_requests SET status = 'denied', account_id = ?2 WHERE id = ?1 AND status = 'pending'").bind(row.id, s.user.id).run();
  return c.json({ ok: true });
});
