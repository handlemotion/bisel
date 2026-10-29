import { Hono, type Context } from "hono";
import { createAuth } from "./accounts";

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
    db.prepare("DELETE FROM boxes WHERE id = ?1").bind(box.id),
  ]);
  console.log(JSON.stringify({ evt: "box_deleted", box: box.id.slice(0, 8), by: "account" }));
  return c.json({ deleted: true });
});
