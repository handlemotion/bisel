import { Hono } from "hono";
import { readBodyCapped, shortHash, clientIp } from "./auth";
import { b64urlEncode, hex } from "./encoding";
import { ConnectPollSchema, ConnectStartSchema } from "./schemas";

/**
 * Device-code connect (DESIGN-accounts.md §6.3), the Worker side.
 *
 * A Mac that wants a box on this server asks for a code pair here, without any credential. The person types nothing:
 * the Mac opens `/connect?code=<user code>` in the browser, they sign in (or create an account) with a passkey and
 * approve, and the Mac, which has been polling with its secret device code, redeems that approval at POST /v1/bootstrap
 * (X-Bisel-Connect) or, for linking an existing box, at the approval itself.
 *
 * The device code is 256 random bits, kept only as a SHA-256 hash; the user code (8 characters) is what the person
 * sees and confirms and is useless without the device code.
 */

export const CONNECT_TTL_SECONDS = 600;
const POLL_INTERVAL_SECONDS = 3;
const MAX_PENDING_PER_IP = 5;
/** No 0/O, 1/I/L, 2/Z confusions: 31 symbols, 8 characters. */
const USER_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const USER_CODE_BODY_LIMIT = 1024;

export const sha256Hex = async (value: string) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));

/** "ABCD-EFGH". Rejection sampling keeps the symbols uniform. */
export function newUserCode(): string {
  const out: string[] = [];
  while (out.length < 8) {
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {
      if (b < 248 && out.length < 8) out.push(USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length]!);
    }
  }
  return `${out.slice(0, 4).join("")}-${out.slice(4).join("")}`;
}

/** What a person might type or paste: any case, with or without the hyphen or spaces. */
export function normalizeUserCode(raw: string): string | null {
  const s = raw.toUpperCase().replace(/[\s-]/g, "");
  if (s.length !== 8 || ![...s].every((ch) => USER_CODE_ALPHABET.includes(ch))) return null;
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

export interface ConnectRow {
  id: string;
  kind: "create" | "claim";
  box_id: string | null;
  device_name: string;
  country: string | null;
  created_at: number;
  expires_at: number;
  status: "pending" | "approved" | "denied" | "consumed";
  account_id: string | null;
}

export const CONNECT_COLS = "id, kind, box_id, device_name, country, created_at, expires_at, status, account_id";

/** A new request row and the answer for the Mac. The caller supplies who is asking and what for. */
export async function createConnectRequest(
  env: Env,
  req: Request,
  now: number,
  kind: "create" | "claim",
  deviceName: string,
  boxId: string | null,
) {
  const deviceCode = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const userCode = newUserCode();
  const id = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
  await env.DB.batch([
    // Expired rows go a little after they stop mattering; bounded work per request.
    env.DB.prepare("DELETE FROM connect_requests WHERE id IN (SELECT id FROM connect_requests WHERE expires_at < ?1 LIMIT 50)").bind(now - 3600),
    env.DB.prepare(
      `INSERT INTO connect_requests (id, device_code_hash, user_code, kind, box_id, device_name, ip_hash, country, created_at, expires_at, status)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending')`,
    ).bind(
      id,
      await sha256Hex(deviceCode),
      userCode,
      kind,
      boxId,
      deviceName,
      await shortHash(clientIp(req)),
      req.headers.get("cf-ipcountry"),
      now,
      now + CONNECT_TTL_SECONDS,
    ),
  ]);
  return {
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${new URL(env.PUBLIC_ORIGIN).origin}/connect?code=${userCode}`,
    expires_in: CONNECT_TTL_SECONDS,
    interval: POLL_INTERVAL_SECONDS,
  };
}

export async function connectByDeviceCode(env: Env, deviceCode: string) {
  return env.DB.prepare(`SELECT ${CONNECT_COLS} FROM connect_requests WHERE device_code_hash = ?1`)
    .bind(await sha256Hex(deviceCode))
    .first<ConnectRow>();
}

export const connect = new Hono<{ Bindings: Env }>();

async function readJson(req: Request): Promise<unknown> {
  const body = await readBodyCapped(req, USER_CODE_BODY_LIMIT);
  if (!body) return undefined;
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    return undefined;
  }
}

const bare = (status: number) => new Response(null, { status });

// POST /v1/connect  { device_name }  ->  { device_code, user_code, verification_uri, expires_in, interval }
// Unsigned on purpose (the Mac has no identity yet). It creates nothing but a short-lived row; the flood limiter and
// the per-address cap of pending requests bound it.
connect.post("/connect", async (c) => {
  const parsed = ConnectStartSchema.safeParse(await readJson(c.req.raw));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const now = Math.floor(Date.now() / 1000);
  const pending = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM connect_requests WHERE ip_hash = ?1 AND status = 'pending' AND expires_at > ?2",
  )
    .bind(await shortHash(clientIp(c.req.raw)), now)
    .first<{ n: number }>();
  if ((pending?.n ?? 0) >= MAX_PENDING_PER_IP) return bare(429);
  return c.json(await createConnectRequest(c.env, c.req.raw, now, "create", parsed.data.device_name, null), 201);
});

// POST /v1/connect/poll  { device_code }  ->  { status, account_has_box? }
//   pending   : waiting for the person
//   approved  : create the box now (POST /v1/bootstrap with X-Bisel-Connect), unless account_has_box
//   consumed  : done (a created box exists, or the claimed box is linked)
//   denied / expired : stop
// An unknown code is "expired": nothing tells a guess from a code that timed out.
connect.post("/connect/poll", async (c) => {
  const parsed = ConnectPollSchema.safeParse(await readJson(c.req.raw));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const row = await connectByDeviceCode(c.env, parsed.data.device_code);
  const now = Math.floor(Date.now() / 1000);
  if (!row || (row.status !== "consumed" && row.expires_at <= now)) return c.json({ status: "expired" });
  if (row.status === "approved" && row.kind === "create" && row.account_id) {
    const owned = await c.env.DB.prepare("SELECT id FROM boxes WHERE owner_id = ?1").bind(row.account_id).first<{ id: string }>();
    return c.json({ status: "approved", account_has_box: owned !== null });
  }
  return c.json({ status: row.status });
});
