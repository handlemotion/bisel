import { createMiddleware } from "hono/factory";
import { b64urlDecode, hex } from "./encoding";
import { MAX_BODY_BYTES } from "./schemas";

export type Principal = { kind: "device"; id: string } | { kind: "recovery" };

export type AppEnv = {
  Bindings: Env;
  Variables: { principal: Principal; body: Uint8Array<ArrayBuffer>; now: number };
};

/** The single response for every authentication failure and every unknown route. */
export const deny = () => new Response(null, { status: 404 });

export const MAX_SKEW_SECONDS = 60;
const NONCE_TTL_SECONDS = 300;
/** Expired rows removed per write: bounds the work of any one request while still outpacing inserts. */
const PRUNE_BATCH = 100;
/** Upper bound on tracked addresses: a flood of spoofed or rotating addresses cannot grow `auth_failures` without limit. */
const MAX_TRACKED_IPS = 20_000;

const RE_DEVICE = /^[A-Za-z0-9_-]{16,64}$/;
const RE_TS = /^\d{1,12}$/;
const RE_NONCE = /^[A-Za-z0-9_-]{16,64}$/;
export const RECOVERY_DEVICE_HEADER = "recovery";

/** Valid public keys of nobody: a request for an unknown principal is verified against these, so it costs the same. */
const DECOY_P256 = "BFwYlCzVcbNbUVVo4ctkabccqBVuxOtyodh8L3rYyRb7R0CZVFOQ3O6zObTDzem4a4dRPevWwd_uGdj23vg0RWU";
const DECOY_ED25519 = "_Edh-W08o87bHVUnuXATeul30lxytWOt0FrBE-W36P8";

export function clientIp(req: Request): string {
  // Cloudflare sets CF-Connecting-IP and overwrites any client-supplied value in production.
  return req.headers.get("cf-connecting-ip") ?? "unknown";
}

/** RFC 3986 percent-encoding: everything except A-Z a-z 0-9 - . _ ~ is escaped (UTF-8 bytes). */
function pct(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** Query params sorted by name then value (code-unit order), each as pct(k)=pct(v), joined with &. */
export function canonicalQuery(url: URL): string {
  const pairs = [...url.searchParams.entries()].map(([k, v]) => [pct(k), pct(v)] as const);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

export async function readBodyCapped(req: Request, limit: number): Promise<Uint8Array<ArrayBuffer> | null> {
  const declared = req.headers.get("content-length");
  if (declared !== null && !(Number(declared) <= limit)) return null; // also catches NaN
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Failed-auth backoff
//
// Design (see README "Failed-auth backoff"): the counter never blocks a *valid* signature, so the
// owner cannot be locked out by anyone else's traffic, whatever address they share. It only
// (a) stops costing D1 writes once an address is over budget, and (b) delays the 404 for that
// address, which makes scanning and guessing from it slow. The Cloudflare zone rate-limit rule is
// what actually sheds floods.

function limits(env: Env) {
  return {
    limit: Number(env.AUTH_FAIL_LIMIT) || 20,
    window: Number(env.AUTH_FAIL_WINDOW_SECONDS) || 600,
    backoffMs: Math.min(Number(env.AUTH_BACKOFF_MS ?? 1000) || 0, 10_000),
  };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Counts one failure for the caller's address and, if the address is over budget, delays the answer.
 * One upsert: past the limit its WHERE clause makes it a no-op (no row written, nothing returned).
 */
export async function recordFailure(env: Env, req: Request, now: number, reason: string, extra: object = {}) {
  const ip = clientIp(req);
  const { limit, window, backoffMs } = limits(env);
  let overBudget = false;
  try {
    const [upsert] = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO auth_failures (ip, window_start, count)
         SELECT ?1, ?2, 1 WHERE (SELECT COUNT(*) FROM auth_failures) < ?5 OR EXISTS (SELECT 1 FROM auth_failures WHERE ip = ?1)
         ON CONFLICT(ip) DO UPDATE SET
           count = CASE WHEN window_start <= ?2 - ?3 THEN 1 ELSE count + 1 END,
           window_start = CASE WHEN window_start <= ?2 - ?3 THEN ?2 ELSE window_start END
         WHERE window_start <= ?2 - ?3 OR count < ?4
         RETURNING count`,
      ).bind(ip, now, window, limit, MAX_TRACKED_IPS),
      env.DB.prepare(
        "DELETE FROM auth_failures WHERE ip IN (SELECT ip FROM auth_failures WHERE window_start <= ?1 - ?2 LIMIT ?3)",
      ).bind(now, window, PRUNE_BATCH),
    ]);
    const row = upsert!.results[0] as { count: number } | undefined;
    overBudget = !row || row.count >= limit;
  } catch (err) {
    console.log(JSON.stringify({ evt: "error", where: "recordFailure", message: String(err) }));
  }
  console.log(
    JSON.stringify({ evt: "auth_fail", reason, ip, over_budget: overBudget, method: req.method, path: new URL(req.url).pathname, ...extra }),
  );
  if (overBudget && backoffMs > 0) await sleep(backoffMs + Math.random() * backoffMs * 0.25);
}

// ---------------------------------------------------------------------------------------------

async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", data));
}

interface PrincipalRow {
  id?: string;
  sig_alg: string;
  sig_pubkey: string;
  revoked_at: number | null;
  last_seen_at: number | null;
}

type Mode = "device" | "recovery";

/** Verifies `sig` over `message`; any import/verify error counts as "invalid". Never throws. */
async function verifySignature(alg: string, pubkeyB64: string, sig: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>) {
  try {
    const raw = b64urlDecode(pubkeyB64);
    if (alg === "p256") {
      const key = await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, message);
    }
    if (alg === "ed25519") {
      const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, message);
    }
  } catch {
    // fall through
  }
  return false;
}

/** The same verification an unknown principal's request goes through, with a key nobody holds. */
export async function decoyVerify(mode: Mode, sig: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>) {
  await verifySignature(mode === "device" ? "p256" : "ed25519", mode === "device" ? DECOY_P256 : DECOY_ED25519, sig, message);
}

/**
 * Signed-request authentication. Every failure path ends in the same empty 404 and performs the same
 * work (one principal read, one signature verification, at most one counter write), so neither the
 * route, the principal's existence/revocation, nor the failing check shows in the response or its timing.
 * Nothing is written to `nonces` until the signature has verified, so an unauthenticated caller can
 * neither burn nonces nor grow the table.
 */
export function authenticate(mode: Mode) {
  return createMiddleware<AppEnv>(async (c, next) => {
    const req = c.req.raw;
    const env = c.env;
    const now = Math.floor(Date.now() / 1000);
    const fail = async (reason: string, extra: object = {}) => {
      await recordFailure(env, req, now, reason, extra);
      return deny();
    };

    try {
      const deviceId = req.headers.get("x-bisel-device") ?? "";
      const ts = req.headers.get("x-bisel-ts") ?? "";
      const nonce = req.headers.get("x-bisel-nonce") ?? "";
      const sigB64 = req.headers.get("x-bisel-sig") ?? "";
      if (!RE_TS.test(ts) || !RE_NONCE.test(nonce)) return await fail("malformed_headers");
      if (mode === "device" ? !RE_DEVICE.test(deviceId) : deviceId !== RECOVERY_DEVICE_HEADER) {
        return await fail("malformed_headers");
      }
      let sig: Uint8Array<ArrayBuffer>;
      try {
        sig = b64urlDecode(sigB64);
      } catch {
        return await fail("malformed_headers");
      }
      if (sig.length !== 64) return await fail("malformed_headers");

      const body = await readBodyCapped(req, MAX_BODY_BYTES);
      if (!body) return await fail("body_too_large");

      const row = await (mode === "device"
        ? env.DB.prepare("SELECT id, sig_alg, sig_pubkey, revoked_at, last_seen_at FROM devices WHERE id = ?1").bind(deviceId)
        : env.DB.prepare("SELECT recovery_alg AS sig_alg, recovery_pubkey AS sig_pubkey, NULL AS revoked_at, NULL AS last_seen_at FROM meta WHERE id = 1")
      ).first<PrincipalRow>();

      const url = new URL(req.url);
      const signed = new TextEncoder().encode(
        [req.method, url.pathname, canonicalQuery(url), await sha256Hex(body), ts, nonce].join("\n"),
      ) as Uint8Array<ArrayBuffer>;

      let valid = false;
      if (row) valid = await verifySignature(row.sig_alg, row.sig_pubkey, sig, signed);
      else await decoyVerify(mode, sig, signed);

      // Evaluated only after the verification so every outcome did the same work.
      if (!row) return await fail(mode === "device" ? "unknown_device" : "not_bootstrapped", { device: deviceId });
      if (row.revoked_at != null) return await fail("revoked_device", { device: deviceId });
      if (Math.abs(now - Number(ts)) > MAX_SKEW_SECONDS) return await fail("clock_skew", { device: deviceId, skew: now - Number(ts) });
      if (!valid) return await fail("bad_signature", { device: deviceId });

      const [ins] = await env.DB.batch([
        env.DB.prepare("INSERT INTO nonces (nonce, ts) VALUES (?1, ?2) ON CONFLICT(nonce) DO NOTHING").bind(nonce, now),
        env.DB.prepare("DELETE FROM nonces WHERE nonce IN (SELECT nonce FROM nonces WHERE ts < ?1 LIMIT ?2)").bind(
          now - NONCE_TTL_SECONDS,
          PRUNE_BATCH,
        ),
      ]);
      if (ins!.meta.changes !== 1) return await fail("replayed_nonce", { device: deviceId });

      if (mode === "device" && (row.last_seen_at ?? 0) < now - 60) {
        await env.DB.prepare("UPDATE devices SET last_seen_at = ?1 WHERE id = ?2").bind(now, deviceId).run();
      }

      c.set("principal", mode === "device" ? { kind: "device", id: deviceId } : { kind: "recovery" });
      c.set("body", body);
      c.set("now", now);
    } catch (err) {
      return await fail("auth_error", { message: String(err) });
    }

    await next();
    const p = c.get("principal");
    console.log(
      JSON.stringify({
        evt: "req",
        who: p.kind === "device" ? p.id : "recovery",
        method: req.method,
        path: new URL(req.url).pathname,
        status: c.res.status,
      }),
    );
  });
}
