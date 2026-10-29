import { createMiddleware } from "hono/factory";
import { b64urlDecode, hex } from "./encoding";

export type Principal = { kind: "device"; id: string } | { kind: "recovery" };

export type AppEnv = {
  Bindings: Env;
  Variables: { principal: Principal; body: Uint8Array<ArrayBuffer>; now: number };
};

/** The single response for every authentication failure and every unknown route. */
export const deny = () => new Response(null, { status: 404 });

export const MAX_SKEW_SECONDS = 60;
const NONCE_TTL_SECONDS = 300;
/** Requests above this are treated as unauthenticated garbage (404), never read further. */
export const MAX_BODY_BYTES = 1024 * 1024;

const RE_DEVICE = /^[A-Za-z0-9_-]{16,64}$/;
const RE_TS = /^\d{1,12}$/;
const RE_NONCE = /^[A-Za-z0-9_-]{16,64}$/;
export const RECOVERY_DEVICE_HEADER = "recovery";

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
  if (declared !== null && Number(declared) > limit) return null;
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

function limits(env: Env) {
  return {
    limit: Number(env.AUTH_FAIL_LIMIT) || 20,
    window: Number(env.AUTH_FAIL_WINDOW_SECONDS) || 600,
  };
}

/** True when this IP has used up its failure budget for the current window. */
export function isBlockedStmt(env: Env, ip: string, now: number) {
  return env.DB.prepare("SELECT count FROM auth_failures WHERE ip = ?1 AND window_start > ?2").bind(
    ip,
    now - limits(env).window,
  );
}

export function isBlocked(env: Env, row: { count: number } | null | undefined): boolean {
  return !!row && row.count >= limits(env).limit;
}

export async function recordFailure(env: Env, req: Request, now: number, reason: string, extra: object = {}) {
  const ip = clientIp(req);
  const { window } = limits(env);
  console.log(JSON.stringify({ evt: "auth_fail", reason, ip, method: req.method, path: new URL(req.url).pathname, ...extra }));
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO auth_failures (ip, window_start, count) VALUES (?1, ?2, 1)
         ON CONFLICT(ip) DO UPDATE SET
           count = CASE WHEN window_start <= ?2 - ?3 THEN 1 ELSE count + 1 END,
           window_start = CASE WHEN window_start <= ?2 - ?3 THEN ?2 ELSE window_start END`,
      ).bind(ip, now, window),
      env.DB.prepare("DELETE FROM auth_failures WHERE window_start <= ?1 - ?2").bind(now, window),
    ]);
  } catch (err) {
    console.log(JSON.stringify({ evt: "error", where: "recordFailure", message: String(err) }));
  }
}

async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", data));
}

interface DeviceAuthRow {
  id: string;
  sig_alg: string;
  sig_pubkey: string;
  revoked_at: number | null;
  last_seen_at: number | null;
}

type Mode = "device" | "recovery";

/**
 * Signed-request authentication. Every failure path ends in the same empty 404.
 * Check order matters: nothing is written to nonces until the signature has verified, so an
 * unauthenticated caller can neither burn nonces nor grow the table.
 */
export function authenticate(mode: Mode) {
  return createMiddleware<AppEnv>(async (c, next) => {
    const req = c.req.raw;
    const env = c.env;
    const now = Math.floor(Date.now() / 1000);
    const fail = async (reason: string, extra: object = {}, count = true) => {
      if (count) await recordFailure(env, req, now, reason, extra);
      else console.log(JSON.stringify({ evt: "auth_fail", reason, ip: clientIp(req), path: new URL(req.url).pathname }));
      return deny();
    };

    try {
      const deviceId = req.headers.get("x-bisel-device") ?? "";
      const ts = req.headers.get("x-bisel-ts") ?? "";
      const nonce = req.headers.get("x-bisel-nonce") ?? "";
      const sigB64 = req.headers.get("x-bisel-sig") ?? "";
      if (!RE_TS.test(ts) || !RE_NONCE.test(nonce)) return fail("malformed_headers");
      if (mode === "device" ? !RE_DEVICE.test(deviceId) : deviceId !== RECOVERY_DEVICE_HEADER) {
        return fail("malformed_headers");
      }
      let sig: Uint8Array<ArrayBuffer>;
      try {
        sig = b64urlDecode(sigB64);
      } catch {
        return fail("malformed_headers");
      }
      if (sig.length !== 64) return fail("malformed_headers");

      const body = await readBodyCapped(req, MAX_BODY_BYTES);
      if (!body) return fail("body_too_large");

      const [blockedRes, principalRes] = await env.DB.batch([
        isBlockedStmt(env, clientIp(req), now),
        mode === "device"
          ? env.DB.prepare(
              "SELECT id, sig_alg, sig_pubkey, revoked_at, last_seen_at FROM devices WHERE id = ?1",
            ).bind(deviceId)
          : env.DB.prepare("SELECT recovery_alg AS sig_alg, recovery_pubkey AS sig_pubkey FROM meta WHERE id = 1"),
      ]);
      if (isBlocked(env, blockedRes!.results[0] as { count: number } | undefined)) {
        return fail("rate_limited", {}, false);
      }
      const row = principalRes!.results[0] as DeviceAuthRow | undefined;
      if (!row) return fail(mode === "device" ? "unknown_device" : "not_bootstrapped", { device: deviceId });
      if (row.revoked_at != null) return fail("revoked_device", { device: deviceId });

      if (Math.abs(now - Number(ts)) > MAX_SKEW_SECONDS) return fail("clock_skew", { device: deviceId, skew: now - Number(ts) });

      const url = new URL(req.url);
      const signed = [req.method, url.pathname, canonicalQuery(url), await sha256Hex(body), ts, nonce].join("\n");

      let valid = false;
      if (mode === "device" && row.sig_alg === "p256") {
        const key = await crypto.subtle.importKey(
          "raw",
          b64urlDecode(row.sig_pubkey),
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"],
        );
        valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, new TextEncoder().encode(signed));
      } else if (mode === "recovery" && row.sig_alg === "ed25519") {
        const key = await crypto.subtle.importKey("raw", b64urlDecode(row.sig_pubkey), { name: "Ed25519" }, false, ["verify"]);
        valid = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(signed));
      }
      if (!valid) return fail("bad_signature", { device: deviceId });

      const [ins] = await env.DB.batch([
        env.DB.prepare("INSERT INTO nonces (nonce, ts) VALUES (?1, ?2) ON CONFLICT(nonce) DO NOTHING").bind(nonce, now),
        env.DB.prepare("DELETE FROM nonces WHERE ts < ?1").bind(now - NONCE_TTL_SECONDS),
      ]);
      if (ins!.meta.changes !== 1) return fail("replayed_nonce", { device: deviceId });

      if (mode === "device" && (row.last_seen_at ?? 0) < now - 60) {
        await env.DB.prepare("UPDATE devices SET last_seen_at = ?1 WHERE id = ?2").bind(now, deviceId).run();
      }

      c.set("principal", mode === "device" ? { kind: "device", id: deviceId } : { kind: "recovery" });
      c.set("body", body);
      c.set("now", now);
    } catch (err) {
      return fail("auth_error", { message: String(err) });
    }

    await next();
    c.header("Cache-Control", "no-store");
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
