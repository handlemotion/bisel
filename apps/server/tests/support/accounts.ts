// A signed-in dashboard session without a browser: the session row Better Auth would have written after a passkey
// sign-in, and the cookie it would have set (value.signature, HMAC-SHA256 under BETTER_AUTH_SECRET). The passkey
// ceremony itself is covered by the opt-in browser test.
import { createHmac, randomBytes } from "node:crypto";
import { inject } from "vitest";
import { sql, AUTH_SECRET } from "./server";

export interface Account {
  id: string;
  name: string;
  /** Request headers for a signed-in, same-origin, state-changing call. */
  headers: Record<string, string>;
  /** Only the cookie: what a plain GET carries. */
  cookie: string;
}

/** `signedInSecondsAgo`: how old the passkey sign-in behind the session is (deleting a box needs a recent one). */
export function signUp(name: string, signedInSecondsAgo = 0): Account {
  const { url, stateDir } = inject("server");
  const id = randomBytes(16).toString("hex");
  const token = randomBytes(24).toString("base64url");
  const at = new Date(Date.now() - signedInSecondsAgo * 1000).toISOString();
  const expires = new Date(Date.now() + 3600_000).toISOString();
  sql(
    stateDir,
    `INSERT INTO "user" (id, name, email, emailVerified, createdAt, updatedAt) VALUES ('${id}', '${name}', '${id}@accounts.bisel.invalid', 0, '${at}', '${at}');
     INSERT INTO "session" (id, expiresAt, token, createdAt, updatedAt, userId) VALUES ('${id}', '${expires}', '${token}', '${at}', '${at}', '${id}')`,
  );
  const signature = createHmac("sha256", AUTH_SECRET).update(token).digest("base64");
  const cookie = `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}`;
  return { id, name, cookie, headers: { Cookie: cookie, "X-Bisel-CSRF": "1", Origin: url } };
}
