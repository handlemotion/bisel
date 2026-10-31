import { betterAuth, type BetterAuthOptions } from "better-auth";
import { setSessionCookie } from "better-auth/cookies";
import { passkey } from "@better-auth/passkey";

/**
 * Accounts (DESIGN-accounts.md §6): Better Auth with passkeys only, no passwords, no email, no social login.
 * An account owns at most one box and decides only who may create storage and see the dashboard. Nothing here
 * ever sees a key: the device-signed /v1 protocol does not call into this file.
 *
 * Better Auth's user table needs an email; accounts get a unique placeholder on a reserved TLD, nothing is ever sent.
 */

/** What a person is called on the dashboard. Shown with textContent, but still no control / format / bidi characters. */
const DISPLAY_NAME = /^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}]{1,40}$/u;

export const cleanDisplayName = (raw: string | null | undefined): string | null => {
  const name = (raw ?? "").trim();
  return DISPLAY_NAME.test(name) ? name : null;
};

const randomId = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
};

export function authOptions(env: Env): BetterAuthOptions {
  const origin = new URL(env.PUBLIC_ORIGIN);
  return {
    appName: "bisel",
    baseURL: origin.origin,
    secret: env.BETTER_AUTH_SECRET,
    database: env.DB,
    emailAndPassword: { enabled: false },
    session: { expiresIn: 7 * 24 * 3600, updateAge: 24 * 3600 },
    trustedOrigins: [origin.origin],
    advanced: {
      useSecureCookies: origin.protocol === "https:",
      // Behind Cloudflare the client address is CF-Connecting-IP; rate limits are keyed on it.
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] },
      defaultCookieAttributes: { httpOnly: true, sameSite: "lax", path: "/" },
    },
    // The Worker-wide limiter (RATE_LIMITER) already sheds floods; this one is per route and survives isolates (D1).
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 60,
      customRules: {
        "/passkey/generate-register-options": { window: 60, max: 10 },
        "/passkey/verify-registration": { window: 60, max: 10 },
        "/passkey/generate-authenticate-options": { window: 60, max: 20 },
        "/passkey/verify-authentication": { window: 60, max: 20 },
      },
    },
    plugins: [
      passkey({
        rpID: origin.hostname,
        rpName: "bisel",
        origin: origin.origin,
        registration: {
          // Passkey-first sign-up: no session yet. The chosen name travels as the ceremony's server-side context.
          requireSession: false,
          resolveUser: ({ context }) => {
            const name = cleanDisplayName(context);
            if (!name) throw new Error("invalid display name");
            // A fresh id: nothing exists until the browser proves it holds the new credential.
            return { id: randomId(), name, displayName: name };
          },
          afterVerification: async ({ ctx, user }) => {
            // Adding a passkey to a signed-in account: the user exists, nothing to create.
            if (await ctx.context.internalAdapter.findUserById(user.id)) return;
            // better-auth 1.7 asks where a new user came from (the source feeds `user.validateUserInfo`, unused here).
            const created = await ctx.context.internalAdapter.createUser(
              {
                name: user.name,
                email: `${user.id}@accounts.bisel.invalid`,
                emailVerified: false,
              },
              { method: "passkey" },
            );
            const session = await ctx.context.internalAdapter.createSession(created.id);
            await setSessionCookie(ctx, { session, user: created });
            return { userId: created.id };
          },
        },
      }),
    ],
  };
}

export const createAuth = (env: Env) => betterAuth(authOptions(env));
export type Auth = ReturnType<typeof createAuth>;
