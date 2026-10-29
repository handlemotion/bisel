-- Accounts: Better Auth tables (DESIGN-accounts.md §3). Generated with Better Auth 1.6.23's own migration compiler from
-- src/accounts.ts (`authOptions`), not written by hand; regenerate and diff when the library or its plugins change.
-- user.email is a unique placeholder (<id>@accounts.bisel.invalid): accounts are passkey-only, nothing is ever mailed.
-- boxes.owner_id (migration 0004) holds user.id.

CREATE TABLE "user" ("id" text not null primary key, "name" text not null, "email" text not null unique, "emailVerified" integer not null, "image" text, "createdAt" date not null, "updatedAt" date not null);

CREATE TABLE "session" ("id" text not null primary key, "expiresAt" date not null, "token" text not null unique, "createdAt" date not null, "updatedAt" date not null, "ipAddress" text, "userAgent" text, "userId" text not null references "user" ("id") on delete cascade);

CREATE TABLE "account" ("id" text not null primary key, "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" date, "refreshTokenExpiresAt" date, "scope" text, "password" text, "createdAt" date not null, "updatedAt" date not null);

CREATE TABLE "verification" ("id" text not null primary key, "identifier" text not null, "value" text not null, "expiresAt" date not null, "createdAt" date not null, "updatedAt" date not null);

CREATE TABLE "passkey" ("id" text not null primary key, "name" text, "publicKey" text not null, "userId" text not null references "user" ("id") on delete cascade, "credentialID" text not null, "counter" integer not null, "deviceType" text not null, "backedUp" integer not null, "transports" text, "createdAt" date, "aaguid" text);

CREATE TABLE "rateLimit" ("id" text not null primary key, "key" text not null unique, "count" integer not null, "lastRequest" bigint not null);

CREATE INDEX "session_userId_idx" ON "session" ("userId");

CREATE INDEX "account_userId_idx" ON "account" ("userId");

CREATE INDEX "verification_identifier_idx" ON "verification" ("identifier");

CREATE INDEX "passkey_userId_idx" ON "passkey" ("userId");

CREATE INDEX "passkey_credentialID_idx" ON "passkey" ("credentialID");
