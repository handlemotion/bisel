# bisel server

> **Deferred.** Bisel is macOS-first and CloudKit-first now. This server still works, its tests still run in CI, and it stays here as an
> optional sync lane, but it is not the default path and is not being developed further for now. See [`DEPLOY.md`](DEPLOY.md) to run your own.

Cloudflare Worker (TypeScript, Hono, Zod, Better Auth) + D1 + static assets (the dashboard). Zero-knowledge sync API: the server stores only
ciphertext blobs, public keys and opaque envelopes. Contract: [`../../docs/SPEC.md`](../../docs/SPEC.md) §6.
This README is the wire-level detail for client implementers.

Everything here runs against `wrangler dev` with a **local** D1. Nothing is deployed and no
Cloudflare account is touched.

## Commands

Run from `apps/server/`. Needs Node 22.18+ (developed on 24; `scripts/smoke.ts` relies on Node's built-in TypeScript stripping) and pnpm.

```sh
pnpm install            # first time
pnpm dev                # creates .dev.vars if missing, applies local D1 migrations, serves http://localhost:8787
pnpm migrate            # apply migrations to the local D1 only (pnpm dev already does this)
pnpm reset              # stop `pnpm dev` first, then wipe local D1 state (.wrangler/state): the next `pnpm dev` is a fresh, un-bootstrapped server
pnpm test               # vitest flow tests over HTTP; a globalSetup starts its own wrangler dev on a free port with a throwaway D1.
                        # Includes two-box isolation, the dashboard API with signed-in sessions and the device-code connect flow.
pnpm test:legacy        # builds a pre-accounts database (migrations 0001-0003 + seed), applies 0004+ on top and checks the old box still works
pnpm test:browser       # opt-in, not in `pnpm test`: the passkey sign-up/sign-in in real Chromium (Playwright, virtual authenticator; port 8788)
pnpm build:web          # bundles web/app.ts into public/app.js (wrangler dev and deploy run it themselves)
pnpm check-types
node scripts/smoke.ts   # manual walk through bootstrap/put/conflict/delete/approve/revoke/recovery against :8787
```

### Verify everything with one command

From the repo root, no untracked file needed (`apps/server/.dev.vars` is created from the example), nothing touches Cloudflare, Doppler or production:

```sh
scripts/check-all.sh            # server + core + app, then a PASS/FAIL summary with timings (about 8 min)
scripts/check-all.sh --server   # pnpm install --frozen-lockfile, typecheck (worker + dashboard), pnpm test, pnpm test:legacy
scripts/check-all.sh --core     # BiselCore Swift flow suite: swift test --traits SoftwareKeys (starts its own wrangler dev servers)
scripts/check-all.sh --app      # xcodegen with project.dev.yml, then a Debug build of the Mac app (software keys) and a compile-only build of the UI tests
scripts/check-all.sh --ui       # opt-in, never in a default run: launches the app and drives the screen (XCUITest, NOT YET RUN, see apps/mac/Bisel/UITests/NEEDED-IDS.md)
scripts/check-all.sh --release  # opt-in: Release build and scripts/check-release-hooks.sh
scripts/check-all.sh -v         # stream each step's output; flags combine, e.g. --server --core
```

`scripts/check-release-hooks.sh` builds Release and fails if any `BISEL_DEV_` string (the Debug-only hooks) is in the shipped bundle;
`--control` also builds Debug and requires the strings there, so a broken grep cannot pass silently.
Every step runs in its own process group that is killed when the step ends, so no dev server survives the script.

Local dev bootstrap token (from `.dev.vars`, created from `.dev.vars.example`): `dev-bootstrap-token`.
The server holds **many boxes** (one per account, plus unowned ones made with the operator token). `POST /v1/bootstrap` with the token
creates another unowned box every time; with `X-Bisel-Connect` it creates the box of the account that approved a device code.
The dashboard is at `http://localhost:8787/` (sign-up and sign-in are passkeys; `localhost` is a valid WebAuthn origin).

Base URL while developing: `http://localhost:8787`.

Optional test hook: in local dev the server keys its failed-auth counter on the `CF-Connecting-IP`
request header (Cloudflare sets and overwrites that header in production, so it cannot be spoofed there).
A test client can send its own value to get an isolated rate-limit bucket.

## Conventions

- **Encoding.** Every binary value (keys, signatures, nonces, blobs, envelopes) is **unpadded base64url**
  (RFC 4648 section 5, alphabet `A-Z a-z 0-9 - _`, no `=`). Padding or `+ /` is rejected.
- **Timestamps** are unix **seconds** (integers). Server-assigned fields (`updated_at`, `created_at`,
  `last_seen_at`, `revoked_at`) use the server clock.
- **Ids** (device ids, item ids) are chosen by the client: regex `^[A-Za-z0-9_-]{16,64}$`.
  Recommended: 16 random bytes as base64url (22 chars). A UUID string also fits.
- **JSON** request bodies, UTF-8, `Content-Type: application/json`. Response bodies are JSON.
- **Keys.**
  - Device signing key: P-256, public key as **X9.63 uncompressed point (65 bytes, `04||X||Y`)**
    = CryptoKit `P256.Signing.PublicKey.x963Representation`.
  - Device encryption public key: P-256, same X9.63 65-byte form. The server only checks it is a valid point.
  - Recovery key: Ed25519, public key **raw 32 bytes** = CryptoKit `Curve25519.Signing.PublicKey.rawRepresentation`.
  - Recovery encryption key: X25519, public key **raw 32 bytes** (`recovery_enc_pubkey`). The server only checks it imports.
- **Envelopes** (`envelope`, `recovery_envelope`) are opaque byte strings to the server (max 4 KiB each).
- **Epoch.** An integer starting at 1 that moves by one on every vault-key rotation. A client states, in every request that carries
  material built from the vault key (PUT item, approve device, recovery register, recovery rotate), the epoch of the key it used.
  A stale epoch is `409 {"error":"stale_epoch","epoch":<current>}` and nothing is written. Learn the current one from `GET /v1/sync`.
- **Blob layout** (client-defined, but the rotation endpoint relies on it): the first **60 bytes** of a blob are the wrapped item key
  (`nonce(12) || key(32) || tag(16)`) = exactly **80 base64url characters**; the rest is the payload ciphertext.
- **Strictness.** Every JSON body is a strict schema: an unknown field, a missing field, a wrong type, a repeated query
  parameter or a body on GET/DELETE is `400`.
- **Limits.** Item `blob` max **262144 bytes decoded** (256 KiB). Hard cap on any request body **4 MiB** (above that you get the
  uniform 404); after authentication each route has its own cap and answers `413 too_large` (item PUT 400 KiB, device/recovery
  routes 32 KiB, rotate 4 MiB, bootstrap 64 KiB). Rotation takes up to 12 000 items and 64 devices. `GET /v1/sync` `limit` 1..500, default 200.

## How a client signs requests

Every request except `POST /v1/bootstrap` carries four headers (plus `X-Bisel-Admin` on the destructive routes, below):

```
X-Bisel-Device: <device id>            (the literal string "recovery" for recovery-key requests)
X-Bisel-Ts:     <unix seconds, decimal>
X-Bisel-Nonce:  <random 128-bit as base64url, 22 chars; 16..64 chars accepted>
X-Bisel-Sig:    <base64url of the 64-byte signature>
```

The signature covers this exact UTF-8 string (fields joined by a single `\n`, no trailing newline):

```
METHOD \n PATH \n SORTED_QUERY \n SHA256_HEX(body) \n TS \n NONCE
```

- `METHOD`: upper-case HTTP method, e.g. `PUT`.
- `PATH`: the request path as sent, e.g. `/v1/items/abc...`. No scheme, host or query.
- `SORTED_QUERY`: the query parameters sorted by name (then by value), each rendered `name=value`
  with RFC 3986 percent-encoding (only `A-Z a-z 0-9 - . _ ~` left unescaped), joined with `&`.
  **Empty string if there are no query parameters** (the line is then empty, so two `\n` in a row).
- `SHA256_HEX(body)`: lower-case hex SHA-256 of the exact request body bytes. For no body it is the hash of
  zero bytes: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  Sign the same bytes you send; do not re-serialize the JSON after hashing.
- `TS`, `NONCE`: exactly the header values.

Algorithms:

| Who               | `X-Bisel-Device` | Algorithm                                                | Signature bytes                                                                      |
| ----------------- | ---------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Registered device | its device id    | ECDSA P-256 over SHA-256 of the string                   | **raw `r \|\| s`, 64 bytes** (CryptoKit `ECDSASignature.rawRepresentation`; NOT DER) |
| Recovery key      | `recovery`       | Ed25519 over the string bytes (pure Ed25519, no prehash) | 64 bytes (CryptoKit `signature(for:)`)                                               |

CryptoKit: `try key.signature(for: Data(signedString.utf8)).rawRepresentation` for P-256 (it hashes with
SHA-256 itself; Secure Enclave keys work the same way). Do not pre-hash.

Server checks: unknown / revoked device, `|now - ts| > 60 s`, bad signature, reused nonce (nonces are remembered for 5 minutes,
pruned 100 rows per write, and only recorded after the signature verified). All checks are evaluated after one signature
verification (against a decoy key for an unknown principal), so every failure costs the same.

**Every authentication failure, and every unknown route/method (`HEAD` and `OPTIONS` included), returns the same empty `404`**
(no body, no content-type, the same headers). The reason is only in the server log. If your client gets a bare 404 check, in this order:
clock skew (> 60 s), signed string differs from what you sent (query order, body bytes), signature format
(raw r||s, not DER), device revoked, nonce reused, or the device id is wrong.

Worked example (for checking your string builder, not a signature):

```
GET /v1/sync?since=5&limit=100   ts=1700000000   nonce=AAAAAAAAAAAAAAAAAAAAAA   (no body)

GET\n/v1/sync\nlimit=100&since=5\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1700000000\nAAAAAAAAAAAAAAAAAAAAAA

PUT /v1/items/<id>   body {"base_rev":0,"blob":"AAAA"}   ts=1700000000   nonce=AAAAAAAAAAAAAAAAAAAAAA

PUT\n/v1/items/<id>\n\n44ea9931e45478b124af6fb811fcdfc8cbf68a330f748ea8b30ef56de79f800a\n1700000000\nAAAAAAAAAAAAAAAAAAAAAA
```

A reference implementation (Node WebCrypto, ~100 lines) is in `tests/support/client.ts`.

### The vault-admin signature (`X-Bisel-Admin`)

`POST /v1/rotate`, `POST /v1/devices`, `DELETE /v1/devices/:id` and `POST /v1/recovery/rotate` need a second signature: Ed25519 by the
**vault-admin key** (seed `HKDF(VK, "bisel/v1/admin-sig")`; its raw 32-byte public key is registered as `admin_pubkey` at bootstrap and
replaced by `new_admin_pubkey` on every rotation). It signs the UTF-8 string `bisel-admin/v1\n<X-Bisel-Device>\n<the exact string the device signature covers>`,
sent base64url in `X-Bisel-Admin`. A missing or wrong one is `403 {"error":"admin_signature_required"}` (the caller is already authenticated).
Because the canonical string includes the nonce and body hash, a signature cannot be reused for another request or by another device.

### Errors for authenticated requests

Once a request is authenticated, failures carry a JSON body `{"error": "<code>", ...}`:

| Status | `error`                                                                             | When                                                                                                                                                             |
| ------ | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | `invalid_request` / `invalid_json` / `invalid_query` / `invalid_id` / `invalid_key` | bad body, query, id, or public key                                                                                                                               |
| 404    | `not_found`                                                                         | item or device id unknown (has a JSON body; auth failures have none)                                                                                             |
| 409    | `conflict`                                                                          | stale `base_rev`; body `{"error":"conflict","current": <item record or null>}`. For `/v1/rotate`: `{"error":"conflict","epoch","head_seq"}`, nothing was changed |
| 403    | `admin_signature_required`                                                          | destructive route without a valid vault-admin signature                                                                                                          |
| 409    | `stale_epoch`                                                                       | key material built for an older vault-key epoch; body has the current `epoch`                                                                                    |
| 409    | `exists`                                                                            | device id already registered                                                                                                                                     |
| 413    | `too_large`                                                                         | blob over 256 KiB, or a body over the route's cap                                                                                                                |
| 500    | `internal`                                                                          | server bug                                                                                                                                                       |

### Failed-auth backoff

A valid signature is **never refused because of failures**, so the owner cannot be locked out by anyone sharing an address.
After `AUTH_FAIL_LIMIT` (20) failed attempts from one `CF-Connecting-IP` inside `AUTH_FAIL_WINDOW_SECONDS` (600), further
_failing_ requests from that address are answered `AUTH_BACKOFF_MS` (1000 ms, plus up to 25 % jitter) late and cause no more D1
writes (the counter stops at the limit; at most 20 000 addresses are tracked). Unknown routes, bad signatures, unknown devices and bad
bootstrap tokens are all treated alike, and an authentication failure is always the same empty 404. Local test hook:
`CF-Connecting-IP` is client-settable under `wrangler dev` (Cloudflare overwrites it in production).

### Flood limit, /healthz, CORS, headers

- **Flood limit.** Cloudflare's Workers rate-limiting binding (`RATE_LIMITER` in `wrangler.jsonc`) allows 300 requests per minute per
  `CF-Connecting-IP`, per Cloudflare location, before any D1 work. Over it, every route answers an empty `429` with `Retry-After: 10`;
  that says nothing about authentication. It is approximate by design (counts are local to a location and eventually consistent), so
  `DEPLOY.md` also adds a WAF rate-limiting rule in front of the Worker. Requests without `CF-Connecting-IP` (local dev only) are not limited.
- **`GET /healthz`** (and `HEAD`): empty `200` when D1 answers a `SELECT 1`, empty `503` when it does not. No version, name, counts or setup state; no signature.
- **CORS.** None, on purpose: the clients are native apps. `OPTIONS` is the same empty 404 as any unknown route and no `Access-Control-*` header is ever sent.
- **Headers.** Every response, 404 and 429 included, carries `Cache-Control: no-store`, `X-Content-Type-Options`, HSTS, a `default-src 'none'` CSP, `Referrer-Policy: no-referrer` and the cross-origin policies from `hono/secure-headers`.
- **Logs.** The Worker writes only `evt` lines: hashed address, device id prefix, method, path, status, reason. Never bodies, blobs, keys, tokens or request headers.
  `env.prod` keeps Workers Logs on with invocation logs and traces off, so Cloudflare adds no request-level records of its own.

## Endpoints

Item record (`item`): `{ "id", "rev", "seq", "deleted": bool, "blob": "<b64url, '' for tombstones>", "updated_at" }`.

### POST /v1/bootstrap

One time. Header `X-Bisel-Bootstrap: <BOOTSTRAP_TOKEN>`. Not signed. Wrong token, malformed headers, or
an already-bootstrapped server all return the uniform 404.

```json
{
  "device": {
    "id": "<device id>",
    "name": "Rodrigo's MacBook",
    "kind": "mac",
    "sig_pubkey": "<P-256 X9.63 65B>",
    "enc_pubkey": "<P-256 X9.63 65B>",
    "envelope": "<device envelope>"
  },
  "recovery_pubkey": "<Ed25519 raw 32B>",
  "recovery_enc_pubkey": "<X25519 raw 32B>",
  "recovery_envelope": "<recovery envelope>",
  "admin_pubkey": "<Ed25519 raw 32B, derived from VK>"
}
```

`kind` is a free tag `^[a-z0-9_-]{1,32}$` (`mac`, `iphone`, ...). Response `201 {"device_id","head_seq":0,"epoch":1}`.
The server imports both public keys, so a malformed key gives `400 invalid_key` (only after the token matched).

### GET /v1/sync?since=\<seq\>&limit=\<n\>

```json
{
  "items": [ /* item records with seq > since, ascending seq, tombstones included, at most `limit` */ ],
  "has_more": false,
  "next_since": 42,               // seq of the last returned item (or `since` if none): pass it as the next `since`
  "head_seq": 42,                 // current head, consistent with this snapshot
  "epoch": 1,                     // current vault-key epoch
  "devices": [ { "id","name","kind","sig_pubkey","enc_pubkey","created_at","last_seen_at" /* hour */,"revoked_at","activates_at" } ],
  "events": [ { "id","ts","device_id","type","subject_id" } ],   // since `events_since` (omit: the latest 50); types: bootstrap approve revoke rotate recovery recovery_rotate
  "recovery": { "alg": "ed25519", "pubkey": "...", "enc_pubkey": "...", "envelope": "..." }   // for .bisel-backup files and rotation
}
```

`seq` is gapless: every successful write takes exactly `head_seq + 1`. A rejected write consumes no seq.
Page until `has_more` is false.

### PUT /v1/items/:id

Body `{"base_rev": <int>, "epoch": <int>, "blob": "<b64url, 1..262144 bytes decoded>"}`. `base_rev` is 0 for a new item.

- `200 {"item": record}` with `rev = base_rev + 1` and a fresh `seq`.
- `409 {"error":"conflict","current": record|null}` when the stored `rev != base_rev` (e.g. creating an id that
  exists, or editing a stale revision). Nothing is written. Writing over a tombstone with its current `rev`
  resurrects the item.
- `409 stale_epoch` when `epoch` is not the current one (the blob's item key is wrapped under a rotated-away vault key).
- `413` over 256 KiB.

### DELETE /v1/items/:id?base_rev=\<n\>

Body `{"epoch": <int>, "marker": "<b64url, <= 256 bytes>"}`: the marker is a short value sealed under VK that other devices verify before honouring the delete; it is stored as the tombstone's blob. Tombstones the item (`deleted: true`, blob = marker, new `rev` and `seq`); the previous state goes to `item_history`. `200 {"item": record}`;
`409` on stale `base_rev` or if already deleted (with `current`); `404 not_found` if the id never existed.

### GET /v1/history?id=&after=&limit=

`200 {"entries":[{"id","item_id","rev","kind","blob","deleted","epoch","replaced_at"}]}`, oldest first, `after` = last `id` seen, `limit` 1..500.
`kind` `overwrite` / `delete`: the whole previous blob (or tombstone marker); `rotate`: the previous 80-char wrapped item key. Rows older than
`HISTORY_RETENTION_DAYS` (30) are pruned on writes. Ciphertext only.

### GET /v1/devices

`200 {"devices": [ ...same device objects as in sync ]}`.

### POST /v1/devices (approve a new device)

Called by an already-registered device. Body is the device object (same shape as `device` in bootstrap,
including `envelope` = VK encrypted to the new device's `enc_pubkey`) plus `"epoch"`, the epoch of that VK.
`201 {"device": {...}}`; the new device can sign requests immediately. `409 exists` if the id is taken,
`409 stale_epoch` if a rotation happened since the approver last synced.

### DELETE /v1/devices/:id

**Emergency only.** Revokes the device without rotating the vault key (any device may revoke any device, including itself).
Effective immediately: every later request signed by it gets the uniform 404, and its stored envelope is wiped.
`200 {"id","revoked_at","rotated":false}`; repeating is a no-op. The revoked device still holds VK, so clients revoke through
`POST /v1/rotate` instead.

### POST /v1/rotate

Vault-key rotation (SPEC §4), optionally revoking a device, in one atomic D1 batch.

```json
{
  "base_epoch": 1, // epoch the client's snapshot is at
  "base_seq": 42, // head_seq the client's item snapshot is at
  "revoke": "<device id>", // or null to rotate only; not the caller, not also listed in `devices`
  "new_admin_pubkey": "<Ed25519 raw 32B, derived from the NEW VK>", // the request itself is signed with the OLD admin key
  "tombstones": [{ "id": "...", "rev": 2, "marker": "<tombstone marker sealed under the NEW VK>" }], // every deleted record
  "items": [{ "id": "...", "rev": 3, "key": "<80 b64url chars = new 60-byte wrapped item key>" }],
  "devices": [{ "id": "...", "envelope": "<VK_new sealed to that device>" }], // every device that stays, the caller included
  "recovery_envelope": "<VK_new sealed to the recovery encryption key>"
}
```

Applied only if **all** of this holds at the moment of the transaction, otherwise `409 conflict` and nothing changes:
`epoch == base_epoch`; `head_seq == base_seq` (no item was written since the snapshot); `items` is exactly the set of live
(not deleted) items, each at exactly the stated `rev`, and `tombstones` is exactly the set of deleted records; `devices` is exactly the set of active devices minus `revoke`; `revoke`,
if given, is an active device.

Effects: each item's blob gets its first 80 characters replaced by `key` (payload, `rev` and AAD are untouched) and a fresh
`seq` (`base_seq + 1 … base_seq + n` in request order, tombstones after them); each listed device gets its new envelope; `recovery_envelope` and the admin key are replaced; the replaced wrapped keys go to `item_history`;
`revoke` is revoked and its envelope wiped; `epoch += 1`; `head_seq += n`.
`200 {"epoch","head_seq","rotated_items","rotated_tombstones","revoked"}`. Validation errors (shape, duplicates, caller missing from `devices`,
`revoke` equal to the caller) are `400` and never reach the database.

### GET /v1/envelope

`200 {"device_id", "envelope", "epoch"}`: the calling device's own envelope and the epoch of the key inside it.

### POST /v1/recovery/session

Signed with the **Ed25519 recovery key** (`X-Bisel-Device: recovery`), no device id.

- Empty body: `200 {"recovery_envelope","head_seq","epoch"}`. Use it to fetch the envelope and derive VK.
- Body `{"device": {id,name,kind,sig_pubkey,enc_pubkey,envelope}, "epoch": <from step 1>}`: additionally registers that
  replacement device (its `envelope` is VK encrypted to its own `enc_pubkey`, which the client can build after step one).
  `200 {"recovery_envelope","head_seq","epoch","device":{..., "activates_at"}}` (`activates_at` is non-null when `RECOVERY_ACTIVATION_DELAY_SECONDS` > 0: the new device gets the bare 404 until then); `409 exists` if the id is taken, `409 stale_epoch` if the
  key was rotated between the two calls (repeat from step 1). From then on the new device authenticates normally.

A fresh-install recovery is therefore: (1) session with empty body, (2) decrypt VK, (3) session with `device`,
(4) normal signed `GET /v1/sync`, (5) `POST /v1/recovery/rotate`.

### POST /v1/recovery/rotate

Signed by a normal device. Body `{"recovery_pubkey": "<Ed25519 raw 32B>", "recovery_enc_pubkey": "<X25519 raw 32B>", "recovery_envelope": "...", "epoch": <int>}`.
Replaces all three (this is a **new phrase**; vault-key rotation keeps the phrase); the old recovery key stops working at once.
`200 {"ok":true}`; `409 stale_epoch` if the envelope was built from a rotated-away key.

## Boxes, accounts, the dashboard

Design and threat model: [`DESIGN-accounts.md`](DESIGN-accounts.md). In short:

- A **box** is the unit the protocol always had (items, devices, recovery keys, epoch). Every box-scoped row carries `box_id`; a device's
  box is its own row, so signed requests are unchanged and a handler never takes a box from the request. Item ids are unique per box.
- Recovery requests (`X-Bisel-Device: recovery`) also send `X-Bisel-Box: <box id>` (bootstrap returns `box_id`). Without it they resolve to
  `legacy_box_00000000`, the box that existed before accounts (kept only for clients that predate the header). On a device request the header is malformed.
- An **account** (Better Auth, passkeys only, no email) owns at most one box. It never sees a key: it decides who may create storage and see the dashboard.
  Sync does not depend on it. A box holds at most `MAX_ITEMS_PER_BOX` items (live and tombstones): beyond that a new item is `409 box_full`.
- The dashboard is static files from `public/` served by the same Worker; `/api/*` is its API (`/api/auth/*` is Better Auth, `/api/box`,
  `/api/connect*` are ours; state-changing routes need `Origin` = `PUBLIC_ORIGIN` and `X-Bisel-CSRF: 1`).

### Device-code connect (no tokens typed)

```
POST /v1/connect            {device_name}            -> 201 {device_code, user_code, verification_uri, expires_in: 600, interval: 3}
POST /v1/connect/poll       {device_code}            -> {status: pending|approved|consumed|denied|expired, account_has_box?}
POST /v1/bootstrap          X-Bisel-Connect: <device_code>, same body as the token bootstrap -> 201 {device_id, box_id, head_seq, epoch}
POST /v1/box/claim          device + admin signed, empty body -> 201 (same shape as /v1/connect); links an existing unowned box
```

The Mac opens `verification_uri` (`/connect?code=ABCD-EFGH`); the person signs in or creates an account and approves; the Mac polls until
`approved`, then redeems the secret `device_code` at `/v1/bootstrap` (once; `409 box_exists` if the account already owns a box, which the poll also
reports as `account_has_box: true`). `claim` is for a box that already exists (the pre-accounts one): the same approval links it to the account and the
poll then answers `consumed`. `/v1/connect*` are unsigned; unknown or expired codes answer `expired`/the bare 404, pending requests are capped per address (bare 429).

## Layout

```
src/index.ts       routes (Hono), bootstrap, item/device/rotate/recovery handlers
src/accounts.ts    Better Auth configuration (passkeys, rate limits, passkey-first sign-up)
src/web.ts         the dashboard's API: box, delete box, connect approve/deny
src/connect.ts     device-code connect (unsigned half: start, poll) and its helpers
web/app.ts         the dashboard (plain DOM), bundled to public/app.js; public/ holds index.html, style.css, _headers (CSP)
legacy-tests/      migration test on a seeded pre-accounts database
src/auth.ts        signed-request middleware, canonical query, failed-auth backoff
src/schemas.ts     Zod schemas
src/encoding.ts    base64url / hex
migrations/        D1 migrations (wrangler d1 migrations)
tests/             vitest flow tests, tests/support/ (signing client, server and session helpers), tests/browser/ (the opt-in passkey test)
scripts/smoke.ts   manual end-to-end script
scripts/wipe-data.sql  empties every table (throwaway data after the first deploy check, DEPLOY.md step 10)
```

## Deploying (not done; only on the user's say-so)

See [`DEPLOY.md`](DEPLOY.md): exact steps, verification, and what the owner has to do. `wrangler.jsonc` has a local default
environment and an `env.prod` for `box.bisel.app` (`pnpm deploy:prod`). The D1 id in `env.prod` is the maintainer's database; a fork
deploying its own server replaces it, and the hostname, with its own.
