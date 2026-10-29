# bisel server

Cloudflare Worker (TypeScript, Hono, Zod) + D1. Zero-knowledge sync API: the server stores only
ciphertext blobs, public keys and opaque envelopes. Contract: [`../SPEC.md`](../SPEC.md) §6.
This README is the wire-level detail for client implementers.

Everything here runs against `wrangler dev` with a **local** D1. Nothing is deployed and no
Cloudflare account is touched.

## Commands

Run from `bisel/server/`. Needs Node 22.18+ (developed on 24; `scripts/smoke.ts` relies on Node's built-in TypeScript stripping) and pnpm.

```sh
pnpm install            # first time
pnpm dev                # creates .dev.vars if missing, applies local D1 migrations, serves http://localhost:8787
pnpm migrate            # apply migrations to the local D1 only (pnpm dev already does this)
pnpm reset              # stop `pnpm dev` first, then wipe local D1 state (.wrangler/state): the next `pnpm dev` is a fresh, un-bootstrapped server
pnpm test               # Playwright flow tests; starts its own wrangler dev on :8788 with a throwaway D1 (AUTH_BACKOFF_MS=400)
pnpm typecheck
node scripts/smoke.ts   # manual walk through bootstrap/put/conflict/delete/approve/revoke/recovery against :8787
```

Local dev bootstrap token (from `.dev.vars`, created from `.dev.vars.example`): `dev-bootstrap-token`.
`POST /v1/bootstrap` works exactly once per database; after `pnpm reset` it works again.

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
  routes 32 KiB, rotate 4 MiB, bootstrap 64 KiB). Rotation takes up to 20 000 items and 64 devices. `GET /v1/sync` `limit` 1..500, default 200.

## How a client signs requests

Every request except `POST /v1/bootstrap` carries four headers:

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

| Who | `X-Bisel-Device` | Algorithm | Signature bytes |
|-----|------------------|-----------|-----------------|
| Registered device | its device id | ECDSA P-256 over SHA-256 of the string | **raw `r \|\| s`, 64 bytes** (CryptoKit `ECDSASignature.rawRepresentation`; NOT DER) |
| Recovery key | `recovery` | Ed25519 over the string bytes (pure Ed25519, no prehash) | 64 bytes (CryptoKit `signature(for:)`) |

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

### Errors for authenticated requests

Once a request is authenticated, failures carry a JSON body `{"error": "<code>", ...}`:

| Status | `error` | When |
|--------|---------|------|
| 400 | `invalid_request` / `invalid_json` / `invalid_query` / `invalid_id` / `invalid_key` | bad body, query, id, or public key |
| 404 | `not_found` | item or device id unknown (has a JSON body; auth failures have none) |
| 409 | `conflict` | stale `base_rev`; body `{"error":"conflict","current": <item record or null>}`. For `/v1/rotate`: `{"error":"conflict","epoch","head_seq"}`, nothing was changed |
| 409 | `stale_epoch` | key material built for an older vault-key epoch; body has the current `epoch` |
| 409 | `exists` | device id already registered |
| 413 | `too_large` | blob over 256 KiB, or a body over the route's cap |
| 500 | `internal` | server bug |

### Failed-auth backoff

A valid signature is **never refused because of failures**, so the owner cannot be locked out by anyone sharing an address.
After `AUTH_FAIL_LIMIT` (20) failed attempts from one `CF-Connecting-IP` inside `AUTH_FAIL_WINDOW_SECONDS` (600), further
*failing* requests from that address are answered `AUTH_BACKOFF_MS` (1000 ms, plus up to 25 % jitter) late and cause no more D1
writes (the counter stops at the limit; at most 20 000 addresses are tracked). Unknown routes, bad signatures, unknown devices and bad
bootstrap tokens are all treated alike. There is no 429, because that would reveal the server. Flood protection is the
Cloudflare zone rate-limit rule described in `DEPLOY.md`. Local test hook: `CF-Connecting-IP` is client-settable under `wrangler dev`
(Cloudflare overwrites it in production).

## Endpoints

Item record (`item`): `{ "id", "rev", "seq", "deleted": bool, "blob": "<b64url, '' for tombstones>", "updated_at" }`.

### POST /v1/bootstrap

One time. Header `X-Bisel-Bootstrap: <BOOTSTRAP_TOKEN>`. Not signed. Wrong token, malformed headers, or
an already-bootstrapped server all return the uniform 404.

```json
{
  "device": {
    "id": "<device id>", "name": "Rodrigo's MacBook", "kind": "mac",
    "sig_pubkey": "<P-256 X9.63 65B>", "enc_pubkey": "<P-256 X9.63 65B>", "envelope": "<device envelope>"
  },
  "recovery_pubkey": "<Ed25519 raw 32B>",
  "recovery_enc_pubkey": "<X25519 raw 32B>",
  "recovery_envelope": "<recovery envelope>"
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
  "devices": [ { "id","name","kind","sig_pubkey","enc_pubkey","created_at","last_seen_at","revoked_at" } ],
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

Tombstones the item (`deleted: true`, empty blob, new `rev` and `seq`). `200 {"item": record}`;
`409` on stale `base_rev` or if already deleted (with `current`); `404 not_found` if the id never existed.

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
  "base_epoch": 1,                 // epoch the client's snapshot is at
  "base_seq": 42,                  // head_seq the client's item snapshot is at
  "revoke": "<device id>" ,        // or null to rotate only; not the caller, not also listed in `devices`
  "items": [ { "id": "...", "rev": 3, "key": "<80 b64url chars = new 60-byte wrapped item key>" } ],
  "devices": [ { "id": "...", "envelope": "<VK_new sealed to that device>" } ],   // every device that stays, the caller included
  "recovery_envelope": "<VK_new sealed to the recovery encryption key>"
}
```

Applied only if **all** of this holds at the moment of the transaction, otherwise `409 conflict` and nothing changes:
`epoch == base_epoch`; `head_seq == base_seq` (no item was written since the snapshot); `items` is exactly the set of live
(not deleted) items, each at exactly the stated `rev`; `devices` is exactly the set of active devices minus `revoke`; `revoke`,
if given, is an active device.

Effects: each item's blob gets its first 80 characters replaced by `key` (payload, `rev` and AAD are untouched) and a fresh
`seq` (`base_seq + 1 … base_seq + n` in request order); each listed device gets its new envelope; `recovery_envelope` is replaced;
`revoke` is revoked and its envelope wiped; `epoch += 1`; `head_seq += n`.
`200 {"epoch","head_seq","rotated_items","revoked"}`. Validation errors (shape, duplicates, caller missing from `devices`,
`revoke` equal to the caller) are `400` and never reach the database.

### GET /v1/envelope

`200 {"device_id", "envelope", "epoch"}`: the calling device's own envelope and the epoch of the key inside it.

### POST /v1/recovery/session

Signed with the **Ed25519 recovery key** (`X-Bisel-Device: recovery`), no device id.
- Empty body: `200 {"recovery_envelope","head_seq","epoch"}`. Use it to fetch the envelope and derive VK.
- Body `{"device": {id,name,kind,sig_pubkey,enc_pubkey,envelope}, "epoch": <from step 1>}`: additionally registers that
  replacement device (its `envelope` is VK encrypted to its own `enc_pubkey`, which the client can build after step one).
  `200 {"recovery_envelope","head_seq","epoch","device":{...}}`; `409 exists` if the id is taken, `409 stale_epoch` if the
  key was rotated between the two calls (repeat from step 1). From then on the new device authenticates normally.

A fresh-install recovery is therefore: (1) session with empty body, (2) decrypt VK, (3) session with `device`,
(4) normal signed `GET /v1/sync`, (5) `POST /v1/recovery/rotate`.

### POST /v1/recovery/rotate

Signed by a normal device. Body `{"recovery_pubkey": "<Ed25519 raw 32B>", "recovery_enc_pubkey": "<X25519 raw 32B>", "recovery_envelope": "...", "epoch": <int>}`.
Replaces all three (this is a **new phrase**; vault-key rotation keeps the phrase); the old recovery key stops working at once.
`200 {"ok":true}`; `409 stale_epoch` if the envelope was built from a rotated-away key.

## Layout

```
src/index.ts       routes (Hono), bootstrap, item/device/rotate/recovery handlers
src/auth.ts        signed-request middleware, canonical query, failed-auth backoff
src/schemas.ts     Zod schemas
src/encoding.ts    base64url / hex
migrations/        D1 migrations (wrangler d1 migrations)
tests/             Playwright flow tests + tests/support/client.ts (signing client)
scripts/smoke.ts   manual end-to-end script
```

## Deploying (not done; only on the user's say-so)

See [`DEPLOY.md`](DEPLOY.md): exact steps, verification, and what the owner has to provide. `wrangler.jsonc` has a local default
environment and an `env.prod` with placeholders (`wrangler deploy --env prod`).
