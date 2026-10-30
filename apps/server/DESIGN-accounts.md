# Accounts, multi-tenant boxes, web dashboard, device-code connect

Status: **approved 2026-10-29** (with the recommendations on §10). All three slices (§9) are built and tested locally (flow tests, a seeded legacy database, a real browser with virtual passkeys); the Mac-side client is not. Nothing deployed, production D1 untouched.

## 1. What changes, in one paragraph

Today one Worker + one D1 = one box, created once with `BOOTSTRAP_TOKEN`. After this: one Worker + one D1 = many boxes. A **box** is the unit that already exists (items, devices, recovery keys, epoch). An **account** (passkey login on the web) _owns_ at most one box. Devices still authenticate exactly as now (P-256 signature, vault-admin signature on destructive routes, uniform empty 404s); the only new thing on the signed path is that a device's row says which box it belongs to. Encryption stays on the clients. The account never holds, derives or receives any key: it decides who may _create storage_ and who sees the dashboard.

## 2. Principles (what must not regress)

1. The server learns nothing new about vault content. No key, envelope, or plaintext reaches `/api/*` (the dashboard API); the dashboard can only show what `GET /v1/devices` already shows.
2. **Sync never depends on the account.** A device-signed request is authorised by the device row alone, so a lost passkey, a deleted account or a dashboard outage does not stop existing devices from syncing and does not lock anyone out of recovery (the 24 words still work).
3. Uniform 404 and equal cost for every failed `/v1/*` request, including the new `X-Bisel-Box` lookup on recovery requests.
4. Account compromise must not be a confidentiality compromise. With a stolen passkey an attacker can: delete the box (the person's Macs still hold their local copy, which re-uploads into a new box), and approve connect codes. They cannot add a device to an existing box (that needs an existing device's envelope plus the admin signature, which need VK). See §8.
5. Minimal slice: one box per account, no sharing, no email, no billing.

## 3. Schema changes (migrations 0004, 0005)

Shared D1, `box_id` on every box-scoped table. Rejected alternatives: a D1 database per box (bindings are static, cannot be created at request time), and a Durable Object per box with SQLite (the strongest isolation and the right long-term answer past the D1 10 GB ceiling, but a rewrite of every query and of the batch-as-transaction assertions; not the smallest slice).

### 0004_accounts.sql: box scoping (table rebuilds, SQLite cannot alter a primary key)

| Table                                   | Change                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `meta` (single row, `id = 1`)           | becomes **`boxes`**: `id TEXT PRIMARY KEY` (box id, `[A-Za-z0-9_-]{16,64}`), same columns as `meta`, plus `owner_id TEXT UNIQUE` (NULL = unowned; UNIQUE gives one box per account, SQLite allows many NULLs), `item_count INTEGER` (kept by an `AFTER INSERT ON items` trigger; the write guard compares it with `MAX_ITEMS_PER_BOX`), `disabled_at INTEGER`. Drops `CHECK (id = 1)`. |
| `devices`                               | `+ box_id TEXT NOT NULL`, index `(box_id)`. Device `id` stays globally unique (it is the auth lookup key).                                                                                                                                                                                                                                                                             |
| `items`                                 | `+ box_id`, primary key becomes **`(box_id, id)`**, `UNIQUE (box_id, seq)`. This is the important one: today `ON CONFLICT(id)` is global, so two tenants sharing an item id would overwrite each other.                                                                                                                                                                                |
| `item_history`                          | `+ box_id`, index `(box_id, item_id, id)`                                                                                                                                                                                                                                                                                                                                              |
| `events`                                | `+ box_id`, index `(box_id, id)`                                                                                                                                                                                                                                                                                                                                                       |
| `nonces`, `auth_failures`, `assertions` | unchanged (global on purpose: replay and flood protection span tenants)                                                                                                                                                                                                                                                                                                                |

New table:

```sql
CREATE TABLE connect_requests (
  id               TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,   -- SHA-256 of the 256-bit secret only the Mac holds
  user_code        TEXT NOT NULL UNIQUE,   -- shown to the person, 8 chars from an unambiguous alphabet
  kind             TEXT NOT NULL,          -- 'create' | 'claim'
  box_id           TEXT,                   -- set for 'claim' (the box being linked)
  device_name      TEXT NOT NULL,
  ip_hash          TEXT NOT NULL,
  country          TEXT,                   -- cf-ipcountry, shown to the approver
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,       -- created_at + 600
  status           TEXT NOT NULL,          -- 'pending' | 'approved' | 'denied' | 'consumed'
  account_id       TEXT                    -- the approver
);
```

### 0005_better_auth.sql: generated, not hand-written

Better Auth's own tables (`user`, `session`, `account`, `verification`, `passkey`) from `npx @better-auth/cli generate` for the Kysely/D1 adapter, committed as a plain SQL migration. Better Auth 1.5+ takes the D1 binding directly; passkeys come from `@better-auth/passkey` (1.6 supports passkey-first registration, `requireSession: false` plus `resolveUser`). The versions get pinned exactly like the rest of `package.json`.

## 4. Migrating the current box (it keeps working and becomes Rodrigo's)

Migration 0004 is pure SQL, no data leaves D1:

1. Create `boxes` from `meta` with `id = 'legacy_box_00000000'` (fixed, 19 chars), `owner_id = NULL`, `item_count` from `COUNT(*)`.
2. Rebuild `devices`, `items`, `item_history`, `events` with `box_id = 'legacy_box_00000000'` on every existing row. Copy with `INSERT … SELECT`, drop the old table, rename.
3. Row counts before and after are asserted in the migration's own verification script (`scripts/verify-0004.sql`, run against a copy).

What keeps working with **no client update**:

- Every device-signed request: the box comes from the device row. Headers and canonical string are unchanged.
- Recovery requests from a client that does not send `X-Bisel-Box`: they resolve to `legacy_box_00000000` (a constant in code, to be deleted once the Mac app sends the header; see §5).
- The bootstrap token path: `POST /v1/bootstrap` with `X-Bisel-Bootstrap` still works (now creating an _unowned_ box instead of "once ever"). After migration the prod `BOOTSTRAP_TOKEN` secret should be deleted; the route then answers the uniform 404 for everyone.

**Becoming Rodrigo's account:** after deploy he signs up on the dashboard (empty account), then on the Mac (already synced to box.bisel.app) chooses _Link to account_. The Mac calls `POST /v1/box/claim` signed by the device **and** by the vault-admin key (so Touch ID is required and a bare device key cannot link the box). That returns a user code; the Mac opens `/connect?code=…`; he approves while signed in; `boxes.owner_id` is set. The same mechanism lets any pre-account box be linked later.

**Production steps, all needing Rodrigo's explicit go (none done):**

1. `wrangler d1 export bisel --remote` to a local file (backup; D1 Time Travel also covers 30 days).
2. Rehearse 0004 on a copy of that export locally; run `verify-0004.sql`.
3. Set secrets: `BETTER_AUTH_SECRET`; deploy; apply migrations `--remote`. Ordering: the new schema and new code are not compatible with each other's opposite (old code has no `box_id`), so migrate then deploy back to back. Rodrigo's single box sees a few seconds of 404/500 on sync, which clients already retry.
4. Smoke: sync from the Mac, then the claim flow.

## 5. Protocol changes on `/v1`

- **Device auth**: `SELECT … FROM devices WHERE id = ?` now also returns `box_id`; the principal becomes `{ kind: "device", id, boxId }`. Every query in `index.ts` takes `boxId` from the principal (about 40 statements). The `assertThat(... FROM meta WHERE id = 1 ...)` guards become `FROM boxes WHERE id = ?box`. A `disabled_at` box answers like a revoked device.
- **Recovery auth**: new header `X-Bisel-Box: <box id>`. Absent → `legacy_box_00000000` (temporary). Unknown box → decoy verification, same cost, uniform 404. The header is not part of the signed string because the signature already verifies against that box's recovery key; a replay against another box fails.
- **Bootstrap** gains a second credential and always returns `box_id`:
  - `X-Bisel-Bootstrap: <token>` (operator/dev path, unowned box), as today.
  - `X-Bisel-Connect: <device_code>` (accounts): valid only if that request is `approved`, `kind = 'create'`, unexpired, unconsumed. Creating the box, setting `owner_id`, inserting the first device and marking the request `consumed` happen in one D1 batch with assertions, so a code is single-use and an account cannot get a second box (UNIQUE `owner_id` is the backstop).
  - Same decoy/timing treatment as today for every failure.
  - Response: `201 { device_id, box_id, head_seq: 0, epoch: 1 }`.
- **New public routes** (unsigned, behind the existing per-IP flood limit and the failed-request counter):
  - `POST /v1/connect` `{ device_name }` → `{ device_code, user_code, verification_uri, expires_in: 600, interval: 3 }`. Creates a `create` request. Per-IP cap on pending requests.
  - `POST /v1/connect/poll` `{ device_code }` → `{ status: 'pending' | 'approved' | 'denied' | 'expired', account_has_box: bool }`. Unknown codes answer `expired`. If `account_has_box` is true the Mac does not bootstrap (see §6.3).
- **New signed route**: `POST /v1/box/claim` (device + admin signature) → `{ user_code, verification_uri, expires_in }`; the Mac then polls `GET /v1/box` (signed) → `{ box_id, linked: bool }`.
- Limits against open sign-up: `boxes.item_count` capped at 5,000 items and `devices` at the existing `MAX_DEVICES`, enforced in the same guarded batch as the write; blob cap stays 256 KiB (worst case ≈ 1.2 GB if someone fills a box, so a per-box byte counter is a **follow-up**, flagged in §10).

## 6. Web: auth, dashboard, connect

### 6.1 Serving

Workers Static Assets from `apps/server/public/`, same Worker, same hostname. `run_worker_first: ["/v1/*", "/api/*", "/healthz"]`, so `/v1/*` keeps its uniform-404 catch-all and every other path is a static file (SPA fallback to `index.html`). A `public/_headers` gives pages a CSP of `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'` plus the same hardening headers. The dashboard is plain TypeScript bundled with esbuild into one file, no framework, no third-party script. Built for the existing design language of the Mac app (dark, minimal).

### 6.2 Auth: Better Auth, passkeys only

- Better Auth on the Worker at `/api/auth/*`, D1 binding directly, `@better-auth/passkey`. `rpID = box.bisel.app` (localhost in dev), `origin = https://box.bisel.app`. No password, no social, no magic link in v1.
- **Sign-up is passkey-first**: the page asks for a display name, the server returns a short-lived signed token for that name (its `resolveUser` verifies it and creates the user), the browser runs the WebAuthn ceremony. Sign-in is a discoverable-credential passkey prompt.
- Better Auth's `user.email` is non-null. In v1 there is no email: the user row gets a synthetic `<random>@accounts.bisel.invalid`, nothing is ever sent. Consequence: **no email recovery**. Losing every passkey means losing dashboard access; the box itself is unaffected (principle 2) and the person can add a passkey on any signed-in browser/device beforehand. The dashboard nags to register a second passkey.
- Sessions: Better Auth cookie, `Secure; HttpOnly; SameSite=Lax`, host-only, 7-day sliding. All state-changing `/api/*` routes additionally require `Origin == https://box.bisel.app` and a custom header `X-Bisel-CSRF: 1` (cannot be set cross-site without a preflight, and there is no CORS).
- `BETTER_AUTH_SECRET` is a Worker secret like `BOOTSTRAP_TOKEN`; nothing in the repo.
- Rate limits: the existing global per-IP limiter covers `/api/*`; plus Better Auth's own rate limiting backed by D1, with a stricter budget on sign-up. Cloudflare Turnstile on sign-up is the cheap next step against farmed accounts (open question 3).

### 6.3 Device-code connect

```
Mac (onboarding, sync step)            Server                          Browser (box.bisel.app)
  POST /v1/connect {name}  ───────────▶ store hash(device_code), user_code
  ◀──── device_code (secret), user_code, uri
  open  /connect?code=ABCD-EFGH ───────────────────────────────────────▶ sign in / sign up (passkey)
  poll /v1/connect/poll every 3 s                                         shows: device name, country, code,
                                                                          "Does your Mac show ABCD-EFGH?"
                                        ◀─── POST /api/connect/approve (session + CSRF)
  poll → approved ◀─────────────────────
  POST /v1/bootstrap  X-Bisel-Connect: device_code, same body as today
  ◀──── 201 { box_id, … }  → Mac stores box_id, normal signed sync from here
```

- The device code never leaves the Mac and the server; the browser only ever sees the short user code. A user code is useless without the matching device code, and the poll needs the device code.
- Approval needs a live session. The page shows the device name, the requesting country and when, and requires the person to confirm the code matches the Mac (a phished link can only say what the attacker's Mac says, which is the point of showing it).
- If the account **already has a box**, approval of a `create` request is refused with a clear message ("This account already has a box. Add this Mac from a device that's already connected, or restore with your recovery phrase."). Joining an existing box needs a VK-holding device (existing enrollment flow, `POST /v1/devices` with the admin signature); the web cannot do that and must not. **Out of the first slice**: joining via device code. The poll's `account_has_box` and returning `box_id` leave the hook for it, and for pointing the existing recovery flow at the right box via `X-Bisel-Box`.
- Expiry 10 min, `interval` 3 s, a request is consumed once; pending requests per IP capped (e.g. 5); user code alphabet `23456789ABCDEFGHJKMNPQRSTUVWXYZ`, 8 chars (≈ 1e12) and lookup is only possible with a session, so guessing costs an authenticated account and rate limiting.

### 6.4 Dashboard (first slice)

Signed-out: sign in / create account. Signed-in: account name, passkeys (add / remove, keep at least one), the box (created date, items count, epoch) and its **devices** (name, kind, added, last seen, revoked), read-only, from the same columns `GET /v1/devices` exposes. One write: **Delete box** (fresh passkey re-authentication, typed confirmation, removes all rows of that `box_id`). Revoking a device is _not_ in the dashboard: a safe revoke rotates the vault key client-side. Sign out.

## 7. Mac app (apple/)

- `SyncClient`: `connectStart`, `connectPoll`, bootstrap with `X-Bisel-Connect`, send `X-Bisel-Box` on recovery requests.
- `LocalIdentity` stores `boxID` (nil for legacy; recovery then omits the header).
- Onboarding: after the recovery phrase, a new **sync step**: "Sync with box.bisel.app" opens the browser to `/connect?code=…`, shows the code and waits (poll), then calls `connectServer` with the connect credential instead of a token; "Skip, keep it on this Mac" stays. Settings gets the same flow and _Link to account_ (claim) for the existing box. The token field disappears for end users (stays under Debug for dev servers).
- Core change is small: `connectServer(_:bootstrapToken:)` gets a credential enum `.token(String) | .connect(deviceCode)`.

## 8. Threat model

| Threat                                                       | Handling                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cross-tenant read/write through a missed `box_id`            | All queries take `boxId` from the authenticated principal, never from input; flow tests run two boxes against every route and assert no read/write crosses. The `(box_id, id)` key removes the id-collision overwrite. Residual risk is a forgotten `WHERE`, which is why the isolation tests are mandatory, not optional. |
| Device-id squatting / probing across tenants                 | Ids are 128-bit random; `exists` on register is the only signal and needs an authenticated or connect-approved call. Negligible.                                                                                                                                                                                           |
| Stolen passkey / session                                     | Cannot read vault content, cannot add a device to an existing box. Can delete the box (clients keep local copies) or squat an empty account's `create`. Fresh passkey re-auth for delete; sessions short.                                                                                                                  |
| Phishing a victim into approving the attacker's connect code | Attacker gets storage under the victim's account, not data. Mitigated by the on-page "does your Mac show this code?" confirmation, device name and country, and by the dashboard showing the device list. Residual: a careless approve on an empty account.                                                                |
| Device-code brute force / interception                       | 256-bit device code, hashed at rest, single-use, 10 min, TLS. User code alone is not a credential.                                                                                                                                                                                                                         |
| CSRF on approve / delete                                     | `Origin` check + custom header + `SameSite=Lax`, no CORS.                                                                                                                                                                                                                                                                  |
| Open sign-up abuse (storage fill, flood)                     | Per-box item and device caps now; Turnstile and a per-box byte cap as follow-ups; D1 total (10 GB) is the scaling ceiling that triggers the Durable-Object move. `boxes.disabled_at` is the operator kill switch.                                                                                                          |
| Account enumeration                                          | No email, display names are not unique-checked publicly; sign-in is discoverable-credential, so no "does this user exist" oracle.                                                                                                                                                                                          |
| Operator (Rodrigo) reading data                              | Unchanged: ciphertext only. The dashboard API cannot return key material because none is stored.                                                                                                                                                                                                                           |
| Dashboard XSS                                                | Strict CSP, no inline script, no third-party script, no `innerHTML` with server strings (device names are shown with `textContent`; server already strips control/bidi characters).                                                                                                                                        |
| Availability: Better Auth outage / bug                       | Isolated to `/api/*` and `/connect`; `/v1` does not call it.                                                                                                                                                                                                                                                               |

## 9. Build plan (the smallest slice, after approval)

1. **Server core**: migration 0004, `boxId` through auth and all queries, bootstrap `box_id`, `X-Bisel-Box` on recovery. Extend `tests/flow.spec.ts` with a two-box isolation flow over every route. _Gate: existing 24 flows still pass unchanged against a migrated copy of a legacy DB._
2. **Accounts**: Better Auth + passkey + migration 0005, static assets, sign-up/sign-in/dashboard, `/api/box`. Flow test drives a real browser with Playwright's virtual authenticator (CDP WebAuthn): sign up, sign in, see devices, delete.
3. **Connect**: `/v1/connect*`, bootstrap via connect code, `/connect` page, claim route. Flow test: script plays the Mac against a local server while Playwright plays the browser. Then Swift side and a run of the real Mac app against `pnpm dev`.
4. Docs: README, SPEC §6, DEPLOY.md (new secret, migration order).

Nothing is deployed and prod D1 is not touched at any point without a separate ask.

## 10. Decisions I need from Rodrigo

1. **No email in v1** (passkey + display name only; no email recovery), or add email now (verification mail needs Cloudflare Email Service)? Recommendation: no email now.
2. **One box per account**, joining a box from a second Mac stays the existing enrollment/recovery flow in the first slice. OK?
3. **Turnstile on sign-up** in the first slice? Recommendation: yes if box.bisel.app will be public, can wait if it stays invite-by-link.
4. **Deleting the prod `BOOTSTRAP_TOKEN`** after migration (so only account-created boxes can appear). Recommendation: yes.
5. Per-box limits (5,000 items) and a byte cap as follow-up: acceptable?

## 11. As built: where it differs from the proposal above

- **Claim polling**: `POST /v1/box/claim` returns the same `device_code` pair as `POST /v1/connect`, and the Mac polls `POST /v1/connect/poll` (answer `consumed` = linked, `denied` = the account already had a box). There is no `GET /v1/box`.
- **Cap**: `item_count` is kept by an insert trigger and the cap is `MAX_ITEMS_PER_BOX` (var, 5000), answered `409 box_full`. No per-box byte cap yet (follow-up, §10 decision 5).
- **Sign-up abuse**: no Turnstile yet. The Worker-wide limiter, Better Auth's per-route limiter (D1-backed) and the per-address cap on pending connect requests are the only brakes.
- **Passkey removal** is enforced in the UI only (the Remove button is disabled for the last passkey); the server-side guard is a follow-up.
- **No events** are written when a box is linked to an account (the Mac client would show an unknown event type as a foreign event).
- **Tests**: `tests/tenancy.test.ts` (isolation, cap, kill switch), `tests/accounts.test.ts` (dashboard API and connect/claim with signed-in sessions), `tests/browser/passkey.spec.ts` (the passkey ceremony in a real browser, opt-in), `legacy-tests/` (migration 0004 on a seeded pre-accounts database).
