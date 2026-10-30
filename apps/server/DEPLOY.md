# Deploying and running the bisel server (box.bisel.app)

Status (2026-10-30): **live**, multi-tenant, with passkey accounts. The Worker is `env.prod` in `wrangler.jsonc`: name `bisel-server`,
Custom Domain `box.bisel.app`, `workers.dev` and preview URLs off. The production D1 database (`bisel`, id in `wrangler.jsonc`) has
migrations **0001 to 0006** applied and holds no real box yet. Nothing in this file has been run by the session that wrote it:
every command is for the owner (or a session on the owner's machine).

Run every command from `bisel/server/` with the pinned wrangler (`pnpm exec wrangler`, never a global one). Every command that touches
Cloudflare carries `--env prod` and, for D1, `--remote` (without `--remote` D1 commands only touch the local dev database). Secrets live
in Doppler (project `bisel`, config `prd`; `doppler setup` binds this directory): `doppler run -- <command>` injects
`CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`. Never print a secret or a recovery phrase into a chat, a log or a repo file.

## 1. What is deployed

| Piece | Where it comes from |
|---|---|
| Worker (Hono API `/v1/*`, dashboard API `/api/*`, `/healthz`) | `src/`, built by wrangler |
| Dashboard (static pages) | `public/`, built by `pnpm build:web`; wrangler runs it from `build.command` on deploy. Served by the assets binding; only `/v1/*`, `/api/*` and `/healthz` run the Worker first, unknown paths fall back to `index.html` (so `/connect` deep-links work) |
| D1 database `bisel` | `migrations/` (0001-0008). Many boxes in one database: `box_id` on every box table |
| Accounts | Better Auth with passkeys only (tables from migration 0005); no passwords, no email |
| Rate limiting | three layers: Workers rate-limiting binding `RATE_LIMITER` (300 req/min per address, bare `429`), a WAF rate-limiting rule (section 4), Better Auth's own per-route limits (D1-backed) |
| Logging | Workers Logs on, invocation logs and traces off; only the Worker's own lines (`evt`, `reason`, 8-char address hash, 8-char device prefix, method, path, status), never bodies, blobs, keys or tokens; query strings redacted |

**Secrets** (Worker secrets, never in `wrangler.jsonc`):

| Name | Purpose | Required |
|---|---|---|
| `BETTER_AUTH_SECRET` | signs dashboard sessions | yes: sign-in fails without it |
| `BOOTSTRAP_TOKEN` | lets the operator create an unowned box with a typed token | no: once only account-created boxes should exist, delete it. Unset means `POST /v1/bootstrap` with a token is closed |

**Vars** (`env.prod.vars`): `PUBLIC_ORIGIN` (`https://box.bisel.app`; passkeys are bound to this hostname, so changing it orphans every passkey),
`AUTH_FAIL_LIMIT` / `AUTH_FAIL_WINDOW_SECONDS` / `AUTH_BACKOFF_MS` (failed-auth delay, never refuses a valid signature),
`HISTORY_RETENTION_DAYS` (30), `MAX_ITEMS_PER_BOX` (5000), `MAX_BOX_BYTES` (64 MiB of blob text per box, also bounds the box's retained history),
`RECOVERY_ACTIVATION_DELAY_SECONDS` (86400: a device added with the 24 words is held back 24 h and announced to every enrolled device).

Confirm the live state (read-only):

```bash
pnpm exec wrangler d1 migrations list bisel --env prod --remote      # which migrations production has
pnpm exec wrangler secret list --env prod                            # expect BETTER_AUTH_SECRET (and BOOTSTRAP_TOKEN until retired)
pnpm exec wrangler deployments list --env prod                       # versions, newest last
```

## 2. Production migrations still to apply (0007 and 0008)

Production has 0001-0006. This work adds two. Apply them **before** deploying the new Worker, in this order:

| # | File | What it does | On the empty production database |
|---|---|---|---|
| 0007 | `0007_drop_rotate_history.sql` | `DELETE FROM item_history WHERE kind = 'rotate'`: the rotation no longer keeps old wrapped item keys | deletes nothing; safe |
| 0008 | `0008_box_bytes.sql` | adds `boxes.stored_bytes`, backfills it, adds three triggers on `items` | no rows to backfill, trigger creation only; safe |

Both are safe to apply to the current (empty) production database, and also to a database that holds boxes (0008's backfill is one `SUM` per box).
The order matters in one direction only: the new Worker reads `stored_bytes`, so the column must exist first. The previous Worker keeps working
with 0007 and 0008 applied (it ignores the column; the triggers maintain it), so a Worker rollback never needs the migrations rolled back.

```bash
pnpm exec wrangler d1 time-travel info bisel --env prod                     # write down the bookmark id it prints
pnpm exec wrangler d1 migrations apply bisel --env prod --remote            # applies 0007, 0008 in order
pnpm exec wrangler d1 migrations list bisel --env prod --remote             # expect all of 0001-0008 applied
doppler run -- pnpm deploy:prod                                             # or: pnpm deploy:prod
```

Verify (section 6, a and b). If something is wrong: roll the Worker back (`pnpm exec wrangler rollback --env prod`); only if data is damaged,
restore the bookmark (section 5.2). 0007 deletes rows and cannot be undone except through the bookmark, which is why the bookmark comes first
(the rows it removes are not read by any client).

Before any deploy, from the repo root (local only; stop on the first red): `scripts/check-all.sh` (server typecheck, `pnpm test`, `pnpm test:legacy`, BiselCore flow suite,
Mac app build); `scripts/check-all.sh --release` before shipping the Mac app.

## 3. Setting the server up from nothing (kept for rebuilding)

1. Prerequisites: the `bisel.app` zone is active on the Cloudflare account; `box.bisel.app` has no existing DNS record (a Custom Domain cannot be
   created over a CNAME); Workers **Paid** is recommended (30-day Time Travel instead of 7, CPU headroom for large rotations).
2. `pnpm install --frozen-lockfile && pnpm check-types && pnpm test` (all local).
3. `pnpm exec wrangler login` (owner's browser), then `pnpm exec wrangler d1 create bisel --location weur`; put the printed `database_id` in
   `env.prod.d1_databases[0].database_id` and commit it (an id is not a credential).
4. `pnpm exec wrangler d1 migrations apply bisel --env prod --remote`.
5. Secret: `openssl rand -base64 48 | pnpm exec wrangler secret put BETTER_AUTH_SECRET --env prod` (or from Doppler, section 5.1).
6. `pnpm deploy:prod`: uploads the Worker and dashboard, creates the Custom Domain (DNS record and certificate included; allow a minute or two).
   In the dashboard (Workers & Pages, bisel-server, Settings, Domains & Routes) the only entry must be `box.bisel.app`.
7. WAF flood rule (dashboard, bisel.app, Security, WAF, Rate limiting rules): hostname equals `box.bisel.app`, per IP, 100 requests / 10 s, block 10 s
   (Free plan limits). Do **not** add a rule that blocks unknown paths or methods: Cloudflare's block page would differ from the Worker's bare 404.
   Optional: SSL/TLS minimum version 1.2, Always Use HTTPS.
8. Create the first account on `https://box.bisel.app/`, then in the Mac app choose to create a box / link to account (device-code connect).
   Only if you want an operator-created box: `wrangler secret put BOOTSTRAP_TOKEN`, bootstrap with it, then `wrangler secret delete BOOTSTRAP_TOKEN`.

## 4. Backups

D1 Time Travel is always on: point-in-time restore for 30 days on Workers Paid, 7 on Free. `pnpm exec wrangler d1 time-travel info bisel --env prod`
prints the current bookmark. It restores the **whole database** (every box and account), see 5.2. Independent of Cloudflare, every device holds
its own copy and the app's `.bisel-backup` plus the 24 words rebuilds a box on any new database. A SQL dump (ciphertext plus account rows, treat it as
sensitive): `pnpm exec wrangler d1 export bisel --env prod --remote --output ~/bisel-d1-$(date +%F).sql`. Scheduled exports: section 7.

## 5. Runbook

### 5.1 Rotate a secret

`BETTER_AUTH_SECRET` (effect: every dashboard session ends, people sign in again with their passkey; passkeys and boxes are unaffected):

```bash
doppler secrets set BETTER_AUTH_SECRET="$(openssl rand -base64 48)"                                   # Doppler stays the source of truth
doppler secrets get BETTER_AUTH_SECRET --plain | pnpm exec wrangler secret put BETTER_AUTH_SECRET --env prod
```

`wrangler secret put` creates and deploys a new Worker version at once. Verify: `GET https://box.bisel.app/` loads and a passkey sign-in works.
`BOOTSTRAP_TOKEN`: same two commands with the new value, or `pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env prod` to close the endpoint (the
normal end state). `CLOUDFLARE_API_TOKEN` (Doppler only): create the replacement in the Cloudflare dashboard (account-owned, Workers Scripts, D1, Zone read,
Workers Routes edit), update Doppler, then delete the old token there. Device keys and the 24 words are not server secrets and are never rotated here.

### 5.2 Restore from a Time Travel bookmark

Use when data was damaged by a bad migration or a bad deploy. Everything written after the restore point is lost for **all** boxes and accounts:
an account created after it must sign up again; devices of a box notice a server that is behind (`serverRolledBack`) and re-upload what the restore lost
(the app's "acknowledge server reset" path), so no device data is lost as long as the devices still hold it.

```bash
pnpm exec wrangler d1 time-travel info bisel --env prod                                   # note the CURRENT bookmark first: it is your undo
pnpm exec wrangler d1 time-travel restore bisel --env prod --bookmark=<id>                # or --timestamp=<RFC3339 or unix seconds>
pnpm exec wrangler d1 time-travel info bisel --env prod                                   # confirm; the restore also printed an undo bookmark
```

Restores are limited to 10 per 10 minutes. If the restore crosses a migration, the schema is restored with it: redeploy the matching Worker version
(5.3) before opening the door again.

### 5.3 Roll back a Worker version together with the migrations

1. Decide what is wrong. A bad Worker with a good schema: `pnpm exec wrangler rollback --env prod` (previous version; `wrangler deployments list --env prod` shows the
   versions). A rollback does not touch D1.
2. The schema only needs to go back if the previous Worker cannot run on it. Rule: migrations are written **additive** (new column, new table, new trigger), so the
   previous Worker keeps working on the new schema and nothing needs to be undone. 0005 to 0008 were written that way.
3. If a migration must be undone, the only complete undo is the Time Travel bookmark taken before it (5.2); then roll the Worker back too. Reversibility per migration:

| Migration | Safely reversible? |
|---|---|
| 0001-0003 | initial schema; never reverse on a database that has data |
| 0004 accounts | **No.** Rebuilds `devices`, `items`, `item_history`, `events` with `box_id`, turns `meta` into `boxes` and drops `meta`. Only a bookmark taken before it restores the old shape |
| 0005 Better Auth tables | Only by dropping the auth tables, which deletes every account and passkey. Reverse with a bookmark instead |
| 0006 connect requests | Droppable (`connect_requests` holds only short-lived codes); the previous Worker never reads it |
| 0007 drop rotate history | **No.** It deletes rows (no client reads them); a bookmark brings them back |
| 0008 box bytes | Yes, if ever needed: drop the three `items_bytes_*` triggers, then `ALTER TABLE boxes DROP COLUMN stored_bytes`. The previous Worker does not need it |

### 5.4 Disable a box (operator kill switch)

A disabled box answers every device and recovery request like a revoked device (bare 404, `box_disabled` in the log); nothing is deleted and sync
resumes the moment the flag is cleared. Dashboard sign-in of the owner is unaffected. Find the box id from the owner's dashboard, a Worker log line (8-char prefix), or:

```bash
pnpm exec wrangler d1 execute bisel --env prod --remote --command "SELECT id, owner_id, created_at, item_count, stored_bytes, disabled_at FROM boxes ORDER BY created_at DESC LIMIT 20"
pnpm exec wrangler d1 execute bisel --env prod --remote --command "UPDATE boxes SET disabled_at = strftime('%s','now') WHERE id = '<box id>'"       # disable
pnpm exec wrangler d1 execute bisel --env prod --remote --command "UPDATE boxes SET disabled_at = NULL WHERE id = '<box id>'"                          # enable again
```

To remove a box for good, the owner deletes it from the dashboard (fresh passkey sign-in); the operator does not delete boxes by hand.

### 5.5 Apply a future migration safely

1. Write it **additive and idempotent in effect**: new nullable or defaulted column, new table, new index/trigger; no rename, drop or rebuild in the same release as the code that needs it
   (rebuilds like 0004 are a two-release job: add and fill, deploy, then remove).
2. Locally: `pnpm check-types && pnpm test && pnpm test:legacy` (the legacy run builds the old schema, seeds a box, applies the new migrations on top and runs the Worker on it).
3. Back up: `wrangler d1 time-travel info bisel --env prod` (write down the bookmark) and, for anything that deletes or rewrites rows, a `wrangler d1 export` too.
4. Apply: `wrangler d1 migrations apply bisel --env prod --remote`. Files apply in order and stop at the first failure; run `migrations list` afterwards and read what failed before retrying.
5. Deploy the Worker that needs it **after** the migration (the old Worker must keep working on the new schema, the reason for rule 1): `pnpm deploy:prod`.
6. Verify (section 6). On a bad Worker: `wrangler rollback`. On damaged data: 5.2.

## 6. Verify a deployment

```bash
H=box.bisel.app
curl -si "https://$H/healthz"                         # a) HTTP/2 200, empty body (503 = D1 not answering)
curl -s -o /dev/null -w 'POST /healthz: %{http_code} %{size_download}\n' -X POST "https://$H/healthz"   # 404 0
for p in /v1/sync /v1/devices /v1/envelope /v1/rotate /v1/history /v1/nope; do
  printf '%-14s' "$p"; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H$p"       # b) every line: 404 0
done
curl -s -o /dev/null -w 'bootstrap, wrong token: %{http_code} %{size_download}\n' -X POST -H 'X-Bisel-Bootstrap: wrong' "https://$H/v1/bootstrap"   # 404 0
diff <(curl -si "https://$H/v1/sync" | grep -viE '^(date|cf-ray|report-to|nel|server-timing):') \
     <(curl -si "https://$H/v1/nope" | grep -viE '^(date|cf-ray|report-to|nel|server-timing):') && echo identical     # c) failures look the same
curl -si "https://$H/v1/sync" | grep -iE '^(cache-control|strict-transport|content-security|x-content-type|x-frame|referrer-policy|cross-origin)'   # d) hardening headers
curl -s -o /dev/null -w 'dashboard: %{http_code}\n' "https://$H/"                                       # e) 200: the sign-in page (static asset), not a 404
```

The dashboard answers on `/` and unknown non-`/v1` paths (single-page fallback); everything under `/v1/` that is not a real signed route is the bare 404.
`workers.dev` must show no route: check Domains & Routes once. If (a) to (d) show anything unexpected, stop and roll back.

## 7. Proposal (not built): scheduled D1 exports and an uptime monitor

**Scheduled exports.** Time Travel covers 30 days but lives in the same Cloudflare account. A second copy outside it, daily:
a scheduled GitHub Actions job (or the owner's Mac via `launchd`) runs `doppler run -- pnpm exec wrangler d1 export bisel --env prod --remote --output dump.sql` with a
dedicated, D1-read-only API token, encrypts the dump with `age` to a key whose private half stays offline (the dump holds ciphertext, but also account rows,
passkey public keys and device lists), and uploads it to a private R2 bucket in a *different* Cloudflare account or to any object store, keeping 30 daily and
12 monthly copies. A failed or missing run alerts (the same channel as the monitor). Do a restore drill into a scratch D1 (`wrangler d1 execute --file`) once per quarter, because an
untested backup is a hope. Cost: free tier. Why not a Cron Trigger Worker: it would need the account API token as a Worker secret, putting the key to the whole account next to the data.

**Uptime monitor.** An external HTTP check on `https://box.bisel.app/healthz` every 1 to 5 minutes, expecting `200` and an empty body, alerting after 2 failures by push/email
(a free external service such as Better Stack or UptimeRobot; Cloudflare Health Checks need a paid plan). `503` means D1 is not answering, a timeout means the Worker or
the zone. `/healthz` counts against the 300/min address limit, which one check every minute does not approach. `healthz` only proves the Worker and D1 are up, not that signed
sync works, so add a **canary device** later: a throwaway box on the same server whose device (software key, `bisel-dev sync`) syncs every 15 minutes from CI and alerts when it
gets anything but 200; it catches a broken migration or auth change that `/healthz` cannot see. Optional third signal: a Cloudflare Notification for Workers error-rate spikes.

## 8. Settings that matter

- `RECOVERY_ACTIVATION_DELAY_SECONDS` = `86400`: recovering after losing every device takes a day before the new Mac can sync (restoring a `.bisel-backup` onto a new server is immediate). `"0"` recovers instantly.
- `HISTORY_RETENTION_DAYS` = `30`: the previous version of every overwritten or deleted item is kept 30 days so a bad write by a stolen device key can be undone from the app. A key rotation keeps no history of its own, and history written before a rotation stays sealed under the old key.
- `MAX_ITEMS_PER_BOX` / `MAX_BOX_BYTES`: an account cannot use the shared database as a file store; `409 box_full` beyond either.
- Destructive routes (rotate, approve, revoke, replace the recovery key, write the vault manifest) need a vault-admin signature that only an unlocked app can make.
- Live logs: `pnpm exec wrangler tail --env prod --format pretty` (the lines show `auth_fail` with a reason).

## 9. Upgrading a live single-box server to accounts (migrations 0004 to 0006): historical

Kept for a server that still runs the pre-accounts schema. Record a Time Travel bookmark and export first; set `BETTER_AUTH_SECRET`; apply the migrations and deploy back
to back (`migrations apply`, then `pnpm deploy:prod`); verify that the existing Mac still syncs and that `https://box.bisel.app/` shows the sign-in page; create your account, link the
box from the Mac (Link to account, Touch ID required); finally `wrangler secret delete BOOTSTRAP_TOKEN --env prod`. If verification fails, restore the bookmark and redeploy the previous Worker version.

## 10. Teardown

`pnpm exec wrangler delete --env prod`, `pnpm exec wrangler d1 delete bisel`, remove the WAF rule. Every box is gone with the database; devices re-upload to a new server, or restore from a backup file.
