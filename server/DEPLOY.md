# Deploying the bisel server to box.bisel.app

Nothing has been deployed yet: no Cloudflare resource exists. This is the exact step list, in order. Run every command from `bisel/server/`
with the pinned wrangler (`pnpm exec wrangler`, never a global one).

The Worker is `env.prod` in `wrangler.jsonc`: name `bisel-server`, route `box.bisel.app` (a Workers *Custom Domain*, so wrangler creates the
proxied DNS record and the certificate itself), `workers.dev` and preview URLs off, per-address flood limit via the Workers rate-limiting binding,
Workers Logs on with invocation logs and traces off. The hostname is public; what protects the data is that every request needs a registered
device's signature and that the server only ever holds ciphertext. The one thing to protect is that **anything that is not a signed device gets a bare 404**.

Legend: **[OWNER]** needs the owner's browser, login or decision; **[ANY]** can be run by a session on the owner's machine once the owner has done the
[OWNER] steps.

## Safety rules for whoever runs this

- Every command here that touches Cloudflare carries `--env prod` and, for D1, `--remote`. Without `--remote`, wrangler's D1 commands only touch the local dev database.
- Never print the bootstrap token or the 24-word phrase into a chat, a log or a file in the repo.
- Never run the wipe in step 10 after the owner's real bootstrap (step 11): it destroys the vault. Time Travel can restore it, but it is not a thing to rely on.

## 0. Prerequisites

| # | What | Who |
|---|------|-----|
| 0.1 | The `bisel.app` zone is **active on the Cloudflare account** the owner will log in with (nameservers at Cloudflare). The apex stays free for the marketing site. | [OWNER] |
| 0.2 | `box.bisel.app` has **no existing DNS record**. A Custom Domain cannot be created over an existing CNAME (check dashboard → bisel.app → DNS → Records, delete any `box` record). | [OWNER] |
| 0.3 | Plan: Workers **Free** works for one person (10 ms CPU and 50 D1 queries per request; a key rotation uses about a dozen queries). **Paid ($5/mo)** adds 30-day Time Travel instead of 7, longer log retention and CPU headroom; recommended. | [OWNER] decides |
| 0.4 | `pnpm install` done in `server/`, and the flow tests pass before touching anything. | [ANY] |

```bash
cd /Users/rodrigo/Workspace/Product/bisel/server
pnpm install --frozen-lockfile
pnpm typecheck && pnpm test          # 26 flow tests, local worker + local D1 only
```

## 1. Log in to Cloudflare  [OWNER]

Opens the owner's browser for OAuth; the token stays in wrangler's local config and is never shown to a session.

```bash
pnpm exec wrangler login
pnpm exec wrangler whoami            # confirm it is the account that holds bisel.app
```

## 2. Create the production database  [ANY]

```bash
pnpm exec wrangler d1 create bisel --location weur     # weur|eeur|enam|wnam|apac|oc: pick the region closest to the owner
```

Decline any offer to add the binding to the config automatically. Copy the printed `database_id` and put it in `wrangler.jsonc`
(`env.prod.d1_databases[0].database_id`, replacing `REPLACE_WITH_D1_DATABASE_ID`):

```bash
DB_ID=<paste-the-uuid>
sed -i '' "s/REPLACE_WITH_D1_DATABASE_ID/$DB_ID/" wrangler.jsonc
grep -n REPLACE wrangler.jsonc || echo "no placeholder left"
```

A D1 id is an identifier, not a credential; commit it (`git commit -m "server: production D1 id"`).

## 3. Apply the migrations to the real database  [ANY]

```bash
pnpm exec wrangler d1 migrations apply bisel --env prod --remote
pnpm exec wrangler d1 migrations list bisel --env prod --remote     # expect: 0001_init, 0002_rotation, 0003_admin_history all applied
```

## 4. Deploy the Worker and attach box.bisel.app  [ANY, after step 1]

```bash
pnpm deploy:prod        # = wrangler deploy --env prod
```

This uploads `bisel-server`, creates the Custom Domain `box.bisel.app` (DNS record and certificate included; allow a minute or two) and the rate-limit
binding. `workers.dev` and preview URLs are off in the config. Until the secret in step 5 exists, the bootstrap endpoint refuses everything.

In the dashboard (Workers & Pages → bisel-server → Settings → Domains & Routes) the only entry must be `box.bisel.app` (Custom Domain). If a
`workers.dev` route or a preview URL shows up, disable it there. [OWNER, one look]

## 5. Set the secret  [ANY]

`BOOTSTRAP_TOKEN` is the only secret the Worker reads. It lives only as a Worker secret (never in `wrangler.jsonc`, `.dev.vars` is local only).
It authorises the one-time creation of the box. Use a throwaway token for the check in step 9, a different one for the real bootstrap in step 11.

```bash
openssl rand -base64 32 | pbcopy                                          # token goes to the clipboard, not the terminal
pbpaste | pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env prod       # reads stdin
```

(`pbcopy` leaves the token on the clipboard for step 9; clear it afterwards with `pbcopy < /dev/null`.)

### Secrets live in Doppler

Project `bisel` (Handlemotion workspace), config `prd`; `doppler setup` in `server/` binds this directory to it. Nothing syncs: `doppler run` injects
the values for a command, so wrangler targets the right account (`CLOUDFLARE_ACCOUNT_ID`, the Bisel account) without a shell export.

```bash
doppler run -- pnpm deploy:prod
doppler secrets get BOOTSTRAP_TOKEN --plain | pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env prod   # token goes Doppler -> Worker, never the terminal
```

Add `CLOUDFLARE_API_TOKEN` there (an account-owned token on the Bisel account: Workers Scripts, D1 and Zone read/Workers Routes edit) to deploy
without the OAuth login. After the real bootstrap, delete `BOOTSTRAP_TOKEN` from both the Worker and Doppler.

## 6. Flood rule in front of the Worker  [OWNER, dashboard]

The binding in the Worker already allows 300 requests per minute per address and answers a bare `429`. It is approximate (counts are per
Cloudflare location). A WAF rate-limiting rule sheds floods before the Worker is even invoked, so add one as a second layer.

Dashboard → bisel.app → Security → WAF → **Rate limiting rules** → Create rule:

- Name: `box flood`
- **If** Hostname **equals** `box.bisel.app`
- Characteristics: IP (the only option on Free)
- Rate: **100 requests / 10 seconds** (Free allows only a 10 s period)
- Action: **Block**, duration 10 seconds on Free (paid plans: 10 minutes)

A device does one request per sync (every ~60 s) plus a few per edit, so 100 per 10 s per IP never touches the owner (a bulk import is slower
than that, and anything above the rule resumes after the block).

Do **not** add a WAF rule that blocks unknown paths or methods: Cloudflare's block page would differ from the Worker's bare 404.

Optional, same area, one click: SSL/TLS → Edge Certificates → **Minimum TLS Version = 1.2**, **Always Use HTTPS** on. [OWNER]

## 7. Verify the deployment (before any bootstrap)  [ANY]

```bash
H=box.bisel.app

# a) Liveness: a bare 200 with no body and no identifying header, and nothing else answers
curl -si "https://$H/healthz"                         # expect: HTTP/2 200, content-length: 0, no server-identifying body
curl -s -o /dev/null -w 'POST /healthz: %{http_code} %{size_download}\n' -X POST "https://$H/healthz"   # expect 404 0

# b) Unauthenticated requests: a bare 404 with an empty body, whatever the path or method
for p in / /v1/sync /v1/devices /v1/envelope /v1/bootstrap /v1/rotate /v1/history /nope; do
  printf '%-14s' "$p"; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H$p"
done
curl -s -o /dev/null -w 'bootstrap, wrong token: %{http_code} %{size_download}\n' -X POST -H 'X-Bisel-Bootstrap: wrong' "https://$H/v1/bootstrap"
# expected: every line "404 0"

# c) Routes and failures are indistinguishable: byte-identical apart from date / cf-ray
diff <(curl -si "https://$H/v1/sync"  | grep -viE '^(date|cf-ray|report-to|nel|server-timing):') \
     <(curl -si "https://$H/nope"     | grep -viE '^(date|cf-ray|report-to|nel|server-timing):') && echo identical

# d) Hardening headers are on the 404 itself, and there is no CORS
curl -si "https://$H/v1/sync" | grep -iE '^(cache-control|strict-transport|content-security|x-content-type|x-frame|referrer-policy|cross-origin)'
curl -si -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' "https://$H/v1/sync" | grep -i '^access-control' || echo "no CORS headers"

# e) workers.dev must be off: the dashboard check in step 4 is the proof; wrangler also reports it on deploy (no "workers.dev" URL in the output)
```

Flood limit (optional, once): `for i in $(seq 1 400); do curl -s -o /dev/null -w '%{http_code}\n' "https://$H/healthz"; done | sort | uniq -c`
should show `429`s (from the Worker binding or the WAF rule), then recover within a minute.

If (a)–(d) show anything but the expected output: stop, do not bootstrap.

## 8. Backups and Time Travel  [ANY]

D1 **Time Travel is always on** for every database (no switch to enable): point-in-time restore for **30 days on Workers Paid, 7 days on Free**.
Check it is recording:

```bash
pnpm exec wrangler d1 time-travel info bisel --env prod          # prints the current bookmark
```

Restore (only ever on the owner's say-so): `pnpm exec wrangler d1 time-travel restore bisel --env prod --timestamp=<RFC3339 or unix seconds>`
(it prints the undo bookmark; restores are limited to 10 per 10 minutes).

Independent of Cloudflare, the app's `.bisel-backup` file plus the 24 words rebuilds the box on any new database. A raw SQL dump of the ciphertext
can also be kept offline: `pnpm exec wrangler d1 export bisel --env prod --remote --output ~/bisel-d1-$(date +%F).sql` (it is ciphertext only).

## 9. Throwaway end-to-end check with the dev CLI  [ANY]

This proves the deployed Worker + D1 work end to end (bootstrap, an encrypted write, a sync) with the software-key dev CLI. It writes test data
that step 10 removes. Use the token from step 5 (still on the clipboard).

```bash
cd ../apple/Tools/bisel-dev
H=/tmp/bisel-prod-check; rm -rf $H
pbpaste | swift run bisel-dev bootstrap --home $H --server https://box.bisel.app --token - --name deploy-check   # prints a throwaway phrase; do not keep it
swift run bisel-dev add  --home $H --title "deploy check" --username x --password "throwaway"
swift run bisel-dev sync --home $H                                    # expect: pushed 0, pulled 0, head seq 2
swift run bisel-dev list --home $H                                    # expect the one item
cd ../../../server
```

Expect `bootstrapped device 'deploy-check' at https://box.bisel.app`. If a step answers 404 or fails, read the Worker logs: `pnpm exec wrangler tail --env prod --format pretty`
(the Worker's own lines show `auth_fail` with a reason).

## 10. Wipe the throwaway data  [ANY]  (only before the real bootstrap)

`scripts/wipe-data.sql` empties every table the Worker writes to and leaves the schema and migration history. Afterwards `POST /v1/bootstrap` is
possible again. Then remove the throwaway token.

```bash
pnpm exec wrangler d1 execute bisel --env prod --remote --file scripts/wipe-data.sql
pnpm exec wrangler d1 execute bisel --env prod --remote --command "SELECT (SELECT COUNT(*) FROM meta) meta, (SELECT COUNT(*) FROM devices) devices, (SELECT COUNT(*) FROM items) items"
#   expect 0, 0, 0
pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env prod       # answer y
rm -rf /tmp/bisel-prod-check; pbcopy < /dev/null
```

## 11. The real bootstrap  [OWNER]

1. Generate the real token into the password manager, not into a chat: `openssl rand -base64 32 | pbcopy`, paste it into the password manager, then
   `pbpaste | pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env prod`.
2. In the Mac app, create the box against `https://box.bisel.app` with that token. Write the 24 words on paper.
3. Immediately remove the secret so the one-time endpoint cannot even be attempted:
   `pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env prod`
   (restoring from a `.bisel-backup` onto a fresh database needs a new token: set one again then).
4. In the app, export a backup file and keep it with the paper.
5. Optional: an uptime monitor on `https://box.bisel.app/healthz` (expects `200`; `503` means D1 is not answering).

## Settings that matter (`env.prod.vars` in `wrangler.jsonc`)

- `RECOVERY_ACTIVATION_DELAY_SECONDS` = `86400`: a device added through the 24 words cannot sign requests for 24 h, every enrolled device announces it at its next sync, and any of them can cancel it by revoking. **Recovering after losing every device takes a day** before the new Mac can sync (restoring a `.bisel-backup` onto a new server is immediate). `"0"` recovers instantly.
- `HISTORY_RETENTION_DAYS` = `30`: the previous version of every overwritten, deleted or re-keyed item is kept 30 days, so a bad write by a stolen device key can be undone from the app.
- `AUTH_FAIL_LIMIT` / `AUTH_FAIL_WINDOW_SECONDS` / `AUTH_BACKOFF_MS`: after 20 failed requests from one address in 10 minutes, its failing requests are answered a second late and cost no more D1 writes. A valid signature is never refused because of this.
- Flood limit: `ratelimits` in `wrangler.jsonc` (300/min per address per location) plus the WAF rule of step 6.
- Destructive routes (rotate, approve, revoke, replace the recovery key) need a vault-admin signature that only an unlocked app can make; nothing to configure.

## Operating notes

- **Logs**: Workers Logs is on for `prod`, with invocation logs and traces off, so the only lines are the Worker's own: `{evt, reason, ip (8-char hash), device (8-char prefix), method, path, status}`. Never bodies, blobs, envelopes, keys, tokens or request headers; query strings are redacted. Live: `pnpm exec wrangler tail --env prod`.
- **Updating**: new migration → `pnpm exec wrangler d1 migrations apply bisel --env prod --remote`, then `pnpm deploy:prod`. Roll back a bad Worker with `pnpm exec wrangler rollback --env prod` (D1 schema changes are not rolled back by it).
- **Key rotation**: revoking a device in the app rotates the vault key in one transaction; nothing to do on the server.
- **Teardown**: `pnpm exec wrangler delete --env prod`, `pnpm exec wrangler d1 delete bisel`, remove the WAF rule. The box is gone with the database; restore from a backup file.
