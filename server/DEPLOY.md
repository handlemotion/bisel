# Deploying the bisel server

Nothing in this repo has been deployed and no Cloudflare resource exists yet. These are the exact steps, in order.
Every command runs from `bisel/server/` and uses the pinned `wrangler` (`pnpm exec wrangler`, no global install).
Do not skip the verification section: the point of this deployment is that it answers **a bare 404 to anyone who is not a signed bisel device**.

## What you must provide or do

| # | What | Why |
|---|------|-----|
| 1 | A Cloudflare account with the **`bisel.app` zone** on it (nameservers pointing at Cloudflare) | the Worker is routed on a subdomain of it |
| 2 | `pnpm exec wrangler login` (browser OAuth as you) | wrangler needs your account; I never see the token |
| 3 | A **random hostname label** you generate yourself (step 1) | the server's only address; keep it out of git, chat logs and screenshots until it is in the app |
| 4 | The **D1 database id** printed by `d1 create` (step 3), pasted into `wrangler.jsonc` | binds the Worker to the database |
| 5 | A **bootstrap token** you generate and paste into `wrangler secret put` (step 5), stored in your password manager | authorises the one-time first-device registration |
| 6 | The **zone rate-limit rule** (step 7), done in the dashboard | sheds floods before the Worker sees them |
| 7 | The `AAAA` DNS record(s) in step 2 | Workers routes need a proxied hostname |
| 8 | Plan: Workers **Free** should do for one person (not measured on Cloudflare: free is limited to 10 ms CPU and 50 D1 queries per request; a key rotation uses about a dozen queries regardless of vault size). Paid ($5) gives headroom and longer log retention. | |

## 1. Pick the secret hostname

```bash
LABEL=$(openssl rand -hex 12)      # 96 random bits, e.g. 3f9a0c1d7e2b4a58c6d19e03
echo "$LABEL.bisel.app"
```

Write it down once in your password manager. Anyone who knows this name can *try* the API (they still need a registered device key, which they cannot get), so treat it as a secret, not as a credential.

## 2. DNS and certificate (keeps the name out of Certificate Transparency)

Cloudflare's free **Universal SSL** certificate already covers `bisel.app` and `*.bisel.app`. Because the certificate is a wildcard, CT logs record only `*.bisel.app`, never your label. Do **not** order an advanced certificate that names the label explicitly.

In the dashboard (DNS → Records), add **one wildcard record** and keep the proxy on:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| `AAAA` | `*` | `100::` | Proxied (orange cloud) |

`100::` is the discard prefix; the record only exists so Cloudflare accepts traffic for every subdomain. With a wildcard, *every* subdomain resolves identically, so DNS gives no way to find your label. (If you already serve something on `bisel.app` itself, leave it alone; the wildcard does not touch the apex.)

## 3. Create the database

```bash
pnpm exec wrangler login
pnpm exec wrangler d1 create bisel          # add --location weur|enam|... if you want to pin the region
```

Copy the printed `database_id` into `wrangler.jsonc`, under `env.prod.d1_databases[0].database_id` (replace `REPLACE_WITH_D1_DATABASE_ID`).
In the same file replace `REPLACE_WITH_RANDOM_LABEL` in `env.prod.routes[0].pattern` with your label, so it reads `3f9a….bisel.app/*`.
**Do not commit those two edits** (they identify your deployment): keep them in the working tree, or `git update-index --skip-worktree wrangler.jsonc`.

## 4. Apply the migrations to the real database

```bash
pnpm exec wrangler d1 migrations apply bisel --env prod --remote
```

Expect `0001_init.sql` and `0002_rotation.sql` to apply. (`--remote` is what touches Cloudflare; without it, the command only touches the local dev database.)

## 5. Deploy, then set the bootstrap token

```bash
pnpm exec wrangler deploy --env prod
openssl rand -base64 32                       # copy this; it is the bootstrap token
pnpm exec wrangler secret put BOOTSTRAP_TOKEN --env prod     # paste it at the prompt
```

Until the secret exists the bootstrap endpoint refuses everything (an empty token never matches). Save the token in your password manager: you type it into the Mac app exactly once, at onboarding.

## 6. Verify (all of it, before you bootstrap)

Replace `H` with `$LABEL.bisel.app`.

```bash
H=3f9a….bisel.app

# a) Unauthenticated requests: a bare 404 with an empty body, whatever the path or method
for p in / /v1/sync /v1/devices /v1/envelope /v1/bootstrap /v1/rotate /nope; do
  printf '%-16s' "$p"; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H$p"
done
curl -s -o /dev/null -w 'bootstrap, wrong token: %{http_code} %{size_download}\n' -X POST -H 'X-Bisel-Bootstrap: wrong' "https://$H/v1/bootstrap"
# expected: every line is "404 0"

# b) Routes and failures are indistinguishable: these two must be byte-identical apart from date / cf-ray
diff <(curl -si "https://$H/v1/sync" | grep -viE '^(date|cf-ray|report-to|nel):') \
     <(curl -si "https://$H/does-not-exist" | grep -viE '^(date|cf-ray|report-to|nel):') && echo identical

# c) Hardening headers are present on the 404 itself
curl -si "https://$H/v1/sync" | grep -iE '^(cache-control|strict-transport|content-security|x-content-type|x-frame|referrer-policy|cross-origin)'

# d) The Worker is not reachable anywhere else
#    workers.dev is disabled in wrangler.jsonc ("workers_dev": false); in the dashboard, Workers & Pages → bisel-server → Settings → Domains & Routes
#    must list only the one route and no workers.dev subdomain.
curl -s -o /dev/null -w 'other label: %{http_code}\n' "https://not-the-label.bisel.app/v1/sync"   # expected: a Cloudflare 52x/1xxx, not 404 with empty body

# e) The label is not in CT logs: https://crt.sh/?q=%25.bisel.app lists only "*.bisel.app", never your label.
```

If (a) or (b) shows anything but `404 0`, or (d) shows our 404 on any other hostname: stop, do not bootstrap, tell me.

## 7. Zone rate-limit rule (Cloudflare dashboard)

Security → WAF → **Rate limiting rules** → Create rule:

- **If** `Hostname` equals `<label>.bisel.app`
- **Characteristics**: IP
- **Rate**: 30 requests per 10 seconds (Free plan: period is fixed at 10 s; paid plans can use 1 minute and a longer block)
- **Then**: Block, duration 10 s (Free) or 10 min (paid)

Why it is needed: the Worker's own failed-auth counter only *delays* repeat offenders and stops charging D1 writes for them; it never refuses a valid signature (so you cannot be locked out by someone sharing your address). Flood protection is this rule. A normal device does one request per sync (every 60 s) plus a few on edits.

Do **not** add a WAF rule that blocks unknown paths: Cloudflare's block page would differ from the Worker's bare 404 and reveal that the hostname is live.

## 8. First start

1. In the Mac app onboarding enter `https://<label>.bisel.app`, the bootstrap token, and a device name. Write the 24 words on paper.
2. Afterwards remove the secret, so the one-time endpoint cannot even be attempted:
   ```bash
   pnpm exec wrangler secret delete BOOTSTRAP_TOKEN --env prod
   ```
   (Restoring a vault from a `.bisel-backup` onto a fresh database needs a new token: set one again then.)
3. Make a backup file from the app (Settings → Export backup) and keep it with the phrase's paper.

## Operating notes

- **Logs**: Workers Logs is on for `prod` (`wrangler tail --env prod`). Lines are JSON: auth failures with the reason, client IP, device id and path; requests with status. They never contain bodies, blobs, envelopes, keys or the token.
- **Database recovery**: D1 Time Travel keeps 30 days (`pnpm exec wrangler d1 time-travel info bisel --env prod`). Independent of that, a `.bisel-backup` plus the 24 words rebuilds the vault on a new database.
- **Key rotation**: revoking a device from the app rotates the vault key in one transaction; nothing to do on the server. Epoch and rotation events are in the `meta` and `events` tables.
- **Updating the Worker**: `pnpm exec wrangler d1 migrations apply bisel --env prod --remote` (only when a new migration exists), then `pnpm exec wrangler deploy --env prod`.
- **Teardown**: `pnpm exec wrangler delete --env prod`, `pnpm exec wrangler d1 delete bisel`, remove the DNS record. The vault is gone with the database; restore from a backup file.
