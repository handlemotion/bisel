# bisel — spec v0.1

A personal, single-user, zero-knowledge password manager for Apple devices. Own server, own apps, no daily master password: unlock is biometrics only.

This file is the contract between `server/` and `apple/`. If an implementation needs to deviate, change this file in the same change and say why.

Terminology: what this spec calls the _vault_ is called a **box** in every user-facing string (UI, panel, docs for users). Code, wire formats and this spec keep "vault" internally. The production server is box.bisel.app; the bisel.app apex is the marketing site.

## 1. Goals and non-goals

Goals

- Fast: the command menu shows results in <50 ms after the hotkey, unlock to fill in ~1 s.
- Biometrics-only daily unlock (Touch ID / Face ID). No master password, no passcode fallback.
- Server sees only ciphertext. A full server breach reveals nothing readable.
- Native Apple UI components, freely designed and themeable (Raycast-style), not stock layouts.
- Safari and system AutoFill (passwords + passkeys) on Mac and iPhone, in later milestones.

Non-goals (v1)

- Sharing, multiple users, teams, Windows/Android/Linux, Chromium extension, passkey sign-in, agent CLI, cards/addresses, attachments, SSH keys.

## 2. Milestones

| #   | Scope                                                                                     | Status    |
| --- | ----------------------------------------------------------------------------------------- | --------- |
| M1  | `server/` Worker + D1, signed-request auth, sync API                                      | this spec |
| M2  | `BiselCore` Swift package: crypto, vault format, recovery, sync client                    | this spec |
| M3  | Mac app: vault UI, ⌘⇧Space command panel, fill engine, devices, recovery, 1pux/CSV import | this spec |
| M4  | Safari/system AutoFill credential provider on Mac (shares M2 core)                        | later     |
| M5  | iPhone app + AutoFill provider, device enrollment by QR                                   | later     |
| M6  | Apple Passwords credential-exchange import (with passkeys)                                | later     |
| M7  | Passkey sign-in everywhere; optional Safari extension for URL context; agent CLI          | later     |

Design now for M4–M7 where it is cheap (shared storage location, key access groups, enrollment endpoints, reserved passkey item type) but do not build them.

## 3. Repo layout

```
bisel/
  SPEC.md
  server/                 TypeScript Cloudflare Worker
  apple/
    project.yml           XcodeGen spec (generates Bisel.xcodeproj; never hand-edit pbxproj)
    Packages/BiselCore/   SwiftPM: crypto, vault, sync client, key store
    Bisel/                Mac app target sources
    Tools/bisel-dev/      SwiftPM executable: dev CLI driving core flows against a server
```

## 4. Cryptography

Use only platform / well-known libraries. No hand-rolled primitives.

- Client: Apple CryptoKit and Security.framework. Server: WebCrypto (built into workerd) only for signature verification. The server never decrypts anything.
- Symmetric AEAD: AES-256-GCM everywhere.
- KDF: HKDF-SHA256. No password hashing (Argon2/PBKDF) is needed: every secret that feeds a KDF is a random 256-bit value.

Key hierarchy

- **VK** (vault key): random 256 bits, generated once on the first device. Never stored in the clear and never sent to the server except wrapped.
- **IK** (item key): random 256 bits per item. The item payload is encrypted under IK. IK is wrapped under VK. AAD for both is `bisel/v1|item|<item id>|<rev>` so ciphertext cannot be swapped between items or revisions.
- **Device keys**, both P-256 in the Secure Enclave:
  - `DK-enc`: access control `.biometryCurrentSet` + `.privateKeyUsage`. Used to unwrap the device envelope (ECIES, `eciesEncryptionCofactorX963SHA256AESGCM`). `biometryCurrentSet` so that adding or removing a fingerprint (which needs only the Mac password) invalidates it instead of letting a thief enrol their own finger; the device then reports `DeviceKeyError.biometryChanged` and is enrolled again from another device or with the phrase (nothing is lost). The enrolled-biometry domain state is also checked. No passcode fallback.
  - `DK-sig`: `.privateKeyUsage` only, no biometric prompt, so background sync never prompts. Signs requests.
- **Device envelope**: VK encrypted to a device's `DK-enc` public key. Stored locally and on the server (the server cannot open it).
- **Recovery phrase**: 24 words (BIP-39 wordlist, 256 bits of entropy), shown once at bootstrap. `RK = phrase entropy`.
  - `RK-enc`: an X25519 key whose seed is `HKDF(RK, "bisel/v1/recovery-enc")`. Its **public** key is stored on the server and on every device. The **recovery envelope** is a copy of VK sealed to it with HPKE (X25519, HKDF-SHA256, AES-256-GCM), stored on the server. Because sealing needs only the public key, any enrolled device can write a fresh recovery envelope (vault-key rotation) without ever holding the phrase; only the phrase opens it. _(v0.1 used a symmetric `RK-wrap` key, which would have forced the phrase to be typed on every rotation.)_
  - `RK-sig`: an Ed25519 key whose seed is `HKDF(RK, "bisel/v1/recovery-sig")`. Its public key is registered at bootstrap and lets a device-less client authenticate to fetch the recovery envelope.
- **Backup file** `.bisel-backup` (format version 2): the server's records (items, recovery pubkeys, recovery envelope) exported to a single file. Only the recovery phrase opens it.
- **Vault-admin key** (`AK`): Ed25519, seed `HKDF(VK, "bisel/v1/admin-sig")`, public key registered at bootstrap and replaced by every rotation. The server requires its signature (`X-Bisel-Admin`, over `bisel-admin/v1 \n device \n <canonical request string>`) in addition to the device signature on `POST /v1/rotate`, `POST /v1/devices`, `DELETE /v1/devices/:id` and `POST /v1/recovery/rotate`. `DK-sig` never prompts and has no VK, so a stolen or malware-driven device key can no longer destroy or re-key the vault; producing the admin signature needs an unlocked vault.
- **Vault manifest**: a reserved record (`bisel-manifest-v1-reserved`) sealed under VK like any item, holding the **roster** (every device the owner approved: id, name, kind, both public keys, how it was added) and the **recovery pins** (RK-sig/RK-enc public keys and a generation). Only a VK holder can write it. Each device keeps its own copy in `LocalIdentity`; it is written by bootstrap, `approveEnrollment`, `recover`, `trustDevice` and merged from the synced manifest. Rotation seals the new VK **only to roster keys** and stops with `IntegrityError.unknownDevices` if the server lists an active device that is not in the roster (or whose keys differ): a device planted by a stolen signing key, a hostile server or a leaked phrase never receives the new key. Fingerprints shown to humans are 96 bits.
- **Key confirmation**: a device that received VK through an envelope must not trust it blindly (the server relays the envelope). (1) The manifest is the canary: if it does not open under the received key the sync fails with `IntegrityError.keyConfirmationFailed` and the vault locks. (2) `HKDF(VK, "bisel/v1/verify")` gives a 40-bit code shown by the approver and by the new device; the human compares, `confirmEnrollment(code:)` checks it. (3) On a not-yet-confirmed device, records existing but none decrypting is a hard error.
- **Tombstones**: a delete carries a marker sealed under a VK-derived key with AAD `<item aad>|tomb`. A device honours a remote delete only after the marker verifies; a delete forged without VK is undone from the local trash as a new revision. Markers are re-sealed on rotation. Item AEADs use distinct AAD labels (`|wrap`, `|body`).
- **Recovery pins**: the recovery public keys are pinned locally (from the phrase, or from the manifest). A different pubkey from the server is reported (`recoveryMaterialChanged`), never adopted, and blocks backup export. The recovery envelope's HPKE `info` binds the epoch and the RK-sig key. A new phrase starts "unconfirmed" until the user proves they wrote it down (`confirmRecovery`, or the 3-word quiz helper).
- **Epoch**: a counter that starts at 1 and moves by one on every vault-key rotation. Every request that carries material derived from VK (item blobs, device envelopes, recovery envelopes) states the epoch it was built for, and the server refuses a stale one. This is what stops a device that has not yet noticed a rotation from writing old-key material into the vault.

Vault-key rotation (on every revoke, or on demand)

- _Why_: removing a device from the server is not enough. A revoked device that kept VK can unwrap the item keys of any ciphertext it still holds or can obtain (server storage, a breach, a backup). Rotation makes everything on the server unreadable to the old VK.
- _What changes_: a new VK; every live item's **wrapped IK** is re-wrapped under it (IKs, payload ciphertext, `rev` and AAD do not change, so a rotation never rewrites an item's content and never changes a revision); a new device envelope for every remaining device; a new recovery envelope sealed to the _same_ recovery key (the existing 24 words keep working). The epoch moves by one.
- _Atomicity_: one request (`POST /v1/rotate`) applies all of it in one D1 batch or none of it. It is built from a snapshot (epoch, `head_seq`, the exact set of live items and revs, the exact set of active devices); if anything changed since (an edit, a new device, another rotation) the server applies nothing, answers 409, and the client re-syncs and retries.
- _Other devices_: on their next sync they see the new epoch, fetch their new envelope, lock themselves, and unlock (one Touch ID) into the new VK. Local edits sealed under the old VK stay pending and are re-wrapped at that unlock, then pushed.
- _Honest limit_: a revoked device still has whatever it already copied (it could read those items at the time, and the plaintext left the vault then). Rotation protects what the server holds from now on and everything written later; after revoking a lost device, change the passwords that matter.
- Padding: item ciphertext is padded to a multiple of 512 bytes before encryption.

Unlock model (client)

1. App launch / unlock: unwrap the device envelope with `DK-enc` (biometric prompt) → VK held in memory (locked, non-swappable memory where possible).
2. VK stays in memory for the **fill window** (default 5 min). It is zeroed on sleep, screen lock, idle timeout, or explicit lock.
3. **Sensitive actions**: edit/delete an item always require a fresh `LAContext` evaluation (`.deviceOwnerAuthenticationWithBiometrics`) even inside the window.
   **Deliberate decision (user, M3 panel):** _revealing and copying a password or OTP inside the fill window does not prompt again._ The command panel shows both in plain text while the vault is unlocked (the Touch ID unlock opened the 5 min window; the panel opens locked and unlocks first if the window expired). Lock on sleep / screen lock / idle and the 30 s clipboard clear still apply, and the panel window is excluded from capture (`NSWindow.sharingType = .none`, setting "Hide from screenshots and screen sharing", default ON in Release, OFF in Debug).
   Setting **"Require Touch ID to reveal or copy password and OTP"** (default OFF) restores the strict rule: values stay masked until a fresh `LAContext` check, and every copy/fill of a password or TOTP asks again.
4. If biometrics are unavailable (e.g. clamshell, no Touch ID keyboard) the app stays locked. The only fallback is the recovery phrase on a fresh enrollment.

Clipboard

- Copies use `NSPasteboard` with `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`, and are excluded from Universal Clipboard with **`NSPasteboard.prepareForNewContents(with: .currentHostOnly)`** (`NSPasteboardContentsCurrentHostOnly`, public AppKit API, macOS 10.12+). It must be the call that starts the write; add data with `setString/setData` on the same pasteboard (not `writeObjects`). Observed: on every copy CoreFoundation logs `MakeGenerationLocalOnly('Apple CFPasteboard general' ... gen: N)` (subsystem `com.apple.CFPasteboard`) with N equal to the write's `changeCount`, and the item carries both marker types. Not verifiable without a second Apple device that actual delivery is suppressed.
- Auto-clear after 30 s only if `changeCount` is unchanged since the copy (also cleared on quit if still ours).

Test-only key store

- `DeviceKeyStore` protocol with a Secure Enclave implementation and a software P-256 implementation. The software one exists only for headless flow runs, is compiled behind `#if BISEL_SOFTWARE_KEYS` (never set for Release), and must say so loudly in logs. In `BiselCore` the flag is defined by the SwiftPM trait `SoftwareKeys`, enabled only by `bisel-dev` and the flow tests (`swift test --traits SoftwareKeys`), so no app or Release build can contain it.

## 5. Data model

### Item payload (plaintext, versioned JSON, encrypted under IK)

```json
{
  "v": 1,
  "type": "login | note | secret | passkey",
  "title": "string",
  "urls": ["https://example.com"],
  "username": "string?",
  "password": "string?",
  "totp": { "secret": "base32", "algo": "SHA1|SHA256|SHA512", "digits": 6, "period": 30 },
  "notes": "string?",
  "fields": [{ "label": "string", "value": "string", "secret": true }],
  "tags": ["string"],
  "createdAt": "RFC3339",
  "updatedAt": "RFC3339",
  "passkey": { "reserved": true }
}
```

`passkey` is reserved: import must be able to store the raw credential blob losslessly, sign-in comes in M7. Types `login`, `note`, `secret` (API keys, env values) are in v1.

### Server record (what the server stores)

`{ id, rev, seq, deleted, blob, updated_at }` where `blob` = `wrapped IK || nonce || ciphertext`. The server sees opaque `id` (128-bit random), `rev`, size, timestamps. Titles, URLs, notes, tags and types are all inside the ciphertext.

## 6. Server (M1)

Stack: TypeScript, Cloudflare Workers, Hono, Zod for validation, D1 with `wrangler d1 migrations`. Query builder (Drizzle or Kysely) is optional; do not hand-roll migrations tooling.

Hosting: the Worker is bound to the public hostname `box.bisel.app` (a Workers Custom Domain; the name is public by decision, what protects the data is that every request needs a registered device's signature). `bisel.app` itself is the brand. The same Worker serves the account dashboard (static assets, `/api/*`, passkey accounts via Better Auth) and many boxes: `box_id` scopes every box table, a device row says which box it belongs to.

### Request authentication

Every request except `POST /v1/bootstrap` (shared-secret header only) carries the four headers below. Recovery requests use `X-Bisel-Device: recovery` and an Ed25519 signature instead of a device id and P-256. Wire details (encodings, signature byte formats, query canonicalization) are in `apps/server/README.md`.

```
X-Bisel-Device: <device id>
X-Bisel-Ts:     <unix seconds>
X-Bisel-Nonce:  <random 128-bit, base64url>
X-Bisel-Sig:    <base64url signature>
```

Signed string: `METHOD \n PATH \n SORTED_QUERY \n SHA256(body) as hex \n TS \n NONCE`. Algorithms: P-256 ECDSA over SHA-256, raw `r||s` signature (device), or Ed25519 (recovery). Binary values on the wire are unpadded base64url; P-256 public keys are X9.63 uncompressed, the Ed25519 public key is raw 32 bytes. Server rejects: unknown or revoked device, |now − ts| > 60 s, reused nonce (stored 5 min in D1, pruned), bad signature.

**Every authentication failure returns the same empty `404`** (destructive routes then also need the vault-admin signature; a missing or wrong one answers `403 admin_signature_required` to the already-authenticated device). Unauthenticated callers learn nothing about boxes, devices or setup state. The only public routes are the dashboard's static pages, `/api/*` (its own session auth), the unsigned device-code connect pair (`POST /v1/connect`, `/v1/connect/poll`) and `GET /healthz` (bare `200`, or `503` when D1 does not answer; no body, version or counts).

Uniformity: an unknown route, a wrong method, `HEAD`/`OPTIONS`, a failed bootstrap and every authentication failure take the same code path (one principal read, one signature verification against a decoy key when the principal is unknown, at most one counter write) and return the same bare `404` with the same headers, so neither the response nor its timing says what exists. Every response, including the 404, carries the hardening headers (`Cache-Control: no-store`, `Strict-Transport-Security`, `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy`).

Rate limiting: flood protection is a Cloudflare rate-limit rule on the zone (see `apps/server/DEPLOY.md`). The Worker-side counter (D1 `auth_failures`, per `CF-Connecting-IP`, default 20 failures / 600 s, tracks at most 20 000 addresses) **never refuses a valid signature**, so the owner cannot be locked out by traffic from a shared address. Past the limit, a _failing_ request from that address is answered `AUTH_BACKOFF_MS` (default 1 s) late and costs no further D1 writes. (v0.1 answered 404 to everything from that address, valid signatures included; that could lock the owner out and was dropped.) Before any D1 work the Worker applies a per-address flood limit (Workers rate-limiting binding, 300 requests/min per `CF-Connecting-IP`) that answers a bare `429` with `Retry-After`, the same for every route and caller; clients wait it out. It is keyed on the address, not the caller, so someone sharing the owner's egress address can make the owner's requests 429 for a minute; accepted. The bootstrap token is compared as two SHA-256 digests with a constant-time compare.

Bodies: anything over 4 MiB is the bare 404 before it is read; after authentication every route has its own cap (413 `too_large`) and a strict Zod schema (unknown fields, repeated query parameters and bodies on GET/DELETE are 400).

After authentication, request errors (bad body, stale `base_rev`, too large) use ordinary statuses with a JSON `{"error": ...}` body; only authentication failures and unknown routes are the bare `404`.

### Endpoints

| Method | Path                                     | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------ | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/v1/bootstrap`                          | One time. Header `X-Bisel-Bootstrap: <secret>` matching the Worker secret `BOOTSTRAP_TOKEN`. Body: first device (id, name, sig pubkey, enc pubkey, device envelope), recovery pubkey, recovery envelope. After success the endpoint always 404s.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| GET    | `/v1/sync?since=<seq>&events_since=<id>` | Returns changes after `seq`: items (incl. tombstones, whose `blob` is the sealed marker), device list (with `activates_at` for held-back devices), current head `seq`, current `epoch`, `events` (bootstrap/approve/revoke/rotate/recovery/recovery_rotate, so every device can announce "a device was added with the recovery phrase"), and the recovery pubkeys + envelope. Paginated by `limit`. Clients check `next_since <= head_seq`, record seqs, and that `head_seq` never decreases.                                                                                                                                                                                                           |
| PUT    | `/v1/items/:id`                          | Body `{ base_rev, epoch, blob }`. `base_rev` is 0 for new items. 409 `conflict` with the current record if stale; 409 `stale_epoch` if the blob's item key is wrapped under a rotated-away VK; 409 `box_full` past `MAX_ITEMS_PER_BOX` items or `MAX_BOX_BYTES` of blob text. Server assigns `rev+1` and a new `seq`. Max blob 256 KiB.                                                                                                                                                                                                                                                                                                                                                                 |
| DELETE | `/v1/items/:id?base_rev=`                | Tombstone. Body `{ epoch, marker }`; the sealed marker is stored as the blob.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| GET    | `/v1/history?id=&after=&limit=`          | Previous states the server retained for `HISTORY_RETENTION_DAYS` (30): `overwrite`/`delete` rows hold the whole previous blob. A rotation keeps no history of its own (a retained old wrapped item key would let a holder of the old vault key open current payloads). Ciphertext only; a client with the key re-saves a wanted version as a new revision.                                                                                                                                                                                                                                                                                                                                              |
| GET    | `/v1/devices`                            | List with name, kind, created, last seen, revoked.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| POST   | `/v1/devices`                            | An existing device approves a new device: registers its pubkeys and stores the device envelope the approver created for it. Body adds `epoch` (the VK the envelope holds); 409 `stale_epoch` if it is not current.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| POST   | `/v1/rotate`                             | **Vault-key rotation**, optionally revoking a device in the same transaction. Admin-signed with the _old_ key; body `{ base_epoch, base_seq, revoke, new_admin_pubkey, items:[{id, rev, key}], tombstones:[{id, rev, marker}], devices:[{id, envelope}], recovery_envelope }`: `key` is the new 60-byte wrapped IK that replaces the first 60 bytes of the item's blob. Applied only if `epoch == base_epoch`, `head_seq == base_seq`, `items` is exactly the live set at exactly those revs and `devices` exactly the active set (minus `revoke`); otherwise 409 and nothing changes. On success every item gets a fresh `seq` (revs untouched), `epoch + 1`, revoked device's envelope wiped. See §4. |
| DELETE | `/v1/devices/:id`                        | Revoke **without** rotating (emergency; the device keeps VK). Effective immediately: later requests from that device 404. Clients revoke through `/v1/rotate`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| GET    | `/v1/envelope`                           | The calling device's own device envelope and its epoch.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| POST   | `/v1/recovery/session`                   | Authenticated by the Ed25519 recovery signature only (the phrase is the root; no admin signature). A device registered here can be held back for `RECOVERY_ACTIVATION_DELAY_SECONDS` (prod: 24 h): it gets the bare 404 until then, other devices see it in the device list and as an event, and any of them can revoke it. Empty body: returns the recovery envelope and `epoch`. Body `{device, epoch}`: also registers a replacement device (two calls, because the client needs the envelope to derive VK before it can build its own device envelope; 409 `stale_epoch` if a rotation happened in between).                                                                                        |
| POST   | `/v1/recovery/rotate`                    | Signed by a normal (e.g. the replacement) device. Replace the recovery pubkeys and envelope with a **new phrase's** (body adds `epoch`). Rotating VK (`/v1/rotate`) keeps the phrase.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

Conflicts: client resolves a 409 by fetching the current record and, if both sides changed, keeping the remote and saving the local edit as a new item titled "<title> (conflict)". No silent overwrite.

Push: not in v1. The Mac polls every 60 s while unlocked, on unlock, and on demand. A Durable Object WebSocket and APNs come with the iPhone.

### D1 schema (sketch)

```
boxes(id, recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, head_seq, epoch, created_at, owner_id UNIQUE, item_count, stored_bytes, disabled_at /* operator kill switch */)
connect_requests(id, device_code_hash, user_code, kind, box_id, device_name, ..., status, account_id)   -- device-code connect
(Better Auth tables: user, session, account, verification, passkey)   -- the dashboard; box_id is also on devices, items, item_history, events
devices(id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, envelope_epoch, created_at, last_seen_at /* hour */, revoked_at, activates_at)
item_history(id, item_id, rev, kind, blob, deleted, epoch, replaced_at)  -- retention, pruned 100 rows per write
items(id, rev, seq UNIQUE, deleted, blob, updated_at)
nonces(nonce, ts)                                  -- pruned 100 rows per write, indexed on ts
events(id, ts, device_id, type, subject_id)        -- bootstrap/approve/revoke/rotate/recovery/recovery_rotate only
auth_failures(ip, window_start, count)             -- Worker-side failed-auth backoff, indexed on window_start, <= 20 000 rows
assertions(ok CHECK ok = 1)                        -- empty at rest; a failing `INSERT ... SELECT CASE WHEN cond ...` aborts a D1 batch
```

Binary columns are unpadded base64url TEXT (D1 returns BLOBs as number arrays); timestamps are unix seconds.
`head_seq` increments inside a D1 batch with the item write so seq is gapless and monotonic. Both statements carry the same `rev == base_rev` and `epoch` guard, so a rejected (409) write consumes no seq. A rotation assigns the rotated items `base_seq+1 … base_seq+N` and advances `head_seq` by `N` in the same batch; its preconditions and postconditions are `assertions` statements, so any violation rolls the whole batch back.

### Secrets and ops

- `BOOTSTRAP_TOKEN` via `wrangler secret put --env prod`, never in the repo. `.dev.vars` (local token) is git-ignored; `.dev.vars.example` is tracked.
- `wrangler.jsonc`: the default environment is local dev (placeholder D1 id, nothing remote); `env.prod` holds the route pattern and D1 id as `REPLACE_…` placeholders that wrangler refuses to deploy until the owner fills them in. Exact steps: `apps/server/DEPLOY.md`.
- A deployed instance is created only on the user's say-so. Everything here is built and verified against `wrangler dev` with local D1.

## 7. BiselCore (M2)

SwiftPM package, Swift 6, macOS 26+ / iOS 26+. No UI.

Module names are prefixed (`BiselCrypto`, `BiselKeyStore`, `BiselVault`, `BiselLane`, `BiselSync`, `BiselRecovery`, `BiselTOTP`) because a module called `Crypto` collides with swift-crypto's (pulled in by the OTP package) and a module called `Vault` would shadow the public `Vault` type. The umbrella module `BiselCore` re-exports them all and defines the `Vault` facade (an `actor`). `BiselLane` is the sync-lane boundary (`SyncLane`, records, verifier); `BiselSync` runs the engine over a lane (`ServerLane` for the server, `RecordBox` for storage-only lanes; see `docs/SYNC-LANES.md` §14). `BiselTestSupport` (dev/test only, never linked by apps) starts a throwaway local server and provides the in-memory `FakeLane` for flow tests.

Modules

- `Crypto`: key hierarchy above, AEAD helpers, recovery phrase encode/decode (use a maintained BIP-39 Swift package, do not hand-write the wordlist), HKDF via CryptoKit.
- `KeyStore`: `DeviceKeyStore` (SE + software).
- `Vault`: item model, encrypt/decrypt, local store.
- `Sync`: signed HTTP client for section 6 and the pull/push engine with conflict handling.
- `Recovery`: phrase generation, backup-file export/import, rebuild-from-phrase.
- `TOTP`: use an existing Swift OTP package, do not hand-roll.

Rotation behaviour (BiselCore). `revoke` needs an unlocked vault (it unlocks first) and fails with a typed `RotationError` (a new type; `SyncError`/`VaultError`/`KeyStoreError` gained no cases, so exhaustive switches keep compiling) when: local edits cannot be pushed (`pendingChanges`), an item does not decrypt (`undecryptableItems`: delete it first), the target is this device (`cannotRevokeThisDevice`), the vault's recovery material predates rotation (`recoveryNeedsUpgrade`: run `rotateRecovery()` once), or the vault keeps changing (`tooManyConflicts`, nothing was changed). Devices that learn of a rotation lock themselves and surface it as `SyncReport.rotationAdopted`; the next `unlock()` (one biometric prompt, two envelopes) re-wraps any local edits made under the old key.

The server's address is not kept in the SQLite file: it lives in the Keychain (same access group, this device only), and the database holds a placeholder. `LocalStore` records the highest `head_seq` it has seen, a 30-day trash of ciphertext the server replaced or deleted, and tombstone verification state.

Local store: SQLite (GRDB or SQLite.swift) holding the same ciphertext records the server holds plus the sync cursor, located in the **App Group container** from day one (`<TEAMID>.app.bisel` for macOS) so the M4/M5 extensions can open it. Keychain items use a shared access group for the same reason. The Mac app is non-sandboxed (Accessibility needs it); the extensions later will be sandboxed, so the store must not depend on app-only paths.

Public surface (names indicative)

```
Vault.bootstrap(server:, bootstrapToken:, deviceName:) -> RecoveryPhrase
Vault.unlock(reason:) async throws          // biometric, fills VK window
Vault.lock()
Vault.items / search source (decrypted in memory only while unlocked)
Vault.save(item), delete(id)
Vault.sync() async throws                   // report.rotationAdopted: another device rotated VK; this one locked itself
Vault.revealPassword(id) / copyTOTP(id)     // each does a fresh LAContext check
Vault.devices()
Vault.revoke(deviceID) -> RotationReport    // = rotateVaultKey(revoking:): cuts the device off AND re-keys the vault (atomic); the report lists what the device could have read (`secretsToChange`)
Vault.rotateVaultKey(revoking: String? = nil)   // unlocks first if needed; fresh biometric check; retries on conflicts; needs every active device in the roster
Vault.verificationCode() / confirmEnrollment(code:) / enrollmentNeedsConfirmation   // key confirmation after an enrollment
Vault.roster() / trustDevice(id:fingerprint:)
Vault.recoveryNeedsConfirmation / confirmRecovery(phrase:) / markRecoveryConfirmed() / recoveryMaterialChanged, RecoveryPhrase.quizPositions() / verify(answers:)
Vault.trash() / serverHistory(itemID:) / restore(_:)    // 30-day local trash and the server's retained versions
Vault.recentEvents(), SyncReport.events / rejectedTombstones / rotationAdopted
Vault.activationDate(), deviceKeyStatus(), removeLocalDevice(), acknowledgeServerReset()
Vault.revokeWithoutRotation(deviceID)       // emergency only (server DELETE); the device keeps VK
Vault.Configuration.secureEnclave(appGroupIdentifier:, keychainAccessGroup:)   // production wiring, identifiers injected
Vault.recover(server:, phrase:, deviceName:)
Vault.exportBackup(to:) / importBackup(from:, phrase:)
```

## 8. Mac app (M3)

Stack: Swift 6, SwiftUI + AppKit, macOS 26. Project generated by XcodeGen from `apps/mac/project.yml`. Bundle id `app.bisel.mac`. Hardened runtime, notarized Developer ID build, **not sandboxed**.

### Surfaces

1. **Menu-bar item + main window**: item list, detail, edit, password generator, devices, recovery, import, settings, theme.
2. **Command panel** on global ⌘⇧Space (`KeyboardShortcuts`; user-configurable). A **fixed-size card, 760 × 460 pt** in a borderless, non-activating, floating `NSPanel`: the window never resizes (so nothing moves while typing); only the content animates. It takes keyboard input without activating bisel, so the previously frontmost app stays frontmost.
   - **Position** (setting): bottom-center (default), top-right, bottom-right, on the screen that has the mouse, inset 16 pt from `visibleFrame` (clears Dock and menu bar). The window opens at the same spot every time.
   - **Layout** (Figma): top bar 48 pt (magnifier glyph 17 pt in a 24 pt box, query 15 pt, placeholder token) + 1 pt separator. Body = **list column 260 pt** | 1 pt separator | **detail pane**. List rows 48 pt (padding 12, gap 12): 24 pt rounded-square icon (radius 6) + 14 pt title, 1 pt separators, full-width selection fill. Detail pane (padding 16, 24 pt between blocks): icon, 12 pt, 24 pt title; pills (height 28, gap 10, 15 pt icon + 13 pt label): primary **Copy** (↩ keycap) and secondary **Fill**, **User ⇥ Pass**; then a "Values" label (12 pt), 10 pt, and a bordered card (1 pt, radius 8) of 40 pt rows: **OTP** (live code + 16 pt countdown ring), **Username**, **Password**, **Website**; label left, value right (13 pt). All sizes, colors, radii, fonts and the spacing scale (4/8/12/16) are `Theme` tokens; no label other than "Values"; no result-category labels.
   - **Material** (setting "Material: glass | solid", default glass): glass = system behind-window blur (`NSVisualEffectView` hud/popover) + theme tint, translucent row/pill/hover/border fills derived from the text color; solid = Figma black (#000) / white with #1b1b1b / #e8e8e8 hairlines. Light and dark follow the system appearance (each theme family has both variants). No shadow, one 1 pt border.
   - **Opens** listing the most recent/frequent items with the first selected; empty query = recents. Search is fuzzy (FuzzyMatch package) over title, URL host, username, tags: prefix and word-start matches rank far above mid-word hits (mid-word counts only for 4+ char queries), no scattered-subsequence matches, typo tolerance only for 5+ char terms, case/diacritic-insensitive, every whitespace term must match; ties by recency then frequency. Best match first and selected. State is fully reset on every show and hide (no stale flash).
   - **Keys**: ↑/↓ select · **↩ copy password** · **⇧↩ copy username** · **⌘↩ copy OTP** · **⌥↩ fill** the focused field (inferred by AX role) · **⌘⌥↩ fill username, Tab, password** · ⌘K more actions · Esc: leave actions, then clear the query, then dismiss. Copy is the default; fill is the secondary route for apps without a good paste target.
   - **Pointer**: hovering a list row selects it (hover = keyboard selection); hovering a Values row or pill highlights it. Hover is driven by polling `NSEvent.mouseLocation` (~30 Hz while visible) because tracking areas / SwiftUI `.onHover` are unreliable in a non-activating panel; list rows are hit-tested arithmetically (fixed 49 pt pitch + scroll offset). **Clicking a list row only selects it.** Clicking a Values row copies that value; clicking a pill runs its action; any other click inside does nothing.
   - **Values card**: Username and Website copy; Password and OTP are shown in plain text (see §4 decision; masked + Touch ID when "Require Touch ID…" is on). The OTP shows the live code and a ring that depletes over the item's period (green, through yellow, to red at ≤10 % left; semantic success/warning/danger tokens); the code changes at the period boundary. A copy flashes "✓ Copied" in place of the value (the Copy pill label for the pill) for ~0.5 s, then the panel dismisses (setting "Close after copy", default on).
   - **Dismissal**, each cause funnels into one `hide()` state machine (hidden → shown → hiding → hidden, a new show cancels a pending hide, monitors removed on hide): Esc; the hotkey; a mouse-down outside the panel (global monitor for other apps/desktop/menu bar/Dock, local monitor for this app's other windows); the frontmost app changing (`didActivateApplication`); `activeSpaceDidChange`; losing key status. Clicks inside never dismiss.
   - **Motion**: open = scale 0.96 → 1 + fade from the position anchor (snappy spring, ~0.18 s, no overshoot); dismiss ~0.11 s; no animation blocks input. Reduce Motion: opacity only.
   - **Accessibility**: the panel works with VoiceOver, Voice Control and Full Keyboard Access without changing its look. The search field is a labelled search field with a usage hint; each list row is one element (title; value "user, site, 3 of 12"; selected trait; press = select; custom actions copy password / username / one-time code / fill); each Values row is a button (label, value, press = copy) and the card is a group named "Values". **Passwords are never in the accessibility tree** (value "Hidden"); the OTP is exposed as "6 digits, about N seconds left" (5 s steps) and only spoken on the "Read code aloud" action. The shortcut legend is one element that reads the shortcuts in words; icons and the countdown ring are hidden from the tree. Because VoiceOver focus stays in the search field while ↑/↓ moves the selection, the panel posts announcements: the selected login ("GitHub, user, site, 2 of 7"), the result count after typing pauses (low priority), "Actions", and "<value> copied"; the toast is announced too. System switches apply live while open: Reduce Motion (opacity only, ring steps once a second), Reduce Transparency (glass falls back to solid), Increase Contrast (stronger borders, dim text, selection; high-contrast appearance), Differentiate Without Color (the OTP ring also shows the seconds as a number and goes dashed in its last quarter). Text tokens clear WCAG AA 4.5:1 in all four built-in themes, solid and glass; to get there the dim label/placeholder color moved from Figma #393939 to #767676 on the dark theme (#767676 light, #947969 Ember dark, #846F62 Ember light) and tertiary/secondary text alphas rose slightly. The panel hides on sleep, display sleep and fast-user-switch, and re-lays out on display changes.
   - **Site icons**: fetched directly from each item's site on this device, never via a third-party icon service, HTTPS only, ephemeral session (no cookies/cache/credentials/Referer, generic UA), ≤3 redirects within the same registrable domain, HTML head ≤64 KB, image ≤256 KB, decoded and re-encoded with ImageIO (96 px PNG), uniform white/transparent margins trimmed, ≤3 concurrent fetches, lazily for visible rows, failures cached 7 days, cache in `Application Support/bisel/icons` keyed by SHA-256 of the registrable domain (+ NSCache). Never stored in the vault or synced; the server never learns domains. Setting "Load site icons" (**default off, opt-in**: each lookup tells the network which sites are in the vault) and "Clear icon cache"; off = monograms only and no requests. Hosts must be public names on port 443 (no IP literals, single-label or local names; every resolved and every connected address public); only png/jpeg/gif/ico images up to 1024 px / 1 MP are decoded; registrable domain from the bundled Public Suffix List; cache file names are an HMAC under a per-install Keychain key (memory-only cache when no Keychain key is available).
   - Passwords are never shown in the _list_; Figma icons: search glyph, copy, send are template assets (`Resources/Assets.xcassets`); other icons are SF Symbols placeholders (User ⇥ Pass pill, actions menu).
3. **Fill engine**: Accessibility API on the focused element of the frontmost app.
   - Field inference from AX role/subrole: `AXSecureTextField` → password; a field whose label/description/identifier suggests a code → TOTP; otherwise username.
   - Preferred delivery: synthesized key events with `CGEventKeyboardSetUnicodeString` (no clipboard). Fallback: temporary paste with clipboard restore. Document which works where.
   - Chromium/Electron apps need accessibility enabled on the app element (`AXManualAccessibility` / `AXEnhancedUserInterface`); handle that.
   - Needs the Accessibility permission; first-run onboarding explains and deep-links to System Settings.
   - A compatibility matrix is a required deliverable: Safari, Chrome-family browser, Firefox, TextEdit, Terminal/Ghostty, System Settings password fields, Slack/Discord (Electron), a native SwiftUI app. For each: username, password, TOTP, secure-input behavior, result and caveat.
4. **Onboarding / bootstrap**: server URL, bootstrap token, device name → generate keys and phrase → show phrase once with a "I have stored it" gate → first sync.
5. **Recovery**: enter the phrase on a fresh install to rebuild. Export/import backup file.
6. **Import**: 1Password `.1pux` and generic CSV (logins, notes, TOTP). Use the standard zip/JSON/CSV libraries. Passkeys in a 1pux are stored losslessly in the reserved `passkey` type if present.

### Implementation notes (as built)

- **Storage.** No Team ID exists yet, so the local store and (Debug only) software keys live in `~/Library/Application Support/bisel/vault`, not the App Group container, and the Secure Enclave store is created with a `nil` keychain access group. Switch both to the shared group when the app is signed (M4).
- **Key store per build.** XcodeGen/Xcode can only set a SwiftPM trait per package reference, not per configuration, so there are two specs: `project.yml` → `Bisel.xcodeproj` (BiselCore **without** `SoftwareKeys`: Secure Enclave only; this is the Release/archive project) and `project.dev.yml` → `BiselDev.xcodeproj` (trait on, `BISEL_SOFTWARE_KEYS` defined for Debug: unsigned runs; loudly logged at startup and in the title bar/panel footer). Never archive `BiselDev.xcodeproj`.
- **Dev fixture.** Compiled only in Debug (`BISEL_DEV_FIXTURE`), and only _used_ when the process is started with `BISEL_DEV_FIXTURE=1`; otherwise the panel runs on the real vault.
- **Lock.** `VaultService` locks the core (VK zeroed) and drops rows, search index and any revealed state on sleep, screen lock, fast-user-switch, system idle (setting, default 5 min) and when the fill window (setting, default 5 min, counted from unlock) ends. Item secrets are decrypted on demand, never cached in the index.
- **Unlock UX.** With the Secure Enclave store the OS shows the Touch ID sheet when DK-enc opens the envelope; with software keys (Debug) the app runs the same `LAContext` gate first.
- **Sync** runs on unlock, panel open, every 60 s while unlocked, after each local save/delete and on demand; failures are shown in the main window as offline/failed, local edits stay pending.
- **Debug-only test hooks** (compiled out of Release): `BISEL_DATA_DIR`, `BISEL_DEV_SKIP_BIOMETRIC`, `BISEL_DEV_AUTOUNLOCK`, `BISEL_DEV_EXPORT_PATH`, and debug path fields in Import / restore so flow tests don't drive the out-of-process open panel.
- **Security hardening (review H4, M5, M6, M9–M13, M15–M17, L4, L8–L10, L12, L13).**
  - Release: `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` plus a build-phase gate that fails the build if `get-task-allow` is in the entitlements; `apps/mac/Tools/check-release.sh Bisel.app` re-checks a built app (entitlements, software keys, fixture, debug hooks). The ATS exception `NSAllowsLocalNetworking` is added to Debug builds only.
  - Strict "Require Touch ID" is enforced in `VaultService.secret` for password and OTP reads from any caller (copy, fill, panel); only the panel's own prompt buys one read (single-use credit, 3 s). An OTP already revealed in the last 35 s refreshes without a new prompt.
  - Fill: before every typed chunk (6 characters) the target must still be frontmost and its focused element must equal the classified one, otherwise typing stops. A password is typed only into a secure field, or into any field when forced from ⌘K; terminals additionally need secure input on. After Tab, ⌥↩ checks the next field before reading the password. The paste fallback runs only if the AX value is readable and unchanged after 500 ms.
  - Item URLs open only as https, or http after a confirmation; file://, smb://, vnc://, x-apple.systempreferences:, javascript: and the rest are refused.
  - Windows that can show secrets (set-up, recovery-phrase display, item editor and popover) set `sharingType = .none` (always for set-up and the phrase; otherwise per the "Hide from screenshots" setting). Revealed values and notes are not selectable; every copy, username and notes included, goes through `SecureClipboard`.
  - A recovery phrase is "unconfirmed" until the user re-types three random words; a marker file survives a quit, and the next unlock issues a new phrase to confirm. The server hostname is not stored in UserDefaults.
- **Import.** `.1pux` via ZIPFoundation + JSON, CSV via SwiftCSV (both pinned). A `passkey` value found anywhere in a 1pux item is stored whole in the item's `passkey` slot; its exact location in real 1Password exports is not verified (only generated fake exports were available).

### Theming

All visuals come from a `Theme` token set (colors, radii, spacing, fonts, row density, blur/glass). Ships light and dark of the default family plus a second family (Ember, with both variants); the variant follows the system appearance; theme JSON files are loadable from `~/Library/Application Support/bisel/themes/`. No view hard-codes a color or radius.

### Security details

- No secrets in logs, crash reports or Spotlight. Redact in all `Logger` calls.
- Secure event input respected: do not fight it.
- Auto-lock: sleep, screen lock, 5 min idle (configurable).
- Screenshots / screen sharing: the detail view's password field is excluded from capture where the OS allows (`NSWindow.sharingType = .none` on reveal windows).

## 9. Testing policy (hard rules)

1. **No unit tests.** No tests that assert what the code obviously does, mirror the implementation, snapshot copy or text, check layout/placement/colors, or pass by construction. If a test would not fail when the real feature is broken, do not write it.
2. Only **flow tests** that exercise real behavior through the public interface, using a proper test library:
   - Server: vitest with plain `fetch` against a real `wrangler dev` with a local D1 (started by a globalSetup on a free port). Flows: bootstrap→sync→edit→conflict→revoke→recovery; replay and bad-signature rejection (all 404); size limits.
   - Core: Swift Testing or XCTest _flow_ tests driving the `bisel-dev` CLI or the package against the real local server with the software key store: two simulated devices, encrypt on one, decrypt on the other, revoke, recover from phrase, backup/restore.
   - Mac app: XCUITest (or equivalent real-UI driving) for the critical paths only: onboarding, unlock, search and copy, fill into a real target app, lock on sleep trigger.
3. **Tests are never the only verification.** Every agent must also run the real thing: start the server, launch the built app, drive it, look at screenshots, and read logs. Report what was actually observed. A task is not done because tests are green.
4. If something can't be verified in this environment (e.g. no signing identity, no Touch ID in CI), say so explicitly. Do not claim it.

## 10. Tooling

Prefer CLIs and libraries to hand-written code.

- Server: `pnpm`, `wrangler`, Hono, Zod, vitest.
- Apple: `xcodegen`, `xcodebuild`, SwiftPM, `KeyboardShortcuts`, a BIP-39 package, an OTP package, GRDB (or SQLite.swift), a fuzzy-match package, `swift-format`.
- Do not vendor or copy library code; pin versions.
- Environment notes: Xcode 27.1; no code-signing identity found on the dev machine yet, so signed Secure Enclave runs may need the user to sign in to Xcode. Agents must report this rather than work around it silently.

## 11. Open items (decide in the milestone, record here)

- ~~Clipboard Universal-Clipboard exclusion mechanism~~ resolved in §4 (`currentHostOnly`).
- Exact AX fill behavior per app (matrix in §8).
- ~~Whether Ed25519 verification in workerd needs a specific algorithm name or a library.~~ Resolved in M1: no library; `crypto.subtle.importKey("raw", pub32, {name: "Ed25519"}, ...)` and `verify({name: "Ed25519"}, ...)` work in workerd (wrangler 4.154 / workerd 1.20261023), verified by the recovery flow tests.
- Whether the local DB should additionally be encrypted at rest (items are already ciphertext).
