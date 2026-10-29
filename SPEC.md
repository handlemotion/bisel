# bisel — spec v0.1

A personal, single-user, zero-knowledge password manager for Apple devices. Own server, own apps, no daily master password: unlock is biometrics only.

This file is the contract between `server/` and `apple/`. If an implementation needs to deviate, change this file in the same change and say why.

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

| # | Scope | Status |
|---|-------|--------|
| M1 | `server/` Worker + D1, signed-request auth, sync API | this spec |
| M2 | `BiselCore` Swift package: crypto, vault format, recovery, sync client | this spec |
| M3 | Mac app: vault UI, ⌘⇧Space command panel, fill engine, devices, recovery, 1pux/CSV import | this spec |
| M4 | Safari/system AutoFill credential provider on Mac (shares M2 core) | later |
| M5 | iPhone app + AutoFill provider, device enrollment by QR | later |
| M6 | Apple Passwords credential-exchange import (with passkeys) | later |
| M7 | Passkey sign-in everywhere; optional Safari extension for URL context; agent CLI | later |

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
  - `DK-enc`: access control `.biometryAny` + `.privateKeyUsage`. Used to unwrap the device envelope (ECIES, `eciesEncryptionCofactorX963SHA256AESGCM`). `biometryAny` so adding or removing fingerprints does not invalidate it. No passcode fallback.
  - `DK-sig`: `.privateKeyUsage` only, no biometric prompt, so background sync never prompts. Signs requests.
- **Device envelope**: VK encrypted to a device's `DK-enc` public key. Stored locally and on the server (the server cannot open it).
- **Recovery phrase**: 24 words (BIP-39 wordlist, 256 bits of entropy), shown once at bootstrap. `RK = phrase entropy`.
  - `RK-wrap = HKDF(RK, "bisel/v1/recovery-wrap")` encrypts a copy of VK: the **recovery envelope**, stored on the server.
  - `RK-sig`: an Ed25519 key whose seed is `HKDF(RK, "bisel/v1/recovery-sig")`. Its public key is registered at bootstrap and lets a device-less client authenticate to fetch the recovery envelope.
- **Backup file** `.bisel-backup`: the server's records (items, recovery pubkey, recovery envelope) exported to a single file. Only the recovery phrase opens it.
- Padding: item ciphertext is padded to a multiple of 512 bytes before encryption.

Unlock model (client)
1. App launch / unlock: unwrap the device envelope with `DK-enc` (biometric prompt) → VK held in memory (locked, non-swappable memory where possible).
2. VK stays in memory for the **fill window** (default 5 min). It is zeroed on sleep, screen lock, idle timeout, or explicit lock.
3. **Sensitive actions**: edit/delete an item always require a fresh `LAContext` evaluation (`.deviceOwnerAuthenticationWithBiometrics`) even inside the window.
   **Deliberate decision (user, M3 panel):** *revealing and copying a password or OTP inside the fill window does not prompt again.* The command panel shows both in plain text while the vault is unlocked (the Touch ID unlock opened the 5 min window; the panel opens locked and unlocks first if the window expired). Lock on sleep / screen lock / idle and the 30 s clipboard clear still apply, and the panel window is excluded from capture (`NSWindow.sharingType = .none`, setting "Hide from screenshots and screen sharing", default ON in Release, OFF in Debug).
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

Hosting: the Worker is bound to a random, unguessable subdomain of `bisel.app` (a wildcard cert keeps the name out of CT logs). `bisel.app` itself is just the brand.

### Request authentication

Every request except `POST /v1/bootstrap` (shared-secret header only) carries the four headers below. Recovery requests use `X-Bisel-Device: recovery` and an Ed25519 signature instead of a device id and P-256. Wire details (encodings, signature byte formats, query canonicalization) are in `server/README.md`.

```
X-Bisel-Device: <device id>
X-Bisel-Ts:     <unix seconds>
X-Bisel-Nonce:  <random 128-bit, base64url>
X-Bisel-Sig:    <base64url signature>
```

Signed string: `METHOD \n PATH \n SORTED_QUERY \n SHA256(body) as hex \n TS \n NONCE`. Algorithms: P-256 ECDSA over SHA-256, raw `r||s` signature (device), or Ed25519 (recovery). Binary values on the wire are unpadded base64url; P-256 public keys are X9.63 uncompressed, the Ed25519 public key is raw 32 bytes. Server rejects: unknown or revoked device, |now − ts| > 60 s, reused nonce (stored 5 min in D1, pruned), bad signature.

**Every failure returns the same empty `404`.** The server must not reveal that it exists to unauthenticated callers. No public health route.

Rate limiting: a Cloudflare rate-limit rule on the zone, plus a Worker-side counter for failed auth (D1 `auth_failures`, per `CF-Connecting-IP`, default 20 failures / 600 s, configurable by vars). Past the limit that IP gets the same empty `404` for every request, valid signatures included; there is no 429, since that would reveal the server.

After authentication, request errors (bad body, stale `base_rev`, too large) use ordinary statuses with a JSON `{"error": ...}` body; only authentication failures and unknown routes are the bare `404`.

### Endpoints

| Method | Path | Notes |
|--------|------|-------|
| POST | `/v1/bootstrap` | One time. Header `X-Bisel-Bootstrap: <secret>` matching the Worker secret `BOOTSTRAP_TOKEN`. Body: first device (id, name, sig pubkey, enc pubkey, device envelope), recovery pubkey, recovery envelope. After success the endpoint always 404s. |
| GET | `/v1/sync?since=<seq>` | Returns changes after `seq`: items (incl. tombstones), device list, current head `seq`, and the recovery pubkey + envelope (needed to write `.bisel-backup`). Paginated by `limit`. |
| PUT | `/v1/items/:id` | Body `{ base_rev, blob }`. `base_rev` is 0 for new items. 409 with the current record if stale. Server assigns `rev+1` and a new `seq`. Max blob 256 KiB. |
| DELETE | `/v1/items/:id?base_rev=` | Tombstone (keeps `seq`, empties blob). |
| GET | `/v1/devices` | List with name, kind, created, last seen, revoked. |
| POST | `/v1/devices` | An existing device approves a new device: registers its pubkeys and stores the device envelope the approver created for it. |
| DELETE | `/v1/devices/:id` | Revoke. Effective immediately: later requests from that device 404. |
| GET | `/v1/envelope` | The calling device's own device envelope. |
| POST | `/v1/recovery/session` | Authenticated by the Ed25519 recovery signature only. Empty body: returns the recovery envelope. Body `{device}`: also registers a replacement device (two calls, because the client needs the envelope to derive VK before it can build its own device envelope). |
| POST | `/v1/recovery/rotate` | Signed by a normal (e.g. the replacement) device. Replace the recovery pubkey and envelope after a recovery. |

Conflicts: client resolves a 409 by fetching the current record and, if both sides changed, keeping the remote and saving the local edit as a new item titled "<title> (conflict)". No silent overwrite.

Push: not in v1. The Mac polls every 60 s while unlocked, on unlock, and on demand. A Durable Object WebSocket and APNs come with the iPhone.

### D1 schema (sketch)

```
meta(id=1, recovery_alg, recovery_pubkey, recovery_envelope, head_seq, created_at)
devices(id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, created_at, last_seen_at, revoked_at)
items(id, rev, seq UNIQUE, deleted, blob, updated_at)
nonces(nonce, ts)
events(id, ts, device_id, type, subject_id)        -- bootstrap/approve/revoke/recovery/recovery_rotate only
auth_failures(ip, window_start, count)             -- Worker-side failed-auth backoff
```
Binary columns are unpadded base64url TEXT (D1 returns BLOBs as number arrays); timestamps are unix seconds.
`head_seq` increments inside a D1 batch with the item write so seq is gapless and monotonic. Both statements carry the same `rev == base_rev` guard, so a rejected (409) write consumes no seq.

### Secrets and ops
- `BOOTSTRAP_TOKEN` via `wrangler secret put`, never in the repo.
- A deployed instance is created only on the user's say-so. Everything here is built and verified against `wrangler dev` with local D1.

## 7. BiselCore (M2)

SwiftPM package, Swift 6, macOS 26+ / iOS 26+. No UI.

Module names are prefixed (`BiselCrypto`, `BiselKeyStore`, `BiselVault`, `BiselSync`, `BiselRecovery`, `BiselTOTP`) because a module called `Crypto` collides with swift-crypto's (pulled in by the OTP package) and a module called `Vault` would shadow the public `Vault` type. The umbrella module `BiselCore` re-exports them all and defines the `Vault` facade (an `actor`). `BiselTestSupport` (dev/test only, never linked by apps) starts a throwaway local server for flow tests.

Modules
- `Crypto`: key hierarchy above, AEAD helpers, recovery phrase encode/decode (use a maintained BIP-39 Swift package, do not hand-write the wordlist), HKDF via CryptoKit.
- `KeyStore`: `DeviceKeyStore` (SE + software).
- `Vault`: item model, encrypt/decrypt, local store.
- `Sync`: signed HTTP client for section 6 and the pull/push engine with conflict handling.
- `Recovery`: phrase generation, backup-file export/import, rebuild-from-phrase.
- `TOTP`: use an existing Swift OTP package, do not hand-roll.

Local store: SQLite (GRDB or SQLite.swift) holding the same ciphertext records the server holds plus the sync cursor, located in the **App Group container** from day one (`<TEAMID>.app.bisel` for macOS) so the M4/M5 extensions can open it. Keychain items use a shared access group for the same reason. The Mac app is non-sandboxed (Accessibility needs it); the extensions later will be sandboxed, so the store must not depend on app-only paths.

Public surface (names indicative)
```
Vault.bootstrap(server:, bootstrapToken:, deviceName:) -> RecoveryPhrase
Vault.unlock(reason:) async throws          // biometric, fills VK window
Vault.lock()
Vault.items / search source (decrypted in memory only while unlocked)
Vault.save(item), delete(id)
Vault.sync() async throws
Vault.revealPassword(id) / copyTOTP(id)     // each does a fresh LAContext check
Vault.devices(), revoke(deviceID)
Vault.recover(server:, phrase:, deviceName:)
Vault.exportBackup(to:) / importBackup(from:, phrase:)
```

## 8. Mac app (M3)

Stack: Swift 6, SwiftUI + AppKit, macOS 26. Project generated by XcodeGen from `apple/project.yml`. Bundle id `app.bisel.mac`. Hardened runtime, notarized Developer ID build, **not sandboxed**.

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
   - **Site icons**: fetched directly from each item's site on this device, never via a third-party icon service, HTTPS only, ephemeral session (no cookies/cache/credentials/Referer, generic UA), ≤3 redirects within the same registrable domain, HTML head ≤64 KB, image ≤256 KB, decoded and re-encoded with ImageIO (96 px PNG), uniform white/transparent margins trimmed, ≤3 concurrent fetches, lazily for visible rows, failures cached 7 days, cache in `Application Support/bisel/icons` keyed by SHA-256 of the registrable domain (+ NSCache). Never stored in the vault or synced; the server never learns domains. Setting "Load site icons" (default on) and "Clear icon cache"; off = monograms only and no requests.
   - Passwords are never shown in the *list*; Figma icons: search glyph, copy, send are template assets (`Resources/Assets.xcassets`); other icons are SF Symbols placeholders (User ⇥ Pass pill, actions menu).
3. **Fill engine**: Accessibility API on the focused element of the frontmost app.
   - Field inference from AX role/subrole: `AXSecureTextField` → password; a field whose label/description/identifier suggests a code → TOTP; otherwise username.
   - Preferred delivery: synthesized key events with `CGEventKeyboardSetUnicodeString` (no clipboard). Fallback: temporary paste with clipboard restore. Document which works where.
   - Chromium/Electron apps need accessibility enabled on the app element (`AXManualAccessibility` / `AXEnhancedUserInterface`); handle that.
   - Needs the Accessibility permission; first-run onboarding explains and deep-links to System Settings.
   - A compatibility matrix is a required deliverable: Safari, Chrome-family browser, Firefox, TextEdit, Terminal/Ghostty, System Settings password fields, Slack/Discord (Electron), a native SwiftUI app. For each: username, password, TOTP, secure-input behavior, result and caveat.
4. **Onboarding / bootstrap**: server URL, bootstrap token, device name → generate keys and phrase → show phrase once with a "I have stored it" gate → first sync.
5. **Recovery**: enter the phrase on a fresh install to rebuild. Export/import backup file.
6. **Import**: 1Password `.1pux` and generic CSV (logins, notes, TOTP). Use the standard zip/JSON/CSV libraries. Passkeys in a 1pux are stored losslessly in the reserved `passkey` type if present.

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
   - Server: Playwright Test (`request` fixture) against a real `wrangler dev` with a local D1. Flows: bootstrap→sync→edit→conflict→revoke→recovery; replay and bad-signature rejection (all 404); size limits.
   - Core: Swift Testing or XCTest *flow* tests driving the `bisel-dev` CLI or the package against the real local server with the software key store: two simulated devices, encrypt on one, decrypt on the other, revoke, recover from phrase, backup/restore.
   - Mac app: XCUITest (or equivalent real-UI driving) for the critical paths only: onboarding, unlock, search and copy, fill into a real target app, lock on sleep trigger.
3. **Tests are never the only verification.** Every agent must also run the real thing: start the server, launch the built app, drive it, look at screenshots, and read logs. Report what was actually observed. A task is not done because tests are green.
4. If something can't be verified in this environment (e.g. no signing identity, no Touch ID in CI), say so explicitly. Do not claim it.

## 10. Tooling

Prefer CLIs and libraries to hand-written code.
- Server: `pnpm`, `wrangler`, Hono, Zod, Playwright.
- Apple: `xcodegen`, `xcodebuild`, SwiftPM, `KeyboardShortcuts`, a BIP-39 package, an OTP package, GRDB (or SQLite.swift), a fuzzy-match package, `swift-format`.
- Do not vendor or copy library code; pin versions.
- Environment notes: Xcode 27.1; no code-signing identity found on the dev machine yet, so signed Secure Enclave runs may need the user to sign in to Xcode. Agents must report this rather than work around it silently.

## 11. Open items (decide in the milestone, record here)

- ~~Clipboard Universal-Clipboard exclusion mechanism~~ resolved in §4 (`currentHostOnly`).
- Exact AX fill behavior per app (matrix in §8).
- ~~Whether Ed25519 verification in workerd needs a specific algorithm name or a library.~~ Resolved in M1: no library; `crypto.subtle.importKey("raw", pub32, {name: "Ed25519"}, ...)` and `verify({name: "Ed25519"}, ...)` work in workerd (wrangler 4.154 / workerd 1.20261023), verified by the recovery flow tests.
- Whether the local DB should additionally be encrypted at rest (items are already ciphertext).
