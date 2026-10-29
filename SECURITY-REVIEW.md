# bisel security review

Adversarial, read-only review of the whole repo against `SPEC.md` (contract and threat model: server breach, stolen or unlocked device, phishing, total device loss; max security first).

- **Reviewed:** 2026-10-28, 18:55 to 19:20 local. Git `HEAD` is `412d947` plus uncommitted work from three sibling sessions (core-hardening, vault-integration, a11y-quality) that were still editing `server/`, `apple/Packages/BiselCore` and `apple/Bisel` while I read. Line numbers are from the working tree at the moment I read the file and will drift. I name functions so findings stay locatable.
- **Method:** read all server, core and Mac-app sources; ran a throwaway `wrangler dev` (ports 8931-8933, scratch D1, nothing deployed) and probed it with signed requests; built the Mac app in Release into a scratch DerivedData and inspected the binary; `pnpm audit`; grep for secrets; ran a decompression test of the icon decoder's ImageIO calls. No repo file other than this one was touched.
- **Status words:** *Confirmed* = reproduced or plainly shown in code. *Suspected* = plausible from code or platform behaviour, not reproduced.

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 4 |
| Medium | 17 |
| Low | 14 |

The crypto primitives, key hierarchy, AAD binding, HKDF contexts, recovery-phrase generation, uniform-404 design, replay protection and D1 batch atomicity are sound. The weak points are all about **who may do what without proving possession of VK**, and about **trusting the server's device list and envelopes**: a device-signing key that needs no biometric can destroy the vault server-side and can plant a device that later receives the rotated vault key.

Resolved or being resolved in the working tree while I reviewed (verified, see "Verified fixed" at the end): lockout design, constant-work auth, revoke-with-rotation.

---

## High

### H1. One device-signing key (DK-sig, no biometric, no VK) can irreversibly destroy the whole server-side vault. *Confirmed*
- **Where:** `server/src/index.ts` `POST /v1/rotate` (~L449), `POST /v1/recovery/rotate` (~L566), `DELETE /v1/devices/:id` (~L400), `DELETE /v1/items/:id` (~L330), `PUT /v1/items/:id` (~L294); `SecureEnclaveKeyStore.swift:38` (`DK-sig` is `.privateKeyUsage` only).
- **Exploit:** anyone who can make the app (or a stolen/unlocked Mac, or malware running as the user inside the app's keychain access group) sign requests needs no Touch ID and no VK. I ran, against the current code: bootstrap, put two items, then `POST /v1/rotate` with random 60-byte "wrapped item keys", a random device envelope and a random recovery envelope. The server answered `200 {"epoch":2,...}` and replaced the first 80 base64url characters of every item blob. Every item key, every device envelope and the recovery envelope are now garbage, the server keeps no history, and the server cannot tell. Earlier probes (pre-rotation code) showed the same via `recovery/rotate` with junk (old recovery key then 404), tombstoning (blob emptied), and a second device revoking the first.
- **Impact:** total, silent loss of everything the server holds. Recovery is possible only from a prior `.bisel-backup`. This defeats the "stolen unlocked device" goal even though VK itself stays safe.
- **Fix:** (1) add a **vault-admin key**: at bootstrap derive an Ed25519 key from VK (`HKDF(VK, "bisel/v1/admin-sig")`) and register its public key; require a second signature from it on `/v1/rotate`, `/v1/devices` (approve), `DELETE /v1/devices/:id`, `/v1/recovery/rotate`, and make rotation re-register the new admin pubkey signed by the old one. Producing it needs VK, i.e. a biometric unlock. (2) Server-side retention: on item overwrite/tombstone and on rotate keep the previous blob/wrapped key for N days (`item_history`), so a bad write is reversible by the owner. (3) Make `DELETE /v1/devices/:id` (non-rotating revoke) also require the admin signature.

### H2. Rotation and approval seal VK to whatever device list the server supplies; a rogue device planted without a biometric receives the *new* vault key. *Confirmed in code*
- **Where:** `Vault.swift rotateOnce` (`let devices = try await client.devices()`, `remaining = active.filter ...`, then `DeviceEnvelope.seal(vaultKey: newRaw, toEncryptionKey: pub)` for every active device); `server POST /v1/devices` accepts any device registration signed by DK-sig alone.
- **Exploit:** attacker with DK-sig (see H1) or an active server compromise calls `POST /v1/devices` with their own `enc_pubkey`. Nothing prompts the owner. The next time the owner revokes a device or rotates (exactly the moment they are reacting to a compromise), the client sees the rogue device in `client.devices()` and seals the fresh VK to it. Revocation then hands the attacker the new key. The same applies if a malicious server swaps an existing device's `enc_pubkey` in the listing.
- **Fix:** keep a **local roster of approved device public keys** (fingerprints), written only by `approveEnrollment`/`bootstrap`/`recover` on this device and mirrored as a VK-encrypted vault record signed with the admin key. `rotateOnce` seals only to keys in the roster; an unknown active device aborts the rotation with an alert listing it (and offers to revoke it). Show the fingerprint (`DevicePublicKeys.fingerprint`, currently only 64 bits; use ≥ 96) when confirming.

### H3. Device envelope has no sender authentication or key confirmation; a malicious or breached server can make a newly enrolled device adopt a VK the server knows. *Confirmed in code*
- **Where:** `Vault.swift completeEnrollment` (~L220: `id.envelope = try await client().envelope()`), `DeviceEnvelope.seal` (`DeviceEnvelope.swift`), ECIES to a public key.
- **Exploit:** `enc_pubkey` is public. A server that controls the enrollment relay replaces the approver's envelope with `ECIES(enc_pubkey, VK')` for a VK' it generated. The new device unlocks VK' without error; existing items show up as "undecryptable" (not surfaced as an error to the user: `ItemListing.undecryptable`, `VaultService.undecryptable`); everything the user then saves from that device is encrypted under a key the server holds. Same shape for the recovered `(vk, epoch)` if the recovery envelope were unauthenticated, but that one is protected by AES-GCM/HPKE under a key derived from the phrase.
- **Fix:** key confirmation before the new device accepts VK: (a) every vault carries a canary item (fixed id, plaintext = vault id) that must decrypt with the received VK, else refuse; (b) the approver shows `HKDF(VK, "bisel/v1/verify")[0..<4]` as a short code the new device recomputes and displays for the human to compare; (c) treat "all records undecryptable on first sync" as a hard error, not a counter.

### H4. The Release build carries `com.apple.security.get-task-allow`. *Confirmed on a built artifact*
- **Where:** `codesign -d --entitlements -` on `Build/Products/Release/Bisel.app` (ad-hoc, `flags=adhoc,runtime`) prints `com.apple.security.get-task-allow = true`. `Bisel.entitlements` is empty; Xcode injects the entitlement into ad-hoc/dev signed builds (`CODE_SIGN_INJECT_BASE_ENTITLEMENTS` default).
- **Impact:** any same-user process can attach (`task_for_pid`/lldb) and read VK, decrypted items and clipboard data from the running app despite hardened runtime. The whole "VK only in a locked page, zeroed on lock" story is moot.
- **Fix:** in `project.yml` Release settings set `CODE_SIGN_INJECT_BASE_ENTITLEMENTS: NO`, and add a release gate: `codesign -d --entitlements - Bisel.app | grep -q get-task-allow && exit 1`. Notarized exports normally strip it, but do not rely on that; the same build setting also matters for the ad-hoc builds you run daily.

---

## Medium

### Crypto and protocol

**M1. `.biometryAny` means a thief with the Mac password can enrol their own finger and unlock the vault.** *Confirmed (design)*. `SecureEnclaveKeyStore.swift:36` (`[.biometryAny, .privateKeyUsage]`), SPEC §4. Adding a fingerprint needs only the account password. Fix: `.biometryCurrentSet`; after enrolment changes the key is invalidated and the device re-enrols from another device or the recovery phrase. If usability wins, at least detect `LAContext.evaluatedPolicyDomainState` changes and force a re-confirmation plus a rotation.

**M2. Rollback, withholding and silent deletion by a hostile server are accepted.** *Confirmed in code*. `Store.swift applyRemote` replaces local state on `rev`/`seq` alone; a tombstone (`deleted: true`, empty blob) from the server overwrites the local ciphertext with an empty blob, so one forged tombstone deletes the item on every device on the next sync. `SyncEngine.pull` trusts `next_since`/`head_seq` (a huge `next_since` skips all later changes forever). AAD binds id+rev so blobs cannot be swapped between items, but nothing authenticates the *set*. Fix: keep the last good ciphertext locally in a `trash` table for 30 days before applying any remote tombstone or overwrite; require tombstones to be sealed markers (AEAD under VK with AAD `id|rev|"tomb"`); validate `next_since <= head_seq` and monotonic `head_seq`; optionally a VK-MACed manifest of `(id, rev)` per sync epoch.

**M3. The cached recovery material is overwritten with whatever the server reports.** *Confirmed*. `Store.swift updateRecovery` (called from `SyncEngine.pull`), and `exportBackup` writes that cached material. A server (or H1 attacker via `recovery/rotate`) can swap in a recovery pubkey/envelope the owner's phrase cannot open; the owner learns it when they need it. Fix: pin the recovery pubkey locally; accept changes only from this device's own `rotateRecovery`; on mismatch alert loudly and refuse to write a backup.

**M4. Recovery has no alert and no cooling period.** *Confirmed (design)*. `server /v1/recovery/session` with a `device` registers a new device immediately. Someone who sees the 24 words once gets silent, full access; the only trace is an `events` row nobody reads (`sync` does not return events). Fix: return `events` in `/v1/sync` and show "new device added / recovery used" on every device at next sync; add a configurable delay (e.g. 24 h) before a recovery-registered device is activated, cancellable from any existing device.

**M5. Recovery phrase can be lost between bootstrap and "I have stored it".** *Confirmed in code*. `VaultService.bootstrap` registers the recovery envelope on the server, then keeps the phrase only in `pendingPhrase`. Quitting or crashing at the gate leaves a server holding a recovery envelope whose phrase nobody saw, and `refreshPhase` proceeds as if set up. `PhraseGateView` accepts a plain toggle with no verification. Fix: persist an "unconfirmed recovery" flag in `LocalIdentity`, force `rotateRecovery` on next unlock until confirmed, require re-entering 3 random words.

**M6. `Require Touch ID` mode does not gate password fill.** *Confirmed*. `VaultSearchSource.swift:19` `requiresFreshBiometricWhenFilled() { self == .totp }`, used in `AppModel.runFill`. SPEC §4 says strict mode asks again for "every copy/fill of a password or TOTP". With the setting ON, ⌥↩ and ⌘⌥↩ still type the password without a prompt. Also, the strict gate is enforced only in UI callers (`VaultService.secret` never calls `Vault.revealPassword`), so any new call path bypasses it. Fix: move the gate into `VaultService.secret(_:for:)` keyed on `SecuritySettings.requireTouchID`.

**M7. `Vault.gate` is a UI-level boolean, not a cryptographic gate.** *Confirmed (design)*. Edit/delete/revoke "require Touch ID" via `LAContext.evaluatePolicy` in-process; code execution inside the app, or `get-task-allow` (H4), skips it. Only `openEnvelope` is bound to the Secure Enclave. Acceptable if documented; the admin-key fix in H1 makes the destructive operations cryptographically gated.

**M8. Revocation does not re-encrypt payloads, and the key itself is only as safe as the roster (H2).** *Confirmed (by design)*. `rotateVaultKey` re-wraps item keys under a new VK but leaves each item's ciphertext untouched, so a revoked device keeps every item key it has already seen and can read every revision it synced. The UI text ("It can no longer sync") does not say so. Fix: after revoking, say plainly which passwords the device could read and offer a "rotate these secrets" checklist; consider per-rev IK rotation for the most sensitive items.

### Mac app

**M9. Fill types into whatever has focus *now*, not into the target the fields were read from.** *Confirmed in code*. `FillEngine.perform`/`deliver`: AX reads `target`'s focused element, but `KeyEventTyper` posts HID events to the current key window. During the modifier wait (up to 700 ms), the 80 ms sleep, up to 5 × 120 ms retries and the Tab step, focus can move (⌘-Tab, notification, Spotlight). Also `.userTabPassword` types the password into the next focused element without checking it is secure, and `.explicit(.password)` into any field (visible text field, chat box, shell prompt: Terminal history). Fix: before every `type`, require `NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier` and that the system-wide focused element equals the one classified (`CFEqual`); refuse to type a password unless `isSecure` (or the user explicitly forced it from ⌘K); in terminals require secure input to be on.

**M10. Items can open `file://` and arbitrary URL schemes.** *Confirmed*. `ItemDetail.swift:186`, `AppModel.swift:129` (via `VaultService.url(for:)`) pass item URLs straight to `NSWorkspace.shared.open`. A URL such as `file:///Users/x/y.command`, `smb://`, `vnc://`, `x-apple.systempreferences:` or a custom scheme launches that handler on a click; imported or synced items are attacker-influenced data. Fix: allow only `https` (and `http` behind a warning); drop everything else.

**M11. Icon decoder processes untrusted images in the process that holds VK, with no pixel limit.** *Confirmed (resource), memory-safety Suspected*. `IconStore.swift normalize` (L233) caps the *download* at 256 KB but never the decoded size. I generated a 194 KB, 40000 × 40000 1-bit PNG and ran the same `CGImageSourceCreateThumbnailAtIndex` call: **8.1 s and 1.6 GB peak RSS**; PNG allows far larger. Three fetches run in parallel and the 10 s resource timeout does not cover decoding. ImageIO is also a recurring zero-click CVE surface (WebP, TIFF, JPEG 2000, ICO). Fix: read `kCGImagePropertyPixelWidth/Height` and reject above ~1024 × 1024 or 1 MP before any decode; allow-list `CGImageSourceGetType` (png, jpeg, gif, ico); decode in a sandboxed XPC helper without keychain or network entitlements.

**M12. Icon fetcher can be pointed at private and local addresses (SSRF), and `registrable()` is not a Public Suffix List.** *Confirmed in code*. `fetchIcon(host:)` builds `https://\(host)/` from item data. `localhost`, `192.168.x.x`, `10.x`, `169.254.169.254`, `*.local` and any public name resolving to private space are fetched; `<link href>` candidates on any subdomain of the item's registrable domain (including `internal.attacker.com` → 127.0.0.1, with a valid certificate for it) allow GETs to arbitrary ports. Impact is blind GETs and LAN probing triggered by importing or syncing an item. `registrable("a.github.io")` = `github.io`, so unrelated tenants share redirects and cache entries. Fix: resolve first and reject loopback, link-local, RFC 1918, CGNAT, ULA and multicast; refuse IP literals, single-label and `.local` hosts, and any port other than 443; use a bundled PSL.

**M13. Site icons leak the whole domain list to the network and DNS resolver.** *Confirmed (by spec, default ON)*. Every domain with a visible row is requested directly (SNI, DNS, source IP), including sites the user rarely visits. This conflicts with "server sees nothing" thinking at the network layer. Fix: default OFF (opt-in), or fetch only for domains the user has opened in the last N days; document it in the setting.

**M14. Password and OTP appear in plain text for the top result as soon as the panel opens.** *Confirmed (spec decision), exposure widened*. `CommandPanelModel.prepareValues` decrypts and displays password and TOTP for the selected row on every selection change; the first recent is selected on open. Shoulder surfing, screen sharing (if M15 holds), and any process with Accessibility permission can read it. Suspected that SwiftUI exposes the password string in the AX tree; a11y-quality should confirm. Fix: reveal only after a deliberate action (⇥ or a click on the row), or mask until the pointer or keyboard dwells; keep AX value masked.

**M15. Capture exclusion covers only the command panel; `sharingType = .none` may not work on current macOS.** *Confirmed gap; effectiveness Suspected*. `sharingType` appears only in `CommandPanel.swift`/`CommandPanelController.swift`. The main window reveals passwords (`ItemDetail`), shows the 24-word recovery phrase (`PhraseGateView`) and takes the phrase as text input (`SetupView`) with default sharing. Separately, ScreenCaptureKit-based capture on recent macOS reportedly ignores `sharingType = .none`. I could not test (no screen-recording grant). Fix: set `sharingType = .none` on every window that can show secrets; test with `screencapture -l` and an SCStream client on the actual OS; warn in the UI when capture is active (`NSScreen`/`CGSession` sharing state).

**M16. Selecting revealed text bypasses `SecureClipboard`.** *Confirmed*. `ItemDetail.valueRow` has `.textSelection(.enabled)` on passwords; ⌘C writes the plain general pasteboard (no `ConcealedType`, no `currentHostOnly`, no 30 s clear, reaches Universal Clipboard). Notes (`textSelection(.enabled)`) and non-secret fields use `NSPasteboard.general` directly. Fix: disable text selection on secret values; route every copy through `SecureClipboard`.

**M17. Local state stores the server hostname in the clear in several places.** *Confirmed*. `UserDefaults "setup.lastServer"` (`SetupView.swift:15,127`), `LocalIdentity.serverURL` in `bisel.sqlite`, and Time Machine copies of both. SPEC §6 treats the hostname as a secret. Fix: store it only in the Keychain (or the encrypted vault) and not in defaults.

---

## Low

**L1. Server tombstones and rollbacks are not recoverable server-side** (covered by H1 fix). Listed separately because `DELETE /v1/devices/:id` (non-rotating revoke) is still reachable by any device; keep it only behind the admin signature.

**L2. `auth_failures.ip` rows persist until the next failure.** The prune runs inside `recordFailure` only, so the owner's IP (from a clock-skew failure) stays in D1 indefinitely and appears in a breach. Fix: prune on every authenticated request, or hash IPs with a daily salt.

**L3. Structured logs carry the client IP and device id on every request** (`auth.ts` `console.log` evt `req`/`auth_fail`). `observability` is disabled, but `wrangler tail` and a later toggle capture them. Fix: log a truncated hash, not the raw IP.

**L4. Device names are plaintext on the server and unsanitized.** I registered a device named with NUL and U+202E and the server returned it verbatim. The UI (`DevicesView`) renders `d.name` and uses it in an accessibility identifier. Fix: strip control and bidi characters server-side and client-side; consider encrypting names under VK.

**L5. Metadata the server learns** (documented, listed for completeness): item ids, `rev` per item, blob size to 512-byte granularity plus fixed overhead, `updated_at` to the second, tombstones, item count, device names, kinds and `last_seen_at` (1-minute resolution), event log (`bootstrap/approve/revoke/recovery/rotate` with timestamps and device ids), client IP via Cloudflare. Fix if desired: bucket timestamps, drop `last_seen_at` or round it to a day, encrypt device names.

**L6. Missing response hardening headers.** Authenticated JSON responses have only `content-type`; add `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` (the working tree now sets it for all responses? verify after merge), and rely on Cloudflare for HSTS. No CORS headers is correct.

**L7. `registrable()` heuristic** (see M12) also keys the on-disk icon cache.

**L8. Icon cache filenames are an unsalted SHA-256 of the registrable domain** (`IconStore.key(for:)`, L46): anyone with disk or backup access can test whether the vault contains `mybank.com`. Fix: HMAC with a per-install random key kept in the Keychain.

**L9. Clipboard restore drops `currentHostOnly`.** `SecureClipboard.restore` re-writes the previous clipboard with `writeObjects`, so a previously local-only secret from another app becomes eligible for Universal Clipboard. Fix: restore through the same `prepareForNewContents(with: .currentHostOnly)` path.

**L10. Fill fallback can type the secret twice** when AX value length lags 120 ms (`deliver`, key events then paste). Reliability and a second exposure of the secret. Fix: only paste-fallback when the AX value is unreadable, not when unchanged.

**L11. Synthesized events are visible to other event taps.** Typing via `cghidEventTap` can be observed by any process with Input Monitoring unless secure event input is on. The code logs `IsSecureEventInputEnabled()` but proceeds. *Suspected*. Fix: offer paste-with-restore as the default for non-secure fields, and warn when secure input is off while filling a password.

**L12. Logging metadata.** `AppModel.finish`, `FillEngine`, `LockMonitor`, `VaultService` log with `privacy: .public`: target bundle id, AX role/subrole, sync counts, "secret copied" with `changeCount`, lock reasons. No secret values, but a persisted timeline of secret use. Fix: use default (private) interpolation for everything except fixed enums.

**L13. `NSAllowsLocalNetworking = true` is in the Release Info.plist** (`project.yml`), and `ServerURLCheck` is only enforced in `SetupView`; `SyncClient` accepts any scheme, follows redirects (custom `X-Bisel-*` headers survive cross-origin redirects), and has no response-size cap. Fix: apply the ATS exception only in Debug, validate scheme in `SyncClient.init`, add a redirect-refusing delegate and a body cap.

**L14. Small crypto and memory hygiene.** (a) `ItemSealer` uses the same AAD for the wrapped key and the payload; add a domain label (`|wrap`, `|body`). (b) `LockedKey.zero()` calls `munlock` on a page that may be shared with another live `LockedKey` (not reference-counted). (c) `withKey`/`rawBytes()`/`openEnvelope` create unzeroed `SymmetricKey`/`Data` copies. (d) The VK lock path is `Task { await vault?.lock() }` on `willSleep`, so zeroing may race the sleep. (e) Fingerprint is 64 bits. None is exploitable on its own.

---

## Supply chain and repository hygiene

- **`pnpm audit`: no known vulnerabilities.** All server dependencies are exact-pinned (`hono 4.13.14`, `zod 4.6.7`, `wrangler 4.154.0`, `typescript 7.0.2`, `@playwright/test 1.64.1`, `@types/node 26.6.5`); lockfile has integrity hashes, no git or tarball resolutions. `pnpm-workspace.yaml` allows build scripts only for `esbuild` and `workerd`.
- **SwiftPM:** `BiselCore/Package.resolved` pins revisions (GRDB 7.11.1, BIP39 1.0.2, SwiftOTP 3.0.2, swift-crypto 3.15.1, swift-asn1 1.7.3). **The app's own packages (KeyboardShortcuts 3.1.0, FuzzyMatch 1.4.0, ZIPFoundation 0.9.20, SwiftCSV 0.10.0) are pinned by tag only** in `project.yml`; the app's `Package.resolved` lives inside the git-ignored `Bisel.xcodeproj`, so revisions are not committed (Medium-Low). Fix: move the four into a small local package with a committed `Package.resolved`, or commit the resolved file and have XcodeGen copy it.
- **BIP39 package** (`pengpengliu/BIP39`, single maintainer): I verified its English wordlist hashes to the official `2f5eed53…dbda` and that `toEntropy` validates the checksum. `lachlanbell/SwiftOTP` 3.0.2 pulls swift-crypto `< 4.0.0`. Both are small single-maintainer packages; vendoring audits are cheap. Re-check on every bump.
- **Secrets in the tree:** none found. Grep over the repo (including `server/.dev.vars`, `.wrangler`, `test-results`, `apple/build`, SwiftPM checkouts) for private keys, API tokens and the dev tokens found only the intentionally public dev token `dev-bootstrap-token` in `server/.dev.vars.example`, `README.md`, `smoke.ts`, `TestServer.swift`. `.dev.vars` is git-ignored and not tracked. A well-known token is fine locally; never `wrangler secret put` it.
- **`.gitignore`:** covers `.wrangler`, `.dev.vars*`, `apple/build`, `*.xcodeproj`, `.build`, `*.bisel-backup`. Add `software-keys.json`, `*.sqlite`, `*.p12`, `*.pem`, `*.mobileprovision`, `usage.json`.
- **`BiselDev.xcodeproj` hazard:** `project.dev.yml` enables the `SoftwareKeys` trait for every configuration of that project. An archive from it would contain the plaintext key store. Fix: in `BiselKeyStore` add `#if BISEL_SOFTWARE_KEYS && !DEBUG #error("software keys in a non-Debug build") #endif`, and add the release gate below.
- **`bisel-dev`** takes `--phrase` and `--token` on the command line (visible in `ps` and shell history). Dev-only; prefer stdin or env.

---

## Release build inspection (Release, ad-hoc, scratch DerivedData)

Built from the current Mac-app sources against the baseline core (the live core was mid-refactor and did not compile). Findings:
- **Compiled out, verified by `strings` and `nm`:** `DevFixtureVault`, the "DEV FIXTURE" / `FIXTURE-…-NOT-A-REAL-PASSWORD` strings, `DebugTools`, `PanelDebugDriver`, `BISEL_DEV_SKIP_BIOMETRIC`, `BISEL_DEV_AUTOPILOT`, `BISEL_DATA_DIR`, `ICONFETCH`, `SoftwareDeviceKeyStore`, `SoftwareGate`, `software-keys.json`, `BISEL_SOFTWARE_KEYS`. The only residue is the harmless UI string "This Debug run uses the fake panel fixture (BISEL_DEV_FIXTURE=1)…".
- **Signature:** `flags=adhoc,runtime` (hardened runtime on), no Team ID. **Entitlements: only `get-task-allow` (H4).** Not sandboxed, as designed. `NSAppTransportSecurity.NSAllowsLocalNetworking = true` (L13). `LSUIElement`.
- **Persistent Secure Enclave keys cannot be created in this build** (no Team ID, no `keychain-access-groups`): `-34018`. See "Could not check".
- Add a release gate script: fail the archive if `strings`/`nm` finds any of the symbols above, or if `codesign -d --entitlements -` contains `get-task-allow`.

---

## What is good (verified)

- AES-256-GCM everywhere with CryptoKit random 96-bit nonces; fresh IK per item makes nonce reuse a non-issue; AAD `bisel/v1|item|<id>|<rev>` on both the wrapped IK and the payload; padding is ISO 7816-4 to 512 bytes.
- HKDF contexts are distinct and versioned (`recovery-wrap`, `recovery-sig`); the phrase is 256 bits of `SecRandomCopyBytes` entropy (not BIP-39 PBKDF2 seed), checksum validated.
- Auth: signature covers method, path, sorted query, body hash, ts, nonce; ±60 s skew; nonce stored only after signature verification (5 min TTL); replay confirmed rejected; every failure and unknown route returns the same empty 404 with identical headers (probed for GET/HEAD/OPTIONS/unknown paths); rotate/put/delete are guarded by `rev`/`epoch` and applied in one D1 batch with a gapless `seq`.
- Bootstrap uses a constant-time compare and is closed after the first success (verified: second attempt 404).
- No secrets in logs from the vault layers; clipboard marks `ConcealedType`/`TransientType`, `currentHostOnly`, 30 s clear if `changeCount` unchanged.
- Hardened runtime on; DYLD injection blocked; software key store absent from the Release binary.

## Verified fixed while reviewing (working tree, 19:00 to 19:15)

- **Lockout:** the failed-auth counter no longer blocks valid signatures; over-budget addresses get a ~1 s delay on failures. I sent 25 bad requests from one IP and then a valid one from the same IP: `200` in 8 ms. The earlier design (20 skewed requests from the owner's own IP, or 20 garbage requests from anyone sharing the IP, locked the owner out for 10 minutes) is gone.
- **Constant-work auth:** unknown, revoked and bad-signature requests now all do one principal read and one signature verification (decoy keys). Unknown routes also pass through `deviceAuth` (`app.all("*", deviceAuth, ...)`), removing the route-existence timing oracle I had flagged as Low.
- **Revoke without rotation:** server `POST /v1/rotate` (epoch, wrapped-key swap, per-device envelopes, optional revoke in one transaction) and client `Vault.revoke → rotateVaultKey` exist; `revokeWithoutRotation` is explicit. I verified the server transaction accepts a rotation (see H1) but **did not run the client flow end to end**; the core did not compile at my last attempt.
- Recovery envelope moved to HPKE sealed to an X25519 recovery key so rotation can re-seal without the phrase; I read it but did not review the HPKE `info`/AAD binding in depth. Bind `epoch` and the recovery pubkey into HPKE `info`.

## Could not check

- **Secure Enclave behaviour on real hardware:** no signing identity, no Team ID, persistent SE keys fail with `-34018`; ACL flags were reviewed in code only. Touch ID prompts, `biometryAny` invalidation and Universal Clipboard delivery were not exercised.
- **`NSWindow.sharingType = .none` effectiveness** against ScreenCaptureKit on this macOS (no Screen Recording grant).
- **Fill engine in real apps** (FILL-MATRIX.md is itself mostly unverified) and Accessibility permission flows.
- **1pux/CSV import:** `apple/Bisel/Import/` is empty; ZIPFoundation and SwiftCSV are only declared. When it lands: cap entry count, per-entry and total uncompressed size, reject `..`/absolute paths and symlinks, cap CSV rows and field length, never follow `data:`/`file:` URLs found in the file, and treat every imported URL as hostile (M10, M12).
- **Full Release build of the live tree** (core mid-refactor). **Notarization, Developer ID signing, App Group entitlements.**
- **Deployment-level controls:** Cloudflare zone rate-limit rule, TLS settings, wildcard certificate, route binding, D1 backups. Nothing is deployed.
- iPhone app, Safari/AutoFill extensions (not built).
- HPKE recovery construction and client rotation flow (just landed, still moving).

---

## Prioritized fix list

1. **Add the vault-admin signature** (VK-derived Ed25519) for rotate, approve, revoke, recovery-rotate; server-side history for item overwrite/tombstone (H1). Biggest single risk reduction.
2. **Pin an approved-device roster locally and seal only to it** in `rotateOnce` and `approveEnrollment`; alert on unknown active devices (H2).
3. **Key confirmation on enrollment** (canary item and short verification code); treat all-undecryptable as an error (H3).
4. **Remove `get-task-allow` from Release** and add a release gate script (symbols, entitlements, software keys) (H4).
5. **Authenticate tombstones and keep a local trash**; pin the recovery pubkey; validate `next_since` (M2, M3).
6. **Fill safety:** verify frontmost app and focused element before each keystroke batch; type passwords only into secure fields (M9). **Gate strict mode in `VaultService.secret`** (M6).
7. **Icon pipeline:** pixel cap and type allow-list now, XPC-sandboxed decode next; block private IPs, non-443 ports; default icons OFF or opt-in (M11, M12, M13).
8. **Phrase handling:** persist "unconfirmed" state and force rotation; word-quiz gate; `sharingType = .none` on every secret-bearing window; test it (M5, M15).
9. **Restrict `NSWorkspace.open` to https**; disable text selection on secrets and route copies through `SecureClipboard` (M10, M16).
10. **Recovery alerts and cooling period**; surface server events (M4). Consider `.biometryCurrentSet` (M1).
11. Housekeeping: commit app package revisions, ignore patterns, `#error` guard for software keys in non-Debug, ATS exception Debug-only, IP pruning/hashing, name sanitizing, log privacy (Low items).
