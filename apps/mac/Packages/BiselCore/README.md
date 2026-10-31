# BiselCore

SwiftPM package behind every bisel app: crypto, vault format, local store, signed sync client, recovery, key store.
Contract: [`../../../SPEC.md`](../../../SPEC.md) §4, §6, §7. Apps use the `BiselCore` umbrella module (the `Vault` actor); the
sub-modules (`BiselCrypto`, `BiselKeyStore`, `BiselVault`, `BiselLane`, `BiselSync`, `BiselRecovery`, `BiselBackup`, `BiselTOTP`) are public for the
extensions and tools.

## CHANGES

**Accounts, box ids and device-code connect (server migrations 0004-0006).** For the Mac-app session. Everything old keeps compiling
(token overloads stay); this is what is new.

- **Box id.** `LocalIdentity.boxID: String?` (nil for identities written before accounts; they decode and sync unchanged: device requests never send a box).
  `/v1/bootstrap` returns it and `bootstrap`, `connectServer`, `reconnectServer`, `importBackup` store it.
  **Recovery must name its box**: `Vault.recover(server:phrase:deviceName:boxID:)`, `RecoveryService.fetchVaultKey(server:phrase:boxID:)`,
  `RecoverySigner(keys:boxID:)` send `X-Bisel-Box`. `boxID: nil` asks for the server's pre-accounts box, which only the production box has:
  on a restore onto a fresh Mac, ask for the box id (dashboard shows it) or take it from `identity().boxID` before the old Mac is lost.
- **Credential.** `SyncClient.BootstrapCredential`: `.token(String)` or `.connect(deviceCode: String)`. New overloads
  `Vault.bootstrap(server:credential:deviceName:)`, `connectServer(_:credential:)`, `reconnectServer(_:credential:)`,
  `importBackup(from:phrase:server:credential:deviceName:)`; `SyncClient.bootstrap(baseURL:credential:…)` returns `BootstrapResult` (`deviceID`, `boxID`, `headSeq`, `epoch`).
  With `.connect`, `ConnectError.accountHasBox` means the approving account already owns a box (nothing created, the code is spent).
- **Connect (no token typed).** `Vault.startConnect(server:deviceName:) -> SyncClient.ConnectCode` (`deviceCode` secret, `userCode`, `verificationURL`,
  `expiresIn`, `interval`), then `Vault.pollConnect(server:deviceCode:) -> SyncClient.ConnectStatus`
  (`.pending`, `.approved(accountHasBox:)`, `.consumed(boxID:)`, `.denied`, `.expired`). Both static, no identity needed.
  Show `userCode`, open `verificationURL`, poll every `interval` s; on `.approved(accountHasBox: false)` call `connectServer(_:credential: .connect(deviceCode:))`.
- **Claim an existing box.** `Vault.claimBox() -> ConnectCode` (unlocked vault + biometric check; device and admin signed; `ConnectError.alreadyLinked`),
  then `Vault.pollClaim(_:)` until `.consumed` (linked) or `.denied` (the account already owns a box).
  The server does not report the box id on claim; the client records it if `consumed(boxID:)` ever carries one.
- **Tests.** `ConnectFlowTests` (create, claim, refusals, recovery with box id, identity without box id). `TestServer` gained `approveConnect/denyConnect/expireConnect`
  (the dashboard's database updates, no browser), `value(_:)` and `onlyBoxID()`. The old flows broke on the server move from `meta` to `boxes` (tampering SQL) and on
  recovery without a box; both fixed.

**Security-review fixes (SECURITY-REVIEW.md H1-H3, M1-M5, M8, M17, Lows).** For the Mac-app session. The `Vault` facade methods you call
keep their signatures; this is what is new or behaves differently.

- **Reset your dev server and vaults.** Blob format (AAD labels `|wrap`/`|body`), tombstones (sealed markers instead of empty blobs), recovery envelope
  (HPKE `info` binds epoch + RK-sig), backup file (adds `epoch`) and server schema (migration 0003) all changed. `pnpm reset` in `server/`, then bootstrap again.
- **Needs an unlocked vault now** (internally they sign with the vault-admin key): `approveEnrollment`, `revoke`, `rotateVaultKey`, `rotateRecovery`, `revokeWithoutRotation`.
- **`revoke(deviceID:)` returns `RotationReport` (`@discardableResult`)**: `.secretsToChange` / `.exposed` are the items the device could have read; show them and offer to change those passwords.
  `rotateVaultKey` returns the same type. It now throws **`IntegrityError.unknownDevices([UnknownDevice])`** when the server lists an active device nobody approved on this device
  (name, 96-bit fingerprint, `pendingActivation`); offer "Revoke" (`revoke(deviceID:)`) or, after the user compared the fingerprint on the device itself, `trustDevice(id:fingerprint:)`.
- **Enrollment**: after `completeEnrollment()` + `unlock()`, show `verificationCode()` on both devices (approver and new) and have the user compare / type it:
  `confirmEnrollment(code:)` (mismatch locks the vault and throws `IntegrityError.verificationCodeMismatch`). `enrollmentNeedsConfirmation` says it is still open.
  `sync()` throws `IntegrityError.keyConfirmationFailed` (and locks) if the received vault key does not open the vault's manifest.
- **Recovery phrase**: `recoveryNeedsConfirmation` is true after `bootstrap` and after `rotateRecovery` until the user proves the phrase is written down:
  use `RecoveryPhrase.quizPositions()` + `phrase.verify(answers:)` while you still hold the phrase, then `markRecoveryConfirmed()`; or `confirmRecovery(phrase:)` with all 24 words.
  If it stays true after a restart, call `rotateRecovery()` to get a phrase you can show again. `recoveryMaterialChanged` (server tried to swap the recovery keys) should raise a loud alert; `exportBackup` refuses then.
- **`sync()`** also: reports `events` (device added/revoked, key rotated, recovery used: show them), `rejectedTombstones` (a forged delete was ignored and the item restored), may throw
  `IntegrityError.serverRolledBack` / `.invalidCursor` / `.pendingActivation(until:)`. A device added with the recovery phrase may be held back by the server for 24 h in production:
  `recover()` returns normally, `activationDate()` tells until when, `sync()` throws `.pendingActivation` before that.
- **Trash and history**: `trash()` (what the server deleted or overwrote, 30 days, local), `serverHistory(itemID:)` (retained by the server, readable with the current key), `restore(_:)`.
- **Biometry** (Secure Enclave, cannot be exercised unsigned): DK-enc is `.biometryCurrentSet`. `deviceKeyStatus()` is `.biometryChanged` after a fingerprint change, `unlock()` then throws `DeviceKeyError.biometryChanged`;
  show "add this Mac again" and call `removeLocalDevice()` before enrolling or recovering again.
- **Server address** is no longer in `bisel.sqlite`: with the Secure Enclave key store `Vault.Configuration` defaults `secrets` to a Keychain store in the same access group (pass your own `SecretStore` to override).
  A database written before this change is migrated on first open.
- `SyncClient` refuses non-https URLs (except localhost), does not follow redirects, caps responses at 64 MiB. `DeviceInfo.name` is stripped of control/bidi characters on decode. Fingerprints are 96 bits.
- `bisel-dev`: `--token`/`--phrase` take `-` (stdin) or `$BISEL_TOKEN`/`$BISEL_PHRASE`; new `verify-code`, `confirm-enrollment`, `trust`, `roster`, `trash`, `history`, `events`, `confirm-recovery`; device ids that start with `-` need `--` before them.
- Lower level: `SyncClient.delete(id:baseRev:marker:epoch:)`, admin-signed calls take an `AdminSigner`, `rotate(…newAdminPublicKey:tombstones:…admin:)`, `RecoveryKeys.seal/open` take the epoch,
  `ItemSealer.sealTombstone/verifyTombstone`, `VaultAdmin` (admin key, verification code), reserved record `ReservedRecord.manifestID` (never shown by `items()`).

**Earlier: vault-key rotation.**

**Vault-key rotation (this change).** What the Mac app can rely on, and what moved:

- **Source-compatible for the `Vault` facade.** Every existing `Vault` call still compiles with the same signature.
  `KeyStoreError`, `SyncError`, `VaultError` and `BiselCryptoError` gained **no cases** (exhaustive `switch`es keep compiling).
  New failures are a separate `RotationError` (a `LocalizedError`, so `error.localizedDescription` is already user-readable).
- **Behaviour changes in the facade**
  - `revoke(deviceID:)` now **rotates the vault key** atomically with the revocation (SPEC §4). It needs an unlocked vault
    (it unlocks first, one Touch ID) plus the usual fresh biometric check, and may throw `RotationError`
    (`pendingChanges`, `undecryptableItems`, `cannotRevokeThisDevice`, `recoveryNeedsUpgrade`, `tooManyConflicts`).
  - `sync()` can now **lock the vault**: when another device rotated the key, the report has `rotationAdopted == true`,
    `isUnlocked` becomes false, and the next `unlock()` brings up the new key. Show "unlock to continue" instead of an error.
  - `unlock()` opens up to two envelopes under one prompt (only after a rotation while local edits were pending).
  - New: `rotateVaultKey(revoking:)`, `revokeWithoutRotation(deviceID:)` (emergency), `Configuration.secureEnclave(appGroupIdentifier:keychainAccessGroup:)`.
  - A device cannot revoke itself any more (`RotationError.cannotRevokeThisDevice`); revoke it from another device.
- **Lower-level API changes** (not used by `apps/mac/Bisel/` today)
  - `SyncClient`: `put(…, epoch:)`; `envelope()` and `recoveryEnvelope()` return `(envelope, epoch)`; `recoveryRegister(device:epoch:)`;
    `rotateRecovery(publicKey:encryptionPublicKey:envelope:epoch:)`; `bootstrap(…recoveryEncryptionPublicKey:…)`; new `rotate(…)`;
    `PutOutcome.staleEpoch`; `SyncPage.epoch`; `RecoveryMaterial.encPubkey`.
  - `RecoveryKeys`: `wrapKey` is gone. The recovery envelope is now HPKE-sealed to a public key derived from the phrase, so any
    device can rewrite it without the phrase. `RecoveryBundle`/`BackupFile` carry the extra public key; **`.bisel-backup` is version 2**
    (version 1 files are rejected). `RecoveryService.fetchVaultKey` also returns the epoch.
  - `LocalIdentity` gained `epoch`, `previousEnvelope`, `recoveryEncryptionPublicKey` (old stored identities decode with defaults).
  - `DeviceKeyStore` gained `openEnvelopes(_:reason:)` with a default implementation (existing conformers compile unchanged).
- **Existing development vaults.** Sync and edits keep working after the server's migration `0002` (epoch 1). But a vault created
  before this change has a symmetric recovery envelope: it cannot rotate (`recoveryNeedsUpgrade`; run `rotateRecovery()` once) and its
  old phrase no longer recovers. For a dev vault, easiest is `pnpm reset` in `server/` and a fresh bootstrap.
- **Hardening**: secrets (`RecoveryPhrase`, `RecoveryKeys`, `Item`, `TOTPParameters`, `LockedKey`, `RecoveryBundle`) print as `…(redacted)` in
  `print`, interpolation, `dump` and `Mirror`; key `Data` is wiped (`memset_s`) after use on the paths that handle VK/IK; no force unwraps left in crypto paths;
  Secure Enclave `sign` uses a non-interactive `LAContext` (can never show Touch ID), Security/LocalAuthentication failures map to typed
  `KeyStoreError` values without key material in the text; builds clean under Swift 6 complete concurrency checking with warnings as errors.

## Running the flows

```sh
swift test --traits SoftwareKeys        # flow tests against a real `wrangler dev` + local D1 (BiselTestSupport starts it)
swift build -c release                  # no traits: the software key store is not compiled in
```

`BiselTestSupport` needs `server/node_modules` (`pnpm install` there). Set `BISEL_SERVER_DIR` if the server is elsewhere.

The lane contract flows live in `BiselLaneContract` (dev/test only) so the signed app can run the same ones against CloudKit.
`BiselCloudKit` (`CloudKitLane`) compiles everywhere but only works in a signed app with the iCloud entitlement; nothing the flow
tests or BiselDev link uses it. The CloudKit run is opt-in and manual: `apps/mac/Tools/run-cloudkit-contract.sh`
(docs/SYNC-LANES.md §15).

## Signed runs (what only a signed app can exercise)

`SecureEnclaveDeviceKeyStore` needs a signed build with a `keychain-access-groups` entitlement and, for the App Group store, the
`com.apple.security.application-groups` entitlement. The package takes both identifiers as arguments
(`Vault.Configuration.secureEnclave(appGroupIdentifier:keychainAccessGroup:)`); nothing is hard-coded. Unsigned,
`SecKeyCreateRandomKey` on the Secure Enclave fails with `-25308` (`bisel-dev se-probe` shows it), so that path has not been run here.
