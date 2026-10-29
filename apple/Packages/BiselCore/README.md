# BiselCore

SwiftPM package behind every bisel app: crypto, vault format, local store, signed sync client, recovery, key store.
Contract: [`../../../SPEC.md`](../../../SPEC.md) §4, §6, §7. Apps use the `BiselCore` umbrella module (the `Vault` actor); the
sub-modules (`BiselCrypto`, `BiselKeyStore`, `BiselVault`, `BiselSync`, `BiselRecovery`, `BiselTOTP`) are public for the
extensions and tools.

## CHANGES

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
- **Lower-level API changes** (not used by `apple/Bisel/` today)
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

## Signed runs (what only a signed app can exercise)

`SecureEnclaveDeviceKeyStore` needs a signed build with a `keychain-access-groups` entitlement and, for the App Group store, the
`com.apple.security.application-groups` entitlement. The package takes both identifiers as arguments
(`Vault.Configuration.secureEnclave(appGroupIdentifier:keychainAccessGroup:)`); nothing is hard-coded. Unsigned,
`SecKeyCreateRandomKey` on the Secure Enclave fails with `-25308` (`bisel-dev se-probe` shows it), so that path has not been run here.
