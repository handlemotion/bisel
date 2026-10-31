# Backups: API for the UI

Encrypted `.bisel-backup` files (format 3, `docs/SPEC.md` §12) and the reminder a box without a second copy must show (D4). Logic only; every screen and word is yours. All calls are on `Vault`.

## Export

```swift
let report = try await vault.exportBackup(to: url)                 // BackupExportReport
let report = try await vault.exportBackup(to: url, phrase: phrase)  // once, after BackupError.needsPhrase
```

- Needs the box unlocked; it unlocks itself (Touch ID) if a sync just locked it. Syncs first when it can.
- `report.items`, `report.historyVersions`, `report.header.fileSize` (bytes), `report.header.createdAt`, `report.header.boxID`.
- Atomic: the file appears whole or not at all. Only ciphertext is ever on disk. Suggested name: `Bisel <date>.bisel-backup` (`BackupArchive.fileExtension`).
- `BackupError.needsPhrase`: a box made before format 3 has no backup key yet. Ask for the 24 words and call again with `phrase:`; from then on it is never needed again on any device of the box. New boxes never see this.
- Other errors: `.unreadableItems(n)` (sync and retry), `.recoveryKeysUnknown` (sync first), `IntegrityError.recoveryMaterialChanged`, `VaultError.locked` if the unlock was cancelled.

## Restore

```swift
let header = try Vault.inspectBackup(at: url)          // no phrase: format, box id, date, size; catches damage early
let report = try await vault.restoreBackup(from: url, phrase: phrase, deviceName: name)   // fresh install
let report = try await vault.mergeBackup(from: url, phrase: phrase)                       // into the open box
```

- `restoreBackup` is for a fresh install (`VaultError.alreadyConfigured` otherwise). The box comes back exactly: same items, ids, dates, history, roster, box key and phrase. It is unlocked afterwards and lives on this Mac until a lane or server is connected. Show the item count (`report.added`).
- `mergeBackup` needs the box unlocked and asks for Touch ID. Nothing is overwritten. `report`:
  - `added`: items the box did not have.
  - `unchanged`: already there, same or newer.
  - `conflicts`: `[(itemID, copyID)]`, both sides changed; the box kept its version, the backup's is the new item `copyID` titled "… (conflict)".
  - `keptDeleted`: item ids deleted here after the backup was made; left deleted. Their last version is usually still in `vault.trash()` (30 days) if the user wants one back.
  - `fromOtherBox`: the file came from a different box (its items were added anyway).
  Then `sync()` uploads the result.
- Refusals, all before anything is written, one message each:
  - `BackupError.wrongPhrase`: valid words, but not this backup's phrase.
  - `.tampered`: changed or damaged after it was written, or forged. Nothing in it is used.
  - `.truncated(expected:actual:)`: incomplete copy or download.
  - `.newerVersion(v)`: made by a newer Bisel; update.
  - `.notABackup`.
  - `BiselCryptoError.invalidRecoveryPhrase` comes earlier, from `RecoveryPhrase(text)`.
- Every `BackupError` has an `errorDescription` you can use or replace.
- Format 2 files (JSON) still restore through `importBackupLocal` / `importBackup(server:)`.

## Reminder

```swift
let status = try await vault.backupStatus()   // works while locked; cheap enough for launch and after each sync
switch status.reminder {
case .none: break
case .noBackupYet: …
case .stale(let lastBackupAt): …
case .manyChanges(let n, let lastBackupAt): …
}
```

- `status.copies`: `.thisDeviceOnly`, `.cloudKitOnly` (both are reminded), `.server` (not reminded by default).
- `status.lastBackupAt`, `status.lastFileName`, `status.changesSinceBackup`.
- Policy: `BackupReminderPolicy(maxAge: 30 days, maxChanges: 25, remindWithServer: false)` is `.standard`; pass your own to `backupStatus(policy:)`.
- State is per device: it is written by every export and restore on this Mac. A backup made on another device does not silence this one.
- D4 says "forced": the core has no snooze. If the UI offers "later", keep that in the app and call `backupStatus()` again at the next launch.

## Not done here

- No UI, no file picker, no scheduling.
- The reminder state does not sync between devices.
- A box whose devices run an older build can lose the backup key from the shared manifest when that build rewrites it; export then asks for the phrase once more.
