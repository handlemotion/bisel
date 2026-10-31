# Lanes: what the UI must show (L4)

For Rodrigo's UI. Design: [`docs/SYNC-LANES.md`](../../../../docs/SYNC-LANES.md) (§4 enrollment, §5 rotation, §6 accounts, §9 moves, §14-§16
what was built). Everything below is on the `Vault` actor (BiselCore) or on `VaultService` (the app). No view, copy or layout was
changed for this; the one call site that moved is "Create a box" (`SetupView.create` now calls `VaultService.createBox`).

"Box" is what the person reads; "vault" and "lane" stay in code.

## Where a box lives

| `LocalIdentity.serverURL`          | What it is                                                      | `vault.laneStatus()` when fine |
| ---------------------------------- | --------------------------------------------------------------- | ------------------------------ |
| nil                                | this Mac only                                                   | `.thisDeviceOnly`              |
| `cloudkit://iCloud.app.bisel/box-…` | the person's iCloud (private database, one zone per box)       | `.active`                      |
| `https://…`                        | the Bisel server (opt-in: `connectServer`)                      | `.active`                      |

New boxes: `VaultService.createBox(deviceName:)` creates the box in iCloud when the signed build has it (`BISEL_CLOUDKIT`) and an
iCloud account is signed in, else on this Mac only. BiselDev never uses iCloud. "I already have one" (`VaultService.recover`) first
looks for a box in this Mac's iCloud that the 24 words open, then the server.

## States the UI must show

Read `VaultService.laneStatus` (refreshed at launch and after every sync; `vault.laneStatus()` underneath). A sync that runs into one
of these throws the matching `LaneError` (the app maps it to `syncState = .offline(…)`, not a failure), and the state stays until a
sync gets through. Nothing is ever lost in any of them: the box keeps working on this Mac and edits stay pending.

| State                        | Meaning                                                              | What the person can do                                                                                                       |
| ---------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `.accountUnavailable(reason)` | iCloud signed out, restricted, or not determined                    | Nothing needed: sign in to iCloud; the next sync resumes by itself. Show it as paused, not as an error.                      |
| `.accountChanged`             | Another Apple Account is signed in than the one the box was put on | Choose: **Move the box to this account** (`putBoxInICloudAgain()`) or **Stop syncing** (`stopSyncing()`). Never automatic. Say the other devices stay on the old account until they do the same. |
| `.storeMissing`               | The box's data in iCloud was deleted (iCloud settings)             | **Upload this Mac's copy** (`putBoxInICloudAgain()`). Other devices then show the existing "server reset" alarm once and carry on after `acknowledgeServerReset()`. |
| `.moved(to:)`                 | Another device moved the box to iCloud and this Mac cannot reach it (no iCloud, another account) | Sign in to the same Apple Account, or keep using this Mac on the old lane.                                                   |

Errors of the actions above (`MigrationError`, all `LocalizedError`):

- `.phraseRequired`: the box never lived in iCloud (or its phrase changed since this Mac saw it): ask for the 24 words and pass them.
- `.wrongPhrase`, `.pendingChanges(n)` (sync first), `.incomplete(missing:)` (nothing switched; retry), `.notInvited`.
- `LaneError.occupied`: that iCloud storage already holds a different box.

## Moving a box to iCloud (migration)

`VaultService.moveToICloud(phrase:)` → `vault.enableLane(address, phrase:)`: syncs the current lane, creates the box in iCloud at
its current key with an envelope for every approved device (no re-enrollment), uploads and reads back every record, then switches.
The server's copy is left alone (detached, not erased). Other devices follow by themselves on their next unlocked sync (the sealed
manifest tells them). Show progress as one busy state (`isBusy`); it returns `LaneMove { created, uploaded }`.

- From the server or "this Mac only" it needs the 24 words (`MigrationError.phraseRequired` otherwise).
- iCloud → server: `stopSyncing()`, then `connectServer`.

## Enrollment over iCloud (a second Mac or an iPhone on the same Apple Account)

The zone is writable by anyone holding the Apple Account session (and by Apple), so the request is bound to an 88-bit pairing
secret only the two devices see (SYNC-LANES §4, D6). The old out-of-band `EnrollmentRequest` path still works on every lane.

New device:
1. `VaultService.startICloudEnrollment(deviceName:)` → `PairingOffer`. **Show** `offer.secret.words` (8 words, the typed form for a
   Mac without camera), `offer.qrPayload` as a QR code, and `offer.fingerprint` (96 bits, to compare). The request is now in iCloud.
2. Poll `VaultService.finishICloudEnrollment()` every few seconds while that screen is up. **States:**
   `EnrollmentError.notApprovedYet` = "waiting for approval on your other device" (keep polling);
   `EnrollmentError.approvalUnproven` = an envelope arrived that nobody with the words approved: **stop, show an alarm**, do not
   continue; success = unlock, then the existing verification-code comparison (`verificationCode()` / `confirmEnrollment(code:)`).
   `LaneError.storeMissing` from step 1 = this iCloud account holds no box ("create one, or recover with the 24 words").

Approving device (unlocked, after a sync):
1. `VaultService.pendingEnrollments()` → `[PendingEnrollment]` (name, kind, `request.fingerprint`, `receivedAt`, `isExpired`).
   Show them as requests, newest first; never approve automatically. Expired ones (15 min after this device first saw them) can
   only be dismissed.
2. The person types the 8 words (or scans the QR) and compares the fingerprint: `VaultService.approve(pending, words:)` (Touch ID
   inside). **Errors:** `EnrollmentError.pairingMismatch` = wrong words *or the request's keys were swapped on the way*: say so
   plainly and approve nothing; `.expired`; `RotationError.vaultKeyRotated` (retry).

Known limits: a key rotation between approval and completion means approving again; a request rewritten by someone else replaces
the genuine one in the list (the new device then has to start over).

## Rotation incomplete

On iCloud, revoking a device is the key rotation itself (`revoke(deviceID:)` / `rotateVaultKey`), and it is staged (SYNC-LANES §5):
the new wrapped keys are written next to the items, read back, then one small atomic commit switches the key, then the items are
folded. A crash or a dropped connection at any point leaves a box every device can read.

- `RotationReport.incomplete == true`: the switch happened but some items still carry the old wrap on the lane. **Show** "Revocation
  finishing…": any unlocked device finishes it on its next sync. Revocation is effective (the revoked device cannot open the new
  key); the lane is just not tidy yet.
- `SyncReport.rotationPending == true` (this device is locked and saw an unfinished rotation): show the same, and ask to unlock so it
  can finish. `SyncReport.folded` counts what this device finished.
- `RotationError.inProgress`: another device is rotating right now (its journal is younger than 15 min). "Another device is changing
  the box key; try again in a moment." Edits made meanwhile stay pending (they go up after the switch).
- `RotationError.laneDroppedWrites`: iCloud did not keep what was written (read-back failed); nothing switched. Retry later.
- On iCloud, also tell the person to remove the revoked device from their Apple Account: it keeps its iCloud session and can still
  delete or spam records (availability, never confidentiality; SYNC-LANES §5, §7).

## Push

`AppDelegate` registers for remote notifications and hands them to `CloudKitLane.handleRemoteNotification`; every push and every
iCloud account change triggers `sync(reason: "push")`. Pushes need the `aps-environment` entitlement (Rodrigo, SYNC-LANES §15); until
then the 60 s poll is the only trigger.

## Backup reminder (D4)

A box only in iCloud has no second copy if the Apple Account is lost. The reminder logic comes with the `.bisel-backup` work (PR #4):
`backupStatus(policy:)` classifies a `cloudkit://` address as iCloud-only. The integration point is marked in
`VaultService.performSync` ("D4").
