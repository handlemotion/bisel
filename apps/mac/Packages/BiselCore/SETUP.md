# First run: what the UI must show

For Rodrigo's UI. First run is iCloud first: a new box goes to the person's iCloud (CloudKit private database, container
`iCloud.app.bisel`, D1), the Bisel server is not part of it (it is opt-in, from Settings: `connectServer`, `AccountLinker`,
[LINKING.md](LINKING.md)). Design: [`docs/SYNC-LANES.md`](../../../../docs/SYNC-LANES.md). Lanes after set-up: [LANES.md](LANES.md).
Backups: [BACKUP.md](BACKUP.md).

The whole of first run is one state machine, `BoxSetup` (Sources/BiselCore/BoxSetup.swift). The app holds one
(`VaultService.setup`, mirrored in `VaultService.setupState`) and the screens call `VaultService`, which calls it. The UI owns no
logic: it shows `state`, and calls the action that state offers.

```swift
let setup = BoxSetup(vault: vault, home: ICloudHome(...))   // home: nil in a build without iCloud (BiselDev)
for await state in await setup.updates() { ... }           // current state first, then every change
await setup.start()                                         // reads this Mac and iCloud; never throws
```

Every action throws a `SetupError` (a `LocalizedError`; `describe(error)` in the app shows its text) and leaves `state` on the
screen to show next; on a failure, on the one it came from. In no failure is anything on this Mac lost or anything half-made left
behind (in iCloud either). The 24 words in `.showPhrase` are the only secret a state holds.

## States

| State | Meaning | Show |
| --- | --- | --- |
| `.checking` | reading this Mac and iCloud | nothing new (a moment at launch) |
| `.welcome(Welcome)` | nothing on this Mac | the welcome screen. `welcome.iCloud` says whether a box can go to iCloud (`.available`, or `.unavailable(reason)`, see below); `welcome.boxesInICloud` lists the boxes this Apple Account already holds. **Not empty: lead with "add this Mac" and "restore", not "create"** (see "Screens to design") |
| `.working(Work)` | `.creating`, `.startingPairing`, `.finishingPairing`, `.restoring`, `.moving` | busy (`VaultService.isBusy` is also set) |
| `.showPhrase(NewBox)` | a new box exists | the 24 words, once (`PhraseGateView`). Continue: `phraseStored()`. Back: `discardNewBox()` |
| `.pairing(PairingOffer)` | this Mac asked to join the box in iCloud | `offer.secret.words` (8 words), `offer.qrPayload` as a QR code, `offer.fingerprint` to compare. Poll `checkPairing()` every few seconds |
| `.compareCode(String)` | the other device approved; the box key is here | this Mac's code, and a field for the code the other device shows: `confirmPairing(code:)` |
| `.done(Done)` | set up | the rest of onboarding (import), then the app. `done.backup.reminder.isDue`: the **forced backup reminder (D4)**, always due for a new iCloud box. `done.iCloudProblem` non-nil: the box is on this Mac only for now (say why, offer `putInICloud` later). `done.activatesAt`: a Mac recovered with the words is held back until then (D7, advisory) |
| `.attention(LaneStatus)` | a box is here, its iCloud needs the person | see "iCloud account changes" |

## 1. Create a box in iCloud

`VaultService.createBox(deviceName:)` → `setup.create(deviceName:)`.

1. iCloud is checked first. Nothing is made if it cannot take the box; the error says why (`SetupError.iCloud(reason)`):

   | `HomeUnavailable` | Means | What the person can do |
   | --- | --- | --- |
   | `.notSignedIn` | no Apple Account in iCloud on this Mac | sign in (System Settings) |
   | `.turnedOffForApp` | signed in, iCloud off for Bisel (or the build has no entitlement) | turn it on for Bisel |
   | `.restricted` | Screen Time or a managed Mac blocks iCloud | nothing here; keep the box on this Mac |
   | `.offline` | no network | connect, try again |
   | `.quotaFull` | iCloud storage full (seen on the first write) | free space, try again |
   | `.temporarilyUnavailable` | account being set up, Apple's service busy | try again in a moment |
   | `.notInThisBuild` | BiselDev: no iCloud at all | nothing: the box is made on this Mac only, as BiselDev always did |

2. iCloud already holds a box for this Apple Account: `SetupError.iCloudHasBox(addresses)`, nothing made. Offer **add this Mac**
   (pairing) or **restore with the 24 words**. Only if the person explicitly wants a separate second box: `createAnyway`
   (`VaultService.createBoxAnyway`).
3. Otherwise the box is made in iCloud → `.showPhrase`. **Continue** → `phraseStored()` → `.done` with the D4 reminder due.
   **Back** → `discardNewBox()`: the box is erased on this Mac *and* in iCloud, so the next Create is not mistaken for a second box.

"Keep it on this Mac only" (iCloud unavailable, or the person does not want iCloud): `createOnThisMacOnly(deviceName:)`
(`VaultService.createBoxOnThisMacOnly`). Never chosen for the person. `putInICloud(words:)` moves it there later.

## 2. Add this Mac to the box in iCloud (D6, same Apple Account only, D2)

1. `startPairing(deviceName:)` (`VaultService.startICloudEnrollment`) → `.pairing(offer)`. Errors: `.noBoxInICloud` (this Apple
   Account holds none: another Apple Account's boxes are never visible), `.chooseBox(addresses)` (several: pass `box:`),
   `.iCloud(reason)`.
2. On the other device: the request appears in `pendingEnrollments()`; the person types the 8 words or scans the QR, compares the
   fingerprint and approves (LANES.md, "Enrollment over iCloud").
3. Here: `checkPairing()` (`finishICloudEnrollment`) every few seconds: `false` = still waiting; `true` = approved, unlocked
   (Touch ID) → `.compareCode(code)`. `SetupError.approvalUnproven` is an **alarm**: something that is not the person's device
   answered. Stop polling, say so, `cancelPairing()`. `.cancelled` (Touch ID): call `checkPairing()` again.
4. `confirmPairing(code:)` (`confirmICloudEnrollment`) with the code the other device shows → `.done`. `.codeMismatch`: the box
   locked itself here; `cancelPairing()` and start again.

A relaunch while the words are up comes back to `.pairing` with the same words. `cancelPairing()` (`cancelICloudEnrollment`)
forgets the half-made keys; the request left in iCloud expires by itself (15 min).

## 3. Restore

**With the 24 words, from iCloud**: `restore(words:deviceName:)` (`VaultService.restore(phrase:deviceName:)`; the "I already have
one" screen). The box in this Apple Account's iCloud that the words open is restored → `.done`. Errors, nothing written in any:
`.noBoxInICloud`, `.wrongPhrase`, `.invalidPhrase`, `.iCloud(reason)`, `.boxForked` (alarm: a removed device wrote a fork, D5) and
`.boxBehind` (iCloud holds an older copy than the box reached: try later or from another device). The server is not tried.

**With a `.bisel-backup` file and the 24 words**: `restore(backup:words:deviceName:)` (`VaultService.restore(backup:phrase:deviceName:)`).
The file is checked against the words first (BACKUP.md errors, as `SetupError.backup(...)`, or `.wrongPhrase`). Then:

| iCloud | What happens |
| --- | --- |
| holds the box (the words open it) | the iCloud copy is restored, as the live one, and the file merged into it: nothing overwritten, conflicts become "… (conflict)" items. `done.restoredItems` = what the file added. No second box |
| holds a box the words do not open | `SetupError.iCloudHasOtherBox`, nothing written |
| holds no box | the file is restored and the box put in iCloud. If iCloud refuses that last step (full, offline), the box stays restored on this Mac: `done.place == .thisMacOnly`, `done.iCloudProblem` says why, `putInICloud(words:)` later |
| unavailable | `SetupError.iCloud(reason)`, nothing written. `restoreOnThisMacOnly` is the person's explicit alternative. BiselDev restores on this Mac |

## 4. iCloud account changes (a box on this Mac)

`refresh()` (run by `start()` at launch; call it again when the iCloud account changes) syncs once and reports:
`.done` when the lane is fine, else `.attention(status)`. The box keeps working on this Mac in every case, edits stay pending, and
**nothing is ever uploaded to an Apple Account the box was not put on** (the lane pins the account; `LaneError.accountChanged`).

| `.attention(…)` | Show | Actions |
| --- | --- | --- |
| `.accountUnavailable(reason)` | "iCloud is signed out / unavailable; your box keeps working here". Not an error | none: `refresh()` once signed back in resumes by itself |
| `.accountChanged` | "Another Apple Account is signed in. Your box was not uploaded to it" | **Move the box to this account**: `moveBoxToThisAccount(words:)` (`VaultService.putBoxInICloudAgain`); refused with `.iCloudHasBox` when that account already holds another box, unless `evenIfItHoldsAnotherBox: true` after the person confirms. **Stop syncing**: `stopSyncing()` (the box stays here, whole). Or sign back in to the old account |
| `.storeMissing` | "Your box's iCloud data was deleted; this Mac has its copy" | `moveBoxToThisAccount()` uploads it again |
| `.moved(to:)` | another device moved the box where this Mac cannot follow | LANES.md |

`moveBoxToThisAccount` needs the box unlocked (`.locked` otherwise) and, for a box that never verified its recovery anchor, the
24 words (`.move(.phraseRequired)`).

## Screens to design (`// UI:` notes in the code)

Wired in the core and in `VaultService`, with no screen yet:

1. **"A box already exists in iCloud"** (`SetupView.create`): when `welcome.iCloudHasBox` or Create throws `.iCloudHasBox`.
   Choices: add this Mac (pairing), restore with the 24 words, or, deliberately, a separate new box (`createAnyway`). Until it
   exists, the error line shows the message and "I already have one" leads to the 24 words.
2. **Pairing** (`SetupView`, at "I already have one"): the 8 words, the QR code and the fingerprint while `.pairing`; the code
   comparison in `.compareCode`; the `approvalUnproven` alarm; "choose a box" for `.chooseBox`.
3. **Restore a `.bisel-backup` file** (`SetupView`, at "I already have one"): a file picker for the backup next to the 24 words.
   ("Upload file" today reads the saved *phrase* text file, not a backup.)
4. **iCloud unavailable** (`SetupView.create`): today only the error line says why. A "keep it on this Mac only" choice
   (`createBoxOnThisMacOnly`, `restoreOnThisMacOnly`) needs a control. The welcome screen can also show `welcome.iCloud` before
   the person presses Create.
5. **Account changes** (`.attention`): the screens of section 4; these belong with the lane states of LANES.md and Settings.

## Open questions

- How macOS reports "iCloud off for Bisel only" has to be checked on a signed build: `ICloudHome` reads it as `.turnedOffForApp`
  from `CKError.missingEntitlement` / `.badContainer` / `.permissionFailure` on the request that follows a signed-in status, and
  as `.notSignedIn` when CloudKit reports no account (or `.notAuthenticated`).
- `createAnyway` allows a second box in one Apple Account. Should it exist at all, and how should pairing choose between two
  boxes (`.chooseBox`)?
- iCloud unavailable at first run: is "keep it on this Mac only" offered, or is iCloud required? The core supports both.
