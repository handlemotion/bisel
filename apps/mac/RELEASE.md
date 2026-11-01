# Releasing the Mac app (Developer ID, CloudKit Production)

Bisel ships outside the Mac App Store: signed with a Developer ID Application certificate, notarized by Apple, stapled, and
packaged as a DMG. The shipped app syncs through CloudKit **Production**, so the schema has to be deployed there first.

Status (2026-10-31): the build side is in the repo, the account side is not done. Steps 1 to 5 below need Rodrigo's Apple account
and have not been run. Nothing in this file has touched the Apple Developer portal or CloudKit Production.

What is in the repo:

| Piece                                   | Where                                                                                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Developer ID signing (Release config)   | `project.yml`, target `Bisel`, `configs: Release`: manual signing, `Developer ID Application`, profile `Bisel Developer ID`, team ZVGTVNUPVA |
| Hardened runtime, secure timestamp      | `ENABLE_HARDENED_RUNTIME: YES`, `OTHER_CODE_SIGN_FLAGS: --options=runtime --timestamp`. No runtime exceptions: the app needs none            |
| Entitlements                            | `Bisel/Bisel.entitlements`: iCloud container `iCloud.app.bisel` (CloudKit), key-value storage, container environment                        |
| CloudKit environment                    | `BISEL_ICLOUD_ENVIRONMENT`: `Development` in Debug, `Production` in Release; `iCloudContainerEnvironment: Production` in the export options |
| Export options                          | `Tools/ExportOptions.plist` (`developer-id`, manual, profile `Bisel Developer ID`)                                                          |
| Release script                          | `Tools/release.sh`: preflight, archive, export, verify, notarize, staple, assess, DMG or zip, Sparkle appcast; `--publish <tag>` uploads     |
| In-app updates (Sparkle 2)              | `project.yml`: the `Sparkle` package, `SUFeedURL`, `SUPublicEDKey` and the update keys in `info`; `Bisel/App/Updater.swift`; see "Updates"  |
| CloudKit schema                         | `CloudKit/schema.ckdb` (created by step 5) and `Tools/cloudkit-schema.sh`                                                                   |

The unsigned builds are unchanged: `project.dev.yml` (BiselDev) and CI never sign, and CI has no signing secrets. The Release job
in CI builds Release unsigned and checks the binary for debug hooks (`scripts/check-release-hooks.sh`).

## One-time setup (Rodrigo only)

Do these in order. Each ends with a check you can run.

### 0. Sign Xcode back in

Xcode on this Mac has no account session (`xcodebuild` reports "No Accounts"). Xcode → Settings → Accounts → **+** → Apple ID, and
sign in with the Apple ID of team ZVGTVNUPVA.

### 1. Developer ID Application certificate

1. Xcode → Settings → Accounts → select your Apple ID → select team **ZVGTVNUPVA** → **Manage Certificates…**
2. **+** (bottom left) → **Developer ID Application**. Only the Account Holder can create it; on an individual team that is you.
3. Back it up: Keychain Access → login → My Certificates → "Developer ID Application: … (ZVGTVNUPVA)" → right-click → Export →
   `.p12` with a strong password, stored outside this Mac. Apple allows only a few Developer ID certificates per team, and losing the
   private key means revoking and re-signing.

Check: `security find-identity -v -p codesigning` lists `Developer ID Application: … (ZVGTVNUPVA)`.

### 2. Developer ID provisioning profile with iCloud

The app carries iCloud entitlements, which are restricted: a Developer ID app that has them but no embedded profile is killed at launch.

1. <https://developer.apple.com/account> → Certificates, IDs & Profiles → **Identifiers** → `app.bisel.mac`. Check that **iCloud** is
   enabled with **CloudKit** selected (Include CloudKit support) and container `iCloud.app.bisel` ticked (Edit next to iCloud).
   Key-value storage comes with the iCloud capability. Save if you changed anything.
2. **Profiles** → **+** → under Distribution choose **Developer ID** → Continue.
3. Profile type Mac, App ID `app.bisel.mac` → Continue.
4. Certificate: the Developer ID Application certificate from step 1 → Continue.
5. Provisioning Profile Name: **`Bisel Developer ID`**, exactly (the build looks it up by this name) → Generate.
6. Install it: Xcode → Settings → Accounts → your Apple ID → **Download Manual Profiles**. (Or download it and double-click.)

Push notifications are not in the entitlements today. When `com.apple.developer.aps-environment` is added (docs/SYNC-LANES.md §15),
enable Push Notifications on the App ID, regenerate this profile, and add `aps-environment` = `production` for the Developer ID build.

### 3. Notary credentials in the keychain

1. <https://account.apple.com> → Sign-In and Security → **App-Specific Passwords** → **+**, label it `bisel-notary`. Copy the password.
2. In Terminal:

   ```bash
   xcrun notarytool store-credentials bisel-notary --apple-id YOUR_APPLE_ID --team-id ZVGTVNUPVA
   ```

   It prompts for the password; paste the app-specific password there, never as an argument. The credentials stay in your login
   keychain under the profile name `bisel-notary` (another name works with `BISEL_NOTARY_PROFILE=<name>`).

Check steps 1 to 3 at once (builds nothing):

```bash
apps/mac/Tools/release.sh --preflight
```

### 4. CloudKit management token

1. <https://icloud.developer.apple.com> → CloudKit Console → account menu (top right) → **Settings** → **Tokens**, under Management
   Tokens click **+**, name it `bisel-cktool`, and copy the token.
2. In Terminal:

   ```bash
   xcrun cktool save-token --type management
   ```

   It prompts; paste the token there. It is stored in the keychain.

Check: `xcrun cktool get-teams` lists team ZVGTVNUPVA.

### 5. Deploy the schema to Production

The Development environment got record type `R` just in time from the CloudKit runs (docs/SYNC-LANES.md §15). Production has no
record types until you deploy them, and the shipped app cannot save a record until then.

1. Export Development into the repo and lint it against what `CloudKitLane` writes:

   ```bash
   apps/mac/Tools/cloudkit-schema.sh export
   ```

   The lint expects exactly `R(k STRING, rev INT64, ep INT64, w STRING, sig BYTES, d BYTES)` with **no** `QUERYABLE`, `SORTABLE` or
   `SEARCHABLE` on any field: the lane never runs a query (it reads zone changes and fetches by record ID), so an index would only
   make CloudKit index box metadata it never needs. If the lint reports indexes that the just-in-time schema added, remove them in
   Development (CloudKit Console → CloudKit Database → `iCloud.app.bisel` → Development → Schema → Indexes, or delete the keywords
   from `schema.ckdb` and run `apps/mac/Tools/cloudkit-schema.sh import-development`), then export again.
   If it reports a missing field, run the contract once (`apps/mac/Tools/run-cloudkit-contract.sh`) so every field is written, then export again.
2. Commit `apps/mac/CloudKit/schema.ckdb` on a branch and merge it by PR.
3. Deploy, one of:
   - CloudKit Console (Apple's documented path): <https://icloud.developer.apple.com> → CloudKit Database → container
     `iCloud.app.bisel` → **Deploy Schema Changes…** → check the list is record type `R` with its six fields and nothing else →
     **Deploy**.
   - Or the script, which exports Production, shows the diff against the repo file and asks you to type a confirmation:

     ```bash
     apps/mac/Tools/cloudkit-schema.sh deploy --production
     ```

     Apple documents the Console as the way to promote a schema; if cktool refuses the Production import, the script says so and
     changes nothing, and the Console path above is the one to use.

Check: `apps/mac/Tools/cloudkit-schema.sh validate --production` reports no drift between Production and the repo file.

### 6. Sparkle update-signing key

Every update is signed with an EdDSA key; the app only installs updates signed by the key whose public half is `SUPublicEDKey` in
`project.yml`. Done once, on the Mac that builds releases.

1. Resolve the packages once (any build does it; `release.sh` puts them in `apps/mac/build-dist/dd/SourcePackages`), then:

   ```bash
   "$(find ~/Library/Developer/Xcode/DerivedData apps/mac/build-dist -path '*artifacts/sparkle/Sparkle/bin/generate_keys' | head -n 1)" --account bisel
   ```

   It stores the private key in the login keychain (item "Private key for signing Sparkle updates", account `bisel`) and prints
   only the public key. Put that in `project.yml` as `SUPublicEDKey`, by PR.
2. Back it up: `generate_keys --account bisel -x bisel-sparkle.key` writes the private key to a file. Store it with the Developer ID
   `.p12`, outside this Mac, and delete the file. **If the key is lost, installed copies can never be updated again**: they reject
   anything signed by another key, and everyone has to download a new DMG by hand.
3. On another Mac: `generate_keys --account bisel -f bisel-sparkle.key` imports it.

The keychain asks once whether Sparkle's tools may read the item (again after a Sparkle upgrade, since the tools change):
**Always Allow**. Check: `release.sh --preflight` reports `sparkle: keychain account "bisel"`; the full run also refuses an app whose
`SUPublicEDKey` is not this key's public half.

### The keychain access group (decided 2026-10-31: pinned)

Device keys and secrets live in `ZVGTVNUPVA.app.bisel`: `keychain-access-groups` in `Bisel.entitlements`, read back at run time
from `BiselKeychainGroup` in Info.plist (`BiselEnvironment.keychainGroup`), so a later AutoFill extension or iPhone app on the same
team can share them. `release.sh` refuses a build without it. Never change it once real boxes exist: device keys in the old group
are stranded and every Mac would have to re-enroll. Signed test builds made before this change kept their keys in the default group;
reset those throwaway boxes.

## Each release

1. On an up-to-date, clean `main`. Bump `CFBundleShortVersionString` (and `CFBundleVersion`) in `project.yml` by PR first.
2. If the schema changed since the last release: deploy it (step 5) **before** shipping the app that writes the new fields.
3. Build:

   ```bash
   apps/mac/Tools/release.sh          # DMG
   apps/mac/Tools/release.sh --zip    # or a zip
   ```

   It stops early, with the step to take, when the certificate, the profile or the notary profile is missing. Then it archives
   (Release, Developer ID), exports with `Tools/ExportOptions.plist`, and verifies before uploading anything: Developer ID authority,
   hardened runtime, secure timestamp, `icloud-container-environment = Production`, the iCloud and key-value storage entitlements, the application and team identifiers the keychain needs,
   the embedded profile, and `Tools/check-release.sh` (no `get-task-allow`, no software keys, no debug hooks). It notarizes the app
   (`notarytool submit --wait`), staples it, requires `spctl -a -vv` to say `source=Notarized Developer ID` and
   `codesign --verify --deep --strict` to pass, then builds the DMG, signs, notarizes, staples and assesses that too. Last, Sparkle's
   `generate_appcast` signs the DMG with the keychain key and writes `appcast.xml` (one item, pointing at
   `releases/download/vX.Y.Z/Bisel-X.Y.Z.dmg`, itself signed), and `sign_update --verify` checks both signatures. Output is in
   `apps/mac/build-dist/`: the DMG, `Bisel-X.Y.Z.dmg.sha256` and `appcast.xml`. Notarization usually takes a few minutes; on
   rejection the script prints Apple's log.
4. Smoke test on a Mac or user account that has never run a Debug build: open the DMG, drag Bisel to Applications, launch. There
   should be no Gatekeeper warning beyond the usual "downloaded from the internet" prompt. Create a box in iCloud and check it syncs.
5. Publish: merge the release-please PR (it tags `vX.Y.Z` and creates the GitHub release), build from that tag's commit, then

   ```bash
   apps/mac/Tools/release.sh --publish vX.Y.Z
   ```

   It uploads the DMG, its `.sha256` and `appcast.xml` to that release with `gh release upload`, after checking that the last build
   is this version from the tagged commit, that the appcast points at this tag and verifies, and that the release does not already
   have the files. From then on every installed copy finds the update within a day, or at once from "Check for Updates…".

## Updates

Sparkle 2 (`SPUStandardUpdaterController`, `Bisel/App/Updater.swift`), with Sparkle's standard dialogs. The app is not sandboxed,
so Sparkle's XPC services are unused.

- **Feed.** `SUFeedURL` is `https://github.com/handlemotion/bisel/releases/latest/download/appcast.xml`: GitHub redirects
  `latest/download/<name>` to the asset of the newest release that is neither a draft nor a pre-release. Between merging the
  release PR and `--publish` that release has no `appcast.xml`, so checks get a 404: background checks fail silently, and
  "Check for Updates…" shows an error. Publish right after the release PR merges.
- **Trust.** `SUPublicEDKey` (step 6). `SURequireSignedFeed` makes the app reject a feed whose signature does not verify, and
  `SUVerifyUpdateBeforeExtraction` checks the DMG's EdDSA signature before it is opened. The update is also a Developer ID
  build of the same team, which Sparkle checks against the running app's signature.
- **Schedule.** `SUEnableAutomaticChecks` and a daily `SUScheduledCheckInterval`. An update found in the background is shown
  without taking focus (gentle reminders, a menu-bar app); "Check for Updates…" in the menu-bar menu checks at once and is
  disabled while a check or an install is under way.
- **Debug builds** never start the updater, so an Xcode run is not offered the shipped release, unless
  `BISEL_DEV_FEED_URL=<appcast url>` is set (compiled out of Release, like the other `BISEL_DEV_` hooks).
- **The first Sparkle build is installed by hand.** 0.1.1 and earlier have no updater: download that one DMG and replace the
  app once. Every later version arrives through the app.

To test an update end to end without touching a real box: build two Debug copies (`project.dev.yml`) with different
`CFBundleShortVersionString` and `CURRENT_PROJECT_VERSION`, a test bundle id (`PRODUCT_BUNDLE_IDENTIFIER=app.bisel.mac.updatetest`,
so Sparkle's state stays out of `app.bisel.mac`'s defaults) and a throwaway key's public half as `SUPublicEDKey`. Put the newer one
in a DMG, run `generate_appcast --ed-key-file <key> --download-url-prefix http://127.0.0.1:<port>/` on it, serve that folder with
`python3 -m http.server --bind 127.0.0.1 <port>`, and open the older copy from a scratch folder with
`BISEL_DEV_FEED_URL=http://127.0.0.1:<port>/appcast.xml`. Sparkle relaunches the updated copy without that environment, so a
Debug copy then opens the default store: point the test copies' `BiselEnvironment.dataDirectory` at a scratch folder first.

The Developer ID app and the signed Debug app share the bundle id `app.bisel.mac`, so on one Mac they share the keychain items and
`~/Library/Application Support/bisel`. A box created by a Debug build lives in the Development environment; the shipped app looks
for it in Production and will not find it. Test a release where no Debug build has run.

## Rolling back

**The app.** Remove the bad release's assets (or mark it as a pre-release) and point people at the previous DMG. Older notarized
builds keep working; a notarization ticket is only revoked by Apple.

**The schema. Production schema changes are additive only.** Once a record type or field is deployed to Production it can never be
deleted, renamed or change type, and CloudKit rejects a deploy that would remove one. There is no undo. So:

- Rolling back a schema change means shipping an app that stops writing (and tolerates reading) the new field or type, and leaving
  it in the schema unused. `CloudKitLane.laneRecord` already ignores fields it does not know.
- Never deploy a field you are not sure about. Try it in Development first: the contract runner
  (`apps/mac/Tools/run-cloudkit-contract.sh`) runs against Development, and `cloudkit-schema.sh validate` shows the drift.
- Development can be put back to match Production: CloudKit Console → CloudKit Database → `iCloud.app.bisel` → **Reset
  Environment**. That deletes **all** Development data, so only do it on purpose.
- Deploy without indexes. Adding one later is an ordinary additive deploy; if one reaches Production by mistake, remove it in
  the Console if it allows, otherwise it only costs indexing.
