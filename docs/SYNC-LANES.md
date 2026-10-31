# Sync lanes: design and feasibility (CloudKit lane)

Status: design. L1 and L2 are built (what changed from the design: §14); L3, the CloudKit spike, is built and was run against real CloudKit (§15); L4 (CloudKit as the default lane: staged rotation, enrollment, account and store states, moves) is built (§16); L5 onwards is not. Companion to `SPEC.md` (§4 crypto, §6 server, §7 BiselCore). When a milestone below lands, move the settled parts into `SPEC.md` in the same change.

Today the Bisel server is the only place a box syncs through. A **lane** is a replica location for a box's ciphertext. The goal: a CloudKit private-database lane so a box can live in the owner's iCloud with no Bisel server involved, the server lane kept optional, both able to run at once. Same crypto, same key hierarchy, same recovery phrase.

Terminology as in SPEC: "box" in anything the user reads, "vault" in code and the wire format.

## 0. What the code does today (the constraints)

- `SyncEngine` (BiselSync) talks to a concrete `SyncClient` and bakes in server semantics: a server-assigned `seq` cursor, `head_seq` that may never decrease, `base_rev` compare-and-set on `PUT`, an epoch guard, an atomic `/v1/rotate`, a server-side device list and event feed, `GET /v1/envelope`.
- `LocalStore` (GRDB) already holds a **full ciphertext replica** per device (records, tombstones, 30-day trash, cursor, known head, event cursor). `StoredRecord.pending` is one bit (`none/put/delete`) and `baseRev` is "what _the_ server confirmed": it assumes exactly one remote.
- The client already refuses to trust the relay: key confirmation against the sealed manifest (`keyUnconfirmed`), tombstone markers sealed under VK, recovery pins, roster-only rotation, `serverRolledBack` / `invalidCursor`, `reseed` after a server reset. Most of the zero-trust work for an untrusted lane exists; it is spread through `SyncEngine`, `Vault` and `LocalStore` instead of sitting behind one boundary.
- A box can already run **local-only** (`LocalIdentity.serverURL == nil`, `bootstrapLocal`, `recoverLocal`). That is the seam: a lane is "where `serverURL` was".
- Item blob = `wrapped IK (60) || nonce || ciphertext`, AAD `bisel/v1/item/<id>|<rev>`; max 256 KiB. A rotation replaces only the first 60 bytes.

## 1. The sync-transport boundary (BiselCore)

Principle: **a lane is dumb, replaceable storage. It never decides anything the client cannot re-check.** Everything with authority (manifest, roster, epoch, recovery pins, membership events) is a record whose authenticity the client verifies, whichever lane delivered it. A lane may _additionally_ enforce (the server lane does); the engine must not depend on that.

New module `BiselLane` (types + protocol + verifier + fake), depended on by `BiselSync`; `SyncClient` becomes the implementation detail of `ServerLane`.

```swift
public struct LaneID: Hashable, Sendable { let rawValue: String }   // "server:box.bisel.app:<boxID>", "cloudkit:<container>:<zone>"

public enum LaneKind: String, Sendable {      // carried in the record, checked by the verifier
    case item, tombstone                      // id = item id
    case manifest                             // sealed under VK (exists today)
    case envelope                             // id = "<epoch>.<deviceID>"; VK sealed to DK-enc
    case recovery                             // RK pubkeys + HPKE envelope
    case head                                 // signed epoch / AK chain / counters (see §3)
    case log                                  // membership log entry (see §4, §9)
    case enroll                               // enrollment request / pairing proof
}

public struct LaneRecord: Sendable, Equatable {
    public var kind: LaneKind
    public var id: String
    public var rev: Int                       // item revision; 0 for control records that use `counter`
    public var epoch: Int                     // VK epoch the material was built for
    public var blob: Data                     // opaque; `item` layout unchanged
    public var writer: String?                // device id, advisory
    public var sig: Data?                     // DK-sig / AK signature over canonical(kind,id,rev,epoch,blob,writer)
    public var tag: LaneTag?                  // lane's own concurrency token (CloudKit recordChangeTag, server seq). Opaque to the engine.
}

public enum LaneExpect: Sendable { case absent, tag(LaneTag), any }
public struct LaneWrite: Sendable { var record: LaneRecord; var expect: LaneExpect }
public enum LaneWriteResult: Sendable {
    case accepted(LaneRecord)                 // carries the new tag
    case conflict(current: LaneRecord?)       // nil = lane has no such record (it lost state)
    case rejected(LaneRejection)              // .staleEpoch(serverEpoch), .tooLarge, .quota, .forbidden
}

public struct LaneChanges: Sendable {
    public var upserts: [LaneRecord]
    public var removed: [LaneRecordRef]       // hard deletes the lane reports (CloudKit only; the server lane never hard-deletes)
    public var cursor: LaneCursor             // opaque, persisted per lane
    public var hasMore: Bool
    public var reset: LaneReset?              // .cursorExpired, .containerReplaced, .accountChanged: engine re-pulls from nil and treats the lane as new
}

public protocol SyncLane: Sendable {
    var id: LaneID { get }
    var capabilities: LaneCapabilities { get }            // .atomicBatch(max:), .enforcesExpect, .pushNotifications, .history, .perDeviceAuth
    func identity() async throws -> LaneIdentity          // who owns this storage (server: box id; CloudKit: hashed userRecordID). Pinned at enable time.
    func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges
    func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult]   // per record; NOT atomic unless capabilities say so and `atomic: true`
    func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult]  // all-or-nothing, only if capabilities.atomicBatch >= count
    func changes() -> AsyncStream<LaneSignal>             // push hint only (.maybeChanged); never carries data
    func erase(confirmed: LaneEraseToken) async throws    // destructive, explicit (migration/detach)
}
```

Deliberately **not** in the interface: device list, event feed, "envelope for me", revoke, recovery-session, rotate. Those are records (`envelope`, `manifest`, `log`, `recovery`, `head`) the engine reads and writes through `fetch`/`write`. `ServerLane` adapts: it maps `/v1/devices`, `/v1/envelope`, `/v1/recovery/*`, `/v1/rotate` onto those kinds and keeps its extra enforcement as an optimisation. The server API on the wire does not change for this milestone.

Engine split:

- `LaneEngine` (new, replaces the generic parts of `SyncEngine`): per-lane `pull → verify → apply to hub → push`, using `LocalStore` as the hub. Conflict resolution, reseed, tombstone verification, manifest merge stay as they are, now lane-agnostic.
- `LaneVerifier` (new): the checks of §2, run on every `LaneChanges` before `applyRemote`.
- `LocalStore` gets a `lane_state(lane, cursor, known_head, identity_hash, state)` table and `lane_ack(lane, id, rev, tag)`. **`pending` stops being a flag and becomes "local rev > acked rev for lane L"**, computed per lane. The existing flag/`baseRev` migrate to the server lane's rows. This is the one invasive schema change and it is what lets two lanes run side by side.

Contract tests: see §10. The test runs identical flows against every `SyncLane`; that is what keeps CloudKit and server honest to the same behaviour.

## 2. Guarantees: server-enforced today vs client-verified on an untrusted lane

| Guarantee today (server)                            | Mechanism                                                                                                 | Untrusted storage (CloudKit)                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Item content integrity and binding to id/rev        | Client AEAD, AAD `id\|rev` (already client-side)                                                          | Unchanged.                                                                                                                                                                                                                                                                                                                                                   |
| Only authorised devices write control state         | Admin signature `X-Bisel-Admin` (AK, derived from VK) on `rotate`, `devices`, `revoke`, `recovery/rotate` | **Client-verified.** Every `manifest`/`envelope`/`recovery`/`head`/`log` record carries an AK or DK-sig signature; clients pin AK (and its chain, see §5) and drop anything unsigned, mis-signed, or from an unpinned key.                                                                                                                                   |
| Device authenticity per request                     | P-256 DK-sig over method/path/query/body/ts/nonce; unknown or revoked device gets `404`                   | **Gone at the storage layer.** Anyone with the iCloud session (any device on the Apple ID, Apple, an attacker who owns the account) can write any record. Authority moves into record signatures + the sealed roster. Item writes stay authenticated only by AEAD (needs VK); optionally also DK-sig'd for attribution.                                      |
| Nonce / timestamp replay protection                 | 60 s skew, nonce table                                                                                    | **Replaced by monotonic state.** Replay = rollback. Per-record rev high-water (already in `applyRemote`), per-writer signed counters, signed head with set hash (§8). No nonces.                                                                                                                                                                             |
| Uniform `404`, no existence oracle                  | Server design                                                                                             | **Not applicable.** The private DB is already private to the account. What Apple sees instead: container, zone, record count and sizes (padded to 512 B), timestamps, `kind`, opaque writer ids. Record type is one generic name (`R`), record names are random ids or fixed control names. Documented leakage, same class as what the D1 server sees today. |
| Revocation: revoked device gets `404` instantly     | `devices.revoked_at`                                                                                      | **No storage-side lock-out exists** for a device on the same Apple ID. Revocation is cryptographic only: VK rotation (§5). Until the user also removes the device from the Apple ID it can still delete or spam records (availability, not confidentiality).                                                                                                 |
| Epoch guard: stale-epoch writes refused             | `409 stale_epoch`                                                                                         | **Client-verified.** `epoch` is stored on each record as a hint; a record that does not open under the current VK is a stale-epoch write, quarantined and surfaced, never applied.                                                                                                                                                                           |
| `base_rev` compare-and-set                          | `PUT … base_rev` guard in D1 batch                                                                        | **Lane-assisted.** CloudKit `.ifServerRecordUnchanged` gives CAS on `recordChangeTag` for honest operation (two honest devices racing). A malicious store can ignore it; correctness of content then rests on rev/AEAD checks, not CAS.                                                                                                                      |
| Atomic multi-record rotation                        | One D1 batch + `assertions`                                                                               | **Not available at scale** (CloudKit atomic ops are bounded, §3). Two-phase staged commit with a signed pointer (§5).                                                                                                                                                                                                                                        |
| `head_seq` never decreases; cursor sanity           | Client check against server counters                                                                      | **Reimplemented on lane-neutral signed head** (§8); the CloudKit change token is opaque and proves nothing about ordering.                                                                                                                                                                                                                                   |
| Events feed ("device added with recovery phrase")   | `events` table                                                                                            | **Signed, hash-chained membership log** records (§4).                                                                                                                                                                                                                                                                                                        |
| Recovery registration hold-back (24 h)              | `activates_at` on the server                                                                              | **Advisory only.** Storage cannot hold a phrase holder back. Honest clients show the event and refuse to _approve_ from it; they cannot stop a phrase holder who also has the Apple ID from writing. See §6.                                                                                                                                                 |
| Bootstrap token, rate limits, size caps, `box_full` | Worker                                                                                                    | CloudKit quotas apply instead (iCloud storage, request rate); engine enforces its own item/size caps before writing.                                                                                                                                                                                                                                         |

Rule of thumb: **anything the server used to refuse, the verifier now rejects after the fact.** The difference is detection instead of prevention, which is why §7 spells out what an attacker can still do.

## 3. CloudKit mapping

Facts below are from Apple documentation and community reports gathered during this review; items marked **verify** were not confirmed against a current official page.

**Container and environment.** Private database only. Container `iCloud.app.bisel`, shared across bundle ids so the iPhone app (M5) can use the same box (decision D1, approved; registered 2026-10-31, see the spike below). Container ids cannot be renamed or deleted. Development builds use the Development environment; a notarized Developer ID build uses **Production**, which needs the record type/fields deployed from the CloudKit Console first (**verify** exact promotion steps). A box written by a dev build is not visible to the shipped app.

**Zone.** One custom zone per box, `box-<boxID>` (boxID = random 128-bit). The default zone has no change tracking; custom zones give `CKFetchRecordZoneChangesOperation` with change tokens and the atomic capability. A per-box zone lets a lane be reset by creating a new zone, and keeps multiple boxes possible.

**Records.** One record type `R`, fields:

| Field      | Type   | Notes                                                                                                                                                          |
| ---------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| recordName |        | item id (128-bit base64url), or fixed names `manifest`, `recovery`, `head`, `env.<epoch>.<deviceID>`, `log.<n>`, `enroll.<deviceID>`, `stage.<epoch>.<itemID>` |
| `k`        | String | kind (§1)                                                                                                                                                      |
| `rev`      | Int64  | item revision                                                                                                                                                  |
| `ep`       | Int64  | epoch                                                                                                                                                          |
| `w`        | String | writer device id                                                                                                                                               |
| `sig`      | Bytes  | signature, control records                                                                                                                                     |
| `d`        | Bytes  | the blob                                                                                                                                                       |

No queries are needed (everything is zone-change fetch), so no queryable/sortable indexes to configure. We do **not** use `CKRecord.encryptedValues`: Bisel's own crypto is the root and must not depend on iCloud Keychain state or ADP.

**Limits.** Record size is documented at about 1 MB excluding assets (**verify** current number); Bisel blobs are capped at 256 KiB, so `d` is a plain Bytes field, no `CKAsset`. Batch size: the commonly reported ceiling is 400 operations per `CKModifyRecordsOperation` but it is undocumented and the server may reject smaller; chunk at 100 records / a few MB and halve on `limitExceeded`. `requestRateLimited` carries `retryAfter`; `quotaExceeded` means the user's iCloud is full (surface as lane state, never as data loss). Atomicity: `atomically: true` is available only within one custom zone and within the batch bound, so rotation cannot assume one atomic commit for a large box (§5).

**Change tokens.** One `CKServerChangeToken` per zone in `lane_state.cursor`. Opaque and unordered: it cannot serve as the freshness check. `changeTokenExpired` ⇒ refetch from nil and merge; `zoneNotFound` / user-deleted zone ⇒ `LaneReset.containerReplaced` ⇒ the same flow as today's `reseedPending` (offer to re-upload from the local replica). Remote **hard deletes** come back as removed record ids. Bisel only hard-deletes `enroll.*` and `stage.*` and GC'd tombstones; a removed `item`/`manifest`/`recovery`/`head` is treated as an incident (§7), not as a delete.

**Subscriptions.** One `CKDatabaseSubscription` on the private DB with `shouldSendContentAvailable` (silent push). Needs the push entitlement on macOS (`com.apple.developer.aps-environment`, **verify** key and Developer ID handling) plus `registerForRemoteNotifications`. Pushes are throttled and best effort, so the existing 60 s poll while unlocked stays as the floor; the push only triggers an early `fetch`. `CKSyncEngine` documents a CloudKit + Remote Notifications requirement and sets up this subscription itself.

**CKSyncEngine vs raw operations** (D3, decided after the L3 spike: raw, see §15). `CKSyncEngine` (macOS 14+) handles batching, retry, tokens, subscription. Raw `CKDatabase` async calls give us control to verify each fetched record **before** the token advances and to run the rotation commit. Recommendation: raw calls behind `CloudKitLane` for v1 (the engine already owns pending state, so CKSyncEngine's pending-change tracking would duplicate it); revisit after the milestone 3 spike.

**Account and availability.** `CKContainer.accountStatus()`; observe `CKAccountChanged`. The lane pins `identity()` = hash of `userRecordID` at enable time. Any mismatch pauses the lane (§6).

### Entitlement spike (done, 2026-10-31)

Real run on Rodrigo's Mac, Xcode 27.2, team ZVGTVNUPVA, bundle id `app.bisel.mac`. The entitlement is committed; the container is registered.

**Wiring.** `Bisel/Bisel.entitlements` is now a hand-kept plist (container `iCloud.app.bisel`, services `CloudKit`) referenced by `CODE_SIGN_ENTITLEMENTS` in `project.yml`. Not the XcodeGen `entitlements:` key: XcodeGen regenerates the plist from `properties` on every `generate` (an empty one overwrote the iCloud keys) and its derived setting beats per-config overrides, so the dev spec could not swap it. `project.dev.yml` sets `CODE_SIGN_ENTITLEMENTS: Bisel/BiselDev.entitlements` (empty plist), so BiselDev builds and runs unsigned without iCloud.

**Registration, exact steps.**

1. Without a profile the signed build fails (`No profiles for 'app.bisel.mac' were found`); ad-hoc fails too (`requires a provisioning profile`).
2. With Xcode signed in, `xcodebuild -project Bisel.xcodeproj -scheme Bisel -configuration Release -destination 'platform=macOS' -derivedDataPath <scratch> -allowProvisioningUpdates build` got one step further and failed with `Device "Rodrigo's MacBook Pro" isn't registered in your developer account`. A development profile needs a registered device; `-allowProvisioningUpdates` does not register one.
3. Adding `-allowProvisioningDeviceRegistration` (registers this Mac only; one of 100 device slots, not removable) made the same command succeed: Xcode registered the device, enabled iCloud/CloudKit on the App ID, created the container `iCloud.app.bisel` and generated "Mac Team Provisioning Profile: app.bisel.mac" (expires 2027-10-31, embedded as `Contents/embedded.provisionprofile`). No agreement or other portal step was needed. Later builds only need `-allowProvisioningUpdates` (or Xcode's automatic signing in the IDE).

**Verified on the signed Release app** (built to a scratch DerivedData path, never launched, nothing in `/Applications` touched):

- `codesign --display --entitlements -` shows `com.apple.developer.icloud-container-identifiers = [iCloud.app.bisel]`, `com.apple.developer.icloud-services = [CloudKit]`, plus `application-identifier` and `team-identifier`. No `get-task-allow`.
- `codesign --verify --deep --strict` passes; signature is Apple Development, hardened runtime flag set.
- The profile's entitlements list `icloud-container-environment = [Production, Development]` and `icloud-services = *`. The profile also grants `ubiquity-kvstore-identifier` and `keychain-access-groups` that the app does not request, which is harmless (the app's entitlements decide).
- `apps/mac/Tools/check-release.sh` on that app: OK. `BiselDev` (SoftwareKeys, unsigned) compiles and its signature has no iCloud keys.
- `scripts/check-release-hooks.sh --control` passes after one change: it now builds with `CODE_SIGNING_ALLOWED=NO` (it only greps strings), because an ad-hoc Release build can no longer be signed with the iCloud entitlement. `scripts/check-all.sh` builds `BiselDev` ad-hoc and is unaffected.

**What a Developer ID / notarized build needs (not done, not verifiable here).**

- Only an Apple Development certificate exists on this Mac. Needs a **Developer ID Application** certificate, and a **Developer ID provisioning profile** for `app.bisel.mac` with iCloud + the container (created in the developer portal or by Xcode's Archive → Distribute → Developer ID). Developer ID builds with restricted entitlements must embed that profile; without it the app is killed at launch.
- Keep hardened runtime and the `get-task-allow` gate; notarize and staple as for any Developer ID app.
- Environment: the profile allows Production and Development. A build signed this way talks to **Production** CloudKit; Xcode-run development builds use **Development** (**verify** whether the `icloud-container-environment` entitlement must be set explicitly for a Developer ID build). Records written by a dev build are not visible to the shipped app.
- **Manual step, only Rodrigo:** the Production environment has no record types until the schema is deployed. In the CloudKit Console (container `iCloud.app.bisel`) run the app once against Development so record type `R` and its fields are created (or define them by hand), then "Deploy Schema Changes to Production". The Console cannot be scripted from here. After deployment, additive changes are the norm; fields and types in Production cannot be removed.
- If the lane gets push (M3+): add `com.apple.developer.aps-environment` and re-check the profile (**verify**).

Consequences to plan for:

- A signed build now needs a profile with the container; the container exists and the profile is generated per machine by Xcode. A fresh machine or CI runner needs Xcode signed in to the team plus `-allowProvisioningUpdates` (and `-allowProvisioningDeviceRegistration` once per new device).
- `BiselDev` uses its own iCloud-free entitlements file (done, see above). When `CloudKitLane` lands, compile it out of the dev build (`#if` or a dev-only lane factory), keeping the rule that dev flows never touch real CloudKit.
- Release needs a **Developer ID** provisioning profile with the iCloud container (see above) and the existing `get-task-allow` gate must still pass. `Tools/check-release.sh` should additionally assert the container id is present in a signed Release (not added yet: it also runs on unsigned builds).
- The app stays unsandboxed; CloudKit does not require the sandbox.
- CloudKit cannot run in the SwiftPM flow tests (no entitlement/profile for the test host). Flow tests use the fake lane; a real-CloudKit check is a manual, signed run on Rodrigo's machine (§10).

## 4. Device enrollment and approval over CloudKit

Today: new device makes keys → `EnrollmentRequest` (public keys only) goes to an enrolled device out of band → approver seals VK to the new `DK-enc`, `POST /v1/devices` → new device `completeEnrollment` fetches its envelope → both show the 40-bit `HKDF(VK,"verify")` code, human compares.

On CloudKit the out-of-band hop can become a record, because every device of the Apple ID reads the same zone:

1. **New device** (same Apple ID, app installed): `prepareEnrollment` as now. It finds the box zone (`fetchAllRecordZones`), writes `enroll.<deviceID>` = `{name, kind, sigPubkey, encPubkey, createdAt, proof}`, signed with its fresh `DK-sig`. It shows a **pairing code** (below) and its 96-bit fingerprint.
2. **Approver** (unlocked, subscription or poll sees the record): shows name, kind and fingerprint, asks the user to confirm the pairing code / fingerprint and does the existing biometric gate. Then `approveEnrollment`: seals VK to `encPubkey`, writes `env.<epoch>.<deviceID>`, appends the device to the sealed manifest roster, appends a `log` entry (AK-signed). `enroll.*` is then deleted.
3. **New device** polls for its envelope, runs `completeEnrollment`, `keyUnconfirmed` / `enrollmentUnconfirmed` apply exactly as today, then the verification-code comparison.

Why not just trust the request: the zone is writable by anyone holding the Apple ID session, and Apple. A planted request is harmless without approval, but a **man-in-the-middle substitution** of the new device's public keys is the real attack (the user approves what they think is their iPhone and seals VK to an attacker key). Defence: bind the request to something the attacker cannot see.

- **Pairing secret.** The new device displays a QR (or, on a Mac without camera, 8 words from the BIP-39 list, 88 bits) containing a random secret `PS`. `proof = HMAC(HKDF(PS,"bisel/v1/enroll"), deviceID | sigPubkey | encPubkey | createdAt)`. The approver verifies `proof` before showing the request as "proven"; unproven requests are shown with a warning or not at all (setting). The attacker who only sees the record cannot forge a proof for substituted keys. 88 bits resists offline guessing without a password hash, which is why the typed form is long. No PBKDF is needed (SPEC §4: every KDF input is high entropy).
- **SPAKE2-style short codes.** A PAKE would allow a 6-digit typed code. There is no SPAKE2 in CryptoKit and SPEC §4 forbids hand-rolled primitives; adopt only if a maintained, audited Swift implementation exists (D6). v1 ships QR / words.
- Fingerprint comparison and the post-enrollment 40-bit code stay; they catch relay faults and lazy approvals.
- Requests expire (approver-side receive time, ~15 min), the approver rate-limits the number of open requests shown, and never auto-approves.
- The 24 h recovery hold-back becomes advisory (see §6).

Membership log (adopted from Deadbolt, §9): `log.<n>` records `{n, prev = hash(log.n-1), type: add|revoke|rotate|recovery|recovery_rotate, subject, epoch, ts}` signed by AK (or by the acting device's DK-sig plus an AK countersign for add/revoke). Devices check the chain and show new entries as the events feed does today. A gap or fork is an integrity alert. The sealed manifest remains the source of "who may receive VK"; the log is the tamper-evident history and the alarm.

## 5. Revocation by vault-key rotation

On this lane revocation **is** rotation. `revokeWithoutRotation` does not exist for it (nothing to cut off at the storage layer). The server lane keeps its emergency endpoint.

Preconditions as today: unlocked, no pending changes, every item decrypts, every active device is in the roster, recovery material is current.

Rotation, in phases, resumable and idempotent (the CloudKit atomic bound makes one transaction impossible for large boxes):

1. **Journal.** CAS-write `head` (AK-signed) with `{state: rotating, from: N, to: N+1, rotator: deviceID, nonce, newAK pubkey, itemCount, setHash}`. This is the mutual-exclusion step: concurrent rotators lose the CAS and abort. Anything written under `to: N+1` by a loser is garbage-collected by nonce.
2. **Stage.** Write `stage.<N+1>.<itemID>` (new 60-byte wrapped IK for each live item and tombstone marker, rev unchanged) and `env.<N+1>.<deviceID>` for each remaining roster device, plus the new recovery envelope (same recovery key) and new manifest. All of these are new records; the existing item records and N-epoch envelopes are untouched, so a crash leaves a fully readable box.
3. **Commit.** CAS-write `head` = `{state: committed, epoch: N+1, AK: newAK, chain: sig_AK_old(newAK)}`. One record, atomic. This is the switch.
4. **Fold.** Any device with VK N+1 folds `stage.*` into the item records (CAS, replacing the first 60 bytes) in the background, then deletes the staged records and the N-epoch envelopes. Readers that see `committed` read the staged key when the item record is not folded yet.

Other devices on their next fetch see `committed`, lock themselves, unlock into their `env.<N+1>` (the existing `rotationAdopted` path, `keyUnconfirmed` until the manifest opens), and re-wrap pending edits at unlock as now.

AK rotates with VK (as today); the new key is chained from the old one in `head`, so a revoked device still holding AK_old cannot produce records that honest, up-to-date clients accept. There is a window between commit and a device noticing in which an old-epoch device could write: its records fail to open under VK N+1 and are quarantined, same as `409 stale_epoch` today but detected on read.

Failure handling: a rotator that dies between 1 and 3 leaves a journal with no commit; after a timeout any device with VK N may abort (CAS `head` back to `committed` N) and clean `stage.*`. Between 3 and 4 nothing is lost either way.

Honest limits, same as SPEC plus one: a revoked device keeps what it already read; **it also keeps its iCloud session** if it is on the same Apple ID. It cannot read new data but can delete or spam. The revocation UI on this lane must say "also remove the device from your Apple Account" and the lane's availability alarms (§7) are the safety net. Revocation of a device on a _different_ Apple ID is not possible by definition (it cannot have been in the zone).

## 6. Recovery with the 24 words

What the phrase gives: `RK-enc` opens the recovery envelope (VK), `RK-sig` proves ownership. What it never gives: the ciphertext. On the server lane the server holds both; on CloudKit the data lives behind the Apple ID. **The phrase recovers the key; the data must still be reachable.** That is the central change in the recovery story.

Flow on a fresh device signed into the same Apple ID: find the zone → fetch `recovery` and `manifest` → derive RK-enc, open the HPKE envelope (info binds epoch and RK-sig key, exactly as now) → VK → check it against the sealed manifest or an item (`keyUnconfirmed`, no uploads before that) → pin recovery keys from the phrase → create device keys, write own `env`, roster entry and a `log` entry of type `recovery`. Other devices show the "device added with the recovery phrase" alarm. The 24 h hold-back cannot be enforced by storage; honest clients refuse to _approve or rotate on behalf of_ a device whose only origin is a `recovery` log entry younger than 24 h, and the alarm stays pinned. Mitigation, not prevention.

Cases:

| Situation                                                 | Outcome                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Same Apple ID, ADP off                                    | Works as above. Apple holds the keys to the iCloud service data; Bisel's ciphertext is opaque anyway. Metadata is visible to Apple (§7).                                                                                                                                                                                                                                                                                                                                                                          |
| Same Apple ID, ADP on                                     | Works as above. ADP changes who can decrypt iCloud service data; Bisel does not rely on it and does not use `encryptedValues`. Apple documents that only fields declared as encrypted get end-to-end treatment, so Bisel's plain `d` field is still "Apple-protected", not E2E, at the iCloud layer; irrelevant to confidentiality because `d` is already our ciphertext, relevant to metadata only. Enabling ADP can force older OS devices off iCloud; the lane sees `noAccount` / `accountChanged` and pauses. |
| ADP toggled on/off while running                          | No Bisel keys or records change. Tokens/zone survive. Lane might pause during the account state transition; it resumes. (**verify** with a real account before shipping; not testable in flow tests.)                                                                                                                                                                                                                                                                                                             |
| iCloud signed out / restricted                            | Lane `paused(noAccount)`. The box keeps working locally; pending edits stay pending; `wouldDiscardData` protection applies.                                                                                                                                                                                                                                                                                                                                                                                       |
| **Different Apple ID on the same Mac**                    | `identity()` mismatch ⇒ lane `paused(accountChanged)`. **Never auto-upload to the new account.** User chooses: re-enable the lane on the new account (full re-upload from the local replica, a migration, §10) or detach.                                                                                                                                                                                                                                                                                         |
| Old Apple ID lost, no device has the box                  | The zone is unreachable; the phrase alone recovers nothing. Needs a `.bisel-backup` file (exists) or the server lane. Therefore: periodic backup-export reminder and/or "server lane as second replica" belong in the product plan for CloudKit-only boxes (D4).                                                                                                                                                                                                                                                  |
| User deletes Bisel data in iCloud settings / zone deleted | `LaneReset.containerReplaced`; devices still hold full replicas, so the lane offers to re-seed (existing `acknowledgeServerReset` precedent).                                                                                                                                                                                                                                                                                                                                                                     |
| Phrase rotation (`rotateRecovery`)                        | New `recovery` record (CAS), AK-signed, `recoveryGeneration + 1` pinned via the manifest. Unchanged semantics.                                                                                                                                                                                                                                                                                                                                                                                                    |

Security delta vs the server lane: today the phrase by itself suffices to register a (held-back) device on the public server. On CloudKit a phrase thief also needs the Apple ID session to reach the ciphertext. The second factor is Apple's account security, which is also the thing the user is now trusting for availability.

## 7. Threat model: Apple (and anyone with the iCloud account) as untrusted storage

Adversary: reads, replays, reorders, withholds, deletes, restores snapshots, and can write arbitrary records. Cannot break AES-GCM/P-256/Ed25519/HPKE, cannot obtain VK, RK, or any device key.

| Attack                                                                             | Result                                                                                                                                                             | Defence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Read everything                                                                    | Sees ciphertext and metadata: item count, padded sizes, timestamps, kinds, writer ids, container/zone, account                                                     | Accepted, documented. Padding (512 B) exists; record type is generic; no titles/URLs/tags anywhere in the clear.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Modify a blob                                                                      | Rejected                                                                                                                                                           | AEAD, AAD `id\|rev` (exists).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Swap blobs between ids/revs                                                        | Rejected                                                                                                                                                           | Same AAD.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Forge/alter manifest, envelope, recovery, head, log                                | Rejected                                                                                                                                                           | AK/DK-sig signatures, pins, hash chain; manifest sealed under VK.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Roll back **one record** to an older valid rev                                     | Detected, ignored                                                                                                                                                  | Per-record rev high-water (`applyRemote` already ignores lower revs); the newer local copy is re-pushed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Roll back **the whole zone** (restore an older snapshot)                           | **Detected by any device that saw newer state; self-heals** (they re-push, as `reseed` does); **not detectable by a fresh device** that has never seen newer state | Signed `head` per device `{deviceID, counter, setHash(id,rev set)}`; each device persists the highest `head` it has seen for every roster device and refuses to go backwards (`IntegrityError.serverRolledBack` generalised). A fresh device cannot know; mitigations: (a) a second, independent witness: `NSUbiquitousKeyValueStore` (separate service, small) holding the latest head counter, or the optional server lane's head; (b) the user's other device compares on first pairing. Document this as the irreducible limit: rollback to a state **the owner previously signed**, never forged state. |
| **Withhold** new records from one device (split view)                              | Detected after the fact                                                                                                                                            | `setHash` in other devices' signed heads: once caught up, a device whose computed set differs from a roster peer's attested set raises an alert. Needs all devices to write heads regularly (on each push and at least daily).                                                                                                                                                                                                                                                                                                                                                                               |
| **Delete** records (CloudKit hard delete, zone delete, Apple, or a revoked device) | Detected, repaired                                                                                                                                                 | Legit deletes are `tombstone` records with a sealed marker (exists). A removed `item`/`manifest`/`recovery` without a tombstone is an incident: restore from the local replica (`reseed`) after surfacing it; never silently honoured. Tombstones are GC'd only on a signed, aged `log` entry. Because every device holds a full replica, loss needs **every** device and the zone gone.                                                                                                                                                                                                                     |
| Delete only the `head`/`log` chain tail                                            | Detected                                                                                                                                                           | Counter regression / chain gap.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Substitute a new device's keys during enrollment                                   | Rejected                                                                                                                                                           | Pairing proof, fingerprint compare, 40-bit code (§4).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Revoked device keeps writing                                                       | Confidentiality safe (no VK N+1, AK_old unpinned). Availability attack possible                                                                                    | Signature/AEAD fail, records quarantined; repeated quarantined writers raise an alarm; user told to remove the device from the Apple Account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Account takeover (Apple ID attacker) + no phrase                                   | Gets ciphertext and can attempt enrollment spam                                                                                                                    | Approval is human + biometric + pairing proof; unproven requests warned.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Account takeover + phrase                                                          | Full compromise                                                                                                                                                    | Same class as server + phrase today; hold-back is advisory here. Stated.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Traffic analysis, timing                                                           | Not covered                                                                                                                                                        | Out of scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Apple withholds service entirely                                                   | Availability loss                                                                                                                                                  | Local replicas keep working; server lane or backup file as second copy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Quarantine DoS (flood of garbage records)                                          | Clients ignore after verification; cost grows                                                                                                                      | Per-writer quarantine cap, GC of quarantined records by any VK holder.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

Principle for implementation: no verification result may _delete_ anything. Rejected records are dropped from the apply path and kept in a quarantine table for diagnostics.

## 8. Freshness and head records

Server lane today: `head_seq` + `next_since <= head_seq` checks. Lane-neutral replacement:

- Each device writes `head.<deviceID>` (DK-sig) `{counter, setHash, epoch, lastLogN}` at the end of each push and on a timer. `counter` is strictly increasing per writer; `setHash` is an order-independent accumulator (sum of SHA-256(id‖rev‖deleted) mod 2^256) over the writer's applied set.
- Verification rules on every `fetch`: no writer's counter decreases; for the writer's own heads, `setHash` equals the set the writer must have had; log chain contiguous; epoch never decreases. The CloudKit token is used only as a sync cursor.
- Per-writer records (not one shared head) avoid CAS contention between devices.

Specified in milestone 2 with the verifier; this section is the invariant list, not the byte format.

## 9. Migration between lanes and running both

A box has one identity (VK, roster, recovery keys) and N lane replicas around the local hub. Nothing about keys changes when lanes change.

**Running both.** The engine runs lanes sequentially: pull A → verify → apply, pull B → verify → apply, then push to each lane whatever it lacks (per-lane `lane_ack`). Order is stable and configurable; no cross-lane transaction exists.

- Divergent edits on two lanes surface as the existing conflict case at the hub (same rev, different blob ⇒ remote kept, local saved as "(conflict)"); no new resolution logic.
- **Rotation must complete on every enabled lane** before the UI says "done". A lane that failed stays `behind(epoch)`; the next unlocked sync catches it up; revocation is reported "incomplete on lane X" until then. A revoked device with access to a lane that is still on the old epoch keeps old-epoch read access to that lane.
- Recovery material and pins are identical across lanes; mismatch between lanes = `recoveryMaterialChanged`.
- The server lane can also serve as the independent **freshness witness** for the CloudKit lane (head counters), at no extra trust in the server.

**Server → CloudKit (enable lane).** Same Apple ID on each device: (1) on a device with the entitlement, create the zone; (2) pin lane identity; (3) upload the hub (all records including tombstones), the sealed manifest, `recovery`, a signed first `head`, `env.<epoch>.<d>` for every **roster** device (VK sealed to each device's known `encPubkey`, so no re-enrollment); (4) append a `log` entry; (5) other devices see the zone and join it by reading their envelope. Devices not on that Apple ID stay on the server lane only.

**CloudKit → server.** Existing `connectServer`/`reconnectServer` plus reseed from the hub.

**Detach.** Stop syncing a lane; deleting its remote data is a separate, explicit step that requires another lane (or a fresh backup) to be verified complete first.

**Local-only boxes** (exist today) are simply "zero lanes".

## 10. Milestones

Each milestone is releasable alone and leaves the server lane working.

| #   | Scope                                                                                                                                                                                                                                                                                                                | Verify                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L1  | `BiselLane`: protocol, record types, `LaneVerifier` skeleton, **`FakeLane` (in memory, in BiselTestSupport)**. Refactor `SyncEngine` into `LaneEngine` over `SyncLane`; `ServerLane` wraps `SyncClient` with zero wire changes. `lane_state`/`lane_ack` migration (including the existing `pending`/`baseRev` data). | One shared contract suite (Swift Testing, `swift test --traits SoftwareKeys`) parameterised over `[FakeLane, ServerLane(local wrangler)]`. Only flows that must not break: two devices converge; conflict keeps remote + "(conflict)" copy; forged/rolled-back/deleted remote state is detected and healed; rotation + revoke; recovery from phrase; migration of an existing pending queue. Existing flow tests stay green. |
| L2  | Verifier for real: signed `head`/`log`/control records, rollback and deletion handling, quarantine; hostile-lane mode in `FakeLane` (rolls back, drops, reorders, replays, deletes).                                                                                                                                 | Same contract suite plus hostile-fake cases. No new test files beyond that suite.                                                                                                                                                                                                                                                                                                                                            |
| L3  | Spike `CloudKitLane` on a signed build: provisioning (D1), zone, `R` record, fetch/write with tokens, subscription, `accountStatus` handling. Raw vs CKSyncEngine decision recorded.                                                                                                                                 | Manual signed run on Rodrigo's Mac, one window capture; not in CI.                                                                                                                                                                                                                                                                                                                                                           |
| L4  | `CloudKitLane` complete: staged rotation, enrollment over `enroll`/`env` records, account-change and zone-reset paths, migration enable/detach. Dev spec without iCloud + `#if`. Production schema deployment.                                                                                                       | Contract suite runs against `CloudKitLane` only behind an opt-in env flag on the signed build (like `test:browser`); the runner exists since L3 (§15).                                                                                                                                                                                                                                                                       |
| L5  | Lane settings UI, alarms (rollback, withheld, quarantine, account changed). **The UI is Rodrigo's;** this milestone is blocked on his design.                                                                                                                                                                        | —                                                                                                                                                                                                                                                                                                                                                                                                                            |
| L6  | Optional: server lane as freshness witness; SPAKE2 pairing if a vetted library exists; iPhone (M5) reuses the lane.                                                                                                                                                                                                  | —                                                                                                                                                                                                                                                                                                                                                                                                                            |

Test economy (AGENTS.md): L1 adds one suite (the contract) and L2 grows it; nothing else is written for lanes. CloudKit-specific behaviour that cannot run headless is verified by running the real signed build once.

## 11. Deadbolt: adopt / avoid

Caveat: this list rests on the description in the brief (Rust, iroh p2p, no recovery, SPAKE2 pairing, membership log). I could not find the repository in a web search, so the code was not reviewed.

Adopt:

- **Membership log**: signed, hash-chained history of add/revoke/rotate. Becomes `log.<n>` (§4); gives tamper-evident history and the alarm channel that the server's `events` table provides today.
- **PAKE-style pairing** so a short human-typed code authenticates a key exchange against a hostile channel. In Bisel's setting the channel is the CloudKit zone. v1 gets the same property with a high-entropy pairing secret (QR / 8 words); SPAKE2 only with a maintained audited library (D6).
- Treating transport as hostile and putting authority in signed state (the whole of §2).

Avoid:

- **iroh/p2p transport**: needs always-on peers or relays, NAT traversal and background networking on iOS, which fits neither the iOS lifecycle nor a phone that is rarely both online and awake with the Mac. CloudKit gives asynchronous store-and-forward and silent push for free.
- **No-recovery stance**: Bisel has the 24-word phrase by design and the product needs it on iOS (lost phone, new Apple ID). Keep recovery; make it honest about "key without data" (§6).
- Anything that makes a peer's availability a condition for sync.

## 12. Risks

1. **Entitlement/profile friction** (spike done): the container `iCloud.app.bisel` is registered and the signed Apple Development build carries the entitlement; the dev build is split. Remaining: Developer ID certificate and profile, Production schema deployment from the CloudKit Console. Containers and registered devices are permanent in the portal.
2. **Rotation without atomicity** (staged commit) is the most complex new protocol; needs the hostile-fake tests before any real data.
3. **Fresh-device freshness** is not solvable against a malicious store; witness options reduce, not remove.
4. **Per-lane pending state** is an invasive schema/engine change touching the sync core; must land with migration of existing queues.
5. **Revocation weaker on CloudKit** for same-Apple-ID devices (cryptographic only); UI must say so.
6. **CloudKit behaviours not verifiable headless** (ADP, account switch, push delivery, quota, production schema). Treated as manual checks.
7. **Apple-side metadata** (counts, sizes, times) is visible to Apple and to anyone with the account.
8. **CloudKit-only boxes can lose data** when the Apple ID is lost and no device or backup remains; the phrase does not help. Product mitigations needed.

## 13. Open decisions for Rodrigo

- **D1. Container id and registration.** Decided: shared `iCloud.app.bisel`, registered 2026-10-31.
- **D2. Same Apple ID only?** The CloudKit lane serves devices on one Apple ID. Anything outside it (a second person, a device on another account) stays on the server lane. Confirm that is acceptable.
- **D3. Raw CloudKit operations vs CKSyncEngine.** Decided: raw `CKDatabase` calls behind `CloudKitLane` (evidence in §15).
- **D4. Second copy for CloudKit-only boxes**: forced reminder to export `.bisel-backup`, or require the server lane, or accept the risk.
- **D5. Freshness witness**: iCloud KVS only, optional server head, or accept the fresh-device limit.
- **D6. PAKE**: QR/8-word pairing shipped in L4 (§16); SPAKE2 only if a vetted Swift implementation is found.
- **D7. Recovery hold-back** is advisory on CloudKit. Acceptable, or should phrase recovery on a CloudKit-only box require a second enrolled device's approval?
- **D8. Lane UI** (L5) needs your design: where lane state, rotation incompleteness and rollback alarms appear.

## 14. What L1 and L2 built, and how it differs from this design

Code: `apps/mac/Packages/BiselCore`, modules `BiselLane` (types, `SyncLane`, `LaneVerifier`, control records, witness), `BiselSync` (`LaneEngine`, `ServerLane`, `RecordBox`), `BiselTestSupport` (`FakeLane`). One contract suite, `Tests/BiselFlowTests/LaneContractTests.swift`: six flows run on `[FakeLane, local server]`, three hostile-storage cases run on `FakeLane` only (the server cannot be made to misbehave at record level).

**Interface changes**

- `BoxLane: SyncLane` carries the control operations (members, admit, rotate, recovery, `ownEnvelope`, `create`, `attest`). They are not "just records" at the interface: `ServerLane` forwards them to the server endpoints (wire untouched), `RecordBox` implements them as signed records on any `SyncLane`. `AdminSigner`/`WireDevice` live in `BiselSync`, so `BoxLane` does too; `BiselLane` is data plane only.
- `SyncLane.read(refs)` added (fetch by id): `RecordBox` needs the current head, log tail and a record's tag before it writes. `commit` is used only by `RecordBox.rotate`.
- `LaneChanges.meta` (epoch, position, members, events, recovery) is what the server reports; for a storage lane the verifier derives it from verified control records (`LaneVerdict.meta`).
- `LaneCapabilities` gained `headIsCursor` (server: position is the cursor) and `repairs` (a write at any revision is accepted, so a lane that lost state is repaired by uploading the replica).
- `DeviceInfo`, `ServerEvent`, `RecoveryMaterial` moved from `Wire.swift` to `BiselLane` unchanged (re-exported).
- `Vault.Configuration.laneProvider` injects a lane; a plain `SyncLane` is wrapped in a `RecordBox`. `Vault.bootstrap(lane:)` and `Vault.recover(lane:…)` are the credential-less entry points. `Vault.sync(audit:)` reads the whole lane.

**Pending state (the one real deviation).** `records.pending`/`base_rev` were **not** replaced by "local rev > acked rev". Revisions are bound into the item AAD and the server computes `rev = base_rev + 1`, so one record cannot sit at different revisions on two lanes. `lane_state`/`lane_ack` exist and are populated (migration `v3-lanes` moves the old cursor, `head_seq`, event cursor and every record's confirmed revision under the key `primary`, which the first lane that syncs adopts), `lane_ack` supplies the compare-and-set tag, and `recordsBehind` (acked rev < local rev, or never acked) drives **repair** on lanes with `repairs`. Running two lanes at once with different revisions per record is therefore still open; it needs lane-independent revisions or a rebase per lane, and belongs with L4's enable-lane flow. Tags are `"<rev>.<order>"` on the server and the fake, opaque on CloudKit.

**Control records (L2).** All JSON, canonical sorted keys, signature over `LaneRecord.canonical` (kind, id, rev, epoch, writer, blob).

| Record             | Signed by               | Content                                                                                 |
| ------------------ | ----------------------- | --------------------------------------------------------------------------------------- |
| `head`             | current admin key (AK)  | epoch and the chain of AKs; link _i_ is signed by link _i-1_ (so a rotation hands over) |
| `log.<n>`          | AK of the entry's epoch | `n`, `prev` (SHA-256 of the previous blob), type, subject, epoch, and the member added  |
| `<epoch>.<device>` | AK of that epoch        | the device envelope                                                                     |
| `recovery`         | AK of that epoch        | recovery public keys and envelope, with a `seq` that only goes up                       |
| `head.<device>`    | that device's DK-sig    | a strictly increasing counter (freshness)                                               |

The verifier pins the AK chain from the first head (anchored on the AK derived from the vault key the device holds, or held back while locked), then checks: signatures against the key of the record's epoch; the log is contiguous, hash-chained and its epochs never go back (out-of-order entries wait in the witness); envelopes and recovery are signed; counters never decrease; item records written for an epoch below the box's are quarantined; hard deletes the lane reports are incidents and the replica is uploaded again. `lane_state.witness` keeps what an incremental fetch cannot show twice; `quarantine` keeps what was refused (newest 200 per lane). Nothing is deleted because of a verdict.

**Freshness.** The signed per-writer counters from §8 are in; `setHash` (withholding detection) is **not**. A silent restore of the whole store keeps its own cursor numbering, so reading only what is new sees nothing: `sync(audit: true)` (full read, compare counters, log tail, and every record this device was told the lane holds) is what finds it, and the app should run one about daily. The server lane keeps its `head_seq` check; both feed the same `IntegrityError.serverRolledBack` and the same `acknowledgeServerReset` + reseed heal.

**Rotation on a storage lane** (L2; replaced by the staged commit in L4, §16) was one atomic `commit` (items and tombstones re-wrapped, new envelopes, recovery, the `rotate` log entry, the new head), refused if the lane's `atomicBatch` is too small. The staged form of §5 is L4 (CloudKit). `revokeWithoutRotation` does not exist on a storage lane (`LaneError.unsupported`).

**Known limits (left for L4, not hidden)**

- (Status of these after L4: §16.) A forged record **overwriting** `head` (or `recovery`) is quarantined, but this device does not yet re-publish the genuine one from its witness, so rotation on that box is blocked until it is. Log slots planted by an attacker are replaced by the next genuine append.
- The membership log and envelopes are not repaired after a restore; a device approved after the snapshot has to be approved again. Items are healed.
- ~~`ownEnvelope` does not check the envelope's signature (key confirmation against the manifest, which exists, covers it).~~ Wrong, fixed 2026-10-31 (SECURITY-REVIEW P1): whoever picks a key can seal a manifest under it. `RecordBox` now verifies the head (chain, signature, pin) and the envelope, and a key adopted on a storage lane is confirmed by its admin key ending the verified chain. Recovery requires the phrase's `anchor` over the chain's first admin key.
- A stale-epoch write that slips past the up-front epoch check (a race with a rotation) is quarantined on read, not re-sent by its writer until that writer has adopted the rotation.
- The window of §5 between a rotation commit and a device noticing is as described there: a revoked device still holding the old AK can write control records an up-to-date device rejects, but a device that has not yet pinned the new chain can be fooled by the first head it sees.
- `FakeLane` hostile modes: rollback (`restore`), `dropSilently`, `hardDelete`, `replay`, `setReordering`, `inject`, `forgeDelete`. Not modelled: `LaneReset` (token expiry, account change), quota errors, concurrent writers racing inside one fetch.

## 15. What L3 built: `CloudKitLane` on real CloudKit (2026-10-31)

Code: `apps/mac/Packages/BiselCore/Sources/BiselCloudKit/CloudKitLane.swift` (target `BiselCloudKit`, depends on `BiselLane` only). It is storage only, like `FakeLane`, and goes inside a `RecordBox`. Nothing in the shipped app links it yet: `project.yml` and `project.dev.yml` are unchanged, so BiselDev and the SwiftPM flow tests still build and run with no iCloud. Wiring it into `VaultService` is L4.

**What it does**

- Private database of `iCloud.app.bisel`, one custom zone per box (`CloudKitLane.zoneName(box:)` = `box-<boxID>`), created on the first write (`prepare()`). One record type `R` with the fields of §3 (`k`, `rev`, `ep`, `w`, `sig`, `d`). The Development schema was created just in time by the first save. Record names are the lane ids; ids starting with `_` (base64url item ids can) are stored as `~_…`, because Apple documents that record names may not start with an underscore.
- `fetch` is `recordZoneChanges(inZoneWith:since:resultsLimit:)`. The cursor is the archived `CKServerChangeToken`. The lane only returns the token; `LaneEngine.pull` persists it after `LaneVerifier.verify` returns, so a refused page is fetched again from the old token. `changeTokenExpired` restarts from nil (`reset: .cursorExpired`); `zoneNotFound` / `userDeletedZone` throws `LaneError.storeMissing`. Deletions come back as `removed`, with the kind read off the fixed control names.
- `write` saves everything with `.ifServerRecordUnchanged`. `LaneExpect` maps onto it: `.absent` saves a new record; `.tag(t)` saves on the system fields of the server copy whose `recordChangeTag` is `t` (cached from earlier reads, else fetched; a different tag is a conflict carrying the server copy); `.any` saves on whatever the server holds right now and retries once if another device got in between. `serverRecordChanged` → `.conflict(current:)`, `unknownItem` → `.conflict(nil)`, `quotaExceeded` → `.rejected(.quota)`, `limitExceeded` halves the request (down to one record, then `.tooLarge`). Writes go in chunks of 100 records / 1.5 MB. `requestRateLimited`, `zoneBusy` and `serviceUnavailable` are retried up to 4 times, honouring `retryAfterSeconds`. Tags are CloudKit's change tags; `order` is the modification time in ms.
- `commit` is `modifyRecords(… atomically: true)` in the zone, capped at 350 records (`capabilities.atomicBatch`; the ceiling reported for one request is 400, undocumented). Larger boxes need the staged rotation (L4).
- `subscribe()` saves one `CKDatabaseSubscription` (`bisel-private-db`, `shouldSendContentAvailable`). `CloudKitLane.handleRemoteNotification(_:)` turns a push into `.maybeChanged` on every lane's `changes()` stream, and so does `CKAccountChanged`. The push only means "fetch now"; the 60 s poll in `VaultService` stays the floor.
- `identity()` = SHA-256 of the container id and the iCloud user record name. Every call first checks `accountStatus()` (cached, dropped on `CKAccountChanged`): not `.available` throws `LaneError.accountUnavailable(reason)`, and a `pinnedIdentity` that no longer matches throws `LaneError.accountChanged`. The engine does not yet turn these into lane states (L4).
- `erase` deletes the zone.

**The contract on CloudKit (opt-in, never CI).** The contract flows moved from `LaneContractTests.swift` into a library target, `BiselLaneContract` (dev/test only, compiled only with the `SoftwareKeys` trait), together with `Device`, `RecordingGate` and `login` from the old `Tests/BiselFlowTests/Support.swift` (deleted). `LaneContractTests` is now a thin Swift Testing wrapper: `LaneContract.flows` × `[fake, server]` and `LaneContract.hostile` on the fake (15 cases, as before). Checks are `Checks.expect` / `require` instead of `#expect` / `#require`, so the same flows also run outside Swift Testing; failures carry file and line. `Rig` takes any `StorageUnderTest` (a lane, how the store loses a record, how it is torn down) instead of hard-coding `FakeLane`.

The signed runner is `apps/mac/Bisel/App/LaneContractRun.swift`. It compiles only under `BISEL_LANE_CONTRACT`, which only `apps/mac/project.contract.yml` defines. That spec is `project.yml` (signed, iCloud entitlement) plus the `SoftwareKeys` trait plus the `BiselCloudKit` and `BiselLaneContract` products, and generates `BiselLaneContract.xcodeproj`; never archive from it. With `BISEL_DEV_LANE_CONTRACT=cloudkit`, `BiselApp.init` hands the process to the runner before any scene, `AppModel` or `VaultService` exists. The real box, its data directory and keychain items are never opened: every device is a throwaway store with software keys in a temp directory, and the script also sets `BISEL_DATA_DIR` to a scratch directory. The runner logs to stdout, a log file and the unified log (category `lane-contract`), and deletes every `bisel-l3-spike-*` zone at the end. The `BISEL_DEV_` prefix means `scripts/check-release-hooks.sh` would catch the hook if it ever reached Release.

```sh
apps/mac/Tools/run-cloudkit-contract.sh [scratch dir]                     # generate, build signed Debug, run once, print the log
BISEL_DEV_LANE_CONTRACT_ONLY=conflict apps/mac/Tools/run-cloudkit-contract.sh   # only flows whose name contains "conflict"
```

**Evidence (this Mac, Development environment, iCloud signed in).** Two launches of the signed Debug app (Apple Development, profile "Mac Team Provisioning Profile: app.bisel.mac", entitlements `icloud-container-identifiers = [iCloud.app.bisel]`, `icloud-services = [CloudKit]`), each about 135 s:

- Run 1: account `available`; the lane identity (a hash of the iCloud user record) resolved; subscription saved. The lane probe passed 13/13: new zone fetches empty; create returns a change tag; `absent` over an existing record is a conflict with the server copy; a write on the expected tag moves it on; a stale tag is a conflict; a second lane instance holding a stale cached tag is refused by CloudKit itself (`serverRecordChanged`); an atomic commit with one refused record saves none (the culprit gets `serverRecordChanged`, the rest `batchRequestFailed`); a fetch from the start returns the newest revision once; a fetch from the returned token sees nothing; a hard delete comes back as `removed`; `resultsLimit: 2` pages through 5 records in 3 pages; a deleted zone fetches as `storeMissing`. Flows 1, 2, 4 and 5 passed (converge, conflict copy, rotation + revoke with the atomic commit, recovery from the phrase). Two failures, both fixed:
  - Flow 3 (lost record): CloudKit reports the hard delete **even to a fetch from nil**, so the audit saw `.removed`, not `.lost`. The repair itself worked. The contract now accepts either incident naming the lost id (`Rig.noticeAndHeal`).
  - Flow 6 (pending queue after migration): with the acknowledgement gone, the engine expected the tag `"<baseRev>.0"`. That works on the fake (whose tags are `"<rev>.<order>"`) and is never right for CloudKit's opaque tags, so the edit came back as a "(conflict)" copy. **Engine fix in `LaneEngine.push`**: when a write conflicts and the lane still holds exactly the revision the edit was made on, it is written again on that record's real tag. Nobody else's edit landed in between, since revisions only move up. This matters beyond the migration: any lost ack on CloudKit made spurious conflict copies.
- Run 2 (after the fixes): probe 13/13, flows 1–6 all PASS (16.4, 15.6, 22.9, 26.0, 16.6, 14.3 s), `RESULT: ALL PASSED`, exit 0. The zone sweep left only `_defaultZone` in the private database. Logs: the shared notes folder, `cloudkit-l3-run1.log`, `cloudkit-l3-run2.log`.
- No window and no window capture: the run has no UI by design (it takes over before any scene).
- `swift test --traits SoftwareKeys`: the contract suite passes on fake and server after the move and the engine fix (12 + 3 cases).

**CloudKit behaviour and limits seen**

- Latency is 0.2–1 s per call; zone create plus subscription about 1–3 s on first use. A two-device flow is 15–25 s, so the full contract is about 2 minutes. No rate limiting, quota or `limitExceeded` was hit at this scale; those paths are written but not exercised.
- Deletions are reported from a nil token too. The verifier treats them as incidents, as designed, and the replica re-uploads.
- Change tags are short opaque strings (`"6"`) that cannot be derived from anything Bisel holds; hence the engine fix.
- The subscription saves **without** the push entitlement. Receiving pushes does not: `registerForRemoteNotifications` failed with `Application not properly entitled for push notifications` (OSStatus 13), and 0 pushes arrived in either run. Adding `com.apple.developer.aps-environment` (`development`) and building with `-allowProvisioningUpdates` failed with `No Accounts: Add a new account in Accounts settings` and `Provisioning profile … doesn't include the Push Notifications capability`: Xcode on this Mac is not signed in to the developer account any more, so it cannot add Push to the App ID or regenerate the profile. The entitlement was taken back out; nothing about push is committed. Whether CloudKit pushes a change to the device that made it is still unverified.
- The subscription `bisel-private-db` stays in the Development private database (it is the id the lane will use, and saving it again is idempotent). The test zones are gone.

**D3, raw `CKDatabase` vs `CKSyncEngine`: decided, raw.** Evidence from the spike:

1. Verify before the token advances. With raw calls the token is just a value in `LaneChanges` and the engine stores it after the verifier accepts the page; that is how all six flows ran. `CKSyncEngine` fetches, advances its own state and hands it back in `stateUpdate` events. We could keep an older serialization, but the running engine has already moved on, and the hostile cases (forged delete, lost record, quarantine) need a refused page to be re-read.
2. Compare-and-set is `LaneExpect`. The probe shows `.ifServerRecordUnchanged` on cached system fields gives exactly `absent` / `tag` / `conflict(current)`, including a race between two lane instances. `CKSyncEngine` owns the pending-change queue and its own conflict loop, which would duplicate `LocalStore`'s pending state and the hub's conflict rule (§1).
3. Rotation needs one atomic save with a known record set. `atomically: true` in one zone worked (probe, and flow 4's rotation commit); `CKSyncEngine` chooses its own batches.
4. What raw costs: the lane is about 450 lines including retry, chunking and the subscription, all exercised above except the error branches CloudKit never returned. What `CKSyncEngine` would add for free (scheduling, push and account events) is small here: the app already schedules sync and the subscription is 10 lines.

**What L4 still had to do** (done unless §16 says otherwise)

- Engine: turn `LaneError.accountUnavailable` / `.accountChanged` / `.storeMissing` and `LaneChanges.reset` into lane states (paused, re-seed) instead of a failed sync. Pin `identity()` in `lane_state` when the lane is enabled. Staged rotation for boxes over 350 records. Enrollment over `enroll.*` / `env.*` with the pairing proof. Two lanes at once (the per-lane revision question in §14). The `setHash` withholding check.
- App: a lane factory in the signed build (`#if canImport(BiselCloudKit)` or a build flag, never in BiselDev), `subscribe()` on enable, push registration and `CloudKitLane.handleRemoteNotification` in `AppDelegate`, `changes()` triggering a sync, enable/detach (§9). The settings UI is L5 and is Rodrigo's.
- `Tools/check-release.sh`: assert the container id in a signed Release (noted in §3, still open).

**What needs Rodrigo (portal and account steps, nothing here can do them)**

1. **Xcode account.** Xcode → Settings → Accounts: sign in to the team ZVGTVNUPVA account again (the build reported "No Accounts"). Needed for any profile change.
2. **Push.** After (1), add `com.apple.developer.aps-environment` = `development` to the contract build's entitlements (and to `Bisel.entitlements` when L4 wires the lane), then build once with `-allowProvisioningUpdates`. Xcode enables Push Notifications on App ID `app.bisel.mac` and regenerates the development profile. Then re-run the contract and check `push: N remote notification(s) received`. Delivery to the writing device is unverified; a second device on the same Apple ID settles it. A Developer ID build needs the push capability in its Developer ID profile too, and `aps-environment` = `production`.
3. **Production schema.** CloudKit Console → `iCloud.app.bisel` → Development: record type `R` now exists with `k` (String), `rev` (Int64), `ep` (Int64), `w` (String), `sig` (Bytes), `d` (Bytes). Check it, then **Deploy Schema Changes to Production**. No indexes are needed (zone-change fetches only, no queries). Fields cannot be removed from Production afterwards.
4. **Developer ID** certificate and provisioning profile with iCloud (and push): unchanged from the entitlement spike in §3.

## 16. What L4 built: CloudKit as the default lane (2026-10-31)

Code in `apps/mac/Packages/BiselCore` (`BiselSync/RecordBox.swift`, `BiselSync/LaneEngine.swift`, `BiselCore/Vault.swift`,
`BiselCrypto/PairingSecret.swift`, `BiselLane/Control.swift`) and the app (`Bisel/Core/CloudBox.swift`, `VaultService`). The API
note for the UI, with every state and error the UI must show, is `apps/mac/Packages/BiselCore/LANES.md`.

**Staged rotation (§5).** `RecordBox.rotate` no longer needs an atomic commit as large as the box. Records of kind `stage`:
the journal `stage` (from, to, nonce, rotator, new admin key, start time, chunk count; signed by the admin key of `from`) and chunks
`stage.<to>.<n>` (the new 60-byte wraps and tombstone markers, about 128 KiB each, signed by the new admin key). Order: journal by
compare-and-set (a concurrent rotator loses it: `RotationError.inProgress`) → chunks and the new epoch's envelopes → every one read
back (a lane that drops writes silently never gets a commit: `RotationError.laneDroppedWrites`) → the items re-checked against the
snapshot → **one atomic commit of three records** (head, recovery, the `rotate` log entry) → the head read back → the fold (each
item rewritten with its staged wrap, compare-and-set on its tag) → journal and chunks removed. Until the commit every item still
opens under the old key; after it, `RecordBox.finishRotation` lets any unlocked device holding the new key finish the fold
(`Vault.sync` calls it; `SyncReport.folded`, `.rotationPending`, `RotationReport.incomplete`). While a fresh journal (under 15 min) is
open, other devices' item writes get `LaneRejection.rotationInProgress` and stay pending; `admit`, `rotateRecovery` and
`recoveryRegister` throw `.inProgress`. A stale journal is taken over or cleaned up. N-epoch envelopes are kept (removing them
would read as an incident, and they give a revoked device nothing it did not have). Limit kept from §14: an edit by a device that
read the head before the journal existed can still land between the re-check and the commit; it is quarantined as a stale-epoch write.

**Enrollment over the lane (§4, D6: QR / 8 words now, no PAKE).** `PairingSecret`: 88 random bits, 8 BIP-39 words or the QR
`bisel-pair:1:<device>:<secret>`; key = HKDF-SHA256(secret, "bisel/v1/enroll"). The new device writes `enroll.<device>` (its public
keys, `createdAt`, proof = HMAC over device id, both keys and `createdAt`; signed with its own DK-sig). The approver's engine keeps
self-signed requests it sees (newest 8, with this device's receive time; expiry 15 min on the approver's clock), the person types the
words, the proof must hold for exactly those keys (`EnrollmentError.pairingMismatch` otherwise: wrong words or swapped keys), then the
usual admit (envelope + log), and `enroll.<device>.approved` (AK-signed HMAC over the sha256 of the envelope it sealed, the chain's root
admin key and the epoch). The new device takes its envelope only with a valid approval it can check with its own copy of the secret
(`.notApprovedYet` / `.approvalUnproven`), deletes both records, then the 40-bit verification code is compared as before. The
pairing MAC runs both ways, so an attacker with write access to the zone can neither get a swapped key approved nor hand the new device
an envelope of their own.

**Accounts and deleted storage (§6).** `LaneEngine` pins `identity()` in `lane_state.identity` on the first sync and refuses storage
that now belongs to someone else (`LaneError.accountChanged`) before anything is pushed or read into the replica. The outcome of the
last sync is kept in `lane_state.state` and read by `Vault.laneStatus()`: `.accountUnavailable(reason)` (signed out, edits pending,
resumes by itself), `.accountChanged`, `.storeMissing`, `.moved(to:)`. Writes no longer create the CloudKit zone (`SyncLane.prepare`,
called only when a box is created or put back), so a zone the person deleted stays deleted until they choose to upload again, and a
deleted zone reads as `storeMissing` from fetch, read and write alike.

**Moves (§9).** `Vault.enableLane(_:phrase:)` is the one way a box gets onto storage that does not hold it: from the server or "this
Mac only" (a migration), back onto the same address after `.storeMissing`, or onto the account now signed in after `.accountChanged`.
It syncs the old lane first (pending edits must be up: `MigrationError.pendingChanges`), writes the control records at the box's
current epoch (`RecordBox.adopt`: recovery, an envelope for every approved device that was not revoked, a fresh log, the head last),
uploads the replica and reads the lane back in full (`.incomplete` and nothing switched if a record is missing), then switches. The
admin-key chain must be vouched for by the recovery key: a chain this device verified on a storage lane with an anchor it verified
(kept in `LocalIdentity.recoveryAnchor`) carries over; otherwise the 24 words sign a new chain rooted at the current admin key
(`.phraseRequired`, `.wrongPhrase`). Storage holding another box is refused (`LaneError.occupied`); storage already holding this box is
joined. The sealed manifest carries `lane` and `laneGeneration`; a move writes it to the old lane before switching, and every other
device follows on its next unlocked sync once it can reach the new lane (checked: the head there ends in the admin key of the key it
holds, `MigrationError.notInvited` otherwise). Edits it made on the old lane in the meantime go up with its replica (higher revisions
win; a different payload at the same revision lands in the trash, never silently lost). The old lane is detached, not erased.
`Vault.detachLane()` makes a box "this Mac only" again; iCloud → server is detach plus `connectServer`. After `enableLane` re-seeds a
store, other devices may see a rolled-back position once: the existing `acknowledgeServerReset` heal applies. An engine fix belongs
here: a pending edit whose record the lane does not hold at all is written as it is on lanes that repair, instead of being re-sealed
at revision 1 where every device holding a newer revision would ignore it.

**The app (CloudKit first).** Under `BISEL_CLOUDKIT` (set in `project.yml` for the signed Bisel target, absent from BiselDev and the
contract spec): `CloudBox` maps `cloudkit://iCloud.app.bisel/box-<id>` addresses to one cached `CloudKitLane` per zone (the change tags
survive between syncs) and is the vault's `laneProvider`; "Create a box" (`VaultService.createBox`) creates the box in iCloud when an
account is signed in and on this Mac only otherwise; "I already have one" tries the boxes in this iCloud account before the server;
`moveToICloud`, `putBoxInICloudAgain`, `stopSyncing`, `startICloudEnrollment` / `finishICloudEnrollment` / `pendingEnrollments` /
`approve` are the logic behind Rodrigo's screens (none was changed; the one call site that moved is `SetupView.create`). `AppDelegate`
registers for remote notifications and hands them to `CloudKitLane.handleRemoteNotification`; every push and account change triggers a
sync. The server lane works as before and is opt-in (`connectServer`). D4: the backup reminder integration point is marked in
`VaultService.performSync` for when the `.bisel-backup` work lands. Storage lanes keep local history (`keepsLocalHistory`), as a box
without a server always did.

**Contract.** `LaneContract.storageOnly` (eight flows, on `FakeLane` in the flow tests and on CloudKit in the signed run; never the
server, which keeps these on its side): rotation through a loud failure while staging; a lane that silently drops staged records;
a fold cut off after the commit and finished by another device; enrollment with the 8 words; swapped keys, wrong words and forged
approvals; sign-out and another account (paused, never uploaded to, moved without loss, the second device joins, the phrase recovers);
a deleted store (noticed, not recreated, put back, the other device's outage edit kept); a move from the server (the flow tests start
the real server; the signed run moves from a second zone instead) with the other device following and its late edit kept. Test
support: `FlakyLane` (fails or silently drops writes after a budget) and `AccountLane` (signed out / another account, over any
storage) wrap every rig's storage; `FakeLane.erase` models a deleted zone.

**Not done in L4**

- Two lanes at once with independent revisions (§14): a move switches the box, it does not run both. Devices on another Apple ID
  cannot follow a move to iCloud (`.moved(to:)`); they keep the old lane.
- The `setHash` withholding check (§8). Production schema deployment and Developer ID (Rodrigo, §15). Push delivery (needs the
  `aps-environment` entitlement, §15).
- An account change on one Mac splits that Mac from the others until they move too; the UI must say so (LANES.md).
- Recovery hold-back stays advisory (D7). Stage records and enrollment records are visible metadata to Apple, like the rest (§7).
