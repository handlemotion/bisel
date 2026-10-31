# Sync lanes: design and feasibility (CloudKit lane)

Status: design only, nothing here is built. Companion to `SPEC.md` (§4 crypto, §6 server, §7 BiselCore). When a milestone below lands, move the settled parts into `SPEC.md` in the same change.

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

**Container and environment.** Private database only. Container `iCloud.app.bisel.mac` as briefed. See open decision D1: if the iPhone app (M5) will share the box, the container should be shared across bundle ids, e.g. `iCloud.app.bisel`; container ids cannot be renamed. Development builds use the Development environment; a notarized Developer ID build uses **Production**, which needs the record type/fields deployed from the CloudKit Console first (**verify** exact promotion steps). A box written by a dev build is not visible to the shipped app.

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

**CKSyncEngine vs raw operations** (open decision D3). `CKSyncEngine` (macOS 14+) handles batching, retry, tokens, subscription. Raw `CKDatabase` async calls give us control to verify each fetched record **before** the token advances and to run the rotation commit. Recommendation: raw calls behind `CloudKitLane` for v1 (the engine already owns pending state, so CKSyncEngine's pending-change tracking would duplicate it); revisit after the milestone 3 spike.

**Account and availability.** `CKContainer.accountStatus()`; observe `CKAccountChanged`. The lane pins `identity()` = hash of `userRecordID` at enable time. Any mismatch pauses the lane (§6).

### Entitlement spike (done, 2026-10-30)

Added to `apps/mac/project.yml` under the `Bisel` target `entitlements.properties` (diff kept in the shared notes folder, not committed):

```yaml
properties:
  com.apple.developer.icloud-container-identifiers: [iCloud.app.bisel.mac]
  com.apple.developer.icloud-services: [CloudKit]
```

Observed:

1. `xcodegen generate` writes both keys into `Bisel/Bisel.entitlements`. Feasible as configured; no other spec change needed.
2. `xcodebuild … build` with the existing signing (Automatic, Apple Development, team ZVGTVNUPVA) **fails**: `No profiles for 'app.bisel.mac' were found … Automatic signing is disabled`. iCloud/CloudKit is a restricted entitlement, so the target needs a provisioning profile that contains it. Overriding to ad-hoc (`CODE_SIGN_IDENTITY=-`, manual) fails too (`"Bisel" requires a provisioning profile`).
3. `CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO` builds (`BUILD SUCCEEDED`); signing that product ad-hoc by hand with the entitlements file and running `codesign -d --entitlements -` shows exactly the two keys. So the entitlement plumbing is correct; only the profile is missing.
4. Not done on purpose: `xcodebuild -allowProvisioningUpdates`. It would create the App ID capability and the `iCloud.app.bisel.mac` container in the Apple Developer account for team ZVGTVNUPVA, which is an outward-facing change that is hard to undo (containers cannot be deleted). Needs Rodrigo's go (D1 first). Nothing was launched.

Consequences to plan for:

- Committing the entitlement breaks every build until the container exists and a profile is available. Land it together with the portal registration, not before.
- `project.dev.yml` includes `project.yml`, so `BiselDev` (software keys, unsigned runs) inherits the entitlement and cannot run unsigned any more. Use a separate entitlements file for the dev spec (without iCloud) and compile `CloudKitLane` out of it (`#if` or a dev-only lane factory), keeping the existing rule that dev flows never touch real CloudKit.
- Release needs a **Developer ID** provisioning profile with the iCloud container (and, for push, the aps entitlement), the production environment, and the existing `get-task-allow` gate must still pass. `scripts/check-release-hooks.sh` and `Tools/check-release.sh` should additionally assert the container id is present in Release.
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
| L4  | `CloudKitLane` complete: staged rotation, enrollment over `enroll`/`env` records, account-change and zone-reset paths, migration enable/detach. Dev spec without iCloud + `#if`. Production schema deployment.                                                                                                       | Contract suite runs against `CloudKitLane` only behind an opt-in env flag on the signed build (like `test:browser`).                                                                                                                                                                                                                                                                                                         |
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

1. **Entitlement/profile friction** (spike): breaks every signed build until the container is registered; dev build must be split; Developer ID profile + production schema needed. Containers are permanent in the portal.
2. **Rotation without atomicity** (staged commit) is the most complex new protocol; needs the hostile-fake tests before any real data.
3. **Fresh-device freshness** is not solvable against a malicious store; witness options reduce, not remove.
4. **Per-lane pending state** is an invasive schema/engine change touching the sync core; must land with migration of existing queues.
5. **Revocation weaker on CloudKit** for same-Apple-ID devices (cryptographic only); UI must say so.
6. **CloudKit behaviours not verifiable headless** (ADP, account switch, push delivery, quota, production schema). Treated as manual checks.
7. **Apple-side metadata** (counts, sizes, times) is visible to Apple and to anyone with the account.
8. **CloudKit-only boxes can lose data** when the Apple ID is lost and no device or backup remains; the phrase does not help. Product mitigations needed.

## 13. Open decisions for Rodrigo

- **D1. Container id and registration.** `iCloud.app.bisel.mac` as briefed vs a shared `iCloud.app.bisel` for the future iPhone app. Permanent. Do you want me to run `xcodebuild -allowProvisioningUpdates` for team ZVGTVNUPVA to register it?
- **D2. Same Apple ID only?** The CloudKit lane serves devices on one Apple ID. Anything outside it (a second person, a device on another account) stays on the server lane. Confirm that is acceptable.
- **D3. Raw CloudKit operations vs CKSyncEngine** for v1 (recommendation: raw, revisit after L3).
- **D4. Second copy for CloudKit-only boxes**: forced reminder to export `.bisel-backup`, or require the server lane, or accept the risk.
- **D5. Freshness witness**: iCloud KVS only, optional server head, or accept the fresh-device limit.
- **D6. PAKE**: ship QR/8-word pairing now; add SPAKE2 only if a vetted Swift implementation is found. OK?
- **D7. Recovery hold-back** is advisory on CloudKit. Acceptable, or should phrase recovery on a CloudKit-only box require a second enrolled device's approval?
- **D8. Lane UI** (L5) needs your design: where lane state, rotation incompleteness and rollback alarms appear.
