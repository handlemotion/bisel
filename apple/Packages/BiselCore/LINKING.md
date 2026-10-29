# Linking this Mac to a bisel account (browser sign-in)

`AccountLinker` (Sources/BiselCore/AccountLinker.swift) is the whole flow as one state machine. The UI owns no logic: it shows
the current `state`, opens a URL, and calls `start`, `cancel`, `retry`, `reset`.

```swift
let linker = AccountLinker(vault: vault)               // the server is fixed: AccountLinker.defaultServer (box.bisel.app)
for await state in await linker.updates() { ... }      // current state first, then every change
await linker.start(deviceName: "Ada's MacBook")        // name only used for a brand-new vault
await linker.cancel()                                  // false when it can no longer be cancelled
await linker.retry()                                   // after a retryable failure
await linker.reset()                                   // forget a finished flow
```

There is no server setting. `AccountLinker(vault:server:transport:timing:)` exists only in DEBUG / SoftwareKeys builds, for tests.

## What it does, by starting point

The mode is read from the vault, never chosen by the UI (`Pending.mode`, `Linked.mode`):

| Mode | The vault is | What happens after the person approves in the browser |
|---|---|---|
| `.newBox` | not created yet | Touch ID, then this Mac makes its keys and the vault, the server makes the box owned by the account. The result carries the **recovery phrase**. |
| `.linkLocalBox` | local-only (made with `bootstrapLocal`) | Touch ID, then the box is created from the existing vault and every local item is uploaded. |
| `.claimServerBox` | already syncing with a box nobody owns (token box, or from before accounts) | Nothing to register: the account takes ownership of that box. |

## States and what the UI shows

| State | Meaning | Show |
|---|---|---|
| `idle` | nothing started | the entry point (a "Sign in with browser" / "Link to account" action) |
| `requestingCode` | asking the server for a code (and, for a local or claimed box, unlocking: a Touch ID sheet may appear first) | a spinner; cancel is allowed |
| `waitingForApproval(Pending)` | a browser sign-in is open or about to be | `userCode` large ("does it match the page?"), a button that opens `url` (`https://box.bisel.app/connect?code=ABCD-EFGH`, built here, safe to open), a countdown to `expiresAt`, a cancel button. If `isOffline` is true show "can't reach the server, still trying": polling continues by itself with back-off and the flag clears when the server answers |
| `registering(mode)` | approved; Touch ID, then this Mac's key is registered | "Approved, finishing…"; no cancel (`cancel()` returns false) |
| `uploading(pending:)` | `.linkLocalBox` only: registered, local items going up | "Uploading N items…" |
| `linked(Linked)` | done | success. `.newBox`: show `recoveryPhrase` **once** and make the person confirm it (`vault.confirmRecovery(phrase:)`; the vault stays `recoveryUnconfirmed` until then). `.linkLocalBox`: `itemsUploaded`; if `itemsStillPending > 0` say the rest will finish uploading (normal sync carries on). `boxID` is the id to use when restoring on another Mac |
| `failed(Failure)` | see below | the reason, and "Try again" when `failure.isRetryable` or "Start over" otherwise |
| `cancelled` | the person cancelled | back to the entry point |

Never show or store the device code: it is not in any state. The recovery phrase is the only secret in a state; do not log it or keep it
after the confirmation.

## Failures

`isRetryable` failures keep the code: `retry()` continues with it (same `userCode` on screen). Any other failure needs `start` again
(a new code); `retry()` does that for you.

| Failure | Means | Retry | Suggested action |
|---|---|---|---|
| `denied` | the person cancelled on the page (for a claim also: that account already owns another box) | no | explain; nothing changed |
| `expired` | the code ran out (10 minutes) or the server does not know it | no | start over |
| `timedOut` | this app's own deadline passed with no answer | no | start over |
| `accountHasBox` | the account that approved already owns a box | no | explain: add this Mac from a connected device or with the recovery phrase. Nothing was created, Touch ID was not asked |
| `alreadyLinked` | a claim, but the box already has an account | no | explain |
| `codeRejected` | the server no longer accepts the approved code (used, or lapsed while registering) | no | start over |
| `biometryRefused` | Touch ID cancelled or failed | **yes** | "Try again" (approval is kept while the code lives); nothing was registered |
| `biometryChanged` | fingerprints changed and the device key is gone | no | enrol this Mac again |
| `network` | the server could not be reached for 6 polls in a row, or a request failed | **yes** | "Try again"; an approval made meanwhile is picked up |
| `server(status:)` | unexpected answer | **yes** | "Try again" |
| `boxMismatch` | the server named another box than this vault's; nothing was written | no | something is wrong with the server: do not continue |
| `vaultUnavailable` | the vault could not unlock or the store is unusable | no | fall back to the normal unlock errors |

## Timing, single use, security

- Polls every `Pending` interval from the server, clamped to 1 to 10 s; on errors the delay doubles up to 30 s; 6 failed polls in a row end with
  `network` (retryable). The hard deadline is the code's lifetime (at most 15 min) plus 5 s, then `timedOut`.
- `cancel()` cannot be undone on the server (the code just times out), but nothing can redeem it without this Mac's device code, which is dropped.
- The device code is single use on the server and short lived (10 min); the user code in the URL is useless without it.
- Touch ID is asked before any key is registered: `.newBox` before the device key is created, `.linkLocalBox` and `.claimServerBox` through the vault's gate (the vault is also unlocked first if it was locked).
- The linker never reads a URL from the server: it builds `…/connect?code=` from the fixed server address and the user code, and refuses a user code that is not `XXXX-XXXX`.
- Nothing is logged by the linker. The only secrets that cross it are the device code (inside the actor, never published) and the recovery phrase (redacted `description`).
- Known gap: if a `.newBox` registration succeeds on the server but the answer is lost, the retry finds the code spent (`codeRejected`) and the account then
  has an empty box the app does not know; restoring it needs the phrase, which the app never showed. Only an empty new vault is at risk.
