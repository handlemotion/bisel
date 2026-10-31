# Bisel

Bisel is a password manager for the Mac that I built for myself. It opens from a command panel (⌘⇧Space), unlocks with Touch ID and keeps every item encrypted on the device, so wherever your box syncs to only ever sees ciphertext. It's open source and pretty early, alpha is the honest word for it.

## Mac first, iCloud first

It started as a Mac app plus my own sync server on Cloudflare, and that server still works. At some point it made more sense to sync through the iCloud account people already have, with no server of mine in the middle, so the default path is a CloudKit lane in your private iCloud database. That lane is being built right now, the design and where it's at are in [docs/SYNC-LANES.md](docs/SYNC-LANES.md). The server stays in the repo as an optional lane and its tests keep running in CI, but I'm not developing it further for now ([apps/server](apps/server/README.md)).

## Zero-knowledge, briefly

Every item gets its own random key, wrapped by a box key that never leaves your devices in the clear, all AES-256-GCM through Apple CryptoKit. Each Mac keeps its device keys in the Secure Enclave and the one that opens the box key needs Touch ID, so there's no master password to type every day. If you lose every device, the 24-word recovery phrase you get at setup brings the box back, and nothing else can. Whatever stores the box, CloudKit or the server, gets ciphertext, public keys and sealed envelopes, and the app verifies everything it gets back whichever lane delivered it. The full design is in [docs/SPEC.md](docs/SPEC.md) and the last review in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md).

## Where it is now

The flows that can't break (crypto and keys, sync and conflicts, recovery) have tests that run in CI on every change. Formats can still change though, and there's no signed build to download yet, so keep your current password manager around for now. It's Mac only and needs macOS 26. Safari and system AutoFill and an iPhone app are planned, the milestones are in the spec.

## Building it

You need Xcode with the macOS 26 SDK, [XcodeGen](https://github.com/yonaskolb/XcodeGen), Node 24 and pnpm.

```bash
brew install xcodegen
pnpm install
cd apps/mac && xcodegen generate --spec project.dev.yml && open BiselDev.xcodeproj
```

`project.dev.yml` builds an unsigned Debug app with software keys, so it runs without an Apple developer account. Never ship from it. The real app comes from `project.yml` (Secure Enclave, iCloud), which needs your own signing team, bundle id and iCloud container in place of mine.

Checks:

```bash
pnpm check && pnpm check-types && pnpm test
cd apps/mac/Packages/BiselCore && swift test --traits SoftwareKeys
pnpm ci:local
```

`pnpm test` runs the server's flow tests against a real Worker on a local D1, and the Swift flow tests start their own local server too, nothing touches Cloudflare. `pnpm ci:local` runs what CI runs, the Mac app build included.

## The repo

- `apps/mac`: the Mac app, its core library `BiselCore` (crypto, box format, local store, sync, recovery) and dev tools.
- `apps/server`: the optional, deferred sync server (Cloudflare Worker + D1) and its dashboard.
- `docs`: the spec, the sync lanes design and the security review.

How to contribute is in [CONTRIBUTING.md](CONTRIBUTING.md), and how to report a vulnerability in [SECURITY.md](SECURITY.md). Rules for people and agents working in the repo are in [AGENTS.md](AGENTS.md).

Bisel is licensed under the [GNU Affero General Public License v3.0](LICENSE), so if you run a modified version for other people, including as a service, you share your changes under the same license.
