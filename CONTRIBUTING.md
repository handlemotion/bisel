# Contributing

Thanks for wanting to help. Bisel is alpha and maintained by one person, so open an issue before a large change, and keep pull requests small and about one thing. Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

Read [AGENTS.md](AGENTS.md) first: it has the repo rules for people and coding agents alike. The design lives in [docs/SPEC.md](docs/SPEC.md); a change that deviates from it updates the spec in the same pull request.

## Setup

See [Building it](README.md#building-it). Nothing in development touches Cloudflare or a real iCloud account: the server runs as a local `wrangler dev` with a local D1, and the Swift flow tests use software keys.

## Tests: few, and only ones that matter

- Write a test only when it proves a flow that must not break: crypto and key handling, sync and conflicts, recovery, authentication, data loss, security boundaries, migrations. Name it after the failure it prevents, and prefer extending an existing flow test over adding a file.
- No unit tests of trivial functions, no tests that restate the implementation, no tests of copy, layout or styling, no snapshot or "it renders" tests, no coverage chasing. Pull requests that add them will be asked to drop them.
- TypeScript uses Vitest (`pnpm test`); Swift uses Swift Testing (`swift test --traits SoftwareKeys` in `apps/mac/Packages/BiselCore`).
- Also run the real thing: build the app, launch it once and look at it.
- **No UI automation.** No XCUITest runs, no `xcodebuild` UI tests, no scripted clicking through System Events or the accessibility tree, no launch loops.

## How CI gates a change

Every pull request runs [.github/workflows/ci.yml](.github/workflows/ci.yml), which calls `scripts/check-all.sh` in four jobs: Server (format, lint, types, server flow tests on a local D1), Core (the Swift flow tests), App (an unsigned BiselDev build) and Release (no debug hooks in the shipped binary). CodeQL scans the workflows, TypeScript and Swift. A pull request merges only when every check is green, squashed into one commit. Run the same checks locally before pushing:

```bash
pnpm check && pnpm check-types && pnpm test
pnpm ci:local   # all four CI modes of scripts/check-all.sh, including the Swift flow suite and the Mac app build
```

## Style

- Format and lint come from `pnpm check` (a pre-commit hook runs them on staged files). Swift formatting is advisory for now: `xcrun swift-format lint --configuration apps/mac/.swift-format`.
- "Box" in anything a user reads; "vault" stays in code, the wire format and the spec.
- The app's UI (SwiftUI views, layout, copy, colors, animation) is the maintainer's design. Open an issue before changing it.
- Use the generators and CLIs that produce boilerplate (`xcodegen`, `pnpm add`, `wrangler types`) instead of writing it by hand.
- Small commits with plain messages.
