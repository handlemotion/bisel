<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": true` in the root `turbo.json` or `turbo.jsonc` to opt in; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->

# Bisel agent rules

Bisel is a personal, self-hosted, zero-knowledge password manager. pnpm + Turborepo monorepo:

- `apps/server`: Cloudflare Worker (Hono, D1, Better Auth passkeys) at `box.bisel.app`, with the dashboard in `apps/server/web` and its assets in `apps/server/public`.
- `apps/mac`: the Swift Mac app (XcodeGen: `project.yml`, `project.dev.yml`), the core in `apps/mac/Packages/BiselCore`, tools in `apps/mac/Tools`.
- `docs/`: `SPEC.md` is the source of truth for the design; `SECURITY-REVIEW.md`; `design/`.

Repo-wide rules only. App-level docs: `apps/server/README.md` and `DEPLOY.md` (the production runbook), `apps/mac/Packages/BiselCore/README.md`. Explicit user instructions override every repository file.

## Testing (HARD RULE)

- Vitest for TypeScript. Swift flow tests with Swift Testing: `swift test --traits SoftwareKeys` in `apps/mac/Packages/BiselCore`.
- Write few tests, and only ones of very high value: a test must prove a flow that cannot be allowed to break (crypto and key handling, sync and conflicts, recovery, authentication, data loss, security boundaries, migrations).
- No low-signal tests. No unit tests of trivial functions, no tests that restate the implementation, no tests of copy, text, layout, placement or styling, no snapshot tests of UI, no coverage chasing, no "it renders" tests. If a test would not catch a real bug that matters, do not write it, and delete it when you find it.
- Name every new test after the failure it prevents. Prefer extending an existing flow test over adding a new file.
- Also verify by running the real thing: build, launch once, one window capture.
- NEVER run UI automation: no XCUITest, no `xcodebuild` UI tests, no System Events or accessibility-tree walking, no app launch loops. It crashed Claude Desktop (2026-10-30).

## Commands

- `pnpm install`, then `pnpm check` (oxfmt + oxlint), `pnpm check-types`, `pnpm test`, `pnpm build`.
- `pnpm test` runs the server vitest flows (its own `wrangler dev`, free port, local D1). Also `pnpm --filter bisel-server test:legacy` (migration test) and, opt-in, `pnpm --filter bisel-server test:browser` (the one Playwright passkey test).
- `pnpm ci:local` is CI on your Mac: `scripts/check-all.sh --server --core --app --release`, the same modes the CI jobs run. `scripts/check-all.sh` alone runs server, core and app; `scripts/check-release-hooks.sh` fails if debug hooks leak into Release.
- Swift formatting is advisory for now: `xcrun swift-format lint --configuration apps/mac/.swift-format`.

## Working rules

- The UI is Rodrigo's. Do not change SwiftUI views, layout, copy, colors or animation unless asked; logic and tests are fair game.
- Use generators and CLIs to create things (`create-turbo`, `oxlint --init`, `xcodegen`, `pnpm add`), never hand-write boilerplate that a tool produces.
- Never touch production (Cloudflare, Doppler, the prod D1) without an explicit ask each time, and never print secrets. `apps/server/DEPLOY.md` is the runbook.
- No attribution lines in commits or PR descriptions.
- Do new work in git worktrees. One build or test run at a time.
- Vocabulary: "box" in anything the user reads; "vault" stays in code, the wire format and `docs/SPEC.md`.

## Shipping

- Never push to `main`. Work on a branch, small commits, rebase on `origin/main`, push the branch, open a PR (`gh pr create`).
- Wait for every CI check on the PR to pass (`gh pr checks --watch`), then squash-merge (`gh pr merge --squash --delete-branch`). A red or pending check is never merged; fix it on the branch.
- CI (`.github/workflows/ci.yml`) runs `scripts/check-all.sh` in four jobs: Server (`--server`), Core (`--core`), App (`--app`, unsigned BiselDev build), Release (`--release`); CodeQL scans actions and TypeScript on every PR, and Swift (~16 min) on every push to `main` and weekly, so it does not gate PRs. The `main` ruleset requires the six PR checks but not an up-to-date branch: green PRs merge back to back, and the post-merge CI on `main` catches a bad combination. Run `pnpm ci:local` before pushing when a change touches more than one of them.
- CI and `scripts/check-all.sh` change together: a new check goes into a check-all mode, and the job calls that mode.
- Workflows: `permissions: contents: read` at the top and only what a job needs; third-party actions pinned to a full commit SHA with the version in a comment; `pull_request` and `push` to `main` only, never `pull_request_target`; no secrets. The repo is public, so fork PRs run this code.
