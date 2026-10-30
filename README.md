# Bisel

A personal, self-hosted, zero-knowledge password manager. The Mac app opens from a command panel (⌘⇧Space), unlocks with Touch ID and keeps everything encrypted on the device; the server only ever holds ciphertext.

- `apps/server`: the sync server (Cloudflare Worker + D1) and the dashboard.
- `apps/mac`: the Mac app and its core library.
- `docs/SPEC.md`: the design. `apps/server/DEPLOY.md`: the production runbook.

```bash
pnpm install
pnpm check         # format + lint
pnpm check-types
pnpm test          # server flow tests (real Worker, local D1)
scripts/check-all.sh   # everything, including the Swift core and the app build
```

Rules for people and agents are in [AGENTS.md](AGENTS.md).
