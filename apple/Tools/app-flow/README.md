# app-flow: end-to-end flows of the real Mac app against the real local server

Not unit tests. `flow.sh` launches the **real Debug app** (software keys, throwaway data dirs, Touch ID bypassed with the
Debug-only `BISEL_DEV_SKIP_BIOMETRIC`) against a **real `wrangler dev` + local D1** and runs `DebugFlow` (Bisel/App/DebugFlow.swift,
compiled only in Debug) inside it: bootstrap → items → panel search/secret/copy → lock/unlock → screen-lock notification →
1pux/CSV import → backup export → recovery on a fresh store → conflict → offline → revoke → restore backup onto a fresh server.

    BISEL_FLOW_DIR=/tmp/bisel-flow apple/Tools/app-flow/setup.sh   # builds tools, fixtures (generated, FAKE data) and the app
    BISEL_FLOW_DIR=/tmp/bisel-flow /tmp/bisel-flow/flow.sh          # prints PASS/FAIL per phase; logs in $BISEL_FLOW_DIR/flow-N-*.log

Uses port 8790 and its own D1 state dir (never `pnpm dev` on 8787). `axdrive.swift` drives ONE pid's windows through the
accessibility API (needs the screen unlocked and the Accessibility permission of your terminal/host); `postnote.swift` posts
the distributed notifications (`com.apple.screenIsLocked`, `app.bisel.dev.snapshot`).

XCUITest (`Bisel/UITests`, `xcodebuild test -scheme Bisel`) needs macOS Automation Mode, which asks for admin authentication once.
