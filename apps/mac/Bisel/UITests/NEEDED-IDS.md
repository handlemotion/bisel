# BiselFlowUITests: status and accessibility identifiers still needed

## Status: written, compiled, never run

`BiselFlowUITests.swift` was rewritten for the current first-run flow (welcome → recovery phrase → import step → settings window)
and it **compiles** (`scripts/check-all.sh --app` runs `build-for-testing`). It is **never run**: UI automation is forbidden in this
repo (AGENTS.md; the first attempt dimmed Rodrigo's screen and crashed Claude Desktop), and there is no script mode that runs it.
Nothing here is known to pass or fail. Each test would use its own throwaway `BISEL_DATA_DIR` and `BISEL_DEV_SKIP_BIOMETRIC=1`;
there is no server involved ("Create a box" makes a local-only box).

If Rodrigo ever runs it by hand, things most likely to need a fix (guesses, not results):

- `app.statusItems.firstMatch` / `menuItems["Open Bisel"]`: reaching the menu-bar extra from XCUITest is untested; the settings and
  relaunch tests depend on it.
- `phrase-save` is a SwiftUI `Menu`; the test looks for a menu button first, then a button.
- `app.buttons["nav-General"]`: sidebar rows may surface as `staticTexts`/`cells` rather than buttons; adjust the query, not the view.

## Identifiers the views do not have yet (Rodrigo adds them; no view was edited)

The tests work around each of these with a label or a proxy element and say so; an identifier makes them robust.

| Where | Element | Suggested id | The test now uses |
|-------|---------|--------------|-------------------|
| `BiselApp.swift` `MenuBarContent` | "Open Bisel" button | `menu-open-bisel` | menu item title `Open Bisel` |
| same | "Command Panel", "Sync Now", "Lock", "Quit Bisel" | `menu-command-panel`, `menu-sync`, `menu-lock`, `menu-quit` | not used yet |
| `BiselApp.swift` `MenuBarExtra` label | the status item | `menu-bar-item` | `statusItems.firstMatch` |
| `PhraseGateView` `Menu` items | Copy, Download… | the ids exist (`phrase-copy`, `phrase-download`) on the buttons inside the `Menu`, but menu items usually do not expose them | menu item titles `Copy`, `Download…` |
| `PhraseGateView` | "Copied" / "Saved as …" feedback | `phrase-save-feedback` | not asserted |
| `MainWindowView` detail pane | root of General / Devices / Import | `section-general`, `section-devices`, `section-import` | a button inside each (`settings-export`, `devices-refresh`, `import-choose`) as a proxy |
| `SettingsView` | "Keep unlocked for", "Lock after idle" pickers | `settings-fill-window`, `settings-idle-lock` | not covered |
| `SettingsView` | Box section "Sync: Not connected" line | `settings-sync-state` | not asserted |
| `DevicesView` | the "only copy of your box" empty state | `devices-empty` | not asserted |
| `OnboardingFrame` (`OnboardingCard.swift`) | the card / progress bar | `onboarding-card`, `onboarding-progress` | not asserted |
| `SetupView` recover step | the 24 cells (`setup-word-N` exist in `PhraseCells`) | already there | recover path is not covered yet (needs a server) |
