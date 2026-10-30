# Fill compatibility matrix (SPEC.md §8)

Status: **mostly unverified.** Almost every row is blocked by the environment, not by a known failure. Read the
"Observed" column literally: it says what was actually seen, and "unverified" means no result was observed.

How fill works: the panel remembers the frontmost app, closes, waits for modifier keys to be released, reads the
focused element through Accessibility (`AXFocusedUIElement`; role `AXSecureTextField` = password, label/identifier
matching otp/2fa/code = TOTP, else username), then types with `CGEventKeyboardSetUnicodeString` key events from a
private event source (no clipboard). If the field's `AXValue` length did not change (non-terminal text fields only), it
retypes by temporary paste (`⌘V`, concealed + current-host-only, clipboard restored). Chromium/Electron apps get
`AXManualAccessibility` / `AXEnhancedUserInterface` set once per process (only if the bundle contains an Electron or
Chromium framework).

Test conditions: debug build, ad-hoc signed. Accessibility was effective only because the test binary was launched from
a shell whose parent app (Claude desktop) already holds the Accessibility grant, so the child inherited it
(`AXIsProcessTrusted() == true`). A normal Finder/`open` launch of the same build was NOT trusted (`false`) and shows the
onboarding window. Computer-use tiers blocked key presses and typing while Safari (read tier), Terminal and Ghostty
(click tier) were frontmost, so those could not be driven. All secrets in these tests are fake dev-fixture values.

| Target | Username | Password | TOTP | Secure input | Result | Caveat |
|---|---|---|---|---|---|---|
| TextEdit (AppKit, plain text) | unverified | unverified | unverified | n/a | unverified | The only run opened TextEdit on its Open dialog, so there was no document field to fill. |
| Safari login form | unverified | unverified | unverified | unverified | unverified | Safari is "read" tier for the automation: hotkey and typing blocked while it is frontmost. Expected: WebKit exposes `AXSecureTextField` for `type=password`. |
| Chrome-family browser | unverified | unverified | unverified | unverified | unverified | None installed on this Mac. |
| Firefox | unverified | unverified | unverified | unverified | unverified | Not installed. |
| Terminal.app | unverified | unverified | n/a | unverified | unverified | "click" tier: keys blocked. Design: no AX text field, so Enter-style inference falls back to username; use ⌘K → Fill password at a password prompt. |
| Ghostty | unverified | unverified | n/a | unverified | unverified | Same. Possible issue: the app may map synthesized events by keycode, ignoring the Unicode string; paste fallback exists but is not verified there. |
| System Settings password field | unverified | unverified | n/a | unverified | unverified | Not attempted (would need a Wi-Fi/password sheet). |
| Slack | unverified | unverified | unverified | unverified | unverified | Not installed. |
| Discord (Electron) | unverified | unverified | unverified | unverified | unverified | Installed, not driven. |
| Claude desktop (Electron, incidental) | username: engine path ran | not run | not run | `IsSecureEventInputEnabled()` false | partial | Twice, with the panel opened by a scripted run, the focused element was classified `role=AXTextArea, text=true, kind=username`, Chromium AX enabling returned `AXManualAccessibility` success (`AXEnhancedUserInterface` unsupported, error -25208), and the log said "Filled username (keyEvents)". The text appearing in the composer was **not** inspected, and this was an unintended target (fake username, not sent). |
| Native SwiftUI app (`BiselFillHarness`) | unverified | unverified | unverified | n/a | unverified | Built (separate target), never frontmost: it is not grantable to the automation. |

## What the user must click to unblock verification

1. **Accessibility for the real build.** System Settings → Privacy & Security → Accessibility → turn on **Bisel**
   (click "Open Accessibility Settings" in the onboarding window; "Add Bisel to the list" if it is missing; `+` and pick
   `Bisel.app`). Ad-hoc signing ties the grant to this exact build, so after every rebuild remove Bisel with `−` and add it
   again. Bisel never toggles this itself.
2. Then try ⌥↩ (fill) and ⌘⌥↩ (user, Tab, password) on: a Safari login form, a Chromium/Electron app
   (Discord/Slack login), Terminal and Ghostty at a password prompt (use ⌘K → Fill password), a System Settings password
   sheet, and the SwiftUI harness. Record method (key events or paste) and any miss here.
3. Secure Keyboard Entry (Terminal → Secure Keyboard Entry) is respected: bisel only logs `IsSecureEventInputEnabled()`,
   it does not try to bypass it.
