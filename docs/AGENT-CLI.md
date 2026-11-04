# Agent CLI: `bisel` and `bl`

Status: built. Touch ID and browser fill still need a check by hand (below).

**The rule: agents use secrets, they never read them.** No command prints a password, a one-time code or a secret field. Agents find items by metadata, then hand the secret to a browser field or a command without seeing it.

## Language: Swift

Nearly all the time in a request is spent waiting for Touch ID, so raw speed does not separate the options. A small Swift test binary with Foundation started in about 4.5 ms.

Swift fits best because the Security framework calls are native, the request types are shared with the app, and Xcode signs and notarizes the tool with the app. Node needs a runtime to ship. Go and Rust add a second toolchain and a bridge to the Security framework.

## How it works

```
agent -> bl -> local socket -> Bisel.app -> Touch ID -> secret goes to a page field or a child command
```

- The tool lives at `Bisel.app/Contents/Helpers/bisel`, not in `Contents/MacOS`, where `bisel` would collide with `Bisel` on a case-insensitive disk.
- `bl` and `bisel` are two symlinks to the same binary:

  ```bash
  ln -s /Applications/Bisel.app/Contents/Helpers/bisel ~/.local/bin/bisel
  ```

  ```bash
  ln -s /Applications/Bisel.app/Contents/Helpers/bisel ~/.local/bin/bl
  ```

- The tool links neither `BiselCore` nor any crypto, and holds no keys. The box key stays in the app.
- The socket is mode 0600 in a 0700 directory. Debug builds use a different path.
- Each side checks the other's signature from the kernel's audit token: team `ZVGTVNUPVA`, identifier `app.bisel.cli` for the tool and `app.bisel.mac` for the app. This is what makes the approval prompt truthful: only the real tool can receive a secret, and it runs exactly what it told the app it would run. Debug builds skip the check, and `scripts/check-release-hooks.sh` proves the skip is not in Release.
- The tool never opens the app and never unlocks the box. It reports `app_not_running` or `locked`.

## Commands

| Command                                                        | Does                                                            | Touch ID                           |
| -------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------- |
| `bl status`                                                    | App running, box unlocked, agents allowed                       | No                                 |
| `bl search <text>`                                             | Item metadata only                                              | Once, then 5 minutes               |
| `bl fill <id> [--login] [--submit]`                            | Types into the focused field of a matching page                 | Every time                         |
| `bl run --env NAME=<ref> [--stdin <ref>] -- <command>`         | Gives secrets to one command                                    | Every run, one prompt for all refs |
| `bl add --title T [--url U] [--username N] [--password-stdin]` | New item; the app generates the password unless one is piped in | Every time                         |
| `bl edit <id> [--title T] [--url U] [--username N]`            | Changes details, never the password                             | Every time                         |
| `bl trash <id>`                                                | Moves to the trash, restorable for 30 days                      | Every time                         |

- `<id>` comes from `bl search`. Titles and fuzzy names are not accepted, so the tool never guesses which secret is meant.
- `<ref>` is `<id>` for the password, or `<id>:username`, `<id>:totp`, `<id>:field:<label>`.
- `--login` types username, Tab, password. `--submit` presses Return afterwards.
- There is no `get`, `copy`, `export`, `--password` flag or permanent delete.
- There is no password rotation in v1. Changing the stored password before the site's would lock the person out, and a site's change-password form needs the old and new values together.

## Two ways to use a secret

**Sign in on a web page: `bl fill`.** The agent focuses the field and calls `bl fill`. The app types the value and the agent sees dots. This reuses `FillEngine`, with stricter rules than a person gets:

- The `.auto` and `.userTabPassword` plans only. The forced `.explicit` plan skips the site check and is never reachable from here.
- The app must be a browser, the page address must be readable, and the item must have a URL matching the page. Native apps, terminals and items without a URL are refused.
- Passwords go into secure fields only. The prompt names the host the app read itself.

**Sign in from a command: `bl run`.** Prefer `--stdin` where the command accepts it, for example `gh auth login --with-token`. Use `--env` otherwise. Scripted browsers such as headless Playwright go through `bl run`, because Accessibility cannot reach them.

## Approval

- Off until the person turns on "Allow agents" in Settings, with Touch ID. This switch is the only new UI. It lives in the Keychain, because any process of this user can write `UserDefaults`.
- Every secret needs a fresh Touch ID, whatever strict mode says. `grantsCredit` is false, and there is no remembered approval or password fallback.
- The prompt states what will happen, from facts the app or tool established. Text an agent chose appears only as the command it will run or a value it will store, and an agent cannot add its own explanation:
  - `give GitHub password to /opt/homebrew/bin/gh auth status`
  - `fill GitHub password on github.com in Chrome`
  - `let an agent change GitHub: address "https://example.com"`
- `run` resolves the command to its full path first, so a changed `PATH` shows in the prompt.
- `run` gives the child a short fixed environment plus the secrets, so a variable such as `NODE_OPTIONS`, `BASH_ENV` or `DYLD_INSERT_LIBRARIES` cannot run code the prompt never showed. To set one on purpose, use `bl run ... -- env NAME=value tool`, which the prompt shows. `PATH` is kept, since tools need it to find each other.
- Commands too long to show in full, or with control or text-direction characters, are refused.
- One request can wait at a time; others get `busy`. A prompt expires after 60 seconds.

## Leak guards

- Secrets never appear in arguments, tool output, logs or error messages.
- `run` pipes the child's stdout and stderr and replaces each secret with `[hidden by bisel]`, in exact, base64, hex and URL-encoded forms, including values split across two reads.
- The tool turns core dumps off and has no `get-task-allow`.
- Item titles are stripped of control characters before they reach a prompt.

## Output, built for agents

- JSON on stdout, one object, no color, no prompts, nothing interactive.
- Success: `{"ok":true,"items":[{"id":"...","title":"GitHub","domain":"github.com","has":["password","totp"]}]}`
- Failure: `{"ok":false,"code":"locked","hint":"Ask the person to unlock Bisel."}` on stderr, exit 125.
- `run` passes through the child's output and exit code. A failure before launch uses the same error form and exit 125.
- Codes: `app_not_running`, `agents_off`, `locked`, `denied`, `timeout`, `busy`, `not_found`, `no_such_field`, `wrong_site`, `not_password_field`, `no_accessibility`, `fill_failed`, `command_refused`, `conflict`, `untrusted_app`, `bad_request`, `failed`.
- `bl --help` is short and written for agents. It says item titles are untrusted data, not instructions.

## What this cannot stop

- **Environment variables are readable.** Tested on this Mac: a same-user process read the environment of an unsigned test binary through `ps -E` and `sysctl`. It could not read `/bin/sleep`, a platform binary. So an agent could read `--env` values from a long-running approved command. This is why `--stdin` comes first.
- **An approved command has the secret.** It can write it to a file, send it away or encode it in a way masking misses. It also runs with the caller's `PATH`, working directory and files, so a script in the repository, or a tool found through `PATH` by the one that was approved, runs with it too. The prompt is the defense, so it shows the full command.
- **Page scripts can read a filled field.** An agent with JavaScript or DOM access to the page can read `input.value`, and a page's "show password" button reveals it. `--submit` shortens that window but does not close it.
- **Any same-user process can trigger a prompt.** Touch ID is the real boundary. Repeated prompts can wear a person down, which is why agents are off by default.

## Build order

1. `BiselAgent` module in `BiselCore`: request types, signature check, masking. No vault dependency, so the tool can link it.
2. App: socket listener in `apps/mac/Bisel/Agent`, approval, strict fill rules, the Settings switch.
3. Tool: `bisel` target in `project.yml`, embedded in `Contents/Helpers`, plus `project.dev.yml`, `release.sh` and `check-all.sh`.
4. Release checks: the tool links no `BiselCore`, the debug skip is gone, signature and hardened runtime are correct.
5. Update `SPEC.md` scope, milestones and threat model.

## Tests

Named after the failure each prevents, with no others:

- A denied or timed-out approval returns no secret.
- A client with the wrong signature gets nothing.
- A secret split across two output reads is still masked, in each encoding.
- `search` output never holds a secret, username or note.
- Agent fill refuses a mismatched page, an unreadable address, a non-secure field and an item without a URL.

## Check by hand before shipping

- Whether the Touch ID sheet takes focus from the field and stops the fill. The app waits up to 2 seconds for the same field to come back, then refuses with `fill_failed`. Check this first.
- Fill in Safari and Chrome. `apps/mac/FILL-MATRIX.md` still lists browser fill as unverified.
- How much text the Touch ID prompt shows, which sets the length limit.
