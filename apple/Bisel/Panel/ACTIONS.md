# Panel actions: create, edit, delete, undo, generate

Logic only. Nothing here draws anything; the views bind to the models and decide copy, layout and motion.
Code: `BiselCore/Sources/BiselCore/{ItemDraft,ItemValidation,ItemActions,PasswordGenerator}.swift`,
`BiselTOTP/TOTPSetup.swift`, app side `Core/VaultService+Actions.swift` and `Panel/PanelItemActions.swift`.
Flow tests: `Packages/BiselCore/Tests/BiselFlowTests/ItemActionFlowTests.swift`.

## What the views touch

`CommandPanelModel.items` (a `PanelItemActions`) is the entry point. It is unavailable (`isAvailable == false`, factories return nil) on the dev fixture.

| Call | Gives |
|---|---|
| `items.newEditor(type:)` | `ItemEditorModel?` for a new login / note / secret |
| `try await items.editor(for: result)` | `ItemEditorModel` for an existing item (decrypts it) |
| `try await items.duplicateEditor(of: result)` | `ItemEditorModel` pre-filled from an item, saved as a new one |
| `await items.trash(result)` | `TrashResult`: `.trashed(receipt)`, `.cancelled`, `.locked`, `.failed(text)` |
| `items.undoable` / `await items.undo()` | the undo offer for `TrashReceipt.undoWindow` (10 s), then it disappears |
| `await items.recentlyDeleted()` / `try await items.restore(receipt)` | "Recently deleted" list (30 days) and its restore |

`items.onChange` is wired to `CommandPanelModel.refresh()`, so the result list updates after every successful change.

## The editor: `ItemEditorModel`

Bind the fields to `editor.draft` (`ItemDraft`, plain strings exactly as typed). Fields: `type` (`.login`, `.note`, `.secret`), `title`, `urls: [String]`, `username`, `password`, `totp` (a bare base32 secret or an `otpauth://totp/...` URI; empty = none), `notes`, `fields: [CustomField]`, `tags: [String]`.

- `editor.issues`, `editor.issues(for: .title)`: live validation, recomputed on every change. Each `ItemIssue` has `field`, `code` and `index` (which address or custom field).
- `editor.canSave`: no issues, not saving, and (for an edit) something changed. Disable Save otherwise.
- `editor.hasChanges`: for "discard changes?" on Escape.
- `await editor.save()`: creates or edits. Watch `editor.state`.
- `editor.generatePassword()` fills `draft.password` from `editor.passwordOptions` (a `PasswordOptions` you bind the generator controls to); `editor.generated` has `entropyBits` / `strength` for a meter. It returns false and changes nothing if the options are invalid.
- `editor.keepEditing()`: leave `.failed` / `.conflict` and return to the form.

### `editor.state`

| State | Meaning | Screen |
|---|---|---|
| `.editing` | normal | the form |
| `.saving` | working; a Touch ID prompt may be up (edit only) | disable the form, no second Save |
| `.done(outcome)` | finished | close the form. See outcomes below |
| `.failed(.invalid)` | `issues` lists what is wrong | show the per-field messages |
| `.failed(.locked)` | the box locked while editing | the panel's unlock state; the draft is kept |
| `.failed(.cancelled)` | Touch ID cancelled | stay on the form, say nothing alarming |
| `.failed(.other(text))` | unexpected | show `text`, keep the form |
| `.conflict(conflict)` | nothing written, owner must choose | the conflict screen below |

Outcomes (`UpdateOutcome`) for `.done`:
- `.saved(item, mergedRemoteChanges:)`. When `mergedRemoteChanges` is true the item had been changed on another device since the form was opened and those changes were kept; worth a one-line note ("also updated elsewhere").
- `.unchanged(item)`: nothing differed; nothing written and no Touch ID.
- `.savedAsCopy(item)`: after "keep both".
- `.discarded(item?)`: after "use theirs" when nothing of the owner's survived.

## Validation rules (one place: `ItemValidator`)

`ItemValidator.issues(for: draft)` is the only source. Codes by field:

| Field | Codes |
|---|---|
| `title` | `required` (blank after trimming), `tooLong` (> 200) |
| `urls` (+ index) | `invalidURL` (spaces, no host, credentials in the address), `unsupportedURLScheme` (javascript:, file:, mailto:, ... only http/https), `tooMany` (> 20) |
| `password` | `required` for type `secret` |
| `totp` | `totpNotBase32`, `totpTooShort` (< 8 characters), `totpUnsupported` (`hotp`), `totpBadParameters` (unknown algorithm, digits not 6-8, period not 1-300) |
| `fields` (+ index) | `labelRequired` (value without a label), `tooLong` (label > 100), `tooMany` (> 50) |
| `tags` | `tooLong` (> 64), `tooMany` (> 50) |
| `type` | `unsupportedType`: passkeys cannot be created, and a passkey item cannot change type |
| `size` | `tooLarge`: the encoded item is over 256 KiB. Show it as a form-level message, not under a field |

Normalisation (what gets stored, no issue raised): title, username, tags and labels are trimmed; blank notes become none; passwords are never trimmed; an address without a scheme gets `https://`, scheme and host are lowercased and a bare trailing `/` dropped; duplicate addresses and tags (case-insensitive) collapse; blank custom-field rows are dropped; a TOTP secret is uppercased with spaces, hyphens and `=` removed. Fields a type cannot hold are dropped (a note keeps only title, notes, custom fields, tags; a secret has no one-time code). Addresses the item already had are kept as they were even if today's rules would refuse them (imports), and only changed fields are ever rewritten.

For an edit, a one-time code with non-default settings is shown in `draft.totp` as an `otpauth://` URI so nothing is lost when the owner edits something else; the default (SHA1, 6 digits, 30 s) shows as the bare secret. Mask this field.

## Edit and stale revisions

An edit draft remembers the item it was opened on (`draft.base`). On save the vault re-reads the stored item and merges field by field (`title`, `urls`, `username`, `password`, `totp`, `notes`, `fields`, `tags`):

- only the owner changed it: the owner's value is written;
- only another device changed it (or neither): the stored value stays, so a stale form never overwrites newer data;
- both changed it to different values: **conflict**. Nothing is written; `state` becomes `.conflict(c)`.

`ItemConflict`: `current` (the item now; nil if it was deleted elsewhere, `itemWasDeleted`), `mine` (the version the owner meant), `fields` (the clashing fields). Show both values for each field in `fields` (or "deleted on another device"), then call `await editor.resolve(choice)`:

| Choice | Result |
|---|---|
| `.useMine` | clashing fields take the owner's values, other devices' non-clashing changes stay. The overwritten version goes to the local trash. Deleted elsewhere: the item comes back with the owner's version |
| `.useTheirs` | clashing fields keep the other device's values, the owner's other edits are applied. Nothing left to apply: `.discarded`. Deleted elsewhere: the draft is dropped |
| `.keepBoth` | the item stays; the owner's version is saved as a new item titled "<title> (conflict)" (same as sync does). Deleted elsewhere: same as `.useMine` |

If the item changed again while the conflict screen was open, `resolve` does not apply the choice; `state` returns to `.conflict` with the new values. Touch ID: any write over an existing item asks once (reason "Edit <title>"); create, `unchanged` and `.keepBoth` never ask.

## Create

`save()` on a new draft. No Touch ID. The draft carries the item's id, so a second Return or a retry never makes a second item (the stored item is returned). Sync runs in the background afterwards.

## Delete and undo

`items.trash(result)` asks for Touch ID ("Delete item") and moves the item to the local trash (30 days, encrypted); sync carries the delete to the server. On `.trashed(receipt)` show the toast with `receipt.title`; `items.undoable` stays set for `TrashReceipt.undoWindow` (10 s) and `items.undo()` brings the item back with the same id and contents, without Touch ID. After the window the item is still in `recentlyDeleted()`; `restore(receipt)` then asks for Touch ID. A cancelled Touch ID is `.cancelled` (nothing changed, show nothing). Undoing an item already restored elsewhere returns it unchanged. If the receipt's trash entry is gone (30 days) `undoTrash` throws `ItemActionError.undoUnavailable`.

There is no "delete forever": a deleted item stays recoverable for 30 days on this Mac and in the server's history, which is what makes the undo safe. Say "Deleted" rather than "Erased".

## Generator

`PasswordGenerator.generate(options) throws(PasswordGeneratorError) -> GeneratedPassword` (system CSPRNG, uniform picks, Fisher-Yates shuffle). `PasswordGenerator.entropyBits(for:)` gives the strength without generating, for a live meter while the owner moves a slider.

`PasswordOptions`: `mode` (`.characters` / `.passphrase`);
- characters: `length` 8...128 (default 20), `lowercase`, `uppercase`, `digits`, `symbols`, `avoidAmbiguous` (drops `0 O 1 l I | ` ' "`); at least one of every chosen class is guaranteed;
- passphrase: `words` 3...12 (default 5, from the 2048-word BIP-39 list), `separator` (up to 3 characters), `capitalize`, `includeNumber` (one digit on a random word).

Errors: `.lengthOutOfRange`, `.noCharacterClass` (all four off), `.wordCountOutOfRange`, `.separatorTooLong`. `GeneratedPassword.strength`: `weak` < 50 bits, `fair` < 70, `strong` < 100, `excellent`. Its description is redacted.

## Other errors the views can meet

`VaultError.locked` (surfaces as `.locked`; the service has already switched the app to the locked phase), `VaultError.notFound` (an item vanished before it was opened or deleted: refresh the list), `KeyStoreError.userCancelled` (Touch ID cancelled). Everything else arrives as `.other(text)` / `.failed(text)` with `describe(error)`.

## Not provided

Tags/URL de-duplication across items, password-reuse or breach checks, bulk delete, permanent erase, and editing passkey credentials.
