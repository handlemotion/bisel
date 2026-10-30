import Foundation
import Observation
import BiselCore

// Non-view state for the panel's add / edit / delete / generate screens. No SwiftUI in here: the views bind to these models.
// ACTIONS.md next to this file says what each operation takes, throws and what the screen has to show.

/// One add or edit form. Create it with `PanelItemActions.newEditor` / `editor(for:)`, bind fields to `draft`, call `save()`.
@MainActor
@Observable
final class ItemEditorModel {
    enum State: Equatable {
        case editing
        case saving
        /// Both sides changed the same field (or the item was deleted elsewhere). Nothing was written; choose with `resolve`.
        case conflict(ItemConflict)
        /// Saved (or nothing to save). The form can close.
        case done(UpdateOutcome)
        case failed(Failure)
    }

    enum Failure: Equatable {
        /// The box is locked: show the unlock state; the draft is kept.
        case locked
        /// Touch ID was cancelled: stay on the form, nothing changed.
        case cancelled
        /// Read `issues` for the per-field list.
        case invalid
        /// Anything else, with the text from `describe(_:)`.
        case other(String)
    }

    @ObservationIgnored private let actions: VaultItemActions
    @ObservationIgnored fileprivate var onChange: (() -> Void)?

    var draft: ItemDraft { didSet { if draft != oldValue { revalidate() } } }
    private(set) var issues: [ItemIssue] = []
    private(set) var state: State = .editing
    /// The last password `generatePassword` made, with its strength, for a strength readout next to the field.
    private(set) var generated: GeneratedPassword?
    var passwordOptions = PasswordOptions()

    var isNew: Bool { draft.isNew }
    var canSave: Bool { issues.isEmpty && state != .saving && hasChanges }
    /// New drafts always count as changed; an edit counts once any field differs from what it was opened on.
    var hasChanges: Bool { draft.base.map { ItemDraft(editing: $0) != draft } ?? true }

    init(draft: ItemDraft, actions: VaultItemActions) {
        self.draft = draft
        self.actions = actions
        revalidate()
    }

    func issues(for field: ItemFieldID) -> [ItemIssue] { issues.filter { $0.field == field } }

    /// Fills `draft.password` from `passwordOptions`. Returns false (and changes nothing) when the options are invalid.
    @discardableResult
    func generatePassword() -> Bool {
        guard let p = try? PasswordGenerator.generate(passwordOptions) else { return false }
        generated = p
        draft.password = p.value
        return true
    }

    func save() async {
        guard state != .saving else { return }
        revalidate()
        guard issues.isEmpty else { state = .failed(.invalid); return }
        await run(resolution: nil)
    }

    func resolve(_ choice: ConflictResolution.Choice) async {
        guard case .conflict(let conflict) = state else { return }
        await run(resolution: ConflictResolution(choice, for: conflict))
    }

    /// Back to the form after a failure or conflict was shown.
    func keepEditing() { state = .editing }

    private func run(resolution: ConflictResolution?) async {
        state = .saving
        do {
            let outcome: UpdateOutcome
            if draft.isNew { outcome = .saved(try await actions.createItem(draft), mergedRemoteChanges: false) }
            else { outcome = try await actions.updateItem(draft, resolution: resolution) }
            state = .done(outcome)
            onChange?()
        } catch let c as ItemConflict {
            state = .conflict(c)
        } catch let e as ItemValidationError {
            issues = e.issues; state = .failed(.invalid)
        } catch BiselVault.VaultError.locked {
            state = .failed(.locked)
        } catch let e as KeyStoreError where e == .userCancelled {
            state = .failed(.cancelled)
        } catch {
            state = .failed(.other(describe(error)))
        }
    }

    private func revalidate() { issues = ItemValidator.issues(for: draft) }
}

/// The deleted item the toast offers to bring back, for `TrashReceipt.undoWindow` seconds.
@MainActor
@Observable
final class PanelItemActions {
    enum TrashResult: Equatable {
        case trashed(TrashReceipt)
        case cancelled
        case locked
        case failed(String)
    }

    @ObservationIgnored private let actions: VaultItemActions?
    @ObservationIgnored var onChange: (() -> Void)?
    @ObservationIgnored private var expiry: Task<Void, Never>?

    /// Set for `TrashReceipt.undoWindow` seconds after a successful `trash`; nil after the window, an undo or a new delete.
    private(set) var undoable: TrashReceipt?

    /// False for sources without a real vault (the dev fixture).
    var isAvailable: Bool { actions != nil }

    init(_ actions: VaultItemActions?) { self.actions = actions }

    /// A form for a new item.
    func newEditor(type: ItemType = .login) -> ItemEditorModel? {
        guard let actions else { return nil }
        let model = ItemEditorModel(draft: ItemDraft(type: type), actions: actions)
        model.onChange = { [weak self] in self?.onChange?() }
        return model
    }

    /// A form for an existing item (decrypts it; throws `VaultError.locked` / `.notFound`).
    func editor(for item: VaultSearchResult) async throws -> ItemEditorModel {
        guard let actions else { throw BiselVault.VaultError.notConfigured }
        let model = ItemEditorModel(draft: try await actions.draftForEditing(id: item.id), actions: actions)
        model.onChange = { [weak self] in self?.onChange?() }
        return model
    }

    /// A form for a copy of an existing item.
    func duplicateEditor(of item: VaultSearchResult) async throws -> ItemEditorModel {
        guard let actions else { throw BiselVault.VaultError.notConfigured }
        let source = try await actions.draftForEditing(id: item.id)
        var copy = ItemDraft(type: source.type)
        copy.title = source.title; copy.urls = source.urls; copy.username = source.username; copy.password = source.password
        copy.totp = source.totp; copy.notes = source.notes; copy.fields = source.fields; copy.tags = source.tags
        let model = ItemEditorModel(draft: copy, actions: actions)
        model.onChange = { [weak self] in self?.onChange?() }
        return model
    }

    func trash(_ item: VaultSearchResult) async -> TrashResult {
        guard let actions else { return .failed("No vault") }
        do {
            let receipt = try await actions.trashItem(id: item.id)
            offerUndo(receipt)
            onChange?()
            return .trashed(receipt)
        } catch BiselVault.VaultError.locked { return .locked }
        catch let e as KeyStoreError where e == .userCancelled { return .cancelled }
        catch { return .failed(describe(error)) }
    }

    /// Brings back the item offered by `undoable`. Returns it, or nil when the offer is gone or the restore failed.
    @discardableResult
    func undo() async -> Item? {
        guard let actions, let receipt = undoable else { return nil }
        expiry?.cancel()
        do {
            let item = try await actions.undoTrash(receipt)
            undoable = nil
            onChange?()
            return item
        } catch {
            Log.app.error("undo failed: \(describe(error))")
            return nil
        }
    }

    /// Items deleted in the last 30 days that are not back, for a "Recently deleted" list (restore with `restore`).
    func recentlyDeleted() async -> [TrashReceipt] { (try? await actions?.recentlyDeleted()) ?? [] }

    /// Restores one from `recentlyDeleted()`. Outside the undo window this asks for Touch ID.
    @discardableResult
    func restore(_ receipt: TrashReceipt) async throws -> Item {
        guard let actions else { throw BiselVault.VaultError.notConfigured }
        let item = try await actions.undoTrash(receipt)
        if undoable == receipt { undoable = nil }
        onChange?()
        return item
    }

    /// Drops the undo offer (the panel closed, the box locked).
    func clearUndo() { expiry?.cancel(); undoable = nil }

    private func offerUndo(_ receipt: TrashReceipt) {
        expiry?.cancel()
        undoable = receipt
        expiry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(TrashReceipt.undoWindow))
            guard !Task.isCancelled, let self, self.undoable == receipt else { return }
            self.undoable = nil
        }
    }
}
