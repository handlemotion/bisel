import BiselCore

/// What the panel's add / edit / delete screens need from the vault. `VaultService` is the real one; the dev fixture has none.
@MainActor
protocol VaultItemActions: AnyObject {
    func createItem(_ draft: ItemDraft) async throws -> Item
    func updateItem(_ draft: ItemDraft, resolution: ConflictResolution?) async throws -> UpdateOutcome
    func trashItem(id: String) async throws -> TrashReceipt
    func undoTrash(_ receipt: TrashReceipt) async throws -> Item
    func recentlyDeleted() async throws -> [TrashReceipt]
    func draftForEditing(id: String) async throws -> ItemDraft
}

extension VaultService: VaultItemActions {
    /// Runs one vault operation; a locked core brings the app's phase in line, and a change refreshes rows and syncs.
    private func perform<T>(_ reason: String?, _ body: (Vault) async throws -> T) async throws -> T {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        do {
            let result = try await body(vault)
            if let reason { await didChangeLocally(reason: reason) }
            return result
        } catch BiselVault.VaultError.locked {
            coreReportedLocked()
            throw BiselVault.VaultError.locked
        }
    }

    func createItem(_ draft: ItemDraft) async throws -> Item {
        try await perform("create") { try await $0.createItem(draft) }
    }

    func updateItem(_ draft: ItemDraft, resolution: ConflictResolution? = nil) async throws -> UpdateOutcome {
        try await perform("edit") { try await $0.updateItem(draft, resolution: resolution) }
    }

    func trashItem(id: String) async throws -> TrashReceipt {
        try await perform("trash") { try await $0.trashItem(id: id) }
    }

    func undoTrash(_ receipt: TrashReceipt) async throws -> Item {
        try await perform("undo") { try await $0.undoTrash(receipt) }
    }

    func recentlyDeleted() async throws -> [TrashReceipt] {
        try await perform(nil) { try await $0.recentlyDeleted() }
    }

    /// A draft for the edit form of the item with this id (it decrypts the item; no biometric check).
    func draftForEditing(id: String) async throws -> ItemDraft {
        ItemDraft(editing: try await perform(nil) { try await $0.item(id: id) })
    }
}
