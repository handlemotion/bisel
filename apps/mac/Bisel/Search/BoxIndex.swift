import Foundation
import BiselCore

/// Non-secret view of an item: what the list, the search index and the panel need. Passwords, notes and TOTP
/// secrets are never held here; they are decrypted on demand through the `Vault` actor.
struct ItemRow: Identifiable, Hashable, Sendable {
    let id: String
    let type: ItemType
    let title: String
    let urls: [String]
    let username: String
    let tags: [String]
    let updatedAt: Date
    let hasPassword: Bool
    let hasTOTP: Bool
    let totpPeriod: Int

    init(_ item: Item) {
        id = item.id; type = item.type; title = item.title; urls = item.urls; username = item.username ?? ""
        tags = item.tags; updatedAt = item.updatedAt; hasPassword = !(item.password ?? "").isEmpty; hasTOTP = item.totp != nil; totpPeriod = item.totp?.period ?? 30
    }

}

/// The unlocked box as the list and the panel see it: rows by id, the search index and every hit the panel can show, made once.
/// Built away from the main actor (`build`) and put in place with `install`.
@MainActor
final class BoxIndex {
    struct Built: Sendable {
        let rows: [ItemRow]
        let byID: [String: ItemRow]
        let index: FuzzySearchIndex.Built
        /// One per searchable record, in the index's positions, and the whole list A to Z.
        let hits: [VaultSearchResult]
        let alphabetical: [VaultSearchResult]
    }

    private let index = FuzzySearchIndex()
    private var rowsByID: [String: ItemRow] = [:]
    private var hits: [VaultSearchResult] = []
    private var alphabetical: [VaultSearchResult] = []

    nonisolated static func build(_ items: [Item], usage: [String: UsageStore.Entry]) -> Built {
        let all = items.map(ItemRow.init)
        let searchable = all.filter { $0.type == .login || $0.type == .secret }
        let records = searchable.map { r in
            let u = usage[r.id]
            return SearchRecord(id: r.id, title: r.title, username: r.username, urls: r.urls, tags: r.tags,
                                lastUsed: u?.last ?? r.updatedAt, useCount: u?.count ?? 0)
        }
        let built = FuzzySearchIndex.build(records)
        let hits = zip(records, searchable).map { record, row in
            VaultSearchResult(id: record.id, title: record.title, username: record.username, domain: record.domain, tags: record.tags,
                              hasPassword: row.hasPassword, hasTOTP: row.hasTOTP)
        }
        return Built(rows: all, byID: Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) }), index: built,
                     hits: hits, alphabetical: built.alphabetical.map { hits[$0] })
    }

    func install(_ built: Built) {
        rowsByID = built.byID
        index.install(built.index)
        hits = built.hits
        alphabetical = built.alphabetical
    }

    func clear() {
        rowsByID = [:]
        index.replace([])
        hits = []
        alphabetical = []
    }

    func row(_ id: String) -> ItemRow? { rowsByID[id] }

    func recordUse(id: String) { index.recordUse(id: id) }

    func search(_ query: String, limit: Int) -> [VaultSearchResult] {
        if FuzzySearchIndex.isEmptyQuery(query) { return limit >= alphabetical.count ? alphabetical : Array(alphabetical.prefix(limit)) }
        return index.matches(query, limit: limit).map { hits[$0] }
    }
}
