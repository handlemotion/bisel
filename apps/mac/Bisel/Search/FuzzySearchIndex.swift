import FuzzyMatch
import Foundation

/// What gets indexed per item. The real vault maps decrypted items to this.
struct SearchRecord: Sendable {
    let id: String
    let title: String
    let username: String
    let urls: [String]
    let tags: [String]
    /// The first address's host. Stored: parsing a URL per item is what opening the panel used to spend its time on.
    let domain: String
    var lastUsed: Date
    var useCount: Int

    init(id: String, title: String, username: String, urls: [String], tags: [String], lastUsed: Date, useCount: Int) {
        self.id = id; self.title = title; self.username = username; self.urls = urls; self.tags = tags
        self.lastUsed = lastUsed; self.useCount = useCount
        domain = Self.domain(of: urls.first)
    }

    static func domain(of url: String?) -> String {
        guard let url, let host = URL(string: url)?.host() else { return "" }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }
}

/// In-memory fuzzy index over title, URLs (host), username and tags, using the maintained
/// `FuzzyMatch` package (ordo-one/FuzzyMatch) for scoring. No scorer of our own: this file only decides which of the
/// library's match kinds count, and how fields are weighted.
///
/// Policy (a password manager is searched by name, so scattered matches are noise):
///  - Each field is matched as a whole and word by word (split on spaces, `.`, `@`, `-`, `_`, `/`), so "git" hits
///    "GitHub (old)" and "gist.github.com" by word start.
///  - Kinds accepted: `.exact`, `.prefix` (of the field or of one of its words) and `.acronym`. A `.substring` hit in
///    the middle of a word ("git" in "diGITal") only counts for queries of 4+ characters, and at a discount.
///    Gap-based subsequence matching is switched off, so "git" never matches d-i-G-i-T-al scatter.
///  - Typo tolerance (1 edit) only for terms of 5+ characters; shorter queries are literal.
///  - Queries are whitespace-separated terms, every term must match (AND); item score is the mean of the terms' best
///    field scores. Ties (within epsilon) break by recency, then frequency (SPEC.md §8).
///  - FuzzyMatch is case- and diacritic-insensitive.
@MainActor
final class FuzzySearchIndex {
    fileprivate struct Field: Sendable {
        let weight: Double
        let whole: String
        let words: [String]
    }
    fileprivate struct Entry: Sendable {
        var record: SearchRecord
        let fields: [Field]
    }

    private struct Term { let text: String; let tolerant: Bool; let literalQ: FuzzyQuery; let tolerantQ: FuzzyQuery }

    private var entries: [Entry] = []
    private var indexByID: [String: Int] = [:]
    /// Positions in `entries`, A to Z: what an empty query lists. Sorted once per build, not per panel open.
    private var alphabetical: [Int] = []

    private static let literal = FuzzyMatcher(config: MatchConfig(minScore: 0.5, algorithm: .editDistance(EditDistanceConfig(
        maxEditDistance: 0, longQueryMaxEditDistance: 0, prefixWeight: 2.0, substringWeight: 0.8,
        wordBoundaryBonus: 0.12, consecutiveBonus: 0.06, acronymWeight: 0.7, isSubsequenceMatchingEnabled: false))))
    private static let tolerant = FuzzyMatcher(config: MatchConfig(minScore: 0.55, algorithm: .editDistance(EditDistanceConfig(
        maxEditDistance: 1, longQueryMaxEditDistance: 2, prefixWeight: 2.0, substringWeight: 0.8,
        wordBoundaryBonus: 0.12, consecutiveBonus: 0.06, acronymWeight: 0.7, isSubsequenceMatchingEnabled: false))))
    private var literalBuffer = FuzzySearchIndex.literal.makeBuffer()
    private var tolerantBuffer = FuzzySearchIndex.tolerant.makeBuffer()

    private nonisolated static let wTitle = 1.0, wDomain = 0.92, wUser = 0.75, wTag = 0.6
    private nonisolated static let separators = CharacterSet(charactersIn: " .@-_/:()[]+,")

    /// An index built away from the main actor (`build`) and put in place with `install`.
    struct Built: Sendable {
        fileprivate let entries: [Entry]
        fileprivate let indexByID: [String: Int]
        let alphabetical: [Int]
    }

    init(records: [SearchRecord] = []) { replace(records) }

    var count: Int { entries.count }

    private nonisolated static func field(_ weight: Double, _ text: String) -> Field {
        let words = text.components(separatedBy: separators).filter { !$0.isEmpty }
        return Field(weight: weight, whole: text, words: words.count > 1 ? words : [])
    }

    func replace(_ records: [SearchRecord]) { install(Self.build(records)) }

    /// Tokenises every record: ~7 µs per record, so 35 ms at 5,000 items and 100 ms at 20,000. Pure, so callers on a
    /// large box run it off the main actor and `install` the result.
    nonisolated static func build(_ records: [SearchRecord]) -> Built {
        let entries = records.map { r in
            var f = [Self.field(Self.wTitle, r.title)]
            if !r.domain.isEmpty { f.append(Self.field(Self.wDomain, r.domain)) }
            for u in r.urls.dropFirst() {
                let d = SearchRecord.domain(of: u)
                if !d.isEmpty, d != r.domain { f.append(Self.field(Self.wDomain * 0.9, d)) }
            }
            if !r.username.isEmpty { f.append(Self.field(Self.wUser, r.username)) }
            for t in r.tags { f.append(Self.field(Self.wTag, t)) }
            return Entry(record: r, fields: f)
        }
        return Built(entries: entries, indexByID: Dictionary(uniqueKeysWithValues: entries.enumerated().map { ($1.record.id, $0) }),
                     alphabetical: entries.indices.sorted { comesFirst(entries[$0].record, entries[$1].record) })
    }

    /// Finder's order: case and accents ignored, "Site 2" before "Site 10". Same titles settle on username, then id.
    private nonisolated static func comesFirst(_ a: SearchRecord, _ b: SearchRecord) -> Bool {
        switch a.title.localizedStandardCompare(b.title) {
        case .orderedAscending: true
        case .orderedDescending: false
        case .orderedSame: (a.username, a.id) < (b.username, b.id)
        }
    }

    func install(_ built: Built) {
        entries = built.entries
        indexByID = built.indexByID
        alphabetical = built.alphabetical
    }

    func recordUse(id: String) {
        guard let i = indexByID[id] else { return }
        entries[i].record.lastUsed = Date()
        entries[i].record.useCount += 1
    }

    func record(id: String) -> SearchRecord? { indexByID[id].map { entries[$0].record } }

    func search(_ query: String, limit: Int) -> [SearchRecord] { matches(query, limit: limit).map { entries[$0].record } }

    /// True when `query` lists everything A to Z, which needs no scoring.
    static func isEmptyQuery(_ query: String) -> Bool { query.allSatisfy(\.isWhitespace) }

    /// Positions in the records given to `build`, best first (A to Z for an empty query).
    func matches(_ query: String, limit: Int) -> [Int] {
        let terms = query.split(whereSeparator: \.isWhitespace).map(String.init)
        if terms.isEmpty { return Array(alphabetical.prefix(limit)) }
        let prepared = terms.map {
            Term(text: $0, tolerant: $0.count >= 5, literalQ: Self.literal.prepare($0), tolerantQ: Self.tolerant.prepare($0))
        }
        // "git hub" should also find "GitHub": a multi-term query is additionally tried as its joined form.
        let joined: Term? = prepared.count > 1 ? {
            let j = terms.joined()
            return Term(text: j, tolerant: j.count >= 5, literalQ: Self.literal.prepare(j), tolerantQ: Self.tolerant.prepare(j))
        }() : nil
        var scored: [(score: Double, position: Int)] = []
        for (position, e) in entries.enumerated() {
            var total = 0.0
            var ok = true
            for t in prepared {
                var best = 0.0
                for f in e.fields {
                    best = max(best, score(f.whole, t, weight: f.weight, isWord: false))
                    for w in f.words { best = max(best, score(w, t, weight: f.weight * 0.97, isWord: true)) }
                }
                if best == 0 { ok = false; break }
                total += best
            }
            var itemScore = ok ? total / Double(prepared.count) : 0
            if let j = joined {
                var best = 0.0
                for f in e.fields { best = max(best, score(f.whole, j, weight: f.weight, isWord: false)) }
                itemScore = max(itemScore, best * 0.95)
            }
            if itemScore > 0 { scored.append((itemScore, position)) }
        }
        scored.sort { a, b in
            if abs(a.score - b.score) > 0.0001 { return a.score > b.score }
            let x = entries[a.position].record, y = entries[b.position].record
            if x.lastUsed != y.lastUsed { return x.lastUsed > y.lastUsed }
            return x.useCount > y.useCount
        }
        return scored.prefix(limit).map(\.position)
    }

    /// One candidate string against one term, applying the kind policy above. 0 = rejected.
    private func score(_ candidate: String, _ t: Term, weight: Double, isWord: Bool) -> Double {
        let m: ScoredMatch?
        if t.tolerant { m = Self.tolerant.score(candidate, against: t.tolerantQ, buffer: &tolerantBuffer) }
        else { m = Self.literal.score(candidate, against: t.literalQ, buffer: &literalBuffer) }
        guard let m else { return 0 }
        switch m.kind {
        case .exact, .prefix: return m.score * weight
        case .acronym: return t.text.count >= 2 ? m.score * weight * 0.8 : 0
        case .substring: return t.text.count >= 4 ? m.score * weight * 0.7 : 0
        default: return 0
        }
    }
}
