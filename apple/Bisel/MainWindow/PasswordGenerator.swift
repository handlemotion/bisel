import Foundation

/// Random password generator. Uses the system CSPRNG (`SystemRandomNumberGenerator` = `arc4random_buf`).
struct PasswordGenerator: Equatable {
    var length = 20
    var lower = true, upper = true, digits = true, symbols = true
    var avoidAmbiguous = true

    private static let ambiguous = Set("0O1lI|`'\"")
    private var classes: [[Character]] {
        var out: [[Character]] = []
        if lower { out.append(Array("abcdefghijklmnopqrstuvwxyz")) }
        if upper { out.append(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) }
        if digits { out.append(Array("0123456789")) }
        if symbols { out.append(Array("!@#$%^&*()-_=+[]{};:,.?/~")) }
        return out.map { c in avoidAmbiguous ? c.filter { !Self.ambiguous.contains($0) } : c }
    }

    func generate() -> String {
        let cls = classes
        guard !cls.isEmpty else { return "" }
        let pool = cls.flatMap { $0 }
        var chars: [Character] = cls.compactMap { $0.randomElement() }   // at least one of each selected class
        while chars.count < max(length, cls.count) { chars.append(pool.randomElement()!) }
        chars.shuffle()
        return String(chars)
    }
}
