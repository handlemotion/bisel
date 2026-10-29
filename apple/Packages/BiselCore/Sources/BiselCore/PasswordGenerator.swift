import Foundation

/// Options for a generated password or passphrase. Everything is validated by `PasswordGenerator.generate`.
public struct PasswordOptions: Sendable, Equatable, Codable {
    public enum Mode: String, Sendable, Codable, CaseIterable { case characters, passphrase }

    public var mode: Mode = .characters

    // characters
    public var length = 20
    public var lowercase = true
    public var uppercase = true
    public var digits = true
    public var symbols = true
    /// Leaves out characters that look alike (0 O 1 l I |) and quote marks.
    public var avoidAmbiguous = true

    // passphrase
    public var words = 5
    public var separator = "-"
    public var capitalize = false
    /// Appends one random digit to a random word.
    public var includeNumber = false

    public init() {}

    public static let lengthRange = 8...128
    public static let wordsRange = 3...12
    public static let maxSeparatorLength = 3
    public static var characters: PasswordOptions { PasswordOptions() }
    public static var passphrase: PasswordOptions { var o = PasswordOptions(); o.mode = .passphrase; return o }
}

public struct GeneratedPassword: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Strength: Int, Sendable, Comparable {
        case weak, fair, strong, excellent
        public static func < (a: Strength, b: Strength) -> Bool { a.rawValue < b.rawValue }
    }

    public let value: String
    /// Entropy of the way it was chosen (log2 of the number of equally likely outputs), in bits. An estimate: forcing one
    /// character of each class shaves a little off.
    public let entropyBits: Double

    public var strength: Strength {
        switch entropyBits { case ..<50: .weak; case ..<70: .fair; case ..<100: .strong; default: .excellent }
    }

    public var description: String { "GeneratedPassword(redacted)" }
    public var debugDescription: String { description }
}

public enum PasswordGeneratorError: Error, Sendable, Equatable {
    case noCharacterClass
    case lengthOutOfRange
    case wordCountOutOfRange
    case separatorTooLong
}

/// Random passwords from the system CSPRNG (`SystemRandomNumberGenerator`: `getentropy`/`arc4random` on Apple platforms).
/// Every pick is uniform (no modulo bias) and the final order is a Fisher-Yates shuffle.
public enum PasswordGenerator {
    private static let ambiguous = Set("0O1lI|`'\"")
    private static let lowerSet = Array("abcdefghijklmnopqrstuvwxyz")
    private static let upperSet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    private static let digitSet = Array("0123456789")
    private static let symbolSet = Array("!@#$%^&*()-_=+[]{};:,.?/~")

    /// The character classes the options select, with ambiguous characters already removed.
    static func classes(_ o: PasswordOptions) -> [[Character]] {
        var out: [[Character]] = []
        if o.lowercase { out.append(lowerSet) }
        if o.uppercase { out.append(upperSet) }
        if o.digits { out.append(digitSet) }
        if o.symbols { out.append(symbolSet) }
        return out.map { c in o.avoidAmbiguous ? c.filter { !ambiguous.contains($0) } : c }
    }

    public static func validate(_ o: PasswordOptions) throws(PasswordGeneratorError) {
        switch o.mode {
        case .characters:
            guard PasswordOptions.lengthRange.contains(o.length) else { throw .lengthOutOfRange }
            guard !classes(o).isEmpty else { throw .noCharacterClass }
        case .passphrase:
            guard PasswordOptions.wordsRange.contains(o.words) else { throw .wordCountOutOfRange }
            guard o.separator.count <= PasswordOptions.maxSeparatorLength else { throw .separatorTooLong }
        }
    }

    public static func generate(_ o: PasswordOptions = PasswordOptions()) throws(PasswordGeneratorError) -> GeneratedPassword {
        try validate(o)
        var rng = SystemRandomNumberGenerator()
        switch o.mode {
        case .characters: return characters(o, &rng)
        case .passphrase: return passphrase(o, &rng)
        }
    }

    /// Entropy of what `generate` would produce for these options, without generating anything (for a live strength readout).
    public static func entropyBits(for o: PasswordOptions) -> Double {
        switch o.mode {
        case .characters:
            let pool = classes(o).reduce(0) { $0 + $1.count }
            return pool > 1 ? Double(o.length) * log2(Double(pool)) : 0
        case .passphrase:
            var bits = Double(o.words) * log2(Double(PassphraseWords.list.count))
            if o.includeNumber { bits += log2(Double(o.words)) + log2(10) }
            return bits
        }
    }

    private static func characters(_ o: PasswordOptions, _ rng: inout SystemRandomNumberGenerator) -> GeneratedPassword {
        let cls = classes(o)
        let pool = cls.flatMap { $0 }
        var chars: [Character] = cls.map { $0.randomElement(using: &rng)! }   // at least one of every selected class
        while chars.count < o.length { chars.append(pool.randomElement(using: &rng)!) }
        chars.shuffle(using: &rng)
        return GeneratedPassword(value: String(chars), entropyBits: entropyBits(for: o))
    }

    private static func passphrase(_ o: PasswordOptions, _ rng: inout SystemRandomNumberGenerator) -> GeneratedPassword {
        var picked = (0..<o.words).map { _ in PassphraseWords.list.randomElement(using: &rng)! }
        if o.capitalize { picked = picked.map { $0.prefix(1).uppercased() + $0.dropFirst() } }
        if o.includeNumber {
            let i = Int.random(in: 0..<picked.count, using: &rng)
            picked[i] += String(Int.random(in: 0...9, using: &rng))
        }
        return GeneratedPassword(value: picked.joined(separator: o.separator), entropyBits: entropyBits(for: o))
    }
}
