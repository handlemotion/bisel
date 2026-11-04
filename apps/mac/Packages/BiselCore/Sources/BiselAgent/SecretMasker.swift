import Foundation

/// Replaces secrets in a child's output, in the forms they most often take, including a value split across two reads. It catches
/// accidents: an approved command that means to hide a value can still do so (docs/AGENT-CLI.md).
public struct SecretMasker {
    public static let mask = Array("[hidden by bisel]".utf8)

    private let patterns: [[UInt8]]   // longest first, so a longer form wins at the same position
    private var held: [UInt8] = []

    public init(secrets: [Data]) {
        patterns = Array(Set(secrets.flatMap(Self.forms))).sorted { $0.count > $1.count }
    }

    /// Feeds one read and returns what is safe to pass on. A tail that could still become a secret is held for the next read.
    public mutating func push(_ chunk: some Sequence<UInt8>) -> [UInt8] {
        held.append(contentsOf: chunk)
        return drain(final: false)
    }

    /// The output ended: nothing more can complete a match.
    public mutating func finish() -> [UInt8] { drain(final: true) }

    private mutating func drain(final: Bool) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(held.count)
        var i = 0
        scan: while i < held.count {
            for pattern in patterns where pattern[0] == held[i] {
                let available = min(pattern.count, held.count - i)
                guard held[i..<(i + available)].elementsEqual(pattern[0..<available]) else { continue }
                if available == pattern.count {
                    out += Self.mask
                    i += available
                    continue scan
                }
                if !final { break scan }
            }
            out.append(held[i])
            i += 1
        }
        held.removeFirst(i)
        return out
    }

    /// The raw value, and for values long enough not to match by chance, its base64, base64url, hex and URL-encoded forms.
    /// Base64 padding is left out, so the padded and unpadded forms both match.
    static func forms(of secret: Data) -> [[UInt8]] {
        guard !secret.isEmpty else { return [] }
        var forms = [Array(secret)]
        guard secret.count >= 4 else { return forms }
        let base64 = secret.base64EncodedString().replacingOccurrences(of: "=", with: "")
        let hex = secret.map { String(format: "%02x", $0) }.joined()
        forms.append(Array(base64.utf8))
        forms.append(Array(base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").utf8))
        forms.append(Array(hex.utf8))
        forms.append(Array(hex.uppercased().utf8))
        let unreserved = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        if let text = String(data: secret, encoding: .utf8), let encoded = text.addingPercentEncoding(withAllowedCharacters: unreserved) {
            forms.append(Array(encoded.utf8))
        }
        return forms
    }
}
