import Foundation

/// Text that came from a box, a file or another device, as it may be put on screen: item titles, usernames, otpauth issuers
/// and labels, device names, import notes, toasts that quote them.
///
/// Such text can carry invisible direction and control characters: U+202E (right-to-left override) makes "moc.evil" render
/// as "live.com", isolates (U+2066–U+2069) and marks (U+200E, U+200F) reorder or hide parts of a name. `clean` drops every
/// control (Cc) and format (Cf) character, except the zero-width joiner and non-joiner, which emoji sequences and several
/// scripts need and which change no direction. Tabs and line breaks become a space, so words stay apart.
///
/// Display only: what is stored, copied or filled is never cleaned.
public enum DisplayText {
    public static func clean(_ text: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator:
                if scalar == "\u{200C}" || scalar == "\u{200D}" { out.append(scalar) }
                else if scalar.properties.isWhitespace { out.append(" ") }
            default:
                out.append(scalar)
            }
        }
        return String(out).trimmingCharacters(in: .whitespaces)
    }
}
