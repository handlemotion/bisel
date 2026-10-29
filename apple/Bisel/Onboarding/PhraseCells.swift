import Observation
import SwiftUI

/// Which onboarding step is up, so the window can be as big as the step needs.
@MainActor
@Observable
final class OnboardingState {
    static let shared = OnboardingState()
    var recovering = false
}

/// Pulls the recovery words out of whatever was pasted or uploaded: plain words, numbered lines ("1. cannon"), or the
/// text file Bisel saves (a heading and a closing sentence around 24 numbered lines).
enum RecoveryPhraseText {
    static func words(in text: String) -> [String] {
        // The saved file: exactly the numbered lines.
        let numbered = text.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
            guard parts.count == 2, parts[0].hasSuffix("."), Int(parts[0].dropLast()) != nil else { return nil }
            let w = parts[1].trimmingCharacters(in: .whitespaces).lowercased()
            return w.allSatisfy(\.isLetter) ? w : nil
        }
        if numbered.count == 24 { return numbered }
        // Anything else: every purely alphabetic token, in order (numbers and punctuation fall away).
        return text.split(whereSeparator: { $0.isWhitespace || $0 == "," })
            .map { $0.trimmingCharacters(in: .punctuationCharacters).lowercased() }
            .filter { !$0.isEmpty && $0.allSatisfy(\.isLetter) }
    }
}

/// One phrase cell: the number on the left, the word on the right.
struct PhraseCellChrome<Word: View>: View {
    let number: Int
    var focused = false
    @ViewBuilder var word: Word
    private let theme = Theme.biselDark

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous)
        HStack(spacing: theme.spacing.s) {
            Text("\(number)").font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.tertiaryText.color)
            Spacer(minLength: theme.spacing.s)
            word
        }
        .padding(.vertical, 10).padding(.horizontal, theme.spacing.m)
        .frame(maxWidth: .infinity)
        .background(shape.fill(theme.colors.field.color))
        .overlay(shape.strokeBorder(focused ? theme.colors.text.color.opacity(0.35) : .clear, lineWidth: theme.card.hairline))
    }
}

/// The 24 cells as an input. Typing a space or pasting several words spreads them over the cells from the one you are in;
/// Return moves on, Delete on an empty cell moves back.
struct PhraseInputGrid: View {
    @Binding var words: [String]
    @FocusState private var focus: Int?
    private let theme = Theme.biselDark

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: theme.spacing.s), count: 4), alignment: .leading, spacing: theme.spacing.s) {
            ForEach(0..<24, id: \.self) { i in
                PhraseCellChrome(number: i + 1, focused: focus == i) {
                    TextField("", text: cell(i))
                        .textFieldStyle(.plain)
                        .multilineTextAlignment(.trailing)
                        .font(theme.font(theme.fonts.value, weight: .medium))
                        .autocorrectionDisabled()
                        .focused($focus, equals: i)
                        .onSubmit { focus = min(i + 1, 23) }
                        .onKeyPress(.delete) {
                            guard words[i].isEmpty, i > 0 else { return .ignored }
                            focus = i - 1
                            return .handled
                        }
                        .accessibilityLabel("Word \(i + 1)")
                        .accessibilityIdentifier("setup-word-\(i + 1)")
                }
            }
        }
        .onAppear { focus = 0 }
    }

    private func cell(_ i: Int) -> Binding<String> {
        Binding(get: { words[i] }, set: { value in
            let parts = RecoveryPhraseText.words(in: value)
            let spreads = parts.count > 1 || (value.last?.isWhitespace ?? false)
            guard spreads else { words[i] = parts.first ?? value.filter(\.isLetter).lowercased(); return }
            var j = i
            for w in parts where j < 24 { words[j] = w; j += 1 }
            if parts.isEmpty { words[i] = "" }
            focus = min(j, 23)
        })
    }
}
