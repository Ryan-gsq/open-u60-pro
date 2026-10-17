import SwiftUI

/// A single, stable text view lets SwiftUI own interpolation and interrupted transitions.
/// No appearance callbacks, placeholder digits, or per-column state need to track the poller.
struct AnimatedNumber: View, Equatable {
    private let value: NumberPresentation
    var font: Font = .system(size: 32, weight: .bold, design: .rounded)
    var textColor: Color = .primary
    var animationDuration: Double = 0.4
    var prefix: String?
    var suffix: String?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(
        value: Int,
        font: Font = .system(size: 32, weight: .bold, design: .rounded),
        textColor: Color = .primary,
        animationDuration: Double = 0.4,
        prefix: String? = nil,
        suffix: String? = nil,
        separator: String? = nil
    ) {
        self.value = .integer(value, separator: separator)
        self.font = font
        self.textColor = textColor
        self.animationDuration = animationDuration
        self.prefix = prefix
        self.suffix = suffix
    }

    init(
        value: Double,
        decimalPlaces: Int = 1,
        font: Font = .system(size: 32, weight: .bold, design: .rounded),
        textColor: Color = .primary,
        animationDuration: Double = 0.4,
        prefix: String? = nil,
        suffix: String? = nil
    ) {
        self.value = .decimal(value, decimalPlaces: decimalPlaces)
        self.font = font
        self.textColor = textColor
        self.animationDuration = animationDuration
        self.prefix = prefix
        self.suffix = suffix
    }

    var body: some View {
        let text = (prefix ?? "") + value.formatted + (suffix ?? "")
        Text(verbatim: text)
            .font(font.monospacedDigit())
            .foregroundStyle(textColor)
            .contentTransition(.numericText(value: value.numericValue))
            // Animate only a displayed change. Re-reading a publication or updating its
            // timestamp cannot restart this transition. Units participate in the same update.
            .animation(reduceMotion || animationDuration <= 0
                       ? nil : .easeInOut(duration: animationDuration), value: text)
            .accessibilityLabel(text)
    }

    static func == (lhs: AnimatedNumber, rhs: AnimatedNumber) -> Bool {
        lhs.value == rhs.value
            && lhs.font == rhs.font
            && lhs.textColor == rhs.textColor
            && lhs.animationDuration == rhs.animationDuration
            && lhs.prefix == rhs.prefix
            && lhs.suffix == rhs.suffix
    }
}
