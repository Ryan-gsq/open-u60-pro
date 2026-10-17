import Foundation

enum NumberPresentation: Equatable {
    case integer(Int, separator: String?)
    case decimal(Double, decimalPlaces: Int)

    var numericValue: Double {
        switch self {
        case .integer(let value, _): Double(value)
        case .decimal(let value, _): value
        }
    }

    var formatted: String {
        switch self {
        case .integer(let value, let separator):
            let digits = String(value.magnitude)
            guard let separator else { return String(value) }
            var result = value < 0 ? "-" : ""
            for (index, digit) in digits.enumerated() {
                if index > 0 && (digits.count - index).isMultiple(of: 3) { result += separator }
                result.append(digit)
            }
            return result
        case .decimal(let value, let decimalPlaces):
            return String(format: "%.*f", locale: Locale(identifier: "en_US_POSIX"),
                          max(0, decimalPlaces), value)
        }
    }

    static func trafficDuration(sampleInterval: TimeInterval, reduceMotion: Bool) -> Double {
        guard !reduceMotion else { return 0 }
        // A delayed publication must not stretch a roll across the next sample.
        let interval = sampleInterval.isFinite ? sampleInterval : 1
        let duration = min(max(interval * 0.35, 0.2), 0.4)
        return (duration * 20).rounded() / 20
    }
}
