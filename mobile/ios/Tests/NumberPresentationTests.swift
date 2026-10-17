import Foundation

@main
struct NumberPresentationTests {
    static func main() {
        for (value, expected) in [(9.9, "9.9"), (205.7, "205.7"), (0, "0.0"), (1, "1.0"), (-82.5, "-82.5")] {
            precondition(NumberPresentation.decimal(value, decimalPlaces: 1).formatted == expected,
                         "Display exactly the formatted value without placeholder zeros")
        }
        precondition(NumberPresentation.integer(1234567, separator: ",").formatted == "1,234,567")
        precondition(NumberPresentation.integer(-1234, separator: ",").formatted == "-1,234")
        precondition(NumberPresentation.integer(Int.min, separator: nil).formatted == String(Int.min))
        precondition(NumberPresentation.decimal(9.99, decimalPlaces: 1).formatted == "10.0")
        // Differences below displayed precision must not trigger another transition.
        precondition(NumberPresentation.decimal(9.91, decimalPlaces: 1).formatted ==
                     NumberPresentation.decimal(9.92, decimalPlaces: 1).formatted)
        for gap in [0.01, 0.5, 1, 2, 4, Double.infinity, Double.nan] {
            let duration = NumberPresentation.trafficDuration(sampleInterval: gap, reduceMotion: false)
            precondition((0.2...0.4).contains(duration), "Late samples must still settle promptly")
            precondition(NumberPresentation.trafficDuration(sampleInterval: gap, reduceMotion: true) == 0)
        }
        precondition(NumberPresentation.trafficDuration(sampleInterval: 1, reduceMotion: false) == 0.35)
        print("Number formatting and animation timing checks passed")
    }
}
