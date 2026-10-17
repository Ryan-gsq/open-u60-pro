import Foundation

// Run from the repository root: sh scripts/test-ios-traffic.sh
@main
struct TrafficSpeedTests {
    static func main() {
        let old = TrafficStats(rxBytes: 10, txBytes: 20,
                               timestamp: Date(timeIntervalSince1970: 0), source: "wwandst")
        let live = DeviceParser.parseWwandstTraffic([
            "real_rx_bytes": 349032201, "real_tx_bytes": 399696948,
            "real_rx_speed": 52_500_000, "real_tx_speed": 5_000_000
        ])!
        let speed = DeviceParser.computeSpeed(previous: old, current: live)
        precondition(speed.downloadBytesPerSec == 52_500_000)
        precondition(speed.uploadBytesPerSec == 5_000_000)
        precondition(DeviceParser.speedComponents(speed.downloadBytesPerSec).number == 420)
        precondition(DeviceParser.speedComponents(speed.uploadBytesPerSec).number == 40)

        // Speed holds a FIXED fraction width at every scale, unlike `bytesComponents`. A live rate
        // swings across decades every second, and because AnimatedNumber keys columns by place
        // value, a moving fraction width inserts and removes columns instead of rolling them.
        let low = DeviceParser.speedComponents(1_000) // 8 Kb/s
        precondition(low.unit == " Kb/s" && low.number == 8 && low.decimalPlaces == 1)
        let mid = DeviceParser.speedComponents(1_500_000) // 12 Mb/s
        precondition(mid.unit == " Mb/s" && mid.number == 12 && mid.decimalPlaces == 1)
        let high = DeviceParser.speedComponents(50_000_000) // 400 Mb/s
        precondition(high.unit == " Mb/s" && high.number == 400 && high.decimalPlaces == 1)

        // Rounding that reaches the next scale must promote the unit rather than render
        // "1000 Kb/s", which would also add a digit column for a single sample.
        let boundary = DeviceParser.speedComponents(124_999) // 999.992 Kb/s
        precondition(boundary.unit == " Mb/s" && boundary.number == 1,
                     "Rounding up to the scale threshold must promote the unit")
        precondition(DeviceParser.speedComponents(0).unit == " b/s")
        precondition(DeviceParser.formatSpeed(50_000_000) == "400.0Mb/s")

        // A delayed counter increase must not override an explicit idle sample.
        let idle = DeviceParser.parseWwandstTraffic([
            "real_rx_bytes": "349032301", "real_tx_bytes": "399697048",
            "real_rx_speed": "0", "real_tx_speed": "0"
        ])!
        precondition(DeviceParser.computeSpeed(previous: live, current: idle) == .zero)
        precondition(DeviceParser.parseWwandstTraffic(["real_rx_bytes": 1]) == nil)

        // Older firmware with counters only still supports deltas, without source-switch spikes.
        var counter = DeviceParser.parseWwandstTraffic([
            "real_rx_bytes": 2010, "real_tx_bytes": 1020
        ])!
        counter.timestamp = Date(timeIntervalSince1970: 2)
        let delta = DeviceParser.computeSpeed(previous: old, current: counter)
        precondition(delta.downloadBytesPerSec == 1000 && delta.uploadBytesPerSec == 500)
        counter.source = "agent"
        precondition(DeviceParser.computeSpeed(previous: old, current: counter) == .zero)
        counter.source = "wwandst"
        counter.rxBytes = 0
        counter.txBytes = 0
        precondition(DeviceParser.computeSpeed(previous: old, current: counter) == .zero)
        print("Traffic speed regression checks passed")
    }
}
