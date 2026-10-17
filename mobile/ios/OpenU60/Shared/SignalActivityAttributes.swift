import ActivityKit
import Foundation

struct SignalActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable, Sendable {
        var schemaVersion: Int = 1
        var sampledAt: UInt64
        var lteRsrp: Double?
        var nrRsrp: Double?
        var lteBars: Int?
        var nrBars: Int?
        var lteSinr: Double?
        var nrSinr: Double?
        var networkType: String?
        var lteCarrierCount: Int?

        var mode: SignalActivityMode {
            SignalActivityMode(networkType: networkType, lteCarrierCount: lteCarrierCount)
        }

        static func carrierCount(_ raw: String?) -> Int? {
            guard let raw, !raw.isEmpty else { return nil }
            let carriers = raw.split(separator: ";").compactMap { row -> String? in
                let columns = row.split(separator: ",", omittingEmptySubsequences: false)
                guard columns.count >= 5, let pci = Int(columns[0]), (0...503).contains(pci),
                      let band = Int(columns[1]), band > 0,
                      let channel = Int(columns[3]), channel >= 0 else { return nil }
                return "\(pci):\(band):\(channel)"
            }
            return carriers.isEmpty ? nil : Set(carriers).count
        }

        static func sample(_ data: [String: Any], at date: Date) -> Self {
            func number(_ name: String, range: ClosedRange<Double>) -> Double? {
                let value = (data[name] as? NSNumber)?.doubleValue
                    ?? (data[name] as? String).flatMap(Double.init)
                return value.flatMap { $0.isFinite && range.contains($0) ? $0 : nil }
            }
            func bars(_ value: Double?) -> Int? {
                value.map { $0 >= -80 ? 4 : $0 >= -90 ? 3 : $0 >= -100 ? 2 : $0 >= -110 ? 1 : 0 }
            }
            let lte = number("lte_rsrp", range: -160 ... -20)
            let nr = number("nr5g_rsrp", range: -160 ... -20)
            return Self(sampledAt: UInt64(max(0, date.timeIntervalSince1970)),
                        lteRsrp: lte, nrRsrp: nr, lteBars: bars(lte), nrBars: bars(nr),
                        lteSinr: number("lte_snr", range: -50 ... 100),
                        nrSinr: number("nr5g_snr", range: -50 ... 100),
                        networkType: data["network_type"] as? String,
                        lteCarrierCount: carrierCount(data["lteca"] as? String))
        }
    }

    let gateway: String
    let expiresAt: UInt64
}
