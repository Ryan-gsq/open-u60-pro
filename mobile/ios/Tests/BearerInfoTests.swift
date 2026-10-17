import Foundation

// Run from the repository root: sh scripts/test-ios-traffic.sh
@main
struct BearerInfoTests {
    /// Decodes the way AgentClient does, so numbers arrive as NSNumber.
    static func signalData(_ json: String) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    }

    static func main() {
        let sa = SignalParser.parseBearer(signalData(#"{"network_type":"NR5G-SA","bearer":{"qci":6,"ambr_dl_mbps":2000.0,"ambr_ul_mbps":200.0}}"#))
        precondition(sa == BearerInfo(qci: 6, ambrDownlinkMbps: 2000, ambrUplinkMbps: 200))
        precondition(sa?.ambrText == "2000 / 200 Mbps")

        let lte = SignalParser.parseBearer(signalData(#"{"bearer":{"qci":9,"ambr_dl_mbps":1200.0,"ambr_ul_mbps":8.64}}"#))
        precondition(lte?.ambrText == "1200 / 8.64 Mbps")

        // Above parseDouble's ±9000 sentinel cut-off.
        let fast = SignalParser.parseBearer(signalData(#"{"bearer":{"qci":9,"ambr_dl_mbps":10000,"ambr_ul_mbps":2000}}"#))
        precondition(fast?.ambrDownlinkMbps == 10000)

        let qciOnly = SignalParser.parseBearer(signalData(#"{"bearer":{"qci":8,"ambr_dl_mbps":null,"ambr_ul_mbps":null}}"#))
        precondition(qciOnly == BearerInfo(qci: 8) && qciOnly?.ambrText == nil)

        let ambrOnly = SignalParser.parseBearer(signalData(#"{"bearer":{"qci":null,"ambr_dl_mbps":0.5,"ambr_ul_mbps":null}}"#))
        precondition(ambrOnly?.qci == nil && ambrOnly?.ambrText == "0.5 / -- Mbps")

        // Down session, older agent, nothing usable.
        precondition(SignalParser.parseBearer(signalData(#"{"bearer":null}"#)) == nil)
        precondition(SignalParser.parseBearer(signalData(#"{"nr5g_rsrp":"-90"}"#)) == nil)
        precondition(SignalParser.parseBearer(signalData(#"{"bearer":{"qci":0,"ambr_dl_mbps":0,"ambr_ul_mbps":-1}}"#)) == nil)

        precondition(BearerInfo.formatMbps(1200.0000000000002) == "1200")
        precondition(BearerInfo.formatMbps(0.03) == "0.03")
        print("11 bearer parsing and format checks passed")
    }
}
