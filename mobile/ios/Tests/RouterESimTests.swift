import Foundation

// Run from the repository root: sh scripts/test-router-esim.sh
@main
struct RouterESimTests {
    /// Decodes the way AgentClient does, so numbers arrive as NSNumber and null as NSNull.
    static func data(_ json: String) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    }

    static func main() {
        let list = RouterESimParser.parseProfiles(data(#"""
        {"enabled_iccid":"8963000000000000001","profiles":[
          {"class":"operational","iccid":"8963000000000000001","isdp_aid":"a0","name":"Operational","nickname":"Smart","provider":"SMART","state":"enabled"},
          {"class":"operational","iccid":"8963000000000000002","isdp_aid":"a1","name":"Globe Philippines ODC","nickname":null,"provider":"GOMO","state":"disabled"},
          {"class":"test","iccid":"8963000000000000003","isdp_aid":"a2","name":"","nickname":null,"provider":"Test","state":"disabled"},
          {"class":"operational","iccid":"","state":"disabled"}]}
        """#))
        precondition(list.count == 3, "entries without an ICCID are dropped")
        precondition(list[0].isEnabled && list[0].displayName == "Smart" && !list[0].canEnable)
        precondition(!list[1].isEnabled && list[1].displayName == "Globe Philippines ODC" && list[1].canEnable)
        precondition(list[1].nickname.isEmpty, "JSON null nickname reads as empty")
        precondition(list[2].displayName == "Test" && !list[2].canEnable, "test profiles cannot be enabled")

        precondition(RouterESimParser.parseProfiles(data(#"{"profiles":null}"#)).isEmpty)
        precondition(RouterESimParser.parseProfiles([:]).isEmpty)

        let chip = RouterESimParser.parseChip(data(#"{"eid":"89000000000000000000000000000001","firmware":"4.2.0","free_nvm_bytes":972020,"free_ram_bytes":16574}"#))
        precondition(chip.eid.hasPrefix("890000") && chip.firmware == "4.2.0" && chip.freeMemoryBytes == 972020)
        precondition(RouterESimParser.parseChip([:]) == .empty)

        precondition(!RouterESimReconnectTracker.isConnected("disconnected"))
        precondition(!RouterESimReconnectTracker.isConnected("connecting"))
        precondition(RouterESimReconnectTracker.isConnected("ipv4_ipv6_connected"))
        var tracker = RouterESimReconnectTracker(targetICCID: "8963000000000000002")
        precondition(tracker.phase(simICCID: "8963000000000000001", status: "connected", elapsed: 3) == .reloading)
        precondition(tracker.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 6) == .registering,
                     "old cached connectivity cannot confirm a new SIM")
        precondition(tracker.phase(simICCID: "8963000000000000002", status: "disconnected", elapsed: 9) == .registering)
        precondition(tracker.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 26) == .registering)
        precondition(tracker.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 29) == .connected)
        var missedDrop = RouterESimReconnectTracker(targetICCID: "8963000000000000002F")
        precondition(missedDrop.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 34) == .registering)
        precondition(missedDrop.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 35) == .registering)
        precondition(missedDrop.phase(simICCID: "8963000000000000002", status: "connected", elapsed: 38) == .connected)
        var waiting = RouterESimReconnectTracker(targetICCID: "8963000000000000002")
        precondition(waiting.phase(simICCID: "8963000000000000001", status: "connected", elapsed: 120) == .waiting)
        precondition(waiting.phase(simICCID: "8963000000000000001", status: "connected", elapsed: 150) == .waiting,
                     "a different SIM must never be reported as recovered")
        let activation = RouterESimActivationCode.parse("  \nlpa:1$smdp.example.com:443$ABC-123\n ")!
        precondition(activation.value == "LPA:1$smdp.example.com:443$ABC-123" && activation.server == "smdp.example.com:443")
        precondition(!activation.needsConfirmationCode)
        precondition(RouterESimActivationCode.parse("LPA:1$smdp.example.com$ABC123$1.3.6.1$1")!.needsConfirmationCode)
        precondition(RouterESimActivationCode.parse("LPA:1$smdp.example.com$$$") != nil)
        for invalid in ["https://example.com", "LPA:2$server$ABC", "LPA:1$$ABC", "LPA:1$server", "LPA:1$server$AB C", "LPA:1$server$AB_C", "LPA:1$server$ABC\nDEF", "LPA:1$server$ABC$0$1$extra", "LPA:1$server$" + String(repeating: "A", count: 513)] {
            precondition(RouterESimActivationCode.parse(invalid) == nil)
        }
        precondition(RouterESimActivationCode.validConfirmationCode("123456"))
        precondition(!RouterESimActivationCode.validConfirmationCode(""))
        precondition(!RouterESimActivationCode.validConfirmationCode(String(repeating: "1", count: 65)))
        precondition(!RouterESimActivationCode.validConfirmationCode("123\n"))
        let status = try! JSONDecoder().decode(RouterESimDownloadStatus.self, from: Data(#"{"state":"confirm","step":"es8p_metadata_parse","provider":"GOMO","name":"Globe","iccid":"8963000000000000002","error":null,"started_at":123}"#.utf8))
        precondition(status.iccid == "8963000000000000002" && status.isBusy && status.canCancel)
        precondition(status.progressText == "Ready to install")
        var install = status
        install.state = "running"; install.step = "es10b_load_bound_profile_package"
        precondition(install.isBusy && !install.canCancel && install.progressText == "Installing on the eSIM…")
        install.state = "cancelling"
        precondition(install.isBusy && !install.canCancel && install.progressText == "Cancelling…")
        install.state = "done"
        precondition(!install.isBusy && !install.canCancel && install.progressText == "GOMO added.")
        print("RouterESimTests: identifiers, reconnection, activation codes, and download stages passed")
    }
}
