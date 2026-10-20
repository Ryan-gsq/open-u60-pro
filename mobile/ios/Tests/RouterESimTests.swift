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
        let inv = RouterESimParser.parseInventory(data(#"""
        {"agent_instance":1792300000000,"generation":3,"observed_at":1792300100,"updating":false,"stale":true,
         "error":{"kind":"sim_reloading","message":"euicc_init","at":1792300110},"pending_receipts":1,
         "profiles":[{"class":"operational","iccid":"8963000000000000001","state":"enabled","provider":"SMART","name":"Operational","nickname":null}]}
        """#))
        precondition(inv.agentInstance == 1792300000000 && inv.generation == 3 && inv.observedAt == 1792300100)
        precondition(inv.stale && !inv.updating && inv.pendingReceipts == 1 && inv.profiles.count == 1)
        precondition(inv.errorText == "The eSIM is still settling after the switch.")
        var older = inv; older.generation = 2
        precondition(older.isOlder(than: inv) && !inv.isOlder(than: older))
        var sameGenEarlier = inv; sameGenEarlier.observedAt -= 1
        precondition(sameGenEarlier.isOlder(than: inv))
        var otherRun = inv; otherRun.agentInstance += 1; otherRun.generation = 0
        precondition(!otherRun.isOlder(than: inv), "A restarted agent's answer is never treated as older")
        precondition(!RouterESimParser.parseInventory(["profiles": []]).isOlder(than: inv), "Older agents carry no counters")
        precondition(RouterESimParser.parseInventory(data(#"{"profiles":[],"error":null,"pending_receipts":null}"#)).errorText == nil)

        // The read counter orders reads of one generation; the router clock jumps hours on attach.
        let jumped = RouterESimParser.parseInventory(data(#"{"agent_instance":5,"generation":2,"observed_at":28900,"observed_seq":4,"profiles":[]}"#))
        let afterJump = RouterESimParser.parseInventory(data(#"{"agent_instance":5,"generation":2,"observed_at":100,"observed_seq":5,"profiles":[]}"#))
        precondition(jumped.observedSeq == 4 && afterJump.observedSeq == 5)
        precondition(!afterJump.isOlder(than: jumped) && jumped.isOlder(than: afterJump),
                     "A later read stamped before the clock jump's time is still the newer one")
        var noSeq = afterJump; noSeq.observedSeq = 0
        precondition(noSeq.isOlder(than: jumped) && !jumped.isOlder(than: noSeq), "Without the counter on one side, read times decide")
        var shownNoSeq = jumped; shownNoSeq.observedSeq = 0
        precondition(afterJump.isOlder(than: shownNoSeq), "Without the counter on the shown side, read times decide")
        var nextGeneration = jumped; nextGeneration.generation = 3; nextGeneration.observedSeq = 1
        precondition(!nextGeneration.isOlder(than: afterJump), "The change counter still comes first")

        // Pre-switch warnings: advisory sentences naming the APN and the target.
        let warned = RouterESimParser.parseInventory(data(#"""
        {"agent_instance":5,"generation":2,"observed_seq":6,"manual_apn":{"name":"Office","apn":"internet.example"},
         "profiles":[
          {"class":"operational","iccid":"8963000000000000001","state":"enabled","provider":"SMART","name":"Operational","nickname":null},
          {"class":"operational","iccid":"8965000000000000002","state":"disabled","provider":"Travel","name":"","nickname":"Trip",
           "switch_warnings":["manual_apn","roaming_off","future_code"]},
          {"class":"operational","iccid":"8963000000000000003","state":"disabled","provider":"GOMO","name":"","nickname":null,
           "switch_warnings":["manual_apn"]}]}
        """#))
        precondition(warned.manualAPN == RouterESimManualAPN(name: "Office", apn: "internet.example"))
        precondition(warned.profiles[0].switchWarnings.isEmpty && warned.profiles[2].switchWarnings == ["manual_apn"])
        precondition(warned.profiles[1].switchWarnings == ["manual_apn", "roaming_off", "future_code"])
        let travel = warned.switchWarnings(for: warned.profiles[1])
        precondition(travel == [
            "The router is set to the manual APN “internet.example”. If Trip needs a different APN, change it in Mobile Network after switching, or it may have no data.",
            "Trip looks like a travel (roaming) profile and Data Roaming is off, so it will have no data until you turn Data Roaming on."
        ], "Both known codes name the APN and the target; the unknown one is skipped")
        precondition(warned.switchWarnings(for: warned.profiles[2]).count == 1)
        precondition(warned.switchWarnings(for: warned.profiles[0]).isEmpty)
        var stillListed = warned.profiles[1]; stillListed.switchWarnings = []
        precondition(warned.switchWarnings(for: stillListed).count == 2, "The dialog's profile takes the list's current codes")
        let apnOff = RouterESimParser.parseInventory(data(#"""
        {"manual_apn":null,"profiles":[{"class":"operational","iccid":"8965000000000000002","state":"disabled","provider":"Travel",
          "switch_warnings":["roaming_off","manual_apn"]}]}
        """#))
        precondition(apnOff.manualAPN == nil)
        precondition(apnOff.switchWarnings(for: apnOff.profiles[0]) == [
            "Travel looks like a travel (roaming) profile and Data Roaming is off, so it will have no data until you turn Data Roaming on."
        ], "manual_apn without the APN itself is skipped")
        let olderAgent = RouterESimParser.parseInventory(data(#"""
        {"agent_instance":5,"generation":2,"observed_at":100,
         "profiles":[{"class":"operational","iccid":"8965000000000000002","state":"disabled","provider":"Travel"}]}
        """#))
        precondition(olderAgent.observedSeq == 0 && olderAgent.manualAPN == nil && olderAgent.profiles[0].switchWarnings.isEmpty)
        precondition(olderAgent.switchWarnings(for: olderAgent.profiles[0]).isEmpty, "An older agent's list gives no warnings")

        let sw = try! JSONDecoder().decode(RouterESimSwitchStatus.self, from: Data(#"{"state":"card_confirmed","target_iccid":"8963000000000000002","generation":4,"started_at":1,"card_confirmed_at":7,"finished_at":0,"note":null}"#.utf8))
        precondition(sw.isRunning && sw.cardConfirmed && sw.phase == .registering && sw.targetICCID == "8963000000000000002")
        for (state, phase, running) in [("reloading", RouterESimConnectionPhase.reloading, true), ("connected", .connected, false),
                                        ("no_data", .waiting, false), ("modem_unconfirmed", .waiting, false), ("not_applied", .unavailable, false)] {
            let st = RouterESimSwitchStatus(state: state)
            precondition(st.phase == phase && st.isRunning == running, state)
        }
        precondition(!RouterESimSwitchStatus(state: "reloading").cardConfirmed && RouterESimSwitchStatus(state: "connected").outcomeNote == nil)
        precondition(RouterESimSwitchStatus(state: "modem_unconfirmed").outcomeNote?.contains("Restart the router") == true)
        let roaming = try! JSONDecoder().decode(RouterESimSwitchStatus.self, from: Data(#"{"state":"no_data","reason":"roaming_off","note":null}"#.utf8))
        precondition(roaming.outcomeNote?.contains("Turn on Data Roaming") == true, "a roaming profile names the fix")
        precondition(RouterESimSwitchStatus(state: "no_data", reason: "data_off").outcomeNote?.contains("Mobile Data is off") == true)
        precondition(RouterESimSwitchStatus(state: "no_data").outcomeNote?.contains("plan or coverage") == true)
        let busy = RouterESimSwitchStatus(state: "card_busy")
        precondition(busy.isRunning && !busy.cardConfirmed && busy.phase == .switching, "a busy retry is still a switch in progress")
        precondition(busy.progressNote?.contains("keeps trying") == true && busy.outcomeNote == nil)
        precondition(RouterESimSwitchStatus(state: "not_applied", reason: "card_busy").outcomeNote?.contains("stayed busy") == true)
        precondition(RouterESimSwitchStatus(state: "not_applied").outcomeNote?.contains("didn't happen") == true)
        precondition(RouterESimSwitchStatus(state: "connected").progressNote == nil)

        print("RouterESimTests: identifiers, reconnection, activation codes, download stages, read ordering, and switch warnings passed")
    }
}
