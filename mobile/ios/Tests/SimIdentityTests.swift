import Foundation

// Run from the repository root: sh scripts/test-router-esim.sh
@main
struct SimIdentityTests {
    /// Decodes the way AgentClient does, so numbers arrive as NSNumber.
    static func data(_ json: String) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    }

    static func stamp(_ instance: UInt64, _ epoch: UInt64, _ phase: String) -> [String: Any] {
        data(#"{"rssi":-71,"agent_instance":\#(instance),"sim_epoch":\#(epoch),"sim_phase":"\#(phase)"}"#)
    }

    static func main() {
        let run: UInt64 = 1760860000000
        var tracker = SimIdentityTracker()
        precondition(!tracker.observe(stamp(run, 0, "idle")), "The first sighting only seeds")
        precondition(!tracker.observe(stamp(run, 0, "idle")), "An identical triple is no change")
        precondition(tracker.observe(stamp(run, 0, "leaving")), "A phase change is a change")
        precondition(tracker.observe(stamp(run, 1, "changed")), "An epoch change is a change")
        precondition(!tracker.observe(stamp(run, 1, "changed")))
        precondition(!tracker.observe(stamp(run, 0, "leaving")), "A late reply from before the change is ignored")
        precondition(!tracker.observe(stamp(run, 0, "online")), "An older epoch is ignored whatever its phase")
        precondition(tracker.observe(stamp(run, 1, "online")), "The same epoch moving on is a change")
        precondition(tracker.observe(stamp(run + 1, 0, "idle")), "A restarted agent is a change, even at a lower epoch")
        precondition(!tracker.observe(stamp(run + 1, 0, "idle")))
        precondition(tracker.observe(stamp(run, 0, "idle")), "Another router or run compares by equality only")

        precondition(!tracker.observe(nil), "No payload")
        precondition(!tracker.observe(data(#"{"rssi":-71}"#)), "Older agents send no stamp")
        precondition(!tracker.observe(data(#"{"agent_instance":1760860000000,"sim_epoch":1}"#)), "A stamp missing its phase is ignored")
        precondition(!tracker.observe(data(#"{"agent_instance":null,"sim_epoch":3,"sim_phase":"online"}"#)))
        precondition(tracker.observe(stamp(run, 0, "online")), "Ignored payloads leave the last identity in place")

        var fresh = SimIdentityTracker()
        precondition(!fresh.observe(data(#"{"sim_phase":"online"}"#)) && !fresh.observe(stamp(run, 2, "online")),
                     "A payload without the fields does not count as the first sighting")
        precondition(fresh.observe(stamp(run, 3, "changed")))

        print("SimIdentityTests: seeding, phase, epoch and instance changes, late replies and older agents passed")
    }
}
