import Foundation

/// Follows the SIM identity stamp the agent writes inside `data` of `/api/network/signal`,
/// `/api/sim/info` and `/api/esim/switch`: `agent_instance`, `sim_epoch` and `sim_phase`.
///
/// The epoch moves when another profile or card is read (about 4 s into a switch), the phase
/// when the router leaves the old SIM and when the WAN is up on the new one (about 35 s in), so
/// a change of the triple is the moment to re-read everything that belongs to the SIM. Older
/// agents send none of the keys and never trigger a refresh.
struct SimIdentityTracker {
    private var last: (instance: UInt64, epoch: UInt64, phase: String)?

    /// Records one response and returns true when it shows a new identity or phase. The first
    /// sighting only seeds; an epoch below the last one from the same agent run is a reply that
    /// arrived late and is ignored. `agent_instance` is compared for equality only: it is the
    /// router's wall clock at agent start, which jumps.
    mutating func observe(_ data: [String: Any]?) -> Bool {
        guard let data,
              let instance = (data["agent_instance"] as? NSNumber)?.uint64Value,
              let epoch = (data["sim_epoch"] as? NSNumber)?.uint64Value,
              let phase = data["sim_phase"] as? String else { return false }
        guard let last else {
            self.last = (instance, epoch, phase)
            return false
        }
        if instance == last.instance {
            if epoch < last.epoch { return false }
            if epoch == last.epoch && phase == last.phase { return false }
        }
        self.last = (instance, epoch, phase)
        return true
    }
}
