import Foundation

/// One profile on the eSIM in the router (GET /api/esim/profiles; the agent runs lpac).
struct RouterESimProfile: Identifiable, Equatable {
    let iccid: String
    let provider: String
    let name: String
    let nickname: String
    let isEnabled: Bool
    let profileClass: String

    var id: String { iccid }

    /// The nickname when set, otherwise the operator's profile name.
    var displayName: String {
        if !nickname.isEmpty { return nickname }
        return name.isEmpty ? provider : name
    }

    /// Only ordinary operator profiles can be switched to (the agent refuses test profiles).
    var canEnable: Bool { !isEnabled && profileClass == "operational" }
}

/// Identity and capacity of the eSIM chip (GET /api/esim/chip).
struct RouterESimChip: Equatable {
    var eid: String = ""
    var firmware: String = ""
    var freeMemoryBytes: Int?

    static let empty = RouterESimChip()
}

/// GET /api/esim/profiles: the list plus how fresh it is. While a switch reloads the SIM, or
/// another eSIM operation holds the card, the agent answers with its last good list marked
/// `updating`; a failed read returns that list as `stale` with `error`.
struct RouterESimInventory: Equatable {
    var profiles: [RouterESimProfile] = []
    var observedAt: UInt64 = 0
    var generation: UInt64 = 0
    var agentInstance: UInt64 = 0
    var updating = false
    var stale = false
    var errorKind: String?
    var errorMessage: String?
    var pendingReceipts: Int?

    /// True when this answer predates the one on screen (same agent run, older change counter
    /// or older read) and must be ignored. Answers from older agents carry no counters.
    func isOlder(than shown: RouterESimInventory) -> Bool {
        guard agentInstance != 0, agentInstance == shown.agentInstance else { return false }
        if generation != shown.generation { return generation < shown.generation }
        return observedAt < shown.observedAt
    }

    /// Text for a failed read; `nil` when the list is current.
    var errorText: String? {
        guard let errorMessage else { return nil }
        switch errorKind {
        case "sim_reloading": return "The eSIM is still settling after the switch."
        case "management_unavailable": return "The eSIM's management app isn't responding (\(errorMessage))."
        case "not_installed": return "The eSIM manager (lpac) isn't installed on the router."
        default: return errorMessage
        }
    }
}

/// GET /api/esim/switch: the agent's verified progress of the last switch.
struct RouterESimSwitchStatus: Decodable, Equatable {
    var state: String = "idle"
    var targetICCID: String?
    var generation: UInt64?
    var startedAt: UInt64?
    var finishedAt: UInt64?
    var note: String?
    /// Why data didn't connect, when the router knows: `roaming_off` or `data_off`.
    var reason: String?

    private enum CodingKeys: String, CodingKey {
        case state, generation, note, reason
        case targetICCID = "target_iccid"
        case startedAt = "started_at"
        case finishedAt = "finished_at"
    }

    var isRunning: Bool { ["card_busy", "reloading", "card_confirmed", "modem_confirmed"].contains(state) }

    /// The card is confirmed: a list read now shows the new active profile.
    var cardConfirmed: Bool { !["idle", "card_busy", "reloading", "card_unconfirmed"].contains(state) }

    var phase: RouterESimConnectionPhase {
        switch state {
        case "card_busy": .switching
        case "reloading": .reloading
        case "card_confirmed", "modem_confirmed": .registering
        case "connected": .connected
        case "no_data", "modem_unconfirmed", "card_unconfirmed": .waiting
        case "not_applied": .unavailable
        default: .checking
        }
    }

    /// Shown while the switch runs: the eSIM refused for now and the router keeps trying.
    var progressNote: String? {
        state == "card_busy" ? "The eSIM is busy and refused the switch for now. The router keeps trying for up to 4 minutes." : nil
    }

    /// Why a finished switch did not reach `connected`.
    var outcomeNote: String? {
        switch state {
        case "no_data":
            switch reason {
            case "roaming_off": "This profile roams on a local network and Data Roaming is off. Turn on Data Roaming in Mobile Network."
            case "data_off": "The profile is active, but Mobile Data is off. Turn it on in Mobile Network."
            default: "The profile is active, but mobile data hasn't connected. Check the plan or coverage."
            }
        case "modem_unconfirmed": "The eSIM switched, but the router still uses the previous SIM. Restart the router to finish."
        case "card_unconfirmed": "The eSIM couldn't be read after the switch. Refresh in a moment."
        case "not_applied":
            reason == "card_busy"
                ? "The eSIM stayed busy and didn't switch; the previous profile is still active. Try again in a few minutes."
                : "The switch didn't happen; the previous profile is still active."
        default: nil
        }
    }
}

enum RouterESimParser {
    static func parseInventory(_ data: [String: Any]) -> RouterESimInventory {
        let error = data["error"] as? [String: Any]
        return RouterESimInventory(
            profiles: parseProfiles(data),
            observedAt: asUInt64(data["observed_at"]),
            generation: asUInt64(data["generation"]),
            agentInstance: asUInt64(data["agent_instance"]),
            updating: data["updating"] as? Bool ?? false,
            stale: data["stale"] as? Bool ?? false,
            errorKind: error?["kind"] as? String,
            errorMessage: error?["message"] as? String,
            pendingReceipts: asInt(data["pending_receipts"])
        )
    }

    static func parseProfiles(_ data: [String: Any]) -> [RouterESimProfile] {
        guard let items = data["profiles"] as? [[String: Any]] else { return [] }
        return items.compactMap { item in
            guard let iccid = item["iccid"] as? String, !iccid.isEmpty else { return nil }
            return RouterESimProfile(
                iccid: iccid,
                provider: item["provider"] as? String ?? "",
                name: item["name"] as? String ?? "",
                nickname: item["nickname"] as? String ?? "",
                isEnabled: (item["state"] as? String) == "enabled",
                profileClass: item["class"] as? String ?? ""
            )
        }
    }

    static func parseChip(_ data: [String: Any]) -> RouterESimChip {
        RouterESimChip(
            eid: data["eid"] as? String ?? "",
            firmware: data["firmware"] as? String ?? "",
            freeMemoryBytes: asInt(data["free_nvm_bytes"])
        )
    }

    private static func asUInt64(_ value: Any?) -> UInt64 {
        if let n = value as? NSNumber { return n.uint64Value }
        if let s = value as? String { return UInt64(s) ?? 0 }
        return 0
    }

    private static func asInt(_ value: Any?) -> Int? {
        if let i = value as? Int { return i }
        if let d = value as? Double { return Int(d) }
        if let s = value as? String { return Int(s) }
        return nil
    }
}

/// Screen-only connection state, separate from whether a profile is active on the card.
enum RouterESimConnectionPhase: String, Equatable {
    case checking, disconnected, switching, reloading, registering, connected, waiting, unavailable

    var blocksSwitching: Bool { self == .switching || self == .reloading || self == .registering }
}

/// The modem's connection response can be cached for 30 seconds. Never mistake the previous
/// profile's cached connection for recovery: require the new SIM identity plus a disconnect,
/// or an expired cache window, and two connected observations.
struct RouterESimReconnectTracker {
    let targetICCID: String
    private var sawDisconnect = false
    private var connectedObservations = 0

    init(targetICCID: String) { self.targetICCID = targetICCID }

    static func isConnected(_ status: String) -> Bool {
        ["connected", "ipv4_connected", "ipv6_connected", "ipv4_ipv6_connected"]
            .contains(status.lowercased().trimmingCharacters(in: .whitespacesAndNewlines))
    }

    mutating func phase(simICCID: String, status: String, elapsed: TimeInterval) -> RouterESimConnectionPhase {
        let connected = Self.isConnected(status)
        if !status.isEmpty && !connected { sawDisconnect = true }
        let matches = !simICCID.isEmpty && normalized(simICCID) == normalized(targetICCID)
        if matches && connected && (sawDisconnect || elapsed >= 35) {
            connectedObservations += 1
            if connectedObservations >= 2 { return .connected }
        } else {
            connectedObservations = 0
        }
        if elapsed >= 120 { return .waiting }
        return matches ? .registering : .reloading
    }

    private func normalized(_ value: String) -> String {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if result.hasSuffix("F") { result.removeLast() }
        return result
    }
}

/// Kept only in the add screen's memory. Never persist or log activation codes.
struct RouterESimActivationCode {
    let value: String
    let server: String
    let needsConfirmationCode: Bool

    static let invalidMessage = "This QR code isn't an eSIM activation code."

    static func parse(_ input: String) -> Self? {
        let code = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.utf8.count <= 512, code.lowercased().hasPrefix("lpa:"),
              !code.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains($0) }) else { return nil }
        let parts = code.dropFirst(4).split(separator: "$", omittingEmptySubsequences: false).map(String.init)
        guard (3...5).contains(parts.count), parts[0] == "1", !parts[1].isEmpty,
              parts[1].utf8.allSatisfy({ asciiAlphanumeric($0) || [46, 45, 58].contains($0) }),
              parts[2].utf8.allSatisfy({ asciiAlphanumeric($0) || $0 == 45 }) else { return nil }
        return Self(value: "LPA:" + code.dropFirst(4), server: parts[1],
                    needsConfirmationCode: parts.count == 5 && parts[4] == "1")
    }

    static func validConfirmationCode(_ code: String) -> Bool {
        !code.isEmpty && code.utf8.count <= 64 && !code.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    }

    private static func asciiAlphanumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
    }
}

struct RouterESimDownloadStatus: Decodable, Equatable {
    var state: String = "idle"
    var step: String?
    var provider: String?
    var name: String?
    var iccid: String?
    var error: String?
    var startedAt: UInt64?
    var finishedAt: UInt64?

    private enum CodingKeys: String, CodingKey {
        case state, step, provider, name, iccid, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
    }

    var isBusy: Bool { ["running", "confirm", "cancelling"].contains(state) }
    var canCancel: Bool { ["running", "confirm"].contains(state) && step != "es10b_load_bound_profile_package" }
    var displayName: String { [provider, name].compactMap { $0 }.first(where: { !$0.isEmpty }) ?? "eSIM profile" }
    var progressText: String {
        if state == "confirm" { return "Ready to install" }
        if state == "cancelling" || step?.hasSuffix("_cancel_session") == true { return "Cancelling…" }
        if state == "done" { return "\(displayName) added." }
        if state == "failed" { return "Couldn’t add the profile" }
        if state == "cancelled" { return "Download cancelled" }
        switch step {
        case "es9p_initiate_authentication", "es10b_authenticate_server", "es9p_authenticate_client": return "Connecting to the operator…"
        case "es8p_metadata_parse": return "Reading profile details…"
        case "es10b_prepare_download", "es9p_get_bound_profile_package": return "Downloading profile…"
        case "es10b_load_bound_profile_package": return "Installing on the eSIM…"
        default: return "Preparing eSIM…"
        }
    }
}
