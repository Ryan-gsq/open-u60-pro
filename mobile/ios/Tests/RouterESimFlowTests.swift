import Foundation

/// In-memory transport: exercises the real view model without touching an eSIM or network.
@MainActor
final class AgentClient {
    var requests: [String] = []
    var bodies: [[String: Any]] = []
    var status: [String: Any] = ["state": "idle"]
    var switchStatus: [String: Any] = ["state": "idle"]
    var inventoryMeta: [String: Any] = [:]
    var postResult: [String: Any] = [:]
    var postError: Error?
    var holdStatus = false
    var statusGate: CheckedContinuation<Void, Never>?
    var entries: [[String: Any]] = [
        ["iccid": "8963000000000000001", "provider": "Smart", "class": "operational", "state": "enabled"],
        ["iccid": "8963000000000000002", "provider": "GOMO", "class": "operational", "state": "disabled"]
    ]
    func get<T: Decodable>(_ path: String) async throws -> T {
        requests.append("GET " + path)
        if holdStatus { await withCheckedContinuation { statusGate = $0 } }
        let source = path == "/api/esim/switch" ? switchStatus : status
        return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: source))
    }
    func getJSON(_ path: String) async throws -> [String: Any] {
        requests.append("GET " + path)
        switch path {
        case "/api/esim/profiles": return inventoryMeta.merging(["profiles": entries]) { _, new in new }
        case "/api/esim/chip": return ["eid": "89000000000000000000000000000001", "firmware": "4.2.0"]
        case "/api/modem/data": return ["connect_status": "connected"]
        default: return [:]
        }
    }
    func postJSON(_ path: String, body: [String: Any]) async throws -> [String: Any] {
        requests.append("POST " + path); bodies.append(body)
        if let postError { throw postError }
        if path == "/api/esim/delete" { entries.removeAll { $0["iccid"] as? String == body["iccid"] as? String } }
        return postResult
    }
}
@MainActor final class AuthManager {}

@main
struct RouterESimFlowTests {
    @MainActor static func main() async {
        let client = AgentClient()
        let vm = RouterESimViewModel(client: client, authManager: AuthManager())
        await vm.refresh()
        precondition(Array(client.requests.prefix(3)) == ["GET /api/esim/download", "GET /api/esim/profiles", "GET /api/esim/chip"], "Discover background work before sequential card reads")
        let beforeRetry = client.requests.count
        await vm.retryProfiles()
        precondition(Array(client.requests.dropFirst(beforeRetry)) == ["GET /api/esim/profiles"],
                     "A list retry must only read profiles, never repeat a switch or access other card data")
        let active = vm.profiles[0], other = vm.profiles[1]
        vm.requestDelete(active)
        precondition(vm.pendingDelete == nil, "The active profile cannot be deleted")
        client.postResult = ["state": "confirm", "provider": "GOMO", "name": "Globe", "started_at": 1]
        await vm.startDownload(code: " lpa:1$example.com$ABC$1.2.3$1 ", confirmationCode: "")
        precondition(client.bodies.isEmpty, "A missing required confirmation code must not reach the router")
        await vm.startDownload(code: " lpa:1$example.com$ABC$1.2.3$1 ", confirmationCode: "1234")
        precondition(client.bodies.last?["activation_code"] as? String == "LPA:1$example.com$ABC$1.2.3$1")
        precondition(client.bodies.last?["preview"] as? Bool == true)
        precondition(vm.download.state == "confirm" && vm.blocksSwitching)
        let beforeBlockedRetry = client.requests.count
        await vm.retryProfiles()
        precondition(client.requests.count == beforeBlockedRetry, "A list retry must respect the download's exclusive card access")
        vm.requestSwitch(to: other); vm.requestDelete(other)
        precondition(vm.pendingSwitch == nil && vm.pendingDelete == nil, "Download excludes switch/delete")
        let readsBeforeRefresh = client.requests.filter { $0 == "GET /api/esim/profiles" }.count
        client.status = client.postResult
        await vm.refresh()
        precondition(client.requests.filter { $0 == "GET /api/esim/profiles" }.count == readsBeforeRefresh, "Never read the card during a download")
        client.postError = AgentError.serverError("{\"ok\":false,\"error\":\"agent password required\"}")
        await vm.confirmDownload()
        precondition(vm.downloadNote == "agent password required", "Successful status reads must not hide a rejected Install action")
        client.postError = nil
        client.postResult = ["state": "running", "step": "es10b_load_bound_profile_package", "started_at": 1]
        await vm.confirmDownload()
        precondition(client.bodies.last?["accept"] as? Bool == true)
        let postsBeforeCancel = client.bodies.count
        await vm.cancelDownload()
        precondition(client.bodies.count == postsBeforeCancel, "No cancellation during installation")
        client.status = ["state": "done", "provider": "GOMO", "iccid": other.iccid, "started_at": 1]
        await vm.retryDownloadStatus()
        precondition(!vm.blocksSwitching && vm.download.state == "done")
        precondition(Array(client.requests.suffix(3)) == ["GET /api/esim/download", "GET /api/esim/profiles", "GET /api/esim/chip"], "Refresh card after completion")
        vm.resetDownloadResult()
        await vm.refresh()
        precondition(vm.download.state == "idle", "An acknowledged old result must not replace a new add form")
        client.postResult = ["deleted_iccid": other.iccid, "operator_notified": false]
        vm.requestDelete(other); vm.pendingDelete = nil // the dialog clears it when it closes
        await vm.confirmDelete(other)
        precondition(vm.profiles.count == 1 && vm.profiles[0].isEnabled)
        precondition(vm.message?.contains("next eSIM change") == true)
        client.postError = AgentError.serverError("{\"ok\":false,\"error\":\"agent password required\"}")
        client.status = ["state": "idle"]
        await vm.startDownload(code: "LPA:1$example.com$ABC", confirmationCode: "")
        precondition(vm.downloadNote == "agent password required", "Show the agent's text without the JSON envelope")
        client.postError = nil
        client.postResult = ["state": "running", "step": "starting", "started_at": 2]
        await vm.startDownload(code: "LPA:1$example.com$ABC", confirmationCode: "")
        client.postResult = ["state": "cancelling", "started_at": 2]
        await vm.cancelDownload()
        precondition(client.requests.last == "POST /api/esim/download/cancel" && vm.download.isBusy)
        client.status = ["state": "cancelled", "error": "cancelled", "started_at": 2]
        await vm.retryDownloadStatus()
        precondition(!vm.download.isBusy && !vm.blocksSwitching)
        let raceClient = AgentClient()
        let raceVM = RouterESimViewModel(client: raceClient, authManager: AuthManager())
        raceClient.postResult = ["state": "running", "step": "starting"]
        await raceVM.startDownload(code: "LPA:1$example.com$ABC", confirmationCode: "")
        raceClient.holdStatus = true
        raceClient.status = ["state": "running", "step": "es10b_load_bound_profile_package"]
        let poll = Task { await raceVM.retryDownloadStatus() }
        while raceClient.statusGate == nil { await Task.yield() }
        let cancel = Task { await raceVM.cancelDownload() }
        while !raceVM.operationInFlight { await Task.yield() }
        raceClient.statusGate?.resume()
        await poll.value
        await cancel.value
        precondition(raceClient.bodies.count == 1, "Recheck a queued cancellation after polling discovers installation has started")
        let switchClient = AgentClient()
        let switchVM = RouterESimViewModel(client: switchClient, authManager: AuthManager())
        await switchVM.refresh()
        let target = switchVM.profiles.first(where: \.canEnable)!
        switchClient.postResult = ["enabled_iccid": target.iccid, "previous_iccid": "8963000000000000001", "reconnecting": true]
        switchVM.requestSwitch(to: target); switchVM.pendingSwitch = nil // the dialog clears it when it closes
        await switchVM.confirmSwitch(to: target)
        precondition(switchClient.requests.contains("POST /api/esim/enable") && switchClient.bodies.last?["iccid"] as? String == target.iccid,
                     "A confirmed switch must reach the router after the dialog cleared its selection")
        let beforeSwitchRetry = switchClient.requests.count
        await switchVM.retryProfiles()
        precondition(switchClient.requests.count == beforeSwitchRetry, "Do not read the card while a switch reloads the SIM")
        let enableAt = switchClient.requests.lastIndex(of: "POST /api/esim/enable")!
        precondition(!switchClient.requests[(enableAt + 1)...].contains("GET /api/esim/profiles"),
                     "No fixed list read right after the switch")
        // While the SIM reloads the agent serves the pre-switch list marked updating: keep the target.
        switchClient.inventoryMeta = ["updating": true, "agent_instance": 5, "generation": 1, "observed_at": 100]
        switchClient.switchStatus = ["state": "reloading", "target_iccid": target.iccid]
        await switchVM.refresh()
        precondition(switchVM.connectionPhase == .reloading)
        precondition(switchVM.enabledProfile?.iccid == target.iccid, "The switch target stays active on screen during the reload")
        switchClient.entries = switchClient.entries.map { e in var e = e; e["state"] = e["iccid"] as? String == target.iccid ? "enabled" : "disabled"; return e }
        switchClient.inventoryMeta = ["updating": false, "agent_instance": 5, "generation": 1, "observed_at": 110]
        switchClient.switchStatus = ["state": "modem_confirmed", "target_iccid": target.iccid]
        await switchVM.refresh()
        precondition(switchVM.connectionPhase == .registering, "card and modem confirmed: registering")
        precondition(switchVM.inventory.observedAt == 110 && switchVM.enabledProfile?.iccid == target.iccid, "List re-read once the card is confirmed")
        switchClient.switchStatus = ["state": "no_data", "target_iccid": target.iccid]
        await switchVM.refresh()
        precondition(switchVM.connectionPhase == .waiting && switchVM.connectionNote?.contains("hasn't connected") == true,
                     "A switch without data reports why and does not switch back")
        precondition(switchClient.requests.filter { $0 == "POST /api/esim/enable" }.count == 1, "Never switched again or back")
        // Older answers are ignored; a failed read keeps the list; a newer clean read clears the error.
        switchClient.inventoryMeta = ["agent_instance": 5, "generation": 0, "observed_at": 999]
        await switchVM.refresh()
        precondition(switchVM.inventory.observedAt == 110, "An answer from before the switch is ignored")
        switchClient.inventoryMeta = ["agent_instance": 5, "generation": 1, "observed_at": 120, "stale": true,
                                      "error": ["kind": "management_unavailable", "message": "euicc_init", "at": 120]]
        await switchVM.refresh()
        precondition(switchVM.listError?.contains("isn't responding") == true && !switchVM.profiles.isEmpty, "A failed read keeps the list and says why")
        switchClient.inventoryMeta = ["agent_instance": 5, "generation": 1, "observed_at": 130, "pending_receipts": 2]
        await switchVM.refresh()
        precondition(switchVM.listError == nil && switchVM.pendingReceipts == 2, "A newer clean read clears the error")
        // Rename passes the profile from the alert and an empty name clears the nickname.
        switchVM.requestRename(target)
        switchVM.pendingRename = nil
        await switchVM.confirmRename(target, to: "  Travel  ")
        precondition(switchClient.requests.last == "GET /api/esim/profiles" && switchClient.bodies.last?["nickname"] as? String == "Travel")
        await switchVM.confirmRename(target, to: String(repeating: "x", count: 65))
        precondition(switchVM.messageIsError && switchClient.bodies.last?["nickname"] as? String == "Travel", "Over-long names never reach the router")
        print("RouterESimFlowTests: request ordering, operation guards, installation safety, resume, deletion, and errors passed")
    }
}
