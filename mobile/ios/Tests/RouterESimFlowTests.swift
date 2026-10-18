import Foundation

/// In-memory transport: exercises the real view model without touching an eSIM or network.
@MainActor
final class AgentClient {
    var requests: [String] = []
    var bodies: [[String: Any]] = []
    var status: [String: Any] = ["state": "idle"]
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
        return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: status))
    }
    func getJSON(_ path: String) async throws -> [String: Any] {
        requests.append("GET " + path)
        switch path {
        case "/api/esim/profiles": return ["profiles": entries]
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
        print("RouterESimFlowTests: request ordering, operation guards, installation safety, resume, deletion, and errors passed")
    }
}
