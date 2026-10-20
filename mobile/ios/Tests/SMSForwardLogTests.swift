import Foundation

// Stand-ins used only by the standalone test executable, never by the iOS target.
@MainActor
final class AgentClient {
    var requests: [String] = []
    /// What GET /api/sms/forward/log answers; a clear keeps only the held entries, like the agent.
    var log: [[String: Any]] = []
    func getJSON(_ path: String) async throws -> [String: Any] { requests.append("GET " + path); return [:] }
    func getJSONArray(_ path: String) async throws -> [[String: Any]] { requests.append("GET " + path); return log }
    func postJSON(_ path: String, body: [String: Any] = [:]) async throws -> [String: Any] {
        requests.append("POST " + path)
        if path == "/api/sms/forward/log/clear" { log.removeAll { $0["pending"] as? Bool != true } }
        return [:]
    }
    func putJSON(_ path: String, body: [String: Any] = [:]) async throws -> [String: Any] { requests.append("PUT " + path); return [:] }
    func deleteJSON(_ path: String, body: [String: Any] = [:]) async throws -> [String: Any] { requests.append("DELETE " + path); return [:] }
}
@MainActor final class AuthManager {}

@main
struct SMSForwardLogTests {
    @MainActor static func main() async {
        let held: [String: Any] = ["timestamp": 1_700_000_100, "sms_id": 2, "sender": "BANK", "rule_name": "All",
                                   "destination_type": "telegram", "success": false,
                                   "error": "no WAN connectivity; held for retry", "pending": true]
        let failed: [String: Any] = ["timestamp": 1_700_000_050, "sms_id": 1, "sender": "SHOP", "success": false, "error": "HTTP 500"]
        let sent: [String: Any] = ["timestamp": 1_700_000_000, "sms_id": 0, "sender": "SHOP", "success": true]

        precondition(SMSForwardParser.parseLogEntry(held)?.pending == true, "A held entry parses as pending")
        precondition(SMSForwardParser.parseLogEntry(failed)?.pending == false, "Older agents send no pending flag: not held")
        precondition(SMSForwardParser.parseLogEntry(sent)?.pending == false)

        let client = AgentClient()
        client.log = [held, failed, sent]
        let vm = SMSForwardViewModel(client: client, authManager: AuthManager())
        await vm.fetchLog()
        precondition(vm.log.count == 3)
        await vm.clearLog()
        precondition(client.requests.suffix(2) == ["POST /api/sms/forward/log/clear", "GET /api/sms/forward/log"],
                     "A clear re-reads the log")
        precondition(vm.log.map(\.smsId) == [2] && vm.log[0].pending, "Held entries survive a clear and stay on screen")
        precondition(vm.message == "Log cleared" && !vm.messageIsError)
        print("SMSForwardLogTests: pending parsing and held entries surviving a clear passed")
    }
}
