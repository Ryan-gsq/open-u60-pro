import SwiftUI

@Observable
@MainActor
final class STKViewModel {
    // USSD state
    var ussdCode: String = ""
    var ussdReply: String = ""
    var ussdResponse: USSDResponse = .empty
    var showUssdResponse: Bool = false

    // STK state
    var stkMenu: STKMenu = .empty
    var stkCommandID = ""
    var stkType = "status"
    var stkReason = ""
    var stkText = ""
    var stkReply = ""
    var stkBusy = false
    var stkRootMenu = true
    var stkYesNo = false
    var stkHidden = false
    var stkDigitsOnly = false
    var stkMin = 0
    var stkMax = 0
    private var stkRevision = 0
    private var stkPollingStopped = false
    var stkNotSupported: Bool = false

    // Common
    var isLoading: Bool = false
    var message: String?
    var messageIsError: Bool = false

    private let client: AgentClient
    private let authManager: AuthManager

    init(client: AgentClient, authManager: AuthManager) {
        self.client = client
        self.authManager = authManager
    }

    var hasSTKMenu: Bool {
        !stkMenu.items.isEmpty
    }

    // MARK: - USSD

    func sendUSSD() async {
        let code = ussdCode.trimmingCharacters(in: .whitespaces)
        guard !code.isEmpty else {
            showMessage("Enter a USSD code", isError: true)
            return
        }

        isLoading = true
        message = nil

        do {
            let data = try await client.postJSON("/api/ussd/send", body: ["code": code])

            if let error = STKParser.parseError(data) {
                showMessage(error, isError: true)
            } else {
                ussdResponse = STKParser.parseUSSDResponse(data)
                showUssdResponse = true
            }
        } catch {
            showMessage("Failed: \(error.localizedDescription)", isError: true)
        }

        isLoading = false
    }

    func respondUSSD() async {
        let reply = ussdReply.trimmingCharacters(in: .whitespaces)
        guard !reply.isEmpty else { return }

        isLoading = true

        do {
            let data = try await client.postJSON("/api/ussd/respond", body: ["reply": reply])

            if let error = STKParser.parseError(data) {
                showMessage(error, isError: true)
            } else {
                ussdResponse = STKParser.parseUSSDResponse(data)
                ussdReply = ""
            }
        } catch {
            showMessage("Failed: \(error.localizedDescription)", isError: true)
        }

        isLoading = false
    }

    func cancelUSSD() async {
        isLoading = true

        do {
            let _ = try await client.postJSON("/api/ussd/cancel")
            ussdResponse = .empty
            showUssdResponse = false
            ussdReply = ""
            showMessage("USSD session ended", isError: false)
        } catch {
            showMessage("Failed: \(error.localizedDescription)", isError: true)
        }

        isLoading = false
    }

    // MARK: - STK

    func loadSTKMenu() async {
        guard !isLoading else { return }
        isLoading = true
        stkPollingStopped = false
        message = nil
        stkRevision += 1
        defer { isLoading = false }
        do {
            applySTK(try await client.getJSON("/api/stk/menu"))
        } catch {
            failSTK(error)
        }
    }

    /// The view owns this task; navigating away cancels polling without selecting or ending a service.
    func watchSTK() async {
        await loadSTKMenu()
        while !Task.isCancelled {
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
            guard !isLoading, !stkPollingStopped else { continue }
            let revision = stkRevision
            do {
                let data = try await client.getJSON("/api/stk/session")
                guard !Task.isCancelled, revision == stkRevision, !isLoading else { continue }
                applySTK(data)
            } catch {
                guard !Task.isCancelled, revision == stkRevision else { continue }
                failSTK(error)
            }
        }
    }

    func selectSTKItem(_ item: STKMenuItem) async {
        await stkAction("select", body: ["item_id": item.id])
    }

    func respondSTK(yes: Bool? = nil) async {
        var body: [String: Any] = ["text": stkReply]
        if let yes { body["yes"] = yes }
        await stkAction("respond", body: body)
    }

    func goBackSTK() async { await stkAction("back") }
    func cancelSTK() async { await stkAction("cancel") }

    private func stkAction(_ action: String, body: [String: Any] = [:]) async {
        guard !isLoading, !stkBusy, !stkCommandID.isEmpty else { return }
        isLoading = true
        message = nil
        stkRevision += 1
        defer { isLoading = false }
        var payload = body
        payload["command_id"] = stkCommandID
        do {
            applySTK(try await client.postJSON("/api/stk/\(action)", body: payload))
        } catch {
            // A timed-out selection may already have reached the SIM. Never replay it automatically.
            failSTK(error)
        }
    }

    private func applySTK(_ data: [String: Any]) {
        if let error = STKParser.parseError(data) {
            stkMenu = .empty
            stkCommandID = ""
            stkPollingStopped = true
            showMessage(error, isError: true)
            return
        }
        let id = data["command_id"] as? String ?? ""
        if id != stkCommandID { stkReply = "" }
        stkCommandID = id
        stkMenu = STKParser.parseSTKMenu(data)
        stkType = data["type"] as? String ?? "status"
        stkReason = data["reason"] as? String ?? ""
        stkText = data["text"] as? String ?? ""
        stkBusy = data["busy"] as? Bool ?? false
        stkRootMenu = data["root_menu"] as? Bool ?? true
        stkNotSupported = data["supported"] as? Bool == false
        let input = data["input"] as? [String: Any] ?? [:]
        stkYesNo = input["yes_no"] as? Bool ?? false
        stkHidden = input["hidden"] as? Bool ?? false
        stkDigitsOnly = input["digits_only"] as? Bool ?? false
        stkMin = input["min"] as? Int ?? 0
        stkMax = input["max"] as? Int ?? 0
    }

    private func failSTK(_ error: Error) {
        stkMenu = .empty
        stkCommandID = ""
        stkType = "status"
        stkText = ""
        stkReply = ""
        stkBusy = false
        stkPollingStopped = true
        stkReason = "Reload the SIM menu to reconnect."
        showMessage(error.localizedDescription, isError: true)
    }

    // MARK: - Private

    private func showMessage(_ text: String, isError: Bool) {
        message = text
        messageIsError = isError
    }
}
