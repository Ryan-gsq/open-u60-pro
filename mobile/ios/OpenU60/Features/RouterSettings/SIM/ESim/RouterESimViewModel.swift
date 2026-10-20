import SwiftUI

@Observable
@MainActor
final class RouterESimViewModel {
    var profiles: [RouterESimProfile] = []
    var chip: RouterESimChip = .empty
    var isLoading = false
    var isSwitching = false
    var message: String?
    var messageIsError = false
    var pendingSwitch: RouterESimProfile?
    var pendingDelete: RouterESimProfile?
    var pendingRename: RouterESimProfile?
    var renameText = ""
    /// The list as last accepted from the agent, with its freshness markers.
    private(set) var inventory = RouterESimInventory()
    /// A failed list read, shown with the list it failed to refresh; cleared only by a newer
    /// clean read.
    private(set) var listError: String?
    /// Operator receipts waiting on the card (`nil` = unknown or an older agent).
    private(set) var pendingReceipts: Int?
    private(set) var receiptsSending = false
    private(set) var download = RouterESimDownloadStatus()
    private(set) var operationInFlight = false
    private(set) var downloadNote: String?
    @ObservationIgnored private var downloadInFlight = false
    @ObservationIgnored private var downloadNoteIsPolling = false
    @ObservationIgnored private var nextDownloadCheck = Date.distantPast
    @ObservationIgnored private var dismissedDownload: RouterESimDownloadStatus?

    private(set) var hasLoaded = false
    private(set) var connectionPhase: RouterESimConnectionPhase = .checking
    private(set) var connectionNote: String?
    private(set) var operatorName = ""
    private(set) var networkType = ""
    private(set) var signalBars = 0
    private(set) var switchingTo: String?

    private let client: AgentClient
    private let authManager: AuthManager
    private let statusPoller = PollingLoop()
    @ObservationIgnored private var statusInFlight = false
    @ObservationIgnored private var nextStatusCheck = Date.distantPast
    @ObservationIgnored private var reconnectTracker: RouterESimReconnectTracker?
    @ObservationIgnored private var switchedAt: Date?
    /// Following the agent's verified switch progress (`GET /api/esim/switch`); off for older
    /// agents, which fall back to `reconnectTracker`.
    @ObservationIgnored private var followSwitch = false
    @ObservationIgnored private var switchListRead = false
    /// The client's SIM identity revision this screen last re-read for.
    @ObservationIgnored private var seenIdentityRevision = 0

    init(client: AgentClient, authManager: AuthManager) {
        self.client = client
        self.authManager = authManager
    }

    /// Shown, not as an error, when a confirmed switch or delete finds the card still in use.
    static let busyText = "The eSIM is busy; try again in a moment."

    var enabledProfile: RouterESimProfile? { profiles.first(where: \.isEnabled) }
    var blocksSwitching: Bool { isLoading || isSwitching || operationInFlight || download.isBusy || connectionPhase.blocksSwitching }

    func refresh() async {
        guard !isLoading, !isSwitching, !operationInFlight, !downloadInFlight else { return }
        if connectionPhase.blocksSwitching {
            _ = await refreshConnection()
            return
        }
        if connectionPhase == .connected { switchingTo = nil }
        isLoading = true
        message = nil
        defer { isLoading = false; hasLoaded = true }
        // Discover an ongoing download before accessing the card (list/chip would be busy).
        await pollDownload(refreshAfterCompletion: false)
        if !download.isBusy {
            await loadProfiles()
            await loadChip()
        }
        if !download.isBusy { _ = await refreshConnection() }
    }

    /// The list warning retries only the read; it must never replay a profile change.
    func retryProfiles() async {
        guard !blocksSwitching, !downloadInFlight else { return }
        isLoading = true
        defer { isLoading = false; hasLoaded = true }
        await loadProfiles()
    }

    func startMonitoring() {
        guard !statusPoller.isRunning else { return }
        nextStatusCheck = .distantPast
        nextDownloadCheck = .distantPast
        seenIdentityRevision = client.identityRevision
        statusPoller.start(interval: .seconds(1)) { [weak self] in
            guard let self else { return .failure }
            guard !self.isLoading, !self.isSwitching, !self.operationInFlight else { return .success }
            // The connection check's own reads carry the router's SIM identity. When it moved
            // (a switch from the card's menu, a swapped card, or the WAN coming up), check now
            // and re-read the list unless a switch or download owns the card.
            if self.client.identityRevision != self.seenIdentityRevision {
                self.seenIdentityRevision = self.client.identityRevision
                self.nextStatusCheck = .distantPast
                if !self.blocksSwitching {
                    // Busy while the agent holds the card for the read, so a switch or delete
                    // confirmed meanwhile waits for it instead of failing with "eSIM manager busy".
                    self.isLoading = true
                    defer { self.isLoading = false }
                    await self.loadProfiles()
                }
            }
            if self.download.isBusy || Date() >= self.nextDownloadCheck {
                await self.pollDownload()
                self.nextDownloadCheck = Date().addingTimeInterval(30)
            }
            guard !self.download.isBusy, Date() >= self.nextStatusCheck else { return .success }
            let result = await self.refreshConnection()
            self.nextStatusCheck = Date().addingTimeInterval(self.connectionPhase.blocksSwitching ? 3 : 12)
            return result ? .success : .failure
        }
    }

    func stopMonitoring() { statusPoller.stop() }

    func requestSwitch(to profile: RouterESimProfile) {
        guard profile.canEnable, !blocksSwitching else { return }
        pendingSwitch = profile
    }

    /// Takes the profile from the dialog button: SwiftUI clears `pendingSwitch` when the dialog
    /// closes, before this task runs. A list read the monitor started meanwhile (a new SIM
    /// identity) holds the card briefly; the switch waits for it rather than being dropped.
    func confirmSwitch(to target: RouterESimProfile) async {
        while isLoading && !Task.isCancelled { try? await Task.sleep(for: .milliseconds(100)) }
        // Checked against the list as now read: the card's own menu may have enabled the target.
        guard profiles.contains(where: { $0.iccid == target.iccid && $0.canEnable }) else { return }
        guard !blocksSwitching else { showMessage(Self.busyText, isError: false); return }
        pendingSwitch = nil
        isSwitching = true
        message = nil
        messageIsError = false
        defer { isSwitching = false; nextStatusCheck = .distantPast }

        do {
            while downloadInFlight { try await Task.sleep(for: .milliseconds(50)) }
            guard !download.isBusy else { return }
            connectionPhase = .switching
            connectionNote = nil
            switchingTo = target.displayName
            let result = try await client.postJSON("/api/esim/enable", body: ["iccid": target.iccid])
            // The agent confirms the new active profile before the modem reconnects.
            if result["enabled_iccid"] as? String == target.iccid {
                profiles = profiles.map {
                    RouterESimProfile(iccid: $0.iccid, provider: $0.provider, name: $0.name,
                                      nickname: $0.nickname, isEnabled: $0.iccid == target.iccid,
                                      profileClass: $0.profileClass, switchWarnings: $0.switchWarnings)
                }
            }
            beginFollowingSwitch(to: target)
        } catch {
            if error.isCancellation {
                if reconnectTracker == nil { connectionPhase = .unavailable; switchingTo = nil }
                return
            }
            if outcomeUnknown(error) {
                // The card command failed or timed out, but the card may have switched: the agent checks.
                beginFollowingSwitch(to: target)
                showMessage("The router is checking whether the switch happened.", isError: false)
                return
            }
            connectionPhase = .unavailable
            switchingTo = nil
            reconnectTracker = nil
            switchedAt = nil
            showMessage("Switch failed: \(errorText(error))", isError: true)
        }
    }

    private func beginFollowingSwitch(to target: RouterESimProfile) {
        reconnectTracker = RouterESimReconnectTracker(targetICCID: target.iccid)
        switchedAt = Date()
        followSwitch = true
        switchListRead = false
        connectionPhase = .reloading
    }

    func requestRename(_ profile: RouterESimProfile) {
        guard !blocksSwitching else { return }
        renameText = profile.nickname
        pendingRename = profile
    }

    /// Takes the profile from the alert button (see `confirmSwitch(to:)`). An empty name clears
    /// the nickname, so the operator's name shows again.
    func confirmRename(_ target: RouterESimProfile, to name: String) async {
        let nickname = name.trimmingCharacters(in: .whitespacesAndNewlines)
        pendingRename = nil
        guard nickname.utf8.count <= 64 else {
            showMessage("Nicknames can be up to 64 bytes.", isError: true)
            return
        }
        guard !blocksSwitching, nickname != target.nickname else { return }
        operationInFlight = true
        message = nil
        defer { operationInFlight = false }
        do {
            while downloadInFlight { try await Task.sleep(for: .milliseconds(50)) }
            _ = try await client.postJSON("/api/esim/nickname", body: ["iccid": target.iccid, "nickname": nickname])
            await loadProfiles()
            showMessage(nickname.isEmpty ? "Nickname cleared." : "Renamed to \(nickname).", isError: false)
        } catch { if !error.isCancellation { showMessage(errorText(error), isError: true) } }
    }

    /// Sends the operator receipts waiting on the card now; the router keeps retrying the rest.
    func sendReceipts() async {
        guard !blocksSwitching, !receiptsSending else { return }
        receiptsSending = true
        defer { receiptsSending = false }
        do {
            _ = try await client.postJSON("/api/esim/notifications/process", body: [:])
            try await Task.sleep(for: .seconds(8))
            let data = try await client.getJSON("/api/esim/notifications")
            if let count = data["count"] as? Int { pendingReceipts = count }
            showMessage(pendingReceipts == 0 ? "Operator receipts sent."
                        : "Some receipts couldn't be sent yet. The router keeps retrying.", isError: pendingReceipts != 0)
        } catch { if !error.isCancellation { showMessage(errorText(error), isError: true) } }
    }

    func requestDelete(_ profile: RouterESimProfile) {
        guard !profile.isEnabled, !blocksSwitching else { return }
        pendingDelete = profile
    }

    /// Takes the profile from the dialog button and waits out a background list read (see
    /// `confirmSwitch(to:)`).
    func confirmDelete(_ target: RouterESimProfile) async {
        while isLoading && !Task.isCancelled { try? await Task.sleep(for: .milliseconds(100)) }
        guard profiles.contains(where: { $0.iccid == target.iccid && !$0.isEnabled }) else { return }
        guard !blocksSwitching else { showMessage(Self.busyText, isError: false); return }
        pendingDelete = nil
        operationInFlight = true
        message = nil
        defer { operationInFlight = false }
        do {
            while downloadInFlight { try await Task.sleep(for: .milliseconds(50)) }
            guard !download.isBusy, profiles.contains(where: { $0.iccid == target.iccid && !$0.isEnabled }) else { return }
            let result = try await client.postJSON("/api/esim/delete", body: ["iccid": target.iccid])
            await loadProfiles()
            await loadChip()
            let suffix = result["operator_notified"] as? Bool == false
                ? " The operator will be notified on the next eSIM change." : ""
            showMessage("\(target.displayName) deleted." + suffix, isError: false)
        } catch { if !error.isCancellation { showMessage(errorText(error), isError: true) } }
    }

    func startDownload(code: String, confirmationCode: String) async {
        guard !blocksSwitching, let parsed = RouterESimActivationCode.parse(code) else { return }
        guard !parsed.needsConfirmationCode || RouterESimActivationCode.validConfirmationCode(confirmationCode) else {
            downloadNote = "Enter the confirmation code from your operator (up to 64 characters)."
            return
        }
        var body: [String: Any] = ["activation_code": parsed.value, "preview": true]
        if !confirmationCode.isEmpty { body["confirmation_code"] = confirmationCode }
        await downloadAction(path: "/api/esim/download", body: body)
    }

    func confirmDownload() async {
        guard download.state == "confirm", !operationInFlight else { return }
        await downloadAction(path: "/api/esim/download/confirm", body: ["accept": true])
    }

    func cancelDownload() async {
        guard download.canCancel, !operationInFlight else { return }
        await downloadAction(path: "/api/esim/download/cancel", body: [:])
    }

    func resetDownloadResult() {
        guard !download.isBusy, !operationInFlight else { return }
        dismissedDownload = download
        download = RouterESimDownloadStatus()
        downloadNote = nil
    }

    func retryDownloadStatus() async { await pollDownload() }

    private func downloadAction(path: String, body: [String: Any]) async {
        guard !operationInFlight else { return }
        operationInFlight = true
        downloadNote = nil
        downloadNoteIsPolling = false
        defer { operationInFlight = false }
        do {
            while downloadInFlight { try await Task.sleep(for: .milliseconds(50)) }
            if path.hasSuffix("/cancel") && !download.canCancel { return }
            if path.hasSuffix("/confirm") && download.state != "confirm" { return }
            if path == "/api/esim/download" && download.isBusy { return }
            let result = try await client.postJSON(path, body: body)
            let data = try JSONSerialization.data(withJSONObject: result)
            download = try JSONDecoder().decode(RouterESimDownloadStatus.self, from: data)
            if !download.isBusy { await loadProfiles(); await loadChip() }
        } catch {
            if !error.isCancellation {
                downloadNote = errorText(error)
                downloadNoteIsPolling = false
                // A lost HTTP response does not mean a background operation stopped.
                await pollDownload()
            }
        }
    }

    private func pollDownload(refreshAfterCompletion: Bool = true) async {
        guard !downloadInFlight else { return }
        downloadInFlight = true
        defer { downloadInFlight = false }
        let wasBusy = download.isBusy
        do {
            let result: RouterESimDownloadStatus = try await client.get("/api/esim/download")
            if !result.isBusy && result == dismissedDownload { return }
            let refreshCard = !result.isBusy && refreshAfterCompletion && (wasBusy || (result.state == "done" && result != download))
            if refreshCard { isLoading = true }
            if downloadNoteIsPolling || result.state != download.state { downloadNote = nil }
            download = result
            if refreshCard {
                await loadProfiles()
                await loadChip()
                isLoading = false
            }
        } catch {
            // Older agents may not have download support; their profile list still works.
            if wasBusy && !error.isCancellation && (downloadNote == nil || downloadNoteIsPolling) {
                downloadNote = errorText(error)
                downloadNoteIsPolling = true
            }
        }
    }

    @discardableResult
    private func refreshConnection() async -> Bool {
        guard !statusInFlight, !isSwitching else { return true }
        statusInFlight = true
        defer { statusInFlight = false }
        if followSwitch, let handled = await followSwitchStatus() {
            return handled
        }
        do {
            let sim = try await client.getJSON("/api/sim/info")
            let data = try await client.getJSON("/api/modem/data")
            let signal = try await client.getJSON("/api/network/signal")
            guard !Task.isCancelled, !isSwitching else { return false }
            let (nr, lte, _, op) = SignalParser.parseNetInfo(signal)
            operatorName = op.provider
            networkType = op.networkType.isEmpty ? "" : op.displayNetworkType(nrConnected: nr.isConnected, lteSignal: lte)
            signalBars = min(max(op.signalBar, 0), 5)
            connectionNote = nil
            let status = data["connect_status"] as? String ?? ""
            if var tracker = reconnectTracker, let switchedAt {
                let simState = (sim["sim_states"] as? String ?? "").lowercased()
                if simState == "wait pin" || simState == "wait puk" {
                    connectionPhase = .waiting
                    connectionNote = "The SIM needs to be unlocked. Open SIM Card to continue."
                } else {
                    connectionPhase = tracker.phase(simICCID: sim["sim_iccid"] as? String ?? "",
                                                    status: status, elapsed: Date().timeIntervalSince(switchedAt))
                }
                reconnectTracker = connectionPhase == .connected ? nil : tracker
            } else {
                connectionPhase = status.isEmpty ? .unavailable : (RouterESimReconnectTracker.isConnected(status) ? .connected : .disconnected)
            }
            return true
        } catch {
            guard !error.isCancellation else { return false }
            connectionNote = errorText(error)
            if let switchedAt, reconnectTracker != nil {
                if Date().timeIntervalSince(switchedAt) >= 120 { connectionPhase = .waiting }
            } else { connectionPhase = .unavailable }
            return false
        }
    }

    /// One step of the agent's verified switch: card → modem identity → data. Returns `nil`
    /// when the agent has no switch endpoint (older agent), so the tracker fallback runs.
    private func followSwitchStatus() async -> Bool? {
        let status: RouterESimSwitchStatus
        do {
            status = try await client.get("/api/esim/switch")
        } catch {
            guard !error.isCancellation else { return false }
            if case AgentError.serverError(let text) = error, text.contains("not found") {
                followSwitch = false
                return nil
            }
            connectionNote = errorText(error)
            return false
        }
        guard !Task.isCancelled, !isSwitching else { return false }
        if status.state == "idle" {
            // The agent restarted and lost the switch: fall back to watching the modem.
            followSwitch = false
            return nil
        }
        connectionPhase = status.phase
        connectionNote = status.progressNote
        if status.cardConfirmed && !switchListRead {
            switchListRead = true
            await loadProfiles()
        }
        if !status.isRunning {
            followSwitch = false
            reconnectTracker = nil
            connectionNote = status.outcomeNote
            await loadProfiles()
        }
        if connectionPhase == .connected { await readNetwork() }
        return true
    }

    private func readNetwork() async {
        guard let signal = try? await client.getJSON("/api/network/signal") else { return }
        let (nr, lte, _, op) = SignalParser.parseNetInfo(signal)
        operatorName = op.provider
        networkType = op.networkType.isEmpty ? "" : op.displayNetworkType(nrConnected: nr.isConnected, lteSignal: lte)
        signalBars = min(max(op.signalBar, 0), 5)
    }

    private func loadProfiles() async {
        do {
            let fresh = RouterESimParser.parseInventory(try await client.getJSON("/api/esim/profiles"))
            // An answer older than what is shown, or the pre-switch list the agent serves while the
            // SIM reloads, must not replace the switch target on screen.
            guard !fresh.isOlder(than: inventory), !(fresh.updating && followSwitch) else { return }
            inventory = fresh
            profiles = fresh.profiles
            pendingReceipts = fresh.pendingReceipts
            listError = fresh.errorText.map { "\($0) Showing the list read at \(Self.clock(fresh.observedAt))." }
        } catch {
            guard !error.isCancellation else { return }
            listError = "Couldn't read eSIM profiles: \(errorText(error))"
        }
    }

    private static func clock(_ unix: UInt64) -> String {
        guard unix > 0 else { return "an earlier time" }
        return Date(timeIntervalSince1970: TimeInterval(unix)).formatted(date: .omitted, time: .shortened)
    }

    /// The agent replies `outcome: "unknown"` when the card command failed or timed out mid-switch.
    private func outcomeUnknown(_ error: Error) -> Bool {
        guard case AgentError.serverError(let text) = error, let data = text.data(using: .utf8),
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return envelope["outcome"] as? String == "unknown"
    }

    private func loadChip() async {
        do { chip = RouterESimParser.parseChip(try await client.getJSON("/api/esim/chip")) }
        catch { /* Profile loading already reports card or agent errors. */ }
    }

    private func errorText(_ error: Error) -> String {
        if case AgentError.serverError(let text) = error {
            if let data = text.data(using: .utf8),
               let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let message = envelope["error"] as? String { return message }
            return text
        }
        return error.localizedDescription
    }

    private func showMessage(_ text: String, isError: Bool) {
        message = text
        messageIsError = isError
    }
}
