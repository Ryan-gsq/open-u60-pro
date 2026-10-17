import ActivityKit
import Observation
import Foundation

/// Owns UI state and ActivityKit task lifetimes on the main actor; URLSession performs I/O asynchronously.
@MainActor @Observable
final class SignalActivityManager {
    private(set) var activity: Activity<SignalActivityAttributes>?
    private(set) var isBusy = false
    private(set) var message = "Show modem signal on your Lock Screen."
    private(set) var errorMessage: String?
    private(set) var lastAcceptedAt: Date?
    private(set) var displayedSampleAt: Date?
    private(set) var isStale = false
    @ObservationIgnored private let client: AgentClient
    @ObservationIgnored private var activityClient: AgentClient?
    @ObservationIgnored private var tokenTask: Task<Void, Never>?
    @ObservationIgnored private var contentTask: Task<Void, Never>?
    @ObservationIgnored private var stateTask: Task<Void, Never>?
    @ObservationIgnored private var registrationTask: Task<Void, Never>?
    @ObservationIgnored private var cleanupPending = false
    @ObservationIgnored private var lastRegistrationAttempt: Date?

    init(client: AgentClient) { self.client = client }

    func start() async {
        guard !isBusy, activity == nil else { return }
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            errorMessage = "Enable Live Activities for OpenU60 in iPhone Settings."
            return
        }
        isBusy = true
        defer { isBusy = false }
        errorMessage = nil
        do {
            let status = try await client.getJSON("/api/live-activity")
            guard status["enabled"] as? Bool == true else {
                errorMessage = "Enable Apple Live Activity updates on the modem first."
                return
            }
            let sampled = Date()
            let data = try await client.getJSON("/api/network/signal")
            let state = SignalActivityAttributes.ContentState.sample(data, at: sampled)
            let attributes = SignalActivityAttributes(gateway: client.baseURL,
                expiresAt: UInt64(Date().addingTimeInterval(3600).timeIntervalSince1970))
            let created = try Activity.request(attributes: attributes,
                content: ActivityContent(state: state, staleDate: sampled.addingTimeInterval(30)), pushType: .token)
            attach(created)
            message = "Waiting for Apple’s activity token…"
        } catch { errorMessage = error.localizedDescription }
    }

    /// Called after login and on foreground transitions; registration survives tab changes.
    func resume() async {
        guard !isBusy else { return }
        if cleanupPending && activity == nil { await removeRegistration() }
        if activity == nil,
           let existing = Activity<SignalActivityAttributes>.activities.first(where: {
               $0.attributes.gateway == client.baseURL && $0.activityState != .ended && $0.activityState != .dismissed
           }) { attach(existing) }
        guard let activity else { return }
        if activity.attributes.gateway != client.baseURL || activity.attributes.expiresAt <= UInt64(Date().timeIntervalSince1970) {
            await stop()
            return
        }
        activityClient?.token = client.token
        if let token = activity.pushToken { queueRegistration(token, for: activity) }
    }

    func refreshStatus() async {
        guard activity != nil, let connection = activityClient else { return }
        do {
            let status = try await connection.getJSON("/api/live-activity")
            if let seconds = status["last_accepted_at"] as? Double {
                lastAcceptedAt = Date(timeIntervalSince1970: seconds)
            }
            if let clockError = status["clock_error"] as? String {
                errorMessage = clockError
            } else if let error = status["last_error"] as? String {
                errorMessage = error
            } else if status["registered"] as? Bool == true {
                errorMessage = nil
            }
            if let recovery = status["recovery_state"] as? String, recovery != "ready" {
                message = recovery == "waiting_for_time"
                    ? "Agent is verifying modem time · retries automatically"
                    : "Agent is waiting for internet · retries automatically"
            } else if status["registered"] as? Bool == true {
                message = "Modem updates enabled · 1-hour session"
            }
            let rejected = (status["last_error"] as? String).map {
                $0.contains("token invalid") || $0.contains("rejected configuration")
            } ?? false
            if status["registered"] as? Bool == false, !rejected,
               status["clock_verified"] as? Bool != false,
               let activity, let token = activity.pushToken,
               activity.attributes.expiresAt > UInt64(Date().timeIntervalSince1970),
               lastRegistrationAttempt.map({ Date().timeIntervalSince($0) >= 60 }) ?? true {
                queueRegistration(token, for: activity)
            }
        } catch { errorMessage = "Cannot reach modem. Existing readings will become stale." }
    }

    func stop() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        tokenTask?.cancel(); stateTask?.cancel(); contentTask?.cancel(); registrationTask?.cancel()
        tokenTask = nil; stateTask = nil; contentTask = nil
        displayedSampleAt = nil
        isStale = false
        // Finish a cancelled PUT before DELETE, so it cannot re-register after stopping.
        await registrationTask?.value
        registrationTask = nil
        let current = activity
        activity = nil
        if let current { await current.end(nil, dismissalPolicy: .immediate) }
        await removeRegistration()
        message = "Show modem signal on your Lock Screen."
        lastAcceptedAt = nil
    }

    private func attach(_ activity: Activity<SignalActivityAttributes>) {
        self.activity = activity
        let connection = AgentClient(baseURL: activity.attributes.gateway)
        connection.token = client.token
        activityClient = connection
        tokenTask?.cancel(); stateTask?.cancel(); contentTask?.cancel()
        displayedSampleAt = Date(timeIntervalSince1970: Double(activity.content.state.sampledAt))
        isStale = activity.activityState == .stale
        contentTask = Task { [weak self] in
            for await content in activity.contentUpdates {
                guard !Task.isCancelled else { return }
                self?.displayedSampleAt = Date(timeIntervalSince1970: Double(content.state.sampledAt))
            }
        }
        tokenTask = Task { [weak self] in
            for await token in activity.pushTokenUpdates {
                guard !Task.isCancelled else { return }
                self?.queueRegistration(token, for: activity)
            }
        }
        stateTask = Task { [weak self] in
            for await state in activity.activityStateUpdates {
                guard !Task.isCancelled else { return }
                self?.isStale = state == .stale
                if state == .ended || state == .dismissed {
                    self?.stateTask = nil
                    await self?.stop()
                    return
                }
            }
        }
        if let token = activity.pushToken { queueRegistration(token, for: activity) }
    }

    private func queueRegistration(_ token: Data, for activity: Activity<SignalActivityAttributes>) {
        guard self.activity?.id == activity.id else { return }
        lastRegistrationAttempt = Date()
        activityClient?.token = client.token
        let previous = registrationTask
        previous?.cancel()
        registrationTask = Task { [weak self] in
            await previous?.value
            for attempt in 0..<4 {
                guard !Task.isCancelled, let self, self.activity?.id == activity.id,
                      let connection = self.activityClient else { return }
                do {
                    _ = try await connection.putJSON("/api/live-activity", body: [
                        "push_token": token.map { String(format: "%02x", $0) }.joined(),
                        "expires_at": activity.attributes.expiresAt
                    ])
                    guard !Task.isCancelled else { return }
                    self.cleanupPending = true
                    self.message = "Modem updates enabled · 1-hour session"
                    self.errorMessage = nil
                    return
                } catch {
                    guard !Task.isCancelled else { return }
                    self.errorMessage = "Phone registration pending. Retrying automatically while the app is open."
                    if attempt < 3 {
                        do { try await Task.sleep(for: .seconds(2 << attempt)) } catch { return }
                    }
                }
            }
        }
    }

    private func removeRegistration() async {
        guard let connection = activityClient else { return }
        do {
            _ = try await connection.deleteJSON("/api/live-activity")
            cleanupPending = false
            activityClient = nil
            errorMessage = nil
        } catch {
            cleanupPending = true
            errorMessage = "Activity closed. Modem unreachable; its registration expires automatically."
        }
    }
}
