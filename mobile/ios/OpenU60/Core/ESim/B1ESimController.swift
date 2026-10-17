import Foundation
import Observation

@Observable
@MainActor
final class B1ESimController {
    private(set) var phase: B1ManagementPhase = .disconnected
    private(set) var card: B1ESimCard?
    private(set) var profiles: [B1ESimProfile] = []
    private(set) var profilesObservedAt: String?
    private(set) var message: String?
    private(set) var lastResult: B1ESimResult?
    private(set) var pendingNotifications: [B1PendingNotification] = []
    private(set) var journalWarning: String?

    @ObservationIgnored private let factory: @MainActor (B1GattSnapshot) -> any B1ESimAdapter
    @ObservationIgnored private let store: any B1NotificationStore
    @ObservationIgnored private var adapter: (any B1ESimAdapter)?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var active: (id: String, action: B1ESimAction, target: String?, sent: Bool, verificationRequired: Bool)?
    private struct NotificationKey: Hashable { let eid: String; let id: String }
    @ObservationIgnored private var completedNotifications: Set<NotificationKey> = []

    init(store: (any B1NotificationStore)? = nil,
         factory: @escaping @MainActor (B1GattSnapshot) -> any B1ESimAdapter = { _ in B1UnverifiedESimAdapter() }) {
        self.store = store ?? B1FileNotificationStore()
        self.factory = factory
        do { pendingNotifications = try self.store.load() }
        catch { journalWarning = B1ESimError.journalUnavailable.localizedDescription }
    }

    var canOperate: Bool { phase == .ready }
    var canRefresh: Bool { phase == .ready || phase == .needsReconciliation }
    var notificationsForCard: [B1PendingNotification] { pendingNotifications.filter { $0.cardEid == card?.eid } }
    func supports(_ action: B1ESimAction) -> Bool { canOperate && card?.capabilities.contains(action) == true }

    func attach(_ snapshot: B1GattSnapshot) async {
        disconnect()
        let epoch = generation
        let next = factory(snapshot)
        adapter = next
        guard next.protocolVerified else {
            phase = .unavailable
            message = B1ESimError.protocolUnavailable.localizedDescription
            return
        }
        phase = .opening
        do {
            let identity = try await next.openSession()
            try check(epoch)
            try validate(identity)
            card = identity
            guard identity.capabilities.contains(.list) else { throw B1ESimError.unsupported(.list) }
            let items = try await next.listProfiles()
            try check(epoch)
            try setProfiles(items)
            phase = .ready
            message = "Card ready. Router Internet has not been verified."
        } catch {
            guard generation == epoch else { return }
            next.invalidateSession()
            phase = .unavailable
            card = nil
            profiles = []
            message = safeMessage(error)
        }
    }

    func disconnect() {
        generation &+= 1
        if let active, active.sent {
            lastResult = result(active.id, active.action, active.target, .unknown,
                                "Operation interrupted. Reconnect and read card state before repeating it.")
        }
        active = nil
        adapter?.invalidateSession()
        adapter = nil
        card = nil
        profiles = []
        profilesObservedAt = nil
        phase = .disconnected
        message = nil
    }

    func refresh() async {
        guard canRefresh, let adapter else { return }
        let recovering = phase == .needsReconciliation
        phase = .busy
        let epoch = generation
        do {
            if recovering { try await recover(adapter, epoch) }
            do {
                let items = try await adapter.listProfiles()
                try check(epoch)
                try setProfiles(items)
            } catch let error as B1ESimError where error.isAmbiguous && !recovering {
                try check(epoch)
                try await recover(adapter, epoch)
                let items = try await adapter.listProfiles()
                try check(epoch)
                try setProfiles(items)
            }
            phase = .ready
            message = "Profiles refreshed."
        } catch {
            guard generation == epoch else { return }
            adapter.invalidateSession()
            phase = .needsReconciliation
            message = safeMessage(error)
        }
    }

    @discardableResult func enable(_ iccid: String) async -> B1ESimResult? { await mutate(.enable, iccid) }
    @discardableResult func disable(_ iccid: String) async -> B1ESimResult? { await mutate(.disable, iccid) }
    @discardableResult func delete(_ iccid: String) async -> B1ESimResult? { await mutate(.delete, iccid) }
    @discardableResult func rename(_ iccid: String, nickname: String) async -> B1ESimResult? {
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= 128,
              !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            if canOperate { message = "Enter a nickname of 1–128 UTF-8 bytes without control characters." }
            return nil
        }
        return await mutate(.rename, iccid, nickname: trimmed)
    }

    private func mutate(_ action: B1ESimAction, _ iccid: String, nickname: String? = nil) async -> B1ESimResult? {
        guard let context = begin(action, target: iccid) else { return nil }
        let (adapter, epoch, id) = context
        do {
            let before = try await adapter.listProfiles()
            try check(epoch)
            try setProfiles(before)
            let target = before.first { $0.iccid == iccid }
            if action == .delete && target == nil { return finish(id, action, iccid, .unchanged, "Profile was already absent.") }
            guard let target else { throw B1ESimError.invalidInput("The target ICCID is not on this card.") }
            if matches(action, iccid, nickname, before) {
                return finish(id, action, iccid, .unchanged, "The requested profile state is already present.")
            }
            if action == .delete && target.canDelete == false { throw B1ESimError.rejected("Card policy prevents deleting this profile.") }
            if action == .disable && target.canDisable == false { throw B1ESimError.rejected("Card policy prevents disabling this profile.") }
            active?.sent = true
            do {
                switch action {
                case .enable: try await adapter.enableProfile(iccid: iccid)
                case .disable: try await adapter.disableProfile(iccid: iccid)
                case .delete: try await adapter.deleteProfile(iccid: iccid)
                case .rename: try await adapter.renameProfile(iccid: iccid, nickname: nickname ?? "")
                default: throw B1ESimError.unsupported(action)
                }
                try check(epoch)
                active?.verificationRequired = true
                let after = try await adapter.listProfiles()
                try check(epoch)
                try setProfiles(after)
                guard matches(action, iccid, nickname, after) else { throw B1ESimError.outcomeUnknown }
            } catch let error as B1ESimError where error.isAmbiguous {
                try check(epoch)
                active?.verificationRequired = true
                // Never resend a mutation after a timeout: recover and read the result first.
                try await recover(adapter, epoch)
                let after = try await adapter.listProfiles()
                try check(epoch)
                try setProfiles(after)
                guard matches(action, iccid, nickname, after) else { throw B1ESimError.outcomeUnknown }
            }
            return finish(id, action, iccid, .verified, successMessage(action))
        } catch {
            return failure(error, context, action, iccid)
        }
    }

    @discardableResult
    func download(_ request: B1DownloadRequest) async -> B1ESimResult? {
        guard journalWarning == nil else { message = journalWarning; return nil }
        guard let context = begin(.download, target: nil) else { return nil }
        let (adapter, epoch, id) = context
        let cardEid = card?.eid
        do {
            active?.sent = true
            var invalidReceipt = false
            let receipt = try await adapter.downloadProfile(request) { [weak self] receipt in
                // Journal confirmed installation before subsequent network work can fail or be canceled.
                if self?.recordReceipt(receipt, cardEid: cardEid) == false { invalidReceipt = true }
                if let self, self.generation == epoch, self.active?.id == id, receipt.installedIccid != nil {
                    self.active?.verificationRequired = true
                }
            }
            guard !invalidReceipt, recordReceipt(receipt, cardEid: cardEid) else { throw B1ESimError.invalidResponse }
            try check(epoch)
            active?.verificationRequired = receipt.installedIccid != nil
            guard let installed = receipt.installedIccid, !installed.isEmpty else { throw B1ESimError.outcomeUnknown }
            let after = try await adapter.listProfiles()
            try check(epoch)
            try setProfiles(after)
            guard after.contains(where: { $0.iccid == installed }) else { throw B1ESimError.outcomeUnknown }
            let text = notificationsForCard.isEmpty ? "Profile installation verified." : "Profile installation verified. Server notifications remain pending; do not reinstall."
            return finish(id, .download, installed, .verified, text)
        } catch { return failure(error, context, .download, nil) }
    }

    @discardableResult
    func retryNotifications() async -> B1ESimResult? {
        guard let context = begin(.notify, target: nil) else { return nil }
        let (adapter, epoch, id) = context
        do {
            for item in notificationsForCard {
                try await adapter.completeNotification(id: item.id)
                try check(epoch)
                let previous = pendingNotifications
                pendingNotifications.removeAll { $0.cardEid == item.cardEid && $0.id == item.id }
                persistNotifications()
                guard journalWarning == nil else { pendingNotifications = previous; throw B1ESimError.journalUnavailable }
                completedNotifications.insert(NotificationKey(eid: item.cardEid, id: item.id))
            }
            return finish(id, .notify, nil, .verified, "Pending server notifications completed.")
        } catch {
            guard generation == epoch else { return nil }
            active = nil
            adapter.invalidateSession()
            phase = .needsReconciliation
            let value = result(id, .notify, nil, .unknown, "Server notification remains pending. Profile installation will not be repeated.")
            lastResult = value
            message = value.message
            return value
        }
    }

    /// Exports an allowlisted metadata snapshot, never provisioning credentials or profile keys.
    func exportMetadata() throws -> B1ExportArtifact {
        guard canOperate, let card, let observedAt = profilesObservedAt else { throw B1ESimError.protocolUnavailable }
        struct Metadata: Encodable {
            let schemaVersion = 1
            let kind = "profileMetadata"
            let portable = false
            let cardEid: String
            let observedAt: String
            let profiles: [B1ESimProfile]
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(Metadata(cardEid: card.eid, observedAt: observedAt, profiles: profiles))
        return B1ExportArtifact(filename: "b1-profile-metadata.json", data: data, isTransferPackage: false)
    }

    func exportTransfer(_ iccid: String) async -> B1ExportArtifact? {
        guard let context = begin(.exportTransfer, target: iccid) else { return nil }
        let (adapter, epoch, id) = context
        do {
            let current = try await adapter.listProfiles()
            try check(epoch)
            try setProfiles(current)
            guard current.contains(where: { $0.iccid == iccid }) else { throw B1ESimError.invalidInput("The target ICCID is not on this card.") }
            let package = try await adapter.exportTransferPackage(iccid: iccid)
            try check(epoch)
            guard !package.data.isEmpty else { throw B1ESimError.invalidResponse }
            _ = finish(id, .exportTransfer, iccid, .verified, "Transfer package exported by the card adapter.")
            return B1ExportArtifact(filename: "b1-transfer-package.bin", data: package.data, isTransferPackage: true)
        } catch {
            _ = failure(error, context, .exportTransfer, iccid)
            return nil
        }
    }

    private func begin(_ action: B1ESimAction, target: String?) -> ((any B1ESimAdapter), UInt64, String)? {
        guard canOperate, let adapter else { return nil }
        guard card?.capabilities.contains(action) == true else { message = B1ESimError.unsupported(action).localizedDescription; return nil }
        phase = .busy
        let id = UUID().uuidString
        active = (id, action, target, false, false)
        message = nil
        return (adapter, generation, id)
    }

    private func recover(_ adapter: any B1ESimAdapter, _ epoch: UInt64) async throws {
        adapter.invalidateSession()
        let identity = try await adapter.recoverSession()
        try check(epoch)
        try validate(identity)
        guard identity.eid == card?.eid else { throw B1ESimError.cardChanged }
        card = identity
    }

    private func validate(_ identity: B1ESimCard) throws {
        guard !identity.eid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw B1ESimError.invalidResponse }
    }

    private func setProfiles(_ values: [B1ESimProfile]) throws {
        guard values.allSatisfy({ !$0.iccid.isEmpty }), Set(values.map(\.iccid)).count == values.count else {
            throw B1ESimError.invalidResponse
        }
        profiles = values
        profilesObservedAt = ISO8601DateFormatter().string(from: Date())
    }

    private func check(_ epoch: UInt64) throws {
        guard generation == epoch, adapter != nil else { throw B1ESimError.staleSession }
        try Task.checkCancellation()
    }

    private func matches(_ action: B1ESimAction, _ iccid: String, _ nickname: String?, _ values: [B1ESimProfile]) -> Bool {
        let target = values.first { $0.iccid == iccid }
        switch action {
        case .enable: return target?.state == .enabled
        case .disable: return target?.state == .disabled
        case .rename: return target?.nickname == nickname
        case .delete: return target == nil
        default: return false
        }
    }

    private func finish(_ id: String, _ action: B1ESimAction, _ target: String?, _ outcome: B1CardOutcome, _ text: String) -> B1ESimResult {
        active = nil
        phase = .ready
        let value = result(id, action, target, outcome, text)
        lastResult = value
        message = text
        return value
    }

    private func failure(_ error: Error, _ context: ((any B1ESimAdapter), UInt64, String), _ action: B1ESimAction, _ target: String?) -> B1ESimResult? {
        let (adapter, epoch, id) = context
        guard generation == epoch else { return nil }
        let typed = error as? B1ESimError
        let definite = typed.map { error in
            switch error { case .rejected, .invalidInput, .unsupported: return true; default: return false }
        } == true && active?.verificationRequired != true
        let ambiguous = active?.sent == true && !definite
        active = nil
        if ambiguous || typed?.isAmbiguous == true || typed == nil || isInvalidSession(typed) {
            adapter.invalidateSession()
            phase = .needsReconciliation
        } else { phase = .ready }
        let value = result(id, action, target, ambiguous ? .unknown : .rejected,
                           ambiguous ? "Operation outcome is unknown. Refresh card state before repeating it." : safeMessage(error))
        lastResult = value
        message = value.message
        return value
    }

    private func isInvalidSession(_ error: B1ESimError?) -> Bool {
        switch error { case .cardChanged?, .invalidResponse?, .staleSession?: return true; default: return false }
    }

    private func result(_ id: String, _ action: B1ESimAction, _ target: String?, _ outcome: B1CardOutcome, _ text: String) -> B1ESimResult {
        B1ESimResult(operationID: id, action: action, targetIccid: target, cardOutcome: outcome, message: text)
    }

    private func safeMessage(_ error: Error) -> String {
        // Unknown SDK errors may contain activation codes or provisioning payloads.
        (error as? B1ESimError)?.localizedDescription ?? "The B1 operation failed. Refresh card state before continuing."
    }

    private func successMessage(_ action: B1ESimAction) -> String {
        switch action {
        case .enable: return "Profile enabled and verified. Router Internet has not been verified."
        case .disable: return "Profile disabled and verified."
        case .rename: return "Profile nickname updated and verified."
        case .delete: return "Profile removal verified."
        default: return "Card operation verified."
        }
    }

    private func persistNotifications() {
        do { try store.save(pendingNotifications); journalWarning = nil }
        catch { journalWarning = B1ESimError.journalUnavailable.localizedDescription }
    }

    private func recordReceipt(_ receipt: B1DownloadReceipt, cardEid: String?) -> Bool {
        guard receipt.pendingNotifications.allSatisfy({ $0.cardEid == cardEid && !$0.id.isEmpty }) else { return false }
        for item in receipt.pendingNotifications where
            !completedNotifications.contains(NotificationKey(eid: item.cardEid, id: item.id)) &&
            !pendingNotifications.contains(where: { $0.cardEid == item.cardEid && $0.id == item.id }) {
            pendingNotifications.append(item)
        }
        persistNotifications()
        return true
    }
}
