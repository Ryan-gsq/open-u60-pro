import Foundation

enum B1ProfileState: String, Codable { case enabled, disabled, unknown }

struct B1ESimProfile: Identifiable, Codable, Equatable {
    let iccid: String
    var nickname: String?
    let provider: String?
    var state: B1ProfileState
    var canDelete: Bool? = nil
    var canDisable: Bool? = nil
    var id: String { iccid }
    var displayName: String { nickname?.isEmpty == false ? nickname ?? iccid : provider ?? iccid }
}

enum B1ESimAction: String, Codable, CaseIterable {
    case list, enable, disable, rename, delete, download, exportTransfer, notify
}

struct B1ESimCard: Codable, Equatable {
    let eid: String
    let capabilities: Set<B1ESimAction>
}

enum B1ManagementPhase { case disconnected, unavailable, opening, ready, busy, needsReconciliation }
enum B1CardOutcome: String, Codable { case verified, unchanged, rejected, unknown }

struct B1ESimResult: Encodable, Equatable {
    let operationID: String
    let action: B1ESimAction
    let targetIccid: String?
    let cardOutcome: B1CardOutcome
    let message: String
    // A card operation never proves router Internet connectivity.
    let routerOutcome: String = "notVerified"
}

/// Provisioning credentials are held in memory and never included in metadata exports or journals.
struct B1DownloadRequest: CustomStringConvertible, CustomDebugStringConvertible {
    let activationCode: String
    let confirmationCode: String?

    init(activationCode: String, confirmationCode: String? = nil) throws {
        let code = activationCode.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = code.split(separator: "$", omittingEmptySubsequences: false)
        guard code.utf8.count <= 8192, parts.count >= 3, parts[0] == "LPA:1", !parts[1].isEmpty,
              !code.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw B1ESimError.invalidInput("Enter an activation code beginning with LPA:1$ and an SM-DP+ address.")
        }
        self.activationCode = code
        self.confirmationCode = confirmationCode?.isEmpty == false ? confirmationCode : nil
    }

    var description: String { "B1DownloadRequest(credentials: redacted)" }
    var debugDescription: String { description }
}

struct B1PendingNotification: Codable, Equatable, Identifiable {
    let id: String
    let cardEid: String
    let profileIccid: String?
}

struct B1DownloadReceipt {
    let installedIccid: String?
    let pendingNotifications: [B1PendingNotification]
}

/// Transfer bytes are supplied only by an adapter that explicitly supports portable export.
struct B1TransferPackage {
    let data: Data
}

struct B1ExportArtifact: Identifiable {
    let id = UUID()
    let filename: String
    let data: Data
    let isTransferPackage: Bool
}

enum B1ESimError: Error, LocalizedError {
    case protocolUnavailable, unsupported(B1ESimAction), invalidInput(String), rejected(String)
    case timeout, transportLost, outcomeUnknown, staleSession, cardChanged, invalidResponse, journalUnavailable

    var errorDescription: String? {
        switch self {
        case .protocolUnavailable: return "B1 authorization and command framing still require a verified protocol adapter."
        case .unsupported(let action): return "The card adapter does not support \(action.rawValue)."
        case .invalidInput(let text), .rejected(let text): return text
        case .timeout: return "The B1 request timed out."
        case .transportLost: return "The B1 management connection was lost."
        case .outcomeUnknown: return "The operation may have reached the card. Refresh to reconcile its state."
        case .staleSession: return "The management session was canceled."
        case .cardChanged: return "Recovery returned a different card. Reconnect before continuing."
        case .invalidResponse: return "The adapter returned invalid card or profile data."
        case .journalUnavailable: return "Pending download notifications could not be stored. Resolve storage before downloading another profile."
        }
    }

    var isAmbiguous: Bool {
        switch self { case .timeout, .transportLost, .outcomeUnknown: return true; default: return false }
    }
}

/// Implementations must authenticate the B1, own only their logical channels, serialize
/// transport commands, use bounded/cancellation-aware exchanges, and return typed card errors.
/// Recovery must reconnect/reopen the management session and return the actual card identity.
@MainActor
protocol B1ESimAdapter: AnyObject {
    var protocolVerified: Bool { get }
    func openSession() async throws -> B1ESimCard
    func recoverSession() async throws -> B1ESimCard
    func listProfiles() async throws -> [B1ESimProfile]
    func enableProfile(iccid: String) async throws
    func disableProfile(iccid: String) async throws
    func renameProfile(iccid: String, nickname: String) async throws
    func deleteProfile(iccid: String) async throws
    /// Publish a confirmed installation receipt before notification work can fail or be
    /// canceled; return the final receipt even if notification work is still pending.
    func downloadProfile(_ request: B1DownloadRequest,
                         onInstalled: @escaping @MainActor (B1DownloadReceipt) -> Void) async throws -> B1DownloadReceipt
    func completeNotification(id: String) async throws
    func exportTransferPackage(iccid: String) async throws -> B1TransferPackage
    func invalidateSession()
}

/// Production guard until the B1 wire contract is established. It sends no card commands.
@MainActor
final class B1UnverifiedESimAdapter: B1ESimAdapter {
    var protocolVerified: Bool { false }
    func openSession() async throws -> B1ESimCard { throw B1ESimError.protocolUnavailable }
    func recoverSession() async throws -> B1ESimCard { throw B1ESimError.protocolUnavailable }
    func listProfiles() async throws -> [B1ESimProfile] { throw B1ESimError.protocolUnavailable }
    func enableProfile(iccid: String) async throws { throw B1ESimError.protocolUnavailable }
    func disableProfile(iccid: String) async throws { throw B1ESimError.protocolUnavailable }
    func renameProfile(iccid: String, nickname: String) async throws { throw B1ESimError.protocolUnavailable }
    func deleteProfile(iccid: String) async throws { throw B1ESimError.protocolUnavailable }
    func downloadProfile(_ request: B1DownloadRequest, onInstalled: @escaping @MainActor (B1DownloadReceipt) -> Void) async throws -> B1DownloadReceipt { throw B1ESimError.protocolUnavailable }
    func completeNotification(id: String) async throws { throw B1ESimError.protocolUnavailable }
    func exportTransferPackage(iccid: String) async throws -> B1TransferPackage { throw B1ESimError.protocolUnavailable }
    func invalidateSession() {}
}

@MainActor
protocol B1NotificationStore {
    func load() throws -> [B1PendingNotification]
    func save(_ items: [B1PendingNotification]) throws
}

@MainActor
final class B1FileNotificationStore: B1NotificationStore {
    private let url: URL?
    init(url: URL? = nil) {
        self.url = url ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("OpenU60/b1-pending-notifications.v1.json")
    }
    func load() throws -> [B1PendingNotification] {
        guard let url else { throw B1ESimError.journalUnavailable }
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode([B1PendingNotification].self, from: data)
    }
    func save(_ items: [B1PendingNotification]) throws {
        guard let url else { throw B1ESimError.journalUnavailable }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(items).write(to: url, options: .atomic)
    }
}
