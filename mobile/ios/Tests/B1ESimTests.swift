import Foundation

@MainActor
private final class MemoryNotifications: B1NotificationStore {
    var items: [B1PendingNotification] = []
    var failSave = false
    var failLoad = false
    func load() throws -> [B1PendingNotification] {
        if failLoad { throw B1ESimError.journalUnavailable }
        return items
    }
    func save(_ values: [B1PendingNotification]) throws {
        if failSave { throw B1ESimError.journalUnavailable }
        items = values
    }
}

@MainActor
private final class FakeESimAdapter: B1ESimAdapter {
    var protocolVerified = true
    var identity = B1ESimCard(eid: "card-A", capabilities: Set(B1ESimAction.allCases))
    var recoveryIdentity: B1ESimCard?
    var profiles = [
        B1ESimProfile(iccid: "old", nickname: "Old", provider: "Carrier A", state: .enabled),
        B1ESimProfile(iccid: "target", nickname: "Target", provider: "Carrier B", state: .disabled)
    ]
    var calls: [String] = []
    var enableError: B1ESimError?
    var applyBeforeError = false
    var holdEnable = false
    var holdDownload = false
    var holdAfterInstall = false
    var enableWaiter: CheckedContinuation<Void, Never>?
    var downloadWaiter: CheckedContinuation<Void, Never>?
    var postInstallWaiter: CheckedContinuation<Void, Never>?
    var failListAt: Set<Int> = []
    var rejectListAt: Set<Int> = []
    var listCount = 0
    var notificationError: B1ESimError?
    var downloadErrorAfterInstall: B1ESimError?
    var receipt = B1DownloadReceipt(installedIccid: "downloaded", pendingNotifications: [])

    func openSession() async throws -> B1ESimCard { calls.append("open"); return identity }
    func recoverSession() async throws -> B1ESimCard { calls.append("recover"); return recoveryIdentity ?? identity }
    func listProfiles() async throws -> [B1ESimProfile] {
        calls.append("list"); listCount += 1
        if failListAt.contains(listCount) { throw B1ESimError.timeout }
        if rejectListAt.contains(listCount) { throw B1ESimError.rejected("Profile read rejected") }
        return profiles
    }
    func enableProfile(iccid: String) async throws {
        calls.append("enable:\(iccid)")
        if holdEnable { await withCheckedContinuation { enableWaiter = $0 } }
        if enableError == nil || applyBeforeError {
            for index in profiles.indices { profiles[index].state = profiles[index].iccid == iccid ? .enabled : .disabled }
        }
        if let enableError { throw enableError }
    }
    func disableProfile(iccid: String) async throws {
        calls.append("disable:\(iccid)")
        if let index = profiles.firstIndex(where: { $0.iccid == iccid }) { profiles[index].state = .disabled }
    }
    func renameProfile(iccid: String, nickname: String) async throws {
        calls.append("rename:\(iccid)")
        if let index = profiles.firstIndex(where: { $0.iccid == iccid }) { profiles[index].nickname = nickname }
    }
    func deleteProfile(iccid: String) async throws { calls.append("delete:\(iccid)"); profiles.removeAll { $0.iccid == iccid } }
    func downloadProfile(_ request: B1DownloadRequest, onInstalled: @escaping @MainActor (B1DownloadReceipt) -> Void) async throws -> B1DownloadReceipt {
        calls.append("download")
        if holdDownload { await withCheckedContinuation { downloadWaiter = $0 } }
        if let iccid = receipt.installedIccid { profiles.append(B1ESimProfile(iccid: iccid, nickname: nil, provider: "New", state: .disabled)) }
        onInstalled(receipt)
        if holdAfterInstall { await withCheckedContinuation { postInstallWaiter = $0 } }
        if let downloadErrorAfterInstall { throw downloadErrorAfterInstall }
        return receipt
    }
    func completeNotification(id: String) async throws {
        calls.append("notify:\(id)")
        if let notificationError { throw notificationError }
    }
    func exportTransferPackage(iccid: String) async throws -> B1TransferPackage {
        calls.append("export:\(iccid)"); return B1TransferPackage(data: Data([1, 2, 3]))
    }
    func invalidateSession() { calls.append("invalidate") }
    func count(_ prefix: String) -> Int { calls.filter { $0.hasPrefix(prefix) }.count }
}

@main
struct B1ESimTests {
    @MainActor
    private static func snapshot() -> B1GattSnapshot {
        B1GattSnapshot(device: B1NearbyDevice(id: "phone-selected", name: nil, rssi: nil, connectable: true, advertisedServices: []),
                       services: [], writeWithResponseLimit: nil, writeWithoutResponseLimit: nil, negotiatedMtu: nil, observedAt: "test")
    }
    @MainActor
    private static func setup(_ selectedAdapter: FakeESimAdapter? = nil, store selectedStore: MemoryNotifications? = nil) async -> (B1ESimController, FakeESimAdapter, MemoryNotifications) {
        let adapter = selectedAdapter ?? FakeESimAdapter()
        let store = selectedStore ?? MemoryNotifications()
        let controller = B1ESimController(store: store, factory: { _ in adapter })
        await controller.attach(snapshot())
        return (controller, adapter, store)
    }
    @MainActor
    private static func waitUntil(_ condition: () -> Bool) async {
        for _ in 0..<100 { if condition() { return }; await Task.yield() }
        preconditionFailure("Expected suspended fake adapter operation")
    }

    @MainActor
    static func main() async throws {
        var passed = 0
        func test(_ body: @MainActor () async throws -> Void) async rethrows { try await body(); passed += 1 }

        await test {
            let store = MemoryNotifications()
            let controller = B1ESimController(store: store)
            await controller.attach(snapshot())
            precondition(controller.phase == .unavailable && controller.profiles.isEmpty)
            let value = await controller.enable("target")
            precondition(value == nil)
        }
        await test {
            let (controller, _, _) = await setup()
            precondition(controller.phase == .ready && controller.card?.eid == "card-A" && controller.profiles.count == 2)
        }
        await test {
            let (controller, adapter, _) = await setup()
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .verified && value?.routerOutcome == "notVerified")
            precondition(adapter.count("enable:") == 1 && adapter.count("disable:") == 0)
            precondition(controller.profiles.first { $0.iccid == "target" }?.state == .enabled)
        }
        await test {
            let (controller, adapter, _) = await setup()
            let value = await controller.enable("old")
            precondition(value?.cardOutcome == .unchanged && adapter.count("enable:") == 0)
        }
        await test {
            let (controller, adapter, _) = await setup()
            let value = await controller.enable("missing")
            precondition(value?.cardOutcome == .rejected && adapter.count("enable:") == 0)
        }
        await test {
            let (controller, _, _) = await setup()
            let value = await controller.disable("old")
            precondition(value?.cardOutcome == .verified && controller.profiles.first { $0.iccid == "old" }?.state == .disabled)
        }
        await test {
            let (controller, adapter, _) = await setup()
            let invalid = await controller.rename("target", nickname: "  ")
            precondition(invalid == nil && adapter.count("rename:") == 0)
            let value = await controller.rename("target", nickname: "  Travel SIM  ")
            precondition(value?.cardOutcome == .verified && controller.profiles.first { $0.iccid == "target" }?.nickname == "Travel SIM")
        }
        await test {
            let (controller, adapter, _) = await setup()
            let value = await controller.delete("target")
            precondition(value?.cardOutcome == .verified && !controller.profiles.contains { $0.iccid == "target" })
            let second = await controller.delete("target")
            precondition(second?.cardOutcome == .unchanged && adapter.count("delete:") == 1)
        }
        await test {
            let adapter = FakeESimAdapter()
            adapter.profiles[1].canDelete = false
            let (controller, _, _) = await setup(adapter)
            let value = await controller.delete("target")
            precondition(value?.cardOutcome == .rejected && adapter.count("delete:") == 0)
        }
        await test {
            let adapter = FakeESimAdapter()
            adapter.enableError = .rejected("Card rejected enable")
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .rejected && controller.phase == .ready)
        }
        await test {
            let adapter = FakeESimAdapter()
            adapter.enableError = .timeout; adapter.applyBeforeError = true
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .verified && adapter.count("enable:") == 1 && adapter.count("recover") == 1)
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.enableError = .timeout
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .unknown && controller.phase == .needsReconciliation)
            let blocked = await controller.enable("target")
            precondition(blocked == nil && adapter.count("enable:") == 1)
            await controller.refresh()
            precondition(controller.phase == .ready && adapter.count("enable:") == 1)
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.enableError = .timeout; adapter.applyBeforeError = true
            adapter.recoveryIdentity = B1ESimCard(eid: "different-card", capabilities: adapter.identity.capabilities)
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .unknown && controller.phase == .needsReconciliation)
            precondition(controller.card?.eid == "card-A")
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.failListAt = [3]
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .verified && adapter.count("enable:") == 1 && adapter.count("recover") == 1)
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.holdEnable = true
            let (controller, _, _) = await setup(adapter)
            let task = Task { await controller.enable("target") }
            await waitUntil { adapter.enableWaiter != nil }
            let count = adapter.listCount
            await controller.refresh()
            let blocked = await controller.disable("old")
            precondition(blocked == nil && adapter.listCount == count && adapter.count("disable:") == 0)
            adapter.enableWaiter?.resume(); adapter.enableWaiter = nil
            let value = await task.value
            precondition(value?.cardOutcome == .verified)
        }
        await test {
            let old = FakeESimAdapter(); old.holdEnable = true
            let fresh = FakeESimAdapter(); fresh.identity = B1ESimCard(eid: "new-card", capabilities: fresh.identity.capabilities)
            var queue = [old, fresh]
            let controller = B1ESimController(store: MemoryNotifications(), factory: { _ in queue.removeFirst() })
            await controller.attach(snapshot())
            let task = Task { await controller.enable("target") }
            await waitUntil { old.enableWaiter != nil }
            controller.disconnect()
            await controller.attach(snapshot())
            old.enableWaiter?.resume(); old.enableWaiter = nil
            let value = await task.value
            precondition(value == nil && controller.card?.eid == "new-card" && controller.phase == .ready)
            precondition(controller.profiles.first { $0.iccid == "target" }?.state == .disabled)
        }
        try await test {
            let adapter = FakeESimAdapter()
            adapter.receipt = B1DownloadReceipt(installedIccid: "downloaded", pendingNotifications: [B1PendingNotification(id: "notice-1", cardEid: "card-A", profileIccid: "downloaded")])
            let (controller, _, store) = await setup(adapter)
            let request = try B1DownloadRequest(activationCode: "LPA:1$example.test$SECRET", confirmationCode: "PINSECRET")
            let value = await controller.download(request)
            precondition(value?.cardOutcome == .verified && store.items.count == 1)
            let saved = String(decoding: try JSONEncoder().encode(store.items), as: UTF8.self)
            precondition(!saved.contains("SECRET") && !String(describing: request).contains("SECRET"))
            adapter.notificationError = .timeout
            _ = await controller.retryNotifications()
            precondition(controller.pendingNotifications.count == 1 && adapter.count("download") == 1)
            adapter.notificationError = nil
            await controller.refresh()
            _ = await controller.retryNotifications()
            precondition(controller.pendingNotifications.isEmpty && store.items.isEmpty && adapter.count("download") == 1)
        }
        try await test {
            let adapter = FakeESimAdapter(); adapter.holdDownload = true
            adapter.receipt = B1DownloadReceipt(installedIccid: "downloaded", pendingNotifications: [B1PendingNotification(id: "late-notice", cardEid: "card-A", profileIccid: "downloaded")])
            let (controller, _, store) = await setup(adapter)
            let request = try B1DownloadRequest(activationCode: "LPA:1$example.test$SECRET")
            let task = Task { await controller.download(request) }
            await waitUntil { adapter.downloadWaiter != nil }
            controller.disconnect()
            adapter.downloadWaiter?.resume(); adapter.downloadWaiter = nil
            let value = await task.value
            precondition(value == nil && controller.phase == .disconnected && store.items.count == 1)
        }
        try await test {
            let store = MemoryNotifications(); store.failLoad = true
            let (controller, adapter, _) = await setup(store: store)
            let value = await controller.download(try B1DownloadRequest(activationCode: "LPA:1$example.test$SECRET"))
            precondition(value == nil && adapter.count("download") == 0)
        }
        await test {
            let store = MemoryNotifications()
            store.items = [B1PendingNotification(id: "notice", cardEid: "card-A", profileIccid: "target")]
            let (controller, _, _) = await setup(store: store)
            store.failSave = true
            _ = await controller.retryNotifications()
            precondition(controller.pendingNotifications.count == 1 && controller.journalWarning != nil)
        }
        try await test {
            let (controller, _, _) = await setup()
            let artifact = try controller.exportMetadata()
            let object = try JSONSerialization.jsonObject(with: artifact.data) as! [String: Any]
            precondition(object["kind"] as? String == "profileMetadata" && object["portable"] as? Bool == false)
            precondition(!artifact.isTransferPackage && object["activationCode"] == nil && object["profileKeys"] == nil)
            precondition((object["profiles"] as? [[String: Any]])?.count == 2)
        }
        await test {
            let adapter = FakeESimAdapter()
            adapter.identity = B1ESimCard(eid: "card-A", capabilities: [.list, .enable])
            let (controller, _, _) = await setup(adapter)
            let artifact = await controller.exportTransfer("target")
            precondition(artifact == nil && adapter.count("export:") == 0)
        }
        await test {
            let (controller, _, _) = await setup()
            let artifact = await controller.exportTransfer("target")
            precondition(artifact?.data == Data([1, 2, 3]) && artifact?.isTransferPackage == true)
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.profiles.append(adapter.profiles[0])
            let (controller, _, _) = await setup(adapter)
            precondition(controller.phase == .unavailable && controller.profiles.isEmpty)
        }
        try await test {
            do { _ = try B1DownloadRequest(activationCode: "arbitrary bytes"); preconditionFailure("Expected invalid activation code") }
            catch is B1ESimError {}
        }
        try await test {
            let adapter = FakeESimAdapter(); adapter.downloadErrorAfterInstall = .timeout
            adapter.receipt = B1DownloadReceipt(installedIccid: "downloaded", pendingNotifications: [B1PendingNotification(id: "progress-notice", cardEid: "card-A", profileIccid: "downloaded")])
            let (controller, _, store) = await setup(adapter)
            let value = await controller.download(try B1DownloadRequest(activationCode: "LPA:1$example.test$SECRET"))
            precondition(value?.cardOutcome == .unknown && store.items.count == 1 && adapter.count("download") == 1)
        }
        try await test {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: directory) }
            let url = directory.appendingPathComponent("notifications.json")
            let store = B1FileNotificationStore(url: url)
            let items = [B1PendingNotification(id: "record", cardEid: "card-A", profileIccid: "target")]
            try store.save(items)
            let restored = try B1FileNotificationStore(url: url).load()
            precondition(restored == items)
        }
        try await test {
            let adapter = FakeESimAdapter(); adapter.holdAfterInstall = true
            adapter.receipt = B1DownloadReceipt(installedIccid: "downloaded", pendingNotifications: [B1PendingNotification(id: "notice", cardEid: "card-A", profileIccid: "downloaded")])
            let (controller, _, store) = await setup(adapter)
            let request = try B1DownloadRequest(activationCode: "LPA:1$example.test$SECRET")
            let task = Task { await controller.download(request) }
            await waitUntil { adapter.postInstallWaiter != nil }
            controller.disconnect()
            await controller.attach(snapshot())
            _ = await controller.retryNotifications()
            precondition(store.items.isEmpty)
            adapter.postInstallWaiter?.resume(); adapter.postInstallWaiter = nil
            _ = await task.value
            precondition(store.items.isEmpty && controller.pendingNotifications.isEmpty,
                         "A late installation receipt must not recreate an already completed notification")
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.rejectListAt = [3]
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .unknown && controller.phase == .needsReconciliation,
                         "A rejected read-back cannot prove the accepted mutation was rejected")
            precondition(adapter.count("enable:") == 1)
        }
        await test {
            let adapter = FakeESimAdapter(); adapter.enableError = .timeout; adapter.rejectListAt = [3]
            let (controller, _, _) = await setup(adapter)
            let value = await controller.enable("target")
            precondition(value?.cardOutcome == .unknown && controller.phase == .needsReconciliation,
                         "A rejected recovery read cannot prove the timed-out mutation was rejected")
            precondition(adapter.count("enable:") == 1)
        }
        print("B1 eSIM tests passed: \(passed) cases for profile actions, serialization, reconciliation, interruption, notification persistence, export and credential isolation")
    }
}
