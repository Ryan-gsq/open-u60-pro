package com.openu60.core.esim

import com.openu60.core.bluetooth.B1GattSnapshot
import com.openu60.core.bluetooth.B1NearbyDevice
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class B1ESimControllerTest {
    private val snapshot = B1GattSnapshot(B1NearbyDevice("selected", null, null, true, emptyList()), emptyList(), observedAt = "test")
    private val request get() = B1DownloadRequest("LPA:1\$example.test\$SECRET", "PINSECRET")
    private class MemoryStore : B1NotificationStore {
        var items = emptyList<B1PendingNotification>()
        var failLoad = false
        var failSave = false
        override fun load(): List<B1PendingNotification> {
            if (failLoad) throw B1ESimError.JournalUnavailable
            return items
        }
        override fun save(items: List<B1PendingNotification>) {
            if (failSave) throw B1ESimError.JournalUnavailable
            this.items = items
        }
    }
    private class FakeAdapter : B1ESimAdapter {
        override var protocolVerified = true
        var identity = B1ESimCard("card-A", B1ESimAction.entries.toSet())
        var recoveryIdentity: B1ESimCard? = null
        var profiles = listOf(
            B1ESimProfile("old", "Old", "Carrier A", B1ProfileState.ENABLED),
            B1ESimProfile("target", "Target", "Carrier B", B1ProfileState.DISABLED),
        )
        val calls = mutableListOf<String>()
        var enableError: B1ESimError? = null
        var applyBeforeError = false
        var enableWaiter: CompletableDeferred<Unit>? = null
        var downloadWaiter: CompletableDeferred<Unit>? = null
        var postInstallWaiter: CompletableDeferred<Unit>? = null
        var listCount = 0
        var failListAt = emptySet<Int>()
        var rejectListAt = emptySet<Int>()
        var notificationError: B1ESimError? = null
        var downloadErrorAfterInstall: B1ESimError? = null
        var receipt = B1DownloadReceipt("downloaded", emptyList())
        override suspend fun openSession(): B1ESimCard { calls.add("open"); return identity }
        override suspend fun recoverSession(): B1ESimCard { calls.add("recover"); return recoveryIdentity ?: identity }
        override suspend fun listProfiles(): List<B1ESimProfile> {
            calls.add("list"); listCount++
            if (listCount in failListAt) throw B1ESimError.Timeout
            if (listCount in rejectListAt) throw B1ESimError.Rejected("Profile read rejected")
            return profiles
        }
        override suspend fun enableProfile(iccid: String) {
            calls.add("enable:$iccid"); enableWaiter?.await()
            if (enableError == null || applyBeforeError) profiles = profiles.map {
                it.copy(state = if (it.iccid == iccid) B1ProfileState.ENABLED else B1ProfileState.DISABLED)
            }
            enableError?.let { throw it }
        }
        override suspend fun disableProfile(iccid: String) { calls.add("disable:$iccid"); profiles = profiles.map { if (it.iccid == iccid) it.copy(state = B1ProfileState.DISABLED) else it } }
        override suspend fun renameProfile(iccid: String, nickname: String) { calls.add("rename:$iccid"); profiles = profiles.map { if (it.iccid == iccid) it.copy(nickname = nickname) else it } }
        override suspend fun deleteProfile(iccid: String) { calls.add("delete:$iccid"); profiles = profiles.filterNot { it.iccid == iccid } }
        override suspend fun downloadProfile(request: B1DownloadRequest, onInstalled: (B1DownloadReceipt) -> Unit): B1DownloadReceipt {
            calls.add("download"); downloadWaiter?.await()
            receipt.installedIccid?.let { profiles = profiles + B1ESimProfile(it, null, "New", B1ProfileState.DISABLED) }
            onInstalled(receipt)
            postInstallWaiter?.await()
            downloadErrorAfterInstall?.let { throw it }
            return receipt
        }
        override suspend fun completeNotification(id: String) { calls.add("notify:$id"); notificationError?.let { throw it } }
        override suspend fun exportTransferPackage(iccid: String): B1TransferPackage { calls.add("export:$iccid"); return B1TransferPackage(byteArrayOf(1, 2, 3)) }
        override fun invalidateSession() { calls.add("invalidate") }
        fun count(prefix: String) = calls.count { it.startsWith(prefix) }
    }
    private suspend fun setup(adapter: FakeAdapter = FakeAdapter(), store: MemoryStore = MemoryStore()): Triple<B1ESimController, FakeAdapter, MemoryStore> {
        val controller = B1ESimController(store) { adapter }
        controller.attach(snapshot)
        return Triple(controller, adapter, store)
    }

    @Test fun productionAdapterBlocksUnverifiedProfileCommands() = runTest {
        val controller = B1ESimController(MemoryStore())
        controller.attach(snapshot)
        assertEquals(B1ManagementPhase.UNAVAILABLE, controller.state.value.phase)
        assertNull(controller.enable("target"))
    }
    @Test fun displaysCardIdentityAndProfileList() = runTest {
        val (controller) = setup()
        assertEquals("card-A", controller.state.value.card?.eid)
        assertEquals(2, controller.state.value.profiles.size)
        assertEquals(B1ManagementPhase.READY, controller.state.value.phase)
    }
    @Test fun switchingVerifiesTargetWithoutPreDisablingOldProfile() = runTest {
        val (controller, adapter) = setup()
        val result = controller.enable("target")
        assertEquals(B1CardOutcome.VERIFIED, result?.cardOutcome)
        assertEquals("notVerified", result?.routerOutcome)
        assertEquals(1, adapter.count("enable:"))
        assertEquals(0, adapter.count("disable:"))
    }
    @Test fun alreadyEnabledIsIdempotent() = runTest {
        val (controller, adapter) = setup()
        assertEquals(B1CardOutcome.UNCHANGED, controller.enable("old")?.cardOutcome)
        assertEquals(0, adapter.count("enable:"))
    }
    @Test fun absentTargetNeverWrites() = runTest {
        val (controller, adapter) = setup()
        assertEquals(B1CardOutcome.REJECTED, controller.enable("missing")?.cardOutcome)
        assertEquals(0, adapter.count("enable:"))
    }
    @Test fun disablingRequiresReadback() = runTest {
        val (controller) = setup()
        assertEquals(B1CardOutcome.VERIFIED, controller.disable("old")?.cardOutcome)
        assertEquals(B1ProfileState.DISABLED, controller.state.value.profiles.first { it.iccid == "old" }.state)
    }
    @Test fun renameValidatesAndTrimsInput() = runTest {
        val (controller, adapter) = setup()
        assertNull(controller.rename("target", "  "))
        assertEquals(0, adapter.count("rename:"))
        assertEquals(B1CardOutcome.VERIFIED, controller.rename("target", "  Travel SIM  ")?.cardOutcome)
        assertEquals("Travel SIM", controller.state.value.profiles.first { it.iccid == "target" }.nickname)
    }
    @Test fun deletionAndAlreadyAbsentAreVerified() = runTest {
        val (controller, adapter) = setup()
        assertEquals(B1CardOutcome.VERIFIED, controller.delete("target")?.cardOutcome)
        assertEquals(B1CardOutcome.UNCHANGED, controller.delete("target")?.cardOutcome)
        assertEquals(1, adapter.count("delete:"))
    }
    @Test fun cardPolicyBlocksDeletion() = runTest {
        val adapter = FakeAdapter()
        adapter.profiles = adapter.profiles.map { it.copy(canDelete = false) }
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.REJECTED, controller.delete("target")?.cardOutcome)
        assertEquals(0, adapter.count("delete:"))
    }
    @Test fun definitiveCardRejectionKeepsSessionReady() = runTest {
        val adapter = FakeAdapter(); adapter.enableError = B1ESimError.Rejected("Card rejected enable")
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.REJECTED, controller.enable("target")?.cardOutcome)
        assertEquals(B1ManagementPhase.READY, controller.state.value.phase)
    }
    @Test fun acceptedEnableTimeoutRecoversWithoutResending() = runTest {
        val adapter = FakeAdapter(); adapter.enableError = B1ESimError.Timeout; adapter.applyBeforeError = true
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.VERIFIED, controller.enable("target")?.cardOutcome)
        assertEquals(1, adapter.count("enable:"))
        assertEquals(1, adapter.count("recover"))
    }
    @Test fun unresolvedTimeoutBlocksMutationsUntilRefresh() = runTest {
        val adapter = FakeAdapter(); adapter.enableError = B1ESimError.Timeout
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.UNKNOWN, controller.enable("target")?.cardOutcome)
        assertEquals(B1ManagementPhase.NEEDS_RECONCILIATION, controller.state.value.phase)
        assertNull(controller.enable("target"))
        controller.refresh()
        assertEquals(B1ManagementPhase.READY, controller.state.value.phase)
        assertEquals(1, adapter.count("enable:"))
    }
    @Test fun recoveryRejectsDifferentCard() = runTest {
        val adapter = FakeAdapter(); adapter.enableError = B1ESimError.Timeout; adapter.applyBeforeError = true
        adapter.recoveryIdentity = adapter.identity.copy(eid = "other-card")
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.UNKNOWN, controller.enable("target")?.cardOutcome)
        assertEquals("card-A", controller.state.value.card?.eid)
        assertEquals(B1ManagementPhase.NEEDS_RECONCILIATION, controller.state.value.phase)
    }
    @Test fun postWriteReadTimeoutReconcilesState() = runTest {
        val adapter = FakeAdapter(); adapter.failListAt = setOf(3)
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.VERIFIED, controller.enable("target")?.cardOutcome)
        assertEquals(1, adapter.count("enable:"))
        assertEquals(1, adapter.count("recover"))
    }
    @Test fun wholeOperationLockBlocksRefreshAndOtherMutation() = runTest {
        val adapter = FakeAdapter(); val waiter = CompletableDeferred<Unit>(); adapter.enableWaiter = waiter
        val (controller) = setup(adapter)
        val job = async { controller.enable("target") }
        runCurrent()
        val count = adapter.listCount
        controller.refresh()
        assertNull(controller.disable("old"))
        assertEquals(count, adapter.listCount)
        waiter.complete(Unit)
        assertEquals(B1CardOutcome.VERIFIED, job.await()?.cardOutcome)
    }
    @Test fun retiredOperationCannotOverwriteAnotherCardSession() = runTest {
        val old = FakeAdapter(); val waiter = CompletableDeferred<Unit>(); old.enableWaiter = waiter
        val fresh = FakeAdapter(); fresh.identity = fresh.identity.copy(eid = "new-card")
        val queue = ArrayDeque(listOf(old, fresh))
        val controller = B1ESimController(MemoryStore()) { queue.removeFirst() }
        controller.attach(snapshot)
        val job = async { controller.enable("target") }
        runCurrent()
        controller.disconnect()
        controller.attach(snapshot)
        waiter.complete(Unit)
        assertNull(job.await())
        assertEquals("new-card", controller.state.value.card?.eid)
        assertEquals(B1ProfileState.DISABLED, controller.state.value.profiles.first { it.iccid == "target" }.state)
    }
    @Test fun installedProfileRetainsNotificationWorkWithoutReinstalling() = runTest {
        val adapter = FakeAdapter()
        adapter.receipt = B1DownloadReceipt("downloaded", listOf(B1PendingNotification("notice", "card-A", "downloaded")))
        val (controller, _, store) = setup(adapter)
        assertEquals(B1CardOutcome.VERIFIED, controller.download(request)?.cardOutcome)
        assertEquals(1, store.items.size)
        assertFalse(Json.encodeToString(store.items).contains("SECRET"))
        assertFalse(request.toString().contains("SECRET"))
        adapter.notificationError = B1ESimError.Timeout
        controller.retryNotifications()
        assertEquals(1, controller.state.value.pendingNotifications.size)
        adapter.notificationError = null
        controller.refresh()
        controller.retryNotifications()
        assertTrue(store.items.isEmpty())
        assertEquals(1, adapter.count("download"))
    }
    @Test fun interruptedDownloadReceiptStillPreservesKnownPendingWork() = runTest {
        val adapter = FakeAdapter(); val waiter = CompletableDeferred<Unit>(); adapter.downloadWaiter = waiter
        adapter.receipt = B1DownloadReceipt("downloaded", listOf(B1PendingNotification("late-notice", "card-A", "downloaded")))
        val (controller, _, store) = setup(adapter)
        val job = async { controller.download(request) }
        runCurrent()
        controller.disconnect()
        waiter.complete(Unit)
        assertNull(job.await())
        assertEquals(1, store.items.size)
        assertEquals(B1ManagementPhase.DISCONNECTED, controller.state.value.phase)
    }
    @Test fun unreadableNotificationJournalBlocksNewDownload() = runTest {
        val store = MemoryStore(); store.failLoad = true
        val (controller, adapter) = setup(store = store)
        assertNull(controller.download(request))
        assertEquals(0, adapter.count("download"))
    }
    @Test fun failedNotificationSaveRetainsPendingRecord() = runTest {
        val store = MemoryStore(); store.items = listOf(B1PendingNotification("notice", "card-A", "target"))
        val (controller) = setup(store = store)
        store.failSave = true
        controller.retryNotifications()
        assertEquals(1, controller.state.value.pendingNotifications.size)
        assertNotNull(controller.state.value.journalWarning)
    }
    @Test fun metadataExportIsAllowlistedAndNotPortable() = runTest {
        val (controller) = setup()
        val artifact = controller.exportMetadata()
        val report = Json.parseToJsonElement(artifact.data.toString(Charsets.UTF_8)).jsonObject
        assertEquals("profileMetadata", report.getValue("kind").jsonPrimitive.content)
        assertEquals(false, report.getValue("portable").jsonPrimitive.boolean)
        assertEquals(2, report.getValue("profiles").jsonArray.size)
        assertFalse(artifact.isTransferPackage)
        assertFalse(report.containsKey("activationCode"))
        assertFalse(report.containsKey("profileKeys"))
    }
    @Test fun transferExportRequiresExplicitCapability() = runTest {
        val adapter = FakeAdapter(); adapter.identity = adapter.identity.copy(capabilities = setOf(B1ESimAction.LIST))
        val (controller) = setup(adapter)
        assertNull(controller.exportTransfer("target"))
        assertEquals(0, adapter.count("export:"))
    }
    @Test fun transferExportUsesAdapterBytes() = runTest {
        val (controller) = setup()
        val artifact = controller.exportTransfer("target")
        assertArrayEquals(byteArrayOf(1, 2, 3), artifact?.data)
        assertTrue(artifact?.isTransferPackage == true)
    }
    @Test fun duplicateProfileIdentifiersCannotBecomeReady() = runTest {
        val adapter = FakeAdapter(); adapter.profiles = adapter.profiles + adapter.profiles.first()
        val (controller) = setup(adapter)
        assertEquals(B1ManagementPhase.UNAVAILABLE, controller.state.value.phase)
        assertTrue(controller.state.value.profiles.isEmpty())
    }
    @Test fun malformedActivationCodeIsRejected() {
        assertThrows(B1ESimError.InvalidInput::class.java) { B1DownloadRequest("arbitrary bytes") }
    }
    @Test fun installationProgressSurvivesSubsequentDownloadTimeout() = runTest {
        val adapter = FakeAdapter(); adapter.downloadErrorAfterInstall = B1ESimError.Timeout
        adapter.receipt = B1DownloadReceipt("downloaded", listOf(B1PendingNotification("progress-notice", "card-A", "downloaded")))
        val (controller, _, store) = setup(adapter)
        assertEquals(B1CardOutcome.UNKNOWN, controller.download(request)?.cardOutcome)
        assertEquals(1, store.items.size)
        assertEquals(1, adapter.count("download"))
    }
    @Test fun lateInstallationReceiptDoesNotRecreateCompletedNotification() = runTest {
        val adapter = FakeAdapter(); val waiter = CompletableDeferred<Unit>(); adapter.postInstallWaiter = waiter
        adapter.receipt = B1DownloadReceipt("downloaded", listOf(B1PendingNotification("notice", "card-A", "downloaded")))
        val (controller, _, store) = setup(adapter)
        val job = async { controller.download(request) }
        runCurrent()
        controller.disconnect()
        controller.attach(snapshot)
        controller.retryNotifications()
        assertTrue(store.items.isEmpty())
        waiter.complete(Unit)
        job.await()
        assertTrue(store.items.isEmpty())
        assertTrue(controller.state.value.pendingNotifications.isEmpty())
    }
    @Test fun rejectedReadbackDoesNotMislabelAcceptedMutation() = runTest {
        val adapter = FakeAdapter(); adapter.rejectListAt = setOf(3)
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.UNKNOWN, controller.enable("target")?.cardOutcome)
        assertEquals(B1ManagementPhase.NEEDS_RECONCILIATION, controller.state.value.phase)
        assertEquals(1, adapter.count("enable:"))
    }
    @Test fun rejectedRecoveryReadDoesNotMislabelTimedOutMutation() = runTest {
        val adapter = FakeAdapter(); adapter.enableError = B1ESimError.Timeout; adapter.rejectListAt = setOf(3)
        val (controller) = setup(adapter)
        assertEquals(B1CardOutcome.UNKNOWN, controller.enable("target")?.cardOutcome)
        assertEquals(B1ManagementPhase.NEEDS_RECONCILIATION, controller.state.value.phase)
        assertEquals(1, adapter.count("enable:"))
    }
}
