package com.openu60.core.esim

import com.openu60.core.bluetooth.B1GattSnapshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.UUID

/** Main-thread operation coordinator; one whole card operation at a time. */
class B1ESimController(
    private val store: B1NotificationStore,
    private val factory: (B1GattSnapshot) -> B1ESimAdapter = { B1UnverifiedESimAdapter() },
) {
    private val mutableState = MutableStateFlow(B1ESimState())
    val state = mutableState.asStateFlow()
    private var adapter: B1ESimAdapter? = null
    private var generation = 0L
    private data class Active(val id: String, val action: B1ESimAction, val target: String?, var sent: Boolean = false, var verificationRequired: Boolean = false)
    private data class Context(val adapter: B1ESimAdapter, val epoch: Long, val id: String)
    private var active: Active? = null
    private val completedNotifications = mutableSetOf<Pair<String, String>>()

    init {
        try { mutableState.value = state.value.copy(pendingNotifications = store.load()) }
        catch (_: Exception) { mutableState.value = state.value.copy(journalWarning = B1ESimError.JournalUnavailable.message) }
    }

    suspend fun attach(snapshot: B1GattSnapshot) {
        disconnect()
        val epoch = generation
        val next = factory(snapshot)
        adapter = next
        if (!next.protocolVerified) {
            mutableState.value = state.value.copy(phase = B1ManagementPhase.UNAVAILABLE, message = B1ESimError.ProtocolUnavailable.message)
            return
        }
        mutableState.value = state.value.copy(phase = B1ManagementPhase.OPENING)
        try {
            val identity = next.openSession()
            check(epoch)
            validate(identity)
            mutableState.value = state.value.copy(card = identity)
            if (B1ESimAction.LIST !in identity.capabilities) throw B1ESimError.Unsupported(B1ESimAction.LIST)
            val profiles = next.listProfiles()
            check(epoch)
            setProfiles(profiles)
            mutableState.value = state.value.copy(phase = B1ManagementPhase.READY, message = "Card ready. Router Internet has not been verified.")
        } catch (error: Exception) {
            if (generation == epoch) {
                next.invalidateSession()
                mutableState.value = state.value.copy(phase = B1ManagementPhase.UNAVAILABLE, card = null,
                    profiles = emptyList(), message = safeMessage(error))
            }
            if (error is CancellationException) throw error
        }
    }

    fun disconnect() {
        generation++
        val previous = active
        val interrupted = previous?.takeIf { it.sent }?.let {
            result(it.id, it.action, it.target, B1CardOutcome.UNKNOWN,
                "Operation interrupted. Reconnect and read card state before repeating it.")
        }
        active = null
        adapter?.invalidateSession()
        adapter = null
        mutableState.value = state.value.copy(phase = B1ManagementPhase.DISCONNECTED, card = null,
            profiles = emptyList(), profilesObservedAt = null, message = null,
            lastResult = interrupted ?: state.value.lastResult)
    }

    suspend fun refresh() {
        if (!state.value.canRefresh) return
        val current = adapter ?: return
        val recovering = state.value.phase == B1ManagementPhase.NEEDS_RECONCILIATION
        mutableState.value = state.value.copy(phase = B1ManagementPhase.BUSY)
        val epoch = generation
        try {
            if (recovering) recover(current, epoch)
            try {
                val profiles = current.listProfiles()
                check(epoch)
                setProfiles(profiles)
            } catch (error: B1ESimError) {
                if (!error.isAmbiguous || recovering) throw error
                check(epoch)
                recover(current, epoch)
                val profiles = current.listProfiles()
                check(epoch)
                setProfiles(profiles)
            }
            mutableState.value = state.value.copy(phase = B1ManagementPhase.READY, message = "Profiles refreshed.")
        } catch (error: Exception) {
            if (generation == epoch) {
                current.invalidateSession()
                mutableState.value = state.value.copy(phase = B1ManagementPhase.NEEDS_RECONCILIATION, message = safeMessage(error))
            }
            if (error is CancellationException) throw error
        }
    }

    suspend fun enable(iccid: String) = mutate(B1ESimAction.ENABLE, iccid)
    suspend fun disable(iccid: String) = mutate(B1ESimAction.DISABLE, iccid)
    suspend fun delete(iccid: String) = mutate(B1ESimAction.DELETE, iccid)
    suspend fun rename(iccid: String, nickname: String): B1ESimResult? {
        val trimmed = nickname.trim()
        if (trimmed.isEmpty() || trimmed.toByteArray(Charsets.UTF_8).size > 128 || trimmed.any { it.isISOControl() }) {
            if (state.value.canOperate) mutableState.value = state.value.copy(message = "Enter a nickname of 1–128 UTF-8 bytes without control characters.")
            return null
        }
        return mutate(B1ESimAction.RENAME, iccid, trimmed)
    }

    private suspend fun mutate(action: B1ESimAction, iccid: String, nickname: String? = null): B1ESimResult? {
        val context = begin(action, iccid) ?: return null
        val current = context.adapter
        try {
            val before = current.listProfiles()
            check(context.epoch)
            setProfiles(before)
            val target = before.firstOrNull { it.iccid == iccid }
            if (action == B1ESimAction.DELETE && target == null) return finish(context.id, action, iccid, B1CardOutcome.UNCHANGED, "Profile was already absent.")
            if (target == null) throw B1ESimError.InvalidInput("The target ICCID is not on this card.")
            if (matches(action, iccid, nickname, before)) return finish(context.id, action, iccid, B1CardOutcome.UNCHANGED, "The requested profile state is already present.")
            if (action == B1ESimAction.DELETE && target.canDelete == false) throw B1ESimError.Rejected("Card policy prevents deleting this profile.")
            if (action == B1ESimAction.DISABLE && target.canDisable == false) throw B1ESimError.Rejected("Card policy prevents disabling this profile.")
            active?.sent = true
            try {
                when (action) {
                    B1ESimAction.ENABLE -> current.enableProfile(iccid)
                    B1ESimAction.DISABLE -> current.disableProfile(iccid)
                    B1ESimAction.RENAME -> current.renameProfile(iccid, nickname ?: "")
                    B1ESimAction.DELETE -> current.deleteProfile(iccid)
                    else -> throw B1ESimError.Unsupported(action)
                }
                check(context.epoch)
                active?.verificationRequired = true
                val after = current.listProfiles()
                check(context.epoch)
                setProfiles(after)
                if (!matches(action, iccid, nickname, after)) throw B1ESimError.OutcomeUnknown
            } catch (error: B1ESimError) {
                if (!error.isAmbiguous) throw error
                check(context.epoch)
                active?.verificationRequired = true
                // Recover and read back after ambiguity; never resend the mutation.
                recover(current, context.epoch)
                val after = current.listProfiles()
                check(context.epoch)
                setProfiles(after)
                if (!matches(action, iccid, nickname, after)) throw B1ESimError.OutcomeUnknown
            }
            return finish(context.id, action, iccid, B1CardOutcome.VERIFIED, successMessage(action))
        } catch (error: Exception) {
            val result = failure(error, context, action, iccid)
            if (error is CancellationException) throw error
            return result
        }
    }

    suspend fun download(request: B1DownloadRequest): B1ESimResult? {
        if (state.value.journalWarning != null) {
            mutableState.value = state.value.copy(message = state.value.journalWarning)
            return null
        }
        val context = begin(B1ESimAction.DOWNLOAD, null) ?: return null
        val eid = state.value.card?.eid
        try {
            active?.sent = true
            var invalidReceipt = false
            val receipt = context.adapter.downloadProfile(request) { receipt ->
                // Persist installation progress before later network work can fail or be canceled.
                if (!recordReceipt(receipt, eid)) invalidReceipt = true
                if (generation == context.epoch && active?.id == context.id && receipt.installedIccid != null) active?.verificationRequired = true
            }
            if (invalidReceipt || !recordReceipt(receipt, eid)) throw B1ESimError.InvalidResponse
            check(context.epoch)
            active?.verificationRequired = receipt.installedIccid != null
            val installed = receipt.installedIccid?.takeIf { it.isNotEmpty() } ?: throw B1ESimError.OutcomeUnknown
            val after = context.adapter.listProfiles()
            check(context.epoch)
            setProfiles(after)
            if (after.none { it.iccid == installed }) throw B1ESimError.OutcomeUnknown
            val text = if (state.value.notificationsForCard.isEmpty()) "Profile installation verified." else
                "Profile installation verified. Server notifications remain pending; do not reinstall."
            return finish(context.id, B1ESimAction.DOWNLOAD, installed, B1CardOutcome.VERIFIED, text)
        } catch (error: Exception) {
            val result = failure(error, context, B1ESimAction.DOWNLOAD, null)
            if (error is CancellationException) throw error
            return result
        }
    }

    suspend fun retryNotifications(): B1ESimResult? {
        val context = begin(B1ESimAction.NOTIFY, null) ?: return null
        try {
            for (item in state.value.notificationsForCard) {
                context.adapter.completeNotification(item.id)
                check(context.epoch)
                val previous = state.value.pendingNotifications
                mutableState.value = state.value.copy(pendingNotifications = previous.filterNot { it.cardEid == item.cardEid && it.id == item.id })
                persistNotifications()
                if (state.value.journalWarning != null) {
                    mutableState.value = state.value.copy(pendingNotifications = previous)
                    throw B1ESimError.JournalUnavailable
                }
                completedNotifications.add(item.cardEid to item.id)
            }
            return finish(context.id, B1ESimAction.NOTIFY, null, B1CardOutcome.VERIFIED, "Pending server notifications completed.")
        } catch (error: Exception) {
            if (generation != context.epoch) {
                if (error is CancellationException) throw error
                return null
            }
            active = null
            context.adapter.invalidateSession()
            val result = result(context.id, B1ESimAction.NOTIFY, null, B1CardOutcome.UNKNOWN,
                "Server notification remains pending. Profile installation will not be repeated.")
            mutableState.value = state.value.copy(phase = B1ManagementPhase.NEEDS_RECONCILIATION, lastResult = result, message = result.message)
            if (error is CancellationException) throw error
            return result
        }
    }

    @Serializable private data class Metadata(
        val schemaVersion: Int = 1, val kind: String = "profileMetadata", val portable: Boolean = false,
        val cardEid: String, val observedAt: String, val profiles: List<B1ESimProfile>,
    )

    /** Allowlisted metadata snapshot, never activation codes or profile keys. */
    fun exportMetadata(): B1ExportArtifact {
        val card = state.value.card
        val observedAt = state.value.profilesObservedAt
        if (!state.value.canOperate || card == null || observedAt == null) throw B1ESimError.ProtocolUnavailable
        val json = Json { prettyPrint = true; encodeDefaults = true }
        val data = json.encodeToString(Metadata(cardEid = card.eid, observedAt = observedAt, profiles = state.value.profiles))
        return B1ExportArtifact("b1-profile-metadata.json", data.toByteArray(Charsets.UTF_8), false)
    }

    suspend fun exportTransfer(iccid: String): B1ExportArtifact? {
        val context = begin(B1ESimAction.EXPORT_TRANSFER, iccid) ?: return null
        try {
            val profiles = context.adapter.listProfiles()
            check(context.epoch)
            setProfiles(profiles)
            if (profiles.none { it.iccid == iccid }) throw B1ESimError.InvalidInput("The target ICCID is not on this card.")
            val packageData = context.adapter.exportTransferPackage(iccid)
            check(context.epoch)
            if (packageData.data.isEmpty()) throw B1ESimError.InvalidResponse
            finish(context.id, B1ESimAction.EXPORT_TRANSFER, iccid, B1CardOutcome.VERIFIED, "Transfer package exported by the card adapter.")
            return B1ExportArtifact("b1-transfer-package.bin", packageData.data, true)
        } catch (error: Exception) {
            failure(error, context, B1ESimAction.EXPORT_TRANSFER, iccid)
            if (error is CancellationException) throw error
            return null
        }
    }

    private fun begin(action: B1ESimAction, target: String?): Context? {
        if (!state.value.canOperate) return null
        val current = adapter ?: return null
        if (state.value.card?.capabilities?.contains(action) != true) {
            mutableState.value = state.value.copy(message = B1ESimError.Unsupported(action).message)
            return null
        }
        val id = UUID.randomUUID().toString()
        active = Active(id, action, target)
        mutableState.value = state.value.copy(phase = B1ManagementPhase.BUSY, message = null)
        return Context(current, generation, id)
    }

    private suspend fun recover(current: B1ESimAdapter, epoch: Long) {
        current.invalidateSession()
        val identity = current.recoverSession()
        check(epoch)
        validate(identity)
        if (identity.eid != state.value.card?.eid) throw B1ESimError.CardChanged
        mutableState.value = state.value.copy(card = identity)
    }

    private fun validate(card: B1ESimCard) { if (card.eid.isBlank()) throw B1ESimError.InvalidResponse }
    private fun setProfiles(profiles: List<B1ESimProfile>) {
        if (profiles.any { it.iccid.isEmpty() } || profiles.distinctBy { it.iccid }.size != profiles.size) throw B1ESimError.InvalidResponse
        mutableState.value = state.value.copy(profiles = profiles, profilesObservedAt = Instant.now().toString())
    }

    private suspend fun check(epoch: Long) {
        if (generation != epoch || adapter == null) throw B1ESimError.StaleSession
        currentCoroutineContext().ensureActive()
    }

    private fun matches(action: B1ESimAction, iccid: String, nickname: String?, profiles: List<B1ESimProfile>): Boolean {
        val target = profiles.firstOrNull { it.iccid == iccid }
        return when (action) {
            B1ESimAction.ENABLE -> target?.state == B1ProfileState.ENABLED
            B1ESimAction.DISABLE -> target?.state == B1ProfileState.DISABLED
            B1ESimAction.RENAME -> target?.nickname == nickname
            B1ESimAction.DELETE -> target == null
            else -> false
        }
    }

    private fun finish(id: String, action: B1ESimAction, target: String?, outcome: B1CardOutcome, text: String): B1ESimResult {
        active = null
        val result = result(id, action, target, outcome, text)
        mutableState.value = state.value.copy(phase = B1ManagementPhase.READY, lastResult = result, message = text)
        return result
    }

    private fun failure(error: Exception, context: Context, action: B1ESimAction, target: String?): B1ESimResult? {
        if (generation != context.epoch) return null
        val typed = error as? B1ESimError
        val definite = (typed is B1ESimError.Rejected || typed is B1ESimError.InvalidInput || typed is B1ESimError.Unsupported) && active?.verificationRequired != true
        val ambiguous = active?.sent == true && !definite
        active = null
        val invalid = typed is B1ESimError.CardChanged || typed is B1ESimError.InvalidResponse || typed is B1ESimError.StaleSession
        val phase = if (ambiguous || typed?.isAmbiguous == true || typed == null || invalid) {
            context.adapter.invalidateSession()
            B1ManagementPhase.NEEDS_RECONCILIATION
        } else B1ManagementPhase.READY
        val result = result(context.id, action, target, if (ambiguous) B1CardOutcome.UNKNOWN else B1CardOutcome.REJECTED,
            if (ambiguous) "Operation outcome is unknown. Refresh card state before repeating it." else safeMessage(error))
        mutableState.value = state.value.copy(phase = phase, lastResult = result, message = result.message)
        return result
    }

    private fun result(id: String, action: B1ESimAction, target: String?, outcome: B1CardOutcome, text: String) =
        B1ESimResult(id, action, target, outcome, text)
    private fun safeMessage(error: Exception) = (error as? B1ESimError)?.message ?: "The B1 operation failed. Refresh card state before continuing."
    private fun successMessage(action: B1ESimAction) = when (action) {
        B1ESimAction.ENABLE -> "Profile enabled and verified. Router Internet has not been verified."
        B1ESimAction.DISABLE -> "Profile disabled and verified."
        B1ESimAction.RENAME -> "Profile nickname updated and verified."
        B1ESimAction.DELETE -> "Profile removal verified."
        else -> "Card operation verified."
    }
    private fun persistNotifications() {
        try { store.save(state.value.pendingNotifications); mutableState.value = state.value.copy(journalWarning = null) }
        catch (_: Exception) { mutableState.value = state.value.copy(journalWarning = B1ESimError.JournalUnavailable.message) }
    }
    private fun recordReceipt(receipt: B1DownloadReceipt, eid: String?): Boolean {
        if (receipt.pendingNotifications.any { it.cardEid != eid || it.id.isEmpty() }) return false
        // An interrupted session's confirmed receipt still belongs in its card's journal.
        val retained = receipt.pendingNotifications.filterNot { (it.cardEid to it.id) in completedNotifications }
        val merged = (state.value.pendingNotifications + retained).distinctBy { it.cardEid to it.id }
        mutableState.value = state.value.copy(pendingNotifications = merged)
        persistNotifications()
        return true
    }
}
