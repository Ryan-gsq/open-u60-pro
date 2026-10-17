package com.openu60.core.esim

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable enum class B1ProfileState {
    @SerialName("enabled") ENABLED, @SerialName("disabled") DISABLED, @SerialName("unknown") UNKNOWN
}

@Serializable
data class B1ESimProfile(
    val iccid: String, val nickname: String?, val provider: String?, val state: B1ProfileState,
    val canDelete: Boolean? = null, val canDisable: Boolean? = null,
) {
    val displayName get() = nickname?.takeIf { it.isNotBlank() } ?: provider ?: iccid
}

@Serializable enum class B1ESimAction { LIST, ENABLE, DISABLE, RENAME, DELETE, DOWNLOAD, EXPORT_TRANSFER, NOTIFY }
@Serializable data class B1ESimCard(val eid: String, val capabilities: Set<B1ESimAction>)
enum class B1ManagementPhase { DISCONNECTED, UNAVAILABLE, OPENING, READY, BUSY, NEEDS_RECONCILIATION }
@Serializable enum class B1CardOutcome { VERIFIED, UNCHANGED, REJECTED, UNKNOWN }

@Serializable
data class B1ESimResult(
    val operationID: String, val action: B1ESimAction, val targetIccid: String?,
    val cardOutcome: B1CardOutcome, val message: String,
) {
    val routerOutcome: String = "notVerified"
}

/** Provisioning credentials are memory-only and excluded from exports and journals. */
class B1DownloadRequest(activationCode: String, confirmationCode: String? = null) {
    val activationCode: String = activationCode.trim()
    val confirmationCode: String? = confirmationCode?.takeIf { it.isNotEmpty() }
    init {
        val parts = this.activationCode.split('$')
        if (this.activationCode.toByteArray(Charsets.UTF_8).size > 8192 || parts.size < 3 ||
            parts[0] != "LPA:1" || parts[1].isEmpty() || this.activationCode.any { it.isISOControl() }) {
            throw B1ESimError.InvalidInput("Enter an activation code beginning with LPA:1$ and an SM-DP+ address.")
        }
    }
    override fun toString() = "B1DownloadRequest(credentials: redacted)"
}

@Serializable data class B1PendingNotification(val id: String, val cardEid: String, val profileIccid: String?)
data class B1DownloadReceipt(val installedIccid: String?, val pendingNotifications: List<B1PendingNotification>)
data class B1TransferPackage(val data: ByteArray)
data class B1ExportArtifact(val filename: String, val data: ByteArray, val isTransferPackage: Boolean)

sealed class B1ESimError(message: String) : Exception(message) {
    data object ProtocolUnavailable : B1ESimError("B1 authorization and command framing still require a verified protocol adapter.")
    class Unsupported(val action: B1ESimAction) : B1ESimError("The card adapter does not support ${action.name.lowercase()}.")
    class InvalidInput(message: String) : B1ESimError(message)
    class Rejected(message: String) : B1ESimError(message)
    data object Timeout : B1ESimError("The B1 request timed out.")
    data object TransportLost : B1ESimError("The B1 management connection was lost.")
    data object OutcomeUnknown : B1ESimError("The operation may have reached the card. Refresh to reconcile its state.")
    data object StaleSession : B1ESimError("The management session was canceled.")
    data object CardChanged : B1ESimError("Recovery returned a different card. Reconnect before continuing.")
    data object InvalidResponse : B1ESimError("The adapter returned invalid card or profile data.")
    data object JournalUnavailable : B1ESimError("Pending download notifications could not be stored. Resolve storage before downloading another profile.")
    val isAmbiguous get() = this is Timeout || this is TransportLost || this is OutcomeUnknown
}

/** Authenticate before opening, own only this session's logical channels and use bounded,
 * cancellation-aware exchanges. Recovery must reconnect/reopen and return the actual card EID. */
interface B1ESimAdapter {
    val protocolVerified: Boolean
    suspend fun openSession(): B1ESimCard
    suspend fun recoverSession(): B1ESimCard
    suspend fun listProfiles(): List<B1ESimProfile>
    suspend fun enableProfile(iccid: String)
    suspend fun disableProfile(iccid: String)
    suspend fun renameProfile(iccid: String, nickname: String)
    suspend fun deleteProfile(iccid: String)
    /** Publish confirmed installation before later work can fail/cancel. Deliver callbacks
     * on the coordinator's main thread, and return a receipt with any remaining notifications. */
    suspend fun downloadProfile(request: B1DownloadRequest, onInstalled: (B1DownloadReceipt) -> Unit): B1DownloadReceipt
    suspend fun completeNotification(id: String)
    suspend fun exportTransferPackage(iccid: String): B1TransferPackage
    fun invalidateSession()
}

/** Production guard until B1's wire contract is established. Sends no card commands. */
class B1UnverifiedESimAdapter : B1ESimAdapter {
    override val protocolVerified = false
    override suspend fun openSession(): B1ESimCard = throw B1ESimError.ProtocolUnavailable
    override suspend fun recoverSession(): B1ESimCard = throw B1ESimError.ProtocolUnavailable
    override suspend fun listProfiles(): List<B1ESimProfile> = throw B1ESimError.ProtocolUnavailable
    override suspend fun enableProfile(iccid: String): Unit = throw B1ESimError.ProtocolUnavailable
    override suspend fun disableProfile(iccid: String): Unit = throw B1ESimError.ProtocolUnavailable
    override suspend fun renameProfile(iccid: String, nickname: String): Unit = throw B1ESimError.ProtocolUnavailable
    override suspend fun deleteProfile(iccid: String): Unit = throw B1ESimError.ProtocolUnavailable
    override suspend fun downloadProfile(request: B1DownloadRequest, onInstalled: (B1DownloadReceipt) -> Unit): B1DownloadReceipt = throw B1ESimError.ProtocolUnavailable
    override suspend fun completeNotification(id: String): Unit = throw B1ESimError.ProtocolUnavailable
    override suspend fun exportTransferPackage(iccid: String): B1TransferPackage = throw B1ESimError.ProtocolUnavailable
    override fun invalidateSession() {}
}

interface B1NotificationStore {
    fun load(): List<B1PendingNotification>
    fun save(items: List<B1PendingNotification>)
}

data class B1ESimState(
    val phase: B1ManagementPhase = B1ManagementPhase.DISCONNECTED,
    val card: B1ESimCard? = null, val profiles: List<B1ESimProfile> = emptyList(),
    val profilesObservedAt: String? = null, val message: String? = null,
    val lastResult: B1ESimResult? = null, val pendingNotifications: List<B1PendingNotification> = emptyList(),
    val journalWarning: String? = null,
) {
    val canOperate get() = phase == B1ManagementPhase.READY
    val canRefresh get() = canOperate || phase == B1ManagementPhase.NEEDS_RECONCILIATION
    val notificationsForCard get() = pendingNotifications.filter { it.cardEid == card?.eid }
    fun supports(action: B1ESimAction) = canOperate && card?.capabilities?.contains(action) == true
}
