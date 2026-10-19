package com.openu60.feature.router.esim

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.openu60.core.model.*
import com.openu60.core.network.AgentClient
import com.openu60.core.network.AgentError
import com.openu60.core.network.AuthManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

data class RouterESimState(
    val profiles: List<RouterESimProfile> = emptyList(),
    val chip: RouterESimChip = RouterESimChip.empty,
    val isLoading: Boolean = false,
    val isSwitching: Boolean = false,
    val pendingSwitch: RouterESimProfile? = null,
    val pendingDelete: RouterESimProfile? = null,
    val pendingRename: RouterESimProfile? = null,
    /** The list as last accepted from the agent, with its freshness markers. */
    val inventory: RouterESimInventory = RouterESimInventory(),
    /** A failed list read; cleared only by a newer clean read. */
    val listError: String? = null,
    /** Operator receipts waiting on the card (null = unknown or an older agent). */
    val pendingReceipts: Int? = null,
    val receiptsSending: Boolean = false,
    val download: RouterESimDownloadStatus = RouterESimDownloadStatus(),
    val operationInFlight: Boolean = false,
    val downloadNote: String? = null,
    val message: String? = null,
    val messageIsError: Boolean = false,
    val hasLoaded: Boolean = false,
    val connectionPhase: RouterESimConnectionPhase = RouterESimConnectionPhase.CHECKING,
    val connectionNote: String? = null,
    val operatorName: String = "",
    val networkType: String = "",
    val signalBars: Int = 0,
    val switchingTo: String? = null,
) {
    val enabledProfile: RouterESimProfile? get() = profiles.firstOrNull { it.isEnabled }
    val blocksSwitching: Boolean get() = isLoading || isSwitching || operationInFlight || download.isBusy || connectionPhase.blocksSwitching
}

@HiltViewModel
class RouterESimViewModel @Inject constructor(
    private val agentClient: AgentClient,
    private val authManager: AuthManager,
) : ViewModel() {
    private val _state = MutableStateFlow(RouterESimState())
    val state: StateFlow<RouterESimState> = _state.asStateFlow()
    private var monitor: Job? = null
    private var statusInFlight = false
    private var reconnectTracker: RouterESimReconnectTracker? = null
    private var switchedAt: Long? = null
    private var nextStatusCheck = 0L
    private var nextDownloadCheck = 0L
    private var downloadInFlight = false
    private var downloadNoteIsPolling = false
    private var dismissedDownload: RouterESimDownloadStatus? = null
    /** Following the agent's verified switch (GET /api/esim/switch); off for older agents. */
    private var followSwitch = false
    private var switchListRead = false

    fun refresh() {
        if (_state.value.isLoading || _state.value.isSwitching || _state.value.operationInFlight || downloadInFlight) return
        if (_state.value.connectionPhase.blocksSwitching) {
            viewModelScope.launch { refreshConnection() }
            return
        }
        _state.value = _state.value.copy(isLoading = true, message = null,
            switchingTo = if (_state.value.connectionPhase == RouterESimConnectionPhase.CONNECTED) null else _state.value.switchingTo)
        viewModelScope.launch {
            try {
                pollDownload(refreshAfterCompletion = false)
                if (!_state.value.download.isBusy) {
                    withReauth { loadProfiles() }
                    loadChip()
                }
                if (!_state.value.download.isBusy) refreshConnection()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                setError("Could not read eSIM profiles: ${errorText(e)}")
            } finally {
                _state.value = _state.value.copy(isLoading = false, hasLoaded = true)
            }
        }
    }

    /** Retry the list read without replaying a profile change or reading other card data. */
    fun retryProfiles() {
        if (_state.value.blocksSwitching || downloadInFlight) return
        _state.value = _state.value.copy(isLoading = true)
        viewModelScope.launch {
            try { withReauth { loadProfiles() } }
            catch (e: CancellationException) { throw e }
            catch (e: Exception) { setError(errorText(e)) }
            finally { _state.value = _state.value.copy(isLoading = false, hasLoaded = true) }
        }
    }

    fun startMonitoring() {
        if (monitor?.isActive == true) return
        nextStatusCheck = 0L
        nextDownloadCheck = 0L
        monitor = viewModelScope.launch {
            while (currentCoroutineContext().isActive) {
                if (!_state.value.isLoading && !_state.value.isSwitching && !_state.value.operationInFlight) {
                    if (_state.value.download.isBusy || SystemClock.elapsedRealtime() >= nextDownloadCheck) {
                        pollDownload()
                        nextDownloadCheck = SystemClock.elapsedRealtime() + 30000
                    }
                    if (!_state.value.download.isBusy && SystemClock.elapsedRealtime() >= nextStatusCheck) {
                        refreshConnection()
                        nextStatusCheck = SystemClock.elapsedRealtime() + if (_state.value.connectionPhase.blocksSwitching) 3000 else 12000
                    }
                }
                delay(1000)
            }
        }
    }

    fun stopMonitoring() { monitor?.cancel(); monitor = null }

    fun requestSwitch(profile: RouterESimProfile) {
        if (!profile.canEnable || _state.value.blocksSwitching) return
        _state.value = _state.value.copy(pendingSwitch = profile)
    }

    fun dismissSwitch() { _state.value = _state.value.copy(pendingSwitch = null) }

    fun confirmSwitch() {
        val target = _state.value.pendingSwitch ?: return
        if (_state.value.blocksSwitching) return
        _state.value = _state.value.copy(
            pendingSwitch = null, isSwitching = true, message = null, messageIsError = false,
        )
        viewModelScope.launch {
            try {
                while (downloadInFlight) delay(50)
                if (_state.value.download.isBusy) return@launch
                _state.value = _state.value.copy(connectionPhase = RouterESimConnectionPhase.SWITCHING, connectionNote = null, switchingTo = target.displayName)
                val result = withReauth {
                    agentClient.post<RouterESimEnableResponse>("/api/esim/enable", Json.encodeToString(mapOf("iccid" to target.iccid)))
                }
                if (result.enabledICCID == target.iccid) {
                    _state.value = _state.value.copy(profiles = _state.value.profiles.map {
                        it.copy(isEnabled = it.iccid == target.iccid)
                    })
                }
                beginFollowingSwitch(target)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (outcomeUnknown(e)) {
                    // The card command failed or timed out, but the card may have switched: the agent checks.
                    beginFollowingSwitch(target)
                    _state.value = _state.value.copy(message = "The router is checking whether the switch happened.", messageIsError = false)
                    return@launch
                }
                reconnectTracker = null
                switchedAt = null
                _state.value = _state.value.copy(connectionPhase = RouterESimConnectionPhase.UNAVAILABLE, switchingTo = null)
                setError("Switch failed: ${errorText(e)}")
            } finally {
                _state.value = _state.value.copy(isSwitching = false)
                nextStatusCheck = 0L
            }
        }
    }


    private fun beginFollowingSwitch(target: RouterESimProfile) {
        reconnectTracker = RouterESimReconnectTracker(target.iccid)
        switchedAt = SystemClock.elapsedRealtime()
        followSwitch = true
        switchListRead = false
        _state.value = _state.value.copy(connectionPhase = RouterESimConnectionPhase.RELOADING)
    }

    fun requestRename(profile: RouterESimProfile) {
        if (_state.value.blocksSwitching) return
        _state.value = _state.value.copy(pendingRename = profile)
    }
    fun dismissRename() { _state.value = _state.value.copy(pendingRename = null) }

    /** An empty name clears the nickname, so the operator's name shows again. */
    fun confirmRename(name: String) {
        val target = _state.value.pendingRename ?: return
        val nickname = name.trim()
        _state.value = _state.value.copy(pendingRename = null)
        if (nickname.toByteArray().size > 64) { setError("Nicknames can be up to 64 bytes."); return }
        if (_state.value.blocksSwitching || nickname == target.nickname) return
        _state.value = _state.value.copy(operationInFlight = true, message = null)
        viewModelScope.launch {
            try {
                while (downloadInFlight) delay(50)
                withReauth { agentClient.postJSON("/api/esim/nickname", mapOf("iccid" to target.iccid, "nickname" to nickname)) }
                withReauth { loadProfiles() }
                _state.value = _state.value.copy(message = if (nickname.isEmpty()) "Nickname cleared." else "Renamed to $nickname.", messageIsError = false)
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { setError(errorText(e)) }
            finally { _state.value = _state.value.copy(operationInFlight = false) }
        }
    }

    /** Sends the operator receipts waiting on the card now; the router keeps retrying the rest. */
    fun sendReceipts() {
        if (_state.value.blocksSwitching || _state.value.receiptsSending) return
        _state.value = _state.value.copy(receiptsSending = true)
        viewModelScope.launch {
            try {
                withReauth { agentClient.postJSON("/api/esim/notifications/process") }
                delay(8000)
                val left = withReauth { agentClient.get<RouterESimNotifications>("/api/esim/notifications") }.count
                _state.value = _state.value.copy(
                    pendingReceipts = left ?: _state.value.pendingReceipts,
                    message = if (left == 0) "Operator receipts sent." else "Some receipts couldn't be sent yet. The router keeps retrying.",
                    messageIsError = left != 0,
                )
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { setError(errorText(e)) }
            finally { _state.value = _state.value.copy(receiptsSending = false) }
        }
    }

    fun requestDelete(profile: RouterESimProfile) {
        if (profile.isEnabled || _state.value.blocksSwitching) return
        _state.value = _state.value.copy(pendingDelete = profile)
    }
    fun dismissDelete() { _state.value = _state.value.copy(pendingDelete = null) }
    fun confirmDelete() {
        val target = _state.value.pendingDelete ?: return
        if (_state.value.blocksSwitching || _state.value.profiles.none { it.iccid == target.iccid && !it.isEnabled }) return
        _state.value = _state.value.copy(pendingDelete = null, operationInFlight = true, message = null)
        viewModelScope.launch {
            try {
                while (downloadInFlight) delay(50)
                if (_state.value.download.isBusy || _state.value.profiles.none { it.iccid == target.iccid && !it.isEnabled }) return@launch
                val result = withReauth {
                    agentClient.post<RouterESimDeleteResponse>("/api/esim/delete", Json.encodeToString(mapOf("iccid" to target.iccid)))
                }
                withReauth { loadProfiles() }
                loadChip()
                val suffix = if (result.operatorNotified) "" else " The operator will be notified on the next eSIM change."
                _state.value = _state.value.copy(message = "${target.displayName} deleted.$suffix", messageIsError = false)
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { setError(errorText(e)) }
            finally { _state.value = _state.value.copy(operationInFlight = false) }
        }
    }

    fun startDownload(code: String, confirmationCode: String) {
        if (_state.value.blocksSwitching) return
        val parsed = RouterESimActivationCode.parse(code) ?: return
        if (parsed.needsConfirmationCode && !RouterESimActivationCode.validConfirmationCode(confirmationCode)) {
            _state.value = _state.value.copy(downloadNote = "Enter the confirmation code from your operator (up to 64 characters).")
            return
        }
        val body = buildJsonObject {
            put("activation_code", parsed.value)
            put("preview", true)
            if (confirmationCode.isNotEmpty()) put("confirmation_code", confirmationCode)
        }.toString()
        downloadAction("/api/esim/download", body)
    }

    fun confirmDownload() {
        if (_state.value.download.state == "confirm") downloadAction("/api/esim/download/confirm", "{\"accept\":true}")
    }
    fun cancelDownload() {
        if (_state.value.download.canCancel) downloadAction("/api/esim/download/cancel", "{}")
    }
    fun resetDownloadResult() {
        if (!_state.value.download.isBusy && !_state.value.operationInFlight) {
            dismissedDownload = _state.value.download
            _state.value = _state.value.copy(download = RouterESimDownloadStatus(), downloadNote = null)
        }
    }
    fun retryDownloadStatus() { viewModelScope.launch { pollDownload() } }

    private fun downloadAction(path: String, body: String) {
        if (_state.value.operationInFlight) return
        downloadNoteIsPolling = false
        _state.value = _state.value.copy(operationInFlight = true, downloadNote = null)
        viewModelScope.launch {
            try {
                while (downloadInFlight) delay(50)
                if (path.endsWith("/cancel") && !_state.value.download.canCancel) return@launch
                if (path.endsWith("/confirm") && _state.value.download.state != "confirm") return@launch
                if (path == "/api/esim/download" && _state.value.download.isBusy) return@launch
                val result = withReauth { agentClient.post<RouterESimDownloadStatus>(path, body) }
                _state.value = _state.value.copy(download = result)
                if (!result.isBusy) { withReauth { loadProfiles() }; loadChip() }
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) {
                downloadNoteIsPolling = false
                _state.value = _state.value.copy(downloadNote = errorText(e))
                pollDownload()
            } finally { _state.value = _state.value.copy(operationInFlight = false) }
        }
    }

    private suspend fun pollDownload(refreshAfterCompletion: Boolean = true) {
        if (downloadInFlight) return
        downloadInFlight = true
        val wasBusy = _state.value.download.isBusy
        try {
            val result = withReauth { agentClient.get<RouterESimDownloadStatus>("/api/esim/download") }
            if (!result.isBusy && result == dismissedDownload) return
            val refreshCard = !result.isBusy && refreshAfterCompletion && (wasBusy || (result.state == "done" && result != _state.value.download))
            _state.value = _state.value.copy(download = result, isLoading = _state.value.isLoading || refreshCard,
                downloadNote = if (downloadNoteIsPolling || result.state != _state.value.download.state) null else _state.value.downloadNote)
            if (refreshCard) {
                try { withReauth { loadProfiles() }; loadChip() }
                finally { _state.value = _state.value.copy(isLoading = false) }
            }
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            if (wasBusy && (_state.value.downloadNote == null || downloadNoteIsPolling)) {
                downloadNoteIsPolling = true
                _state.value = _state.value.copy(downloadNote = errorText(e))
            }
        } finally { downloadInFlight = false }
    }

    private fun errorText(error: Exception): String {
        val text = (error.message ?: "Couldn’t contact the router.").removePrefix("Server error: ")
        return runCatching { Json.parseToJsonElement(text).jsonObject["error"]?.jsonPrimitive?.contentOrNull }.getOrNull() ?: text
    }

    private suspend fun refreshConnection() {
        if (statusInFlight || _state.value.isSwitching) return
        statusInFlight = true
        if (followSwitch) {
            val handled = try { followSwitchStatus() }
            catch (e: CancellationException) { statusInFlight = false; throw e }
            catch (e: Exception) { _state.value = _state.value.copy(connectionNote = errorText(e)); true }
            if (handled) { statusInFlight = false; return }
        }
        try {
            val sim = withReauth { agentClient.get<RouterESimSIMStatus>("/api/sim/info") }
            val data = withReauth { agentClient.getJSON("/api/modem/data") }
            val signal = withReauth { agentClient.getJSON("/api/network/signal") }
            if (_state.value.isSwitching) return
            val parsed = SignalParser.parseNetInfo(signal)
            val status = data["connect_status"] as? String ?: ""
            val tracker = reconnectTracker
            var note: String? = null
            val phase = if (tracker != null && switchedAt != null) {
                if (sim.status.orEmpty().lowercase() in setOf("wait pin", "wait puk")) {
                    note = "The SIM needs to be unlocked. Open SIM Card to continue."
                    RouterESimConnectionPhase.WAITING
                } else tracker.phase(sim.iccid.orEmpty(), status, (SystemClock.elapsedRealtime() - switchedAt!!) / 1000.0)
            } else if (status.isEmpty()) RouterESimConnectionPhase.UNAVAILABLE
            else if (RouterESimReconnectTracker.isConnected(status)) RouterESimConnectionPhase.CONNECTED
            else RouterESimConnectionPhase.DISCONNECTED
            if (phase == RouterESimConnectionPhase.CONNECTED) reconnectTracker = null
            _state.value = _state.value.copy(
                connectionPhase = phase, connectionNote = note,
                operatorName = parsed.operatorInfo.provider,
                networkType = if (parsed.operatorInfo.networkType.isEmpty()) "" else parsed.operatorInfo.displayNetworkType(parsed.nr.isConnected, parsed.lte),
                signalBars = parsed.operatorInfo.signalBar.coerceIn(0, 5),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val started = switchedAt
            val phase = if (started != null && reconnectTracker != null) {
                if (SystemClock.elapsedRealtime() - started >= 120000) RouterESimConnectionPhase.WAITING else _state.value.connectionPhase
            } else RouterESimConnectionPhase.UNAVAILABLE
            _state.value = _state.value.copy(connectionPhase = phase, connectionNote = e.message)
        } finally { statusInFlight = false }
    }

    /**
     * One step of the agent's verified switch: card, then modem identity, then data. Returns
     * false when the agent has no switch endpoint (older agent), so the tracker fallback runs.
     */
    private suspend fun followSwitchStatus(): Boolean {
        val status = try {
            withReauth { agentClient.get<RouterESimSwitchStatus>("/api/esim/switch") }
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            if (errorText(e).contains("not found")) { followSwitch = false; return false }
            _state.value = _state.value.copy(connectionNote = errorText(e))
            return true
        }
        if (_state.value.isSwitching) return true
        if (status.state == "idle") { followSwitch = false; return false }
        _state.value = _state.value.copy(connectionPhase = status.phase, connectionNote = status.progressNote)
        if (status.cardConfirmed && !switchListRead) {
            switchListRead = true
            withReauth { loadProfiles() }
        }
        if (!status.isRunning) {
            followSwitch = false
            reconnectTracker = null
            _state.value = _state.value.copy(connectionNote = status.outcomeNote)
            withReauth { loadProfiles() }
        }
        if (_state.value.connectionPhase == RouterESimConnectionPhase.CONNECTED) {
            runCatching {
                val parsed = SignalParser.parseNetInfo(withReauth { agentClient.getJSON("/api/network/signal") })
                _state.value = _state.value.copy(
                    operatorName = parsed.operatorInfo.provider,
                    networkType = if (parsed.operatorInfo.networkType.isEmpty()) "" else parsed.operatorInfo.displayNetworkType(parsed.nr.isConnected, parsed.lte),
                    signalBars = parsed.operatorInfo.signalBar.coerceIn(0, 5),
                )
            }
        }
        return true
    }

    private suspend fun loadProfiles() {
        try {
            val fresh = RouterESimParser.parseInventory(agentClient.get<RouterESimProfilesResponse>("/api/esim/profiles"))
            val shown = _state.value.inventory
            // An older answer, or the pre-switch list served while the SIM reloads, must not replace
            // the switch target on screen.
            if (fresh.isOlderThan(shown) || (fresh.updating && followSwitch)) return
            _state.value = _state.value.copy(
                inventory = fresh,
                profiles = fresh.profiles,
                pendingReceipts = fresh.pendingReceipts,
                listError = fresh.errorText?.let { "$it Showing the list read at ${clock(fresh.observedAt)}." },
            )
        } catch (e: CancellationException) { throw e }
        catch (e: AgentError.Unauthorized) { throw e }
        catch (e: Exception) {
            _state.value = _state.value.copy(listError = "Couldn't read eSIM profiles: ${errorText(e)}")
        }
    }

    private fun clock(unix: Long): String =
        if (unix <= 0) "an earlier time"
        else java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(unix * 1000))

    /** The agent replies `outcome: "unknown"` when the card command failed or timed out mid-switch. */
    private fun outcomeUnknown(error: Exception): Boolean {
        val text = (error.message ?: return false).removePrefix("Server error: ")
        return runCatching { Json.parseToJsonElement(text).jsonObject["outcome"]?.jsonPrimitive?.contentOrNull }.getOrNull() == "unknown"
    }

    private suspend fun loadChip() {
        try {
            val chip = RouterESimParser.parseChip(withReauth { agentClient.get<RouterESimChipResponse>("/api/esim/chip") })
            _state.value = _state.value.copy(chip = chip)
        } catch (e: CancellationException) { throw e }
        catch (_: Exception) { /* The profile list already reports card or agent errors. */ }
    }

    private suspend fun <T> withReauth(block: suspend () -> T): T = try { block() }
    catch (e: AgentError.Unauthorized) {
        if (!authManager.reauthenticate()) throw e
        block()
    }

    private fun setError(msg: String) { _state.value = _state.value.copy(message = msg, messageIsError = true) }
}
