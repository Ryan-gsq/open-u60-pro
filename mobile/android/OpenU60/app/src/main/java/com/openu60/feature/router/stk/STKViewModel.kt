package com.openu60.feature.router.stk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.openu60.core.model.STKMenu
import com.openu60.core.model.STKMenuItem
import com.openu60.core.model.STKParser
import com.openu60.core.model.USSDResponse
import com.openu60.core.network.AgentClient
import com.openu60.core.network.AgentError
import com.openu60.core.network.AuthManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import javax.inject.Inject

data class STKState(
    val stkMenu: STKMenu = STKMenu.empty,
    val commandId: String = "",
    val stkType: String = "status",
    val stkReason: String = "",
    val stkText: String = "",
    val stkReply: String = "",
    val stkBusy: Boolean = false,
    val stkRootMenu: Boolean = true,
    val stkYesNo: Boolean = false,
    val stkHidden: Boolean = false,
    val stkDigitsOnly: Boolean = false,
    val stkMin: Int = 0,
    val stkMax: Int = 0,
    val ussdCode: String = "",
    val ussdReply: String = "",
    val ussdResponse: USSDResponse = USSDResponse.empty,
    val showUssdResponse: Boolean = false,
    val stkNotSupported: Boolean = false,
    val isLoading: Boolean = false,
    val message: String? = null,
    val messageIsError: Boolean = false,
)

@HiltViewModel
class STKViewModel @Inject constructor(
    private val agentClient: AgentClient,
    private val authManager: AuthManager,
) : ViewModel() {

    private val _state = MutableStateFlow(STKState())
    val state: StateFlow<STKState> = _state.asStateFlow()

    fun updateUssdCode(code: String) {
        _state.value = _state.value.copy(ussdCode = code)
    }

    fun updateUssdReply(reply: String) {
        _state.value = _state.value.copy(ussdReply = reply)
    }

    private var stkRevision = 0
    private var pollingStopped = false

    fun updateStkReply(reply: String) {
        _state.value = _state.value.copy(stkReply = reply)
    }

    fun loadSTKMenu() { viewModelScope.launch { refreshSTK() } }

    private suspend fun refreshSTK() {
        if (_state.value.isLoading) return
        pollingStopped = false
        stkRevision++
        _state.value = _state.value.copy(isLoading = true, message = null)
        try {
            applySTK(agentClient.getJSON("/api/stk/menu"))
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { failSTK(e)
        } finally { _state.value = _state.value.copy(isLoading = false) }
    }

    suspend fun watchSTK() {
        refreshSTK()
        while (currentCoroutineContext().isActive) {
            delay(1000)
            if (_state.value.isLoading || pollingStopped) continue
            val revision = stkRevision
            try {
                val data = agentClient.getJSON("/api/stk/session")
                if (revision == stkRevision && !_state.value.isLoading) applySTK(data)
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) { if (revision == stkRevision) failSTK(e) }
        }
    }

    fun selectSTKItem(item: STKMenuItem) = stkAction("select", mapOf("item_id" to item.id))
    fun respondSTK(yes: Boolean? = null) = stkAction("respond",
        if (yes == null) mapOf("text" to _state.value.stkReply) else mapOf("yes" to yes))
    fun goBackSTK() = stkAction("back")
    fun cancelSTK() = stkAction("cancel")

    private fun stkAction(action: String, body: Map<String, Any> = emptyMap()) {
        if (_state.value.isLoading || _state.value.stkBusy || _state.value.commandId.isEmpty()) return
        val commandId = _state.value.commandId
        stkRevision++
        _state.value = _state.value.copy(isLoading = true, message = null)
        viewModelScope.launch {
            try {
                applySTK(agentClient.postJSON("/api/stk/$action", body + ("command_id" to commandId)))
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) {
                // A timeout can follow a successful SIM operation. Never replay the selection.
                failSTK(e)
            } finally { _state.value = _state.value.copy(isLoading = false) }
        }
    }

    private fun applySTK(data: Map<String, Any?>) {
        val error = STKParser.parseError(data)
        if (error != null) { failSTK(IllegalStateException(error)); return }
        val id = data["command_id"] as? String ?: ""
        val input = data["input"] as? Map<*, *> ?: emptyMap<Any, Any>()
        _state.value = _state.value.copy(
            stkMenu = STKParser.parseSTKMenu(data), commandId = id,
            stkType = data["type"] as? String ?: "status",
            stkReason = data["reason"] as? String ?: "",
            stkText = data["text"] as? String ?: "",
            stkReply = if (id == _state.value.commandId) _state.value.stkReply else "",
            stkBusy = data["busy"] as? Boolean ?: false,
            stkRootMenu = data["root_menu"] as? Boolean ?: true,
            stkYesNo = input["yes_no"] as? Boolean ?: false,
            stkHidden = input["hidden"] as? Boolean ?: false,
            stkDigitsOnly = input["digits_only"] as? Boolean ?: false,
            stkMin = (input["min"] as? Number)?.toInt() ?: 0,
            stkMax = (input["max"] as? Number)?.toInt() ?: 0,
            stkNotSupported = data["supported"] == false,
        )
    }

    private fun failSTK(error: Exception) {
        pollingStopped = true
        _state.value = _state.value.copy(stkMenu = STKMenu.empty, commandId = "",
            stkType = "status", stkText = "", stkReply = "", stkBusy = false,
            stkReason = "Reload the SIM menu to reconnect.")
        setError(error.message)
    }

    fun sendUSSD() {
        val code = _state.value.ussdCode.trim()
        if (code.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, message = null, showUssdResponse = false)
            try {
                val data = agentClient.postJSON("/api/ussd/send", mapOf("code" to code))
                val response = STKParser.parseUSSDResponse(data)
                _state.value = _state.value.copy(
                    ussdResponse = response,
                    showUssdResponse = true,
                    isLoading = false,
                )
            } catch (e: AgentError.Unauthorized) {
                if (authManager.reauthenticate()) sendUSSD() else setError(e.message)
            } catch (e: Exception) {
                setError(e.message)
            }
        }
    }

    fun respondUSSD() {
        val reply = _state.value.ussdReply.trim()
        if (reply.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, message = null)
            try {
                val data = agentClient.postJSON("/api/ussd/respond", mapOf("response" to reply))
                val response = STKParser.parseUSSDResponse(data)
                _state.value = _state.value.copy(
                    ussdResponse = response,
                    ussdReply = "",
                    isLoading = false,
                )
            } catch (e: AgentError.Unauthorized) {
                if (authManager.reauthenticate()) respondUSSD() else setError(e.message)
            } catch (e: Exception) {
                setError(e.message)
            }
        }
    }

    fun cancelUSSD() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, message = null)
            try {
                agentClient.postJSON("/api/ussd/cancel")
                _state.value = _state.value.copy(
                    showUssdResponse = false,
                    ussdResponse = USSDResponse.empty,
                    ussdReply = "",
                    isLoading = false,
                    message = "USSD session cancelled",
                    messageIsError = false,
                )
            } catch (e: AgentError.Unauthorized) {
                if (authManager.reauthenticate()) cancelUSSD() else setError(e.message)
            } catch (e: Exception) {
                setError(e.message)
            }
        }
    }

    private fun setError(msg: String?) {
        _state.value = _state.value.copy(isLoading = false, message = msg ?: "Unknown error", messageIsError = true)
    }
}
