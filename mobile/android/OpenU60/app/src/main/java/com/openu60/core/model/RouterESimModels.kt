package com.openu60.core.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** One profile on the eSIM in the router (GET /api/esim/profiles; the agent runs lpac). */
data class RouterESimProfile(
    val iccid: String,
    val provider: String = "",
    val name: String = "",
    val nickname: String = "",
    val isEnabled: Boolean = false,
    val profileClass: String = "",
) {
    /** The nickname when set, otherwise the operator's profile name. */
    val displayName: String
        get() = nickname.ifEmpty { name.ifEmpty { provider } }

    /** Only ordinary operator profiles can be switched to (the agent refuses test profiles). */
    val canEnable: Boolean
        get() = !isEnabled && profileClass == "operational"
}

/** Identity and capacity of the eSIM chip (GET /api/esim/chip). */
data class RouterESimChip(
    val eid: String = "",
    val firmware: String = "",
    val freeMemoryBytes: Long? = null,
) {
    companion object {
        val empty = RouterESimChip()
    }
}

// Wire types, decoded with AgentClient.get<T>(): the untyped getJSON() map turns digit-only
// strings into numbers, which would corrupt 19–20 digit ICCIDs and the 32-digit EID.

@Serializable
data class RouterESimProfileDto(
    val iccid: String? = null,
    val state: String? = null,
    val nickname: String? = null,
    val provider: String? = null,
    val name: String? = null,
    @SerialName("class") val profileClass: String? = null,
)

@Serializable
data class RouterESimProfilesResponse(
    val profiles: List<RouterESimProfileDto> = emptyList(),
)

@Serializable
data class RouterESimChipResponse(
    val eid: String? = null,
    val firmware: String? = null,
    @SerialName("free_nvm_bytes") val freeNvmBytes: Long? = null,
)

object RouterESimParser {
    fun parseProfiles(response: RouterESimProfilesResponse): List<RouterESimProfile> =
        response.profiles.mapNotNull { p ->
            val iccid = p.iccid
            if (iccid.isNullOrEmpty()) return@mapNotNull null
            RouterESimProfile(
                iccid = iccid,
                provider = p.provider.orEmpty(),
                name = p.name.orEmpty(),
                nickname = p.nickname.orEmpty(),
                isEnabled = p.state == "enabled",
                profileClass = p.profileClass.orEmpty(),
            )
        }

    fun parseChip(response: RouterESimChipResponse): RouterESimChip = RouterESimChip(
        eid = response.eid.orEmpty(),
        firmware = response.firmware.orEmpty(),
        freeMemoryBytes = response.freeNvmBytes,
    )
}

/** An active card profile and a connected mobile data session are different states. */
enum class RouterESimConnectionPhase {
    CHECKING, DISCONNECTED, SWITCHING, RELOADING, REGISTERING, CONNECTED, WAITING, UNAVAILABLE;

    val blocksSwitching: Boolean
        get() = this == SWITCHING || this == RELOADING || this == REGISTERING
}

/** Do not accept the previous profile's cached data connection as switch recovery. */
class RouterESimReconnectTracker(private val targetICCID: String) {
    private var sawDisconnect = false
    private var connectedObservations = 0

    fun phase(simICCID: String, status: String, elapsedSeconds: Double): RouterESimConnectionPhase {
        val connected = isConnected(status)
        if (status.isNotEmpty() && !connected) sawDisconnect = true
        val matches = simICCID.isNotEmpty() && normalize(simICCID) == normalize(targetICCID)
        if (matches && connected && (sawDisconnect || elapsedSeconds >= 35)) {
            connectedObservations++
            if (connectedObservations >= 2) return RouterESimConnectionPhase.CONNECTED
        } else connectedObservations = 0
        if (elapsedSeconds >= 120) return RouterESimConnectionPhase.WAITING
        return if (matches) RouterESimConnectionPhase.REGISTERING else RouterESimConnectionPhase.RELOADING
    }

    private fun normalize(value: String) = value.trim().uppercase().removeSuffix("F")

    companion object {
        fun isConnected(status: String): Boolean = status.trim().lowercase() in setOf(
            "connected", "ipv4_connected", "ipv6_connected", "ipv4_ipv6_connected",
        )
    }
}

/** Typed decoding preserves the SIM identifier's exact digits. */
@Serializable
data class RouterESimSIMStatus(
    @SerialName("sim_iccid") val iccid: String? = null,
    @SerialName("sim_states") val status: String? = null,
)

@Serializable
data class RouterESimEnableResponse(
    @SerialName("enabled_iccid") val enabledICCID: String? = null,
)

/** A secret held only in the add screen. Deliberately no generated toString(). */
class RouterESimActivationCode private constructor(
    val value: String, val server: String, val needsConfirmationCode: Boolean,
) {
    companion object {
        const val INVALID_MESSAGE = "This QR code isn't an eSIM activation code."
        fun parse(input: String): RouterESimActivationCode? {
            val code = input.trim()
            if (code.toByteArray().size > 512 || !code.startsWith("LPA:", ignoreCase = true) ||
                code.any { it.isWhitespace() || it.isISOControl() }) return null
            val parts = code.drop(4).split('$')
            fun ascii(c: Char) = c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z'
            if (parts.size !in 3..5 || parts[0] != "1" || parts[1].isEmpty() ||
                !parts[1].all { ascii(it) || it in ".-:" } || !parts[2].all { ascii(it) || it == '-' }) return null
            return RouterESimActivationCode("LPA:" + code.drop(4), parts[1], parts.getOrNull(4) == "1")
        }
        fun validConfirmationCode(code: String) = code.isNotEmpty() && code.toByteArray().size <= 64 && code.none { it.isISOControl() }
    }
}

@Serializable
data class RouterESimDownloadStatus(
    val state: String = "idle", val step: String? = null, val provider: String? = null,
    val name: String? = null, val iccid: String? = null, val error: String? = null,
    @SerialName("started_at") val startedAt: Long? = null,
    @SerialName("finished_at") val finishedAt: Long? = null,
) {
    val isBusy: Boolean get() = state in setOf("running", "confirm", "cancelling")
    val canCancel: Boolean get() = state in setOf("running", "confirm") && step != "es10b_load_bound_profile_package"
    val displayName: String get() = listOfNotNull(provider, name).firstOrNull { it.isNotEmpty() } ?: "eSIM profile"
    val progressText: String get() = when {
        state == "confirm" -> "Ready to install"
        state == "cancelling" || step?.endsWith("_cancel_session") == true -> "Cancelling…"
        state == "done" -> "$displayName added."
        state == "failed" -> "Couldn’t add the profile"
        state == "cancelled" -> "Download cancelled"
        step in setOf("es9p_initiate_authentication", "es10b_authenticate_server", "es9p_authenticate_client") -> "Connecting to the operator…"
        step == "es8p_metadata_parse" -> "Reading profile details…"
        step in setOf("es10b_prepare_download", "es9p_get_bound_profile_package") -> "Downloading profile…"
        step == "es10b_load_bound_profile_package" -> "Installing on the eSIM…"
        else -> "Preparing eSIM…"
    }
}

@Serializable
data class RouterESimDeleteResponse(
    @SerialName("deleted_iccid") val deletedICCID: String? = null,
    @SerialName("operator_notified") val operatorNotified: Boolean = true,
)
