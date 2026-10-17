package com.openu60.core.bluetooth

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put

enum class B1ConnectionPhase(val title: String) {
    IDLE("Disconnected"), PREPARING("Checking Bluetooth"), SCANNING("Scanning"),
    CONNECTING("Connecting"), DISCOVERING("Bluetooth connected · discovering services"),
    CONNECTED_UNVERIFIED("Bluetooth connected · B1 session unverified"), FAILED("Connection stopped");

    val canScan get() = this == IDLE || this == FAILED
    val canConnect get() = this == IDLE || this == SCANNING
}

@Serializable
data class B1NearbyDevice(
    val id: String,
    val name: String?,
    val rssi: Int?,
    val connectable: Boolean?,
    val advertisedServices: List<String>,
) {
    val displayName get() = name?.takeIf { it.isNotBlank() } ?: "Unnamed BLE device"
}

@Serializable
data class B1GattCharacteristic(val instance: Int, val uuid: String, val properties: List<String>)

@Serializable
data class B1GattService(val instance: Int, val uuid: String, val characteristics: List<B1GattCharacteristic>)

/** GATT observations do not establish B1 identity, authorization or command semantics. */
@Serializable
data class B1GattSnapshot(
    val device: B1NearbyDevice,
    val services: List<B1GattService>,
    val writeWithResponseLimit: Int? = null,
    val writeWithoutResponseLimit: Int? = null,
    val negotiatedMtu: Int? = null,
    val observedAt: String,
) {
    fun evidenceJSON(): String {
        val json = Json { prettyPrint = true; encodeDefaults = true }
        val report = buildJsonObject {
            put("schemaVersion", 1)
            put("platform", "android")
            put("protocolStatus", "unverified")
            put("observation", json.encodeToJsonElement(this@B1GattSnapshot))
            put("b1Protocol", buildJsonObject {
                listOf("discovery", "serviceUuid", "outgoingCharacteristic", "incomingCharacteristic",
                    "authorization", "initialization", "messageFormat", "fragmentation", "responses",
                    "sessionBehavior").forEach { put(it, JsonNull) }
            })
        }
        return json.encodeToString(report)
    }
}

data class B1BluetoothState(
    val sessionGeneration: Long = 0,
    val phase: B1ConnectionPhase = B1ConnectionPhase.IDLE,
    val devices: List<B1NearbyDevice> = emptyList(),
    val selectedDevice: B1NearbyDevice? = null,
    val snapshot: B1GattSnapshot? = null,
    val message: String? = null,
)

sealed interface B1BluetoothEvent {
    data object Scanning : B1BluetoothEvent
    data class Discovered(val device: B1NearbyDevice) : B1BluetoothEvent
    data object Connected : B1BluetoothEvent
    data class GattDiscovered(val snapshot: B1GattSnapshot) : B1BluetoothEvent
    data object Disconnected : B1BluetoothEvent
    data class Failure(val reason: String) : B1BluetoothEvent
}

/** Main-thread BLE boundary. A verified protocol adapter will own authorization,
 * subscriptions, framing and serialized commands above this connection layer. */
interface B1BluetoothTransport {
    var onEvent: ((B1BluetoothEvent) -> Unit)?
    fun startScan()
    fun stopScan()
    fun connect(deviceID: String)
    fun close()
}
