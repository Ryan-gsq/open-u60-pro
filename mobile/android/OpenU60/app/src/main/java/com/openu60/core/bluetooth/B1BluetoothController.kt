package com.openu60.core.bluetooth

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Call on the main thread; each retired transport's callbacks are invalidated. */
class B1BluetoothController(
    private val scope: CoroutineScope,
    private val factory: () -> B1BluetoothTransport,
    private val timeoutMillis: Long = 20_000,
) {
    private val mutableState = MutableStateFlow(B1BluetoothState())
    val state = mutableState.asStateFlow()
    private var transport: B1BluetoothTransport? = null
    private var generation = 0L
    private var deadline: Job? = null

    fun scan() {
        if (!state.value.phase.canScan) return
        invalidate()
        mutableState.value = B1BluetoothState(sessionGeneration = generation, phase = B1ConnectionPhase.PREPARING)
        val currentGeneration = generation
        val next = factory()
        transport = next
        next.onEvent = { event ->
            if (generation == currentGeneration && transport != null) receive(event)
        }
        armDeadline("Bluetooth setup timed out. Check permission and try scanning again.")
        next.startScan()
    }

    fun stopScan() {
        if (state.value.phase == B1ConnectionPhase.PREPARING) { disconnect(); return }
        if (state.value.phase != B1ConnectionPhase.SCANNING) return
        deadline?.cancel()
        transport?.stopScan()
        mutableState.value = state.value.copy(
            phase = B1ConnectionPhase.IDLE,
            message = if (state.value.devices.isEmpty()) "No devices found. Make the B1 discoverable and scan again." else null,
        )
    }

    fun connect(device: B1NearbyDevice) {
        if (!state.value.phase.canConnect || device.connectable == false ||
            state.value.devices.none { it.id == device.id }) return
        val current = transport ?: return
        deadline?.cancel()
        current.stopScan()
        mutableState.value = state.value.copy(
            phase = B1ConnectionPhase.CONNECTING, selectedDevice = device, snapshot = null, message = null,
        )
        armDeadline("Connection timed out. Scan again to reconnect.")
        current.connect(device.id)
    }

    fun disconnect() {
        invalidate()
        mutableState.value = state.value.copy(sessionGeneration = generation, phase = B1ConnectionPhase.IDLE, devices = emptyList(), selectedDevice = null)
    }

    private fun invalidate() {
        generation++
        deadline?.cancel()
        deadline = null
        val previous = transport
        transport = null
        previous?.onEvent = null
        previous?.close()
    }

    private fun fail(reason: String) {
        invalidate()
        mutableState.value = state.value.copy(
            sessionGeneration = generation, phase = B1ConnectionPhase.FAILED, devices = emptyList(), selectedDevice = null, message = reason,
        )
    }

    private fun receive(event: B1BluetoothEvent) {
        when (event) {
            B1BluetoothEvent.Scanning -> {
                if (state.value.phase != B1ConnectionPhase.PREPARING) return
                mutableState.value = state.value.copy(phase = B1ConnectionPhase.SCANNING)
                armDeadline(null)
            }
            is B1BluetoothEvent.Discovered -> {
                if (state.value.phase != B1ConnectionPhase.SCANNING) return
                val devices = state.value.devices.toMutableList()
                val index = devices.indexOfFirst { it.id == event.device.id }
                if (index >= 0) devices[index] = event.device else if (devices.size < 100) devices.add(event.device)
                mutableState.value = state.value.copy(devices = devices)
            }
            B1BluetoothEvent.Connected -> {
                if (state.value.phase != B1ConnectionPhase.CONNECTING) return
                mutableState.value = state.value.copy(phase = B1ConnectionPhase.DISCOVERING)
                armDeadline("GATT discovery timed out. Scan again to reconnect.")
            }
            is B1BluetoothEvent.GattDiscovered -> {
                if (state.value.phase != B1ConnectionPhase.DISCOVERING ||
                    event.snapshot.device.id != state.value.selectedDevice?.id) return
                deadline?.cancel()
                mutableState.value = state.value.copy(
                    phase = B1ConnectionPhase.CONNECTED_UNVERIFIED, snapshot = event.snapshot,
                    message = "Profile management requires the verified B1 protocol. Router Internet has not been verified.",
                )
            }
            B1BluetoothEvent.Disconnected -> fail("The Bluetooth device disconnected. Scan again to reconnect.")
            is B1BluetoothEvent.Failure -> fail(event.reason)
        }
    }

    private fun armDeadline(failure: String?) {
        deadline?.cancel()
        val expectedGeneration = generation
        val expectedPhase = state.value.phase
        deadline = scope.launch {
            delay(timeoutMillis)
            if (generation == expectedGeneration && state.value.phase == expectedPhase) {
                if (failure != null) fail(failure) else stopScan()
            }
        }
    }
}
