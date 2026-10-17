package com.openu60.core.bluetooth

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class B1BluetoothControllerTest {
    private val device = B1NearbyDevice("selected", "User selected device", -60, true, emptyList())
    private val snapshot = B1GattSnapshot(device, emptyList(), observedAt = "test")

    private class FakeTransport : B1BluetoothTransport {
        override var onEvent: ((B1BluetoothEvent) -> Unit)? = null
        val connections = mutableListOf<String>()
        var closes = 0
        override fun startScan() { onEvent?.invoke(B1BluetoothEvent.Scanning) }
        override fun stopScan() {}
        override fun connect(deviceID: String) { connections.add(deviceID) }
        override fun close() { closes++ }
    }

    @Test fun doubleTapDoesNotStartTwoConnections() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport })
        controller.scan()
        transport.onEvent?.invoke(B1BluetoothEvent.Discovered(device))
        controller.connect(device)
        controller.connect(device)
        assertEquals(listOf(device.id), transport.connections)
        controller.disconnect()
    }

    @Test fun gattDiscoveryDoesNotImplyAuthorizedB1Session() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport })
        controller.scan()
        transport.onEvent?.invoke(B1BluetoothEvent.Discovered(device))
        controller.connect(device)
        transport.onEvent?.invoke(B1BluetoothEvent.Connected)
        assertEquals(B1ConnectionPhase.DISCOVERING, controller.state.value.phase)
        transport.onEvent?.invoke(B1BluetoothEvent.GattDiscovered(snapshot))
        assertEquals(B1ConnectionPhase.CONNECTED_UNVERIFIED, controller.state.value.phase)
        controller.disconnect()
    }

    @Test fun retiredCallbacksCannotAffectNewConnection() = runTest {
        val first = FakeTransport()
        val second = FakeTransport()
        val transports = ArrayDeque(listOf(first, second))
        val controller = B1BluetoothController(this, { transports.removeFirst() })
        controller.scan()
        val late = first.onEvent
        controller.disconnect()
        controller.scan()
        late?.invoke(B1BluetoothEvent.Failure("late failure"))
        late?.invoke(B1BluetoothEvent.Connected)
        late?.invoke(B1BluetoothEvent.GattDiscovered(snapshot))
        assertEquals(B1ConnectionPhase.SCANNING, controller.state.value.phase)
        assertNull(controller.state.value.snapshot)
        controller.disconnect()
    }

    @Test fun timeoutRetiresSessionAndRejectsLateConnection() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport }, timeoutMillis = 20)
        controller.scan()
        transport.onEvent?.invoke(B1BluetoothEvent.Discovered(device))
        controller.connect(device)
        val late = transport.onEvent
        advanceTimeBy(21)
        runCurrent()
        late?.invoke(B1BluetoothEvent.Connected)
        assertEquals(B1ConnectionPhase.FAILED, controller.state.value.phase)
        assertEquals(1, transport.closes)
    }

    @Test fun scanStopsAtDeadline() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport }, timeoutMillis = 20)
        controller.scan()
        advanceTimeBy(21)
        runCurrent()
        assertEquals(B1ConnectionPhase.IDLE, controller.state.value.phase)
        controller.disconnect()
    }

    @Test fun wrongDeviceSnapshotCannotCompleteConnection() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport })
        controller.scan()
        transport.onEvent?.invoke(B1BluetoothEvent.Discovered(device))
        controller.connect(device)
        transport.onEvent?.invoke(B1BluetoothEvent.Connected)
        transport.onEvent?.invoke(B1BluetoothEvent.GattDiscovered(snapshot.copy(device = device.copy(id = "other"))))
        assertNull(controller.state.value.snapshot)
        controller.disconnect()
    }

    @Test fun remoteDisconnectClosesGattSession() = runTest {
        val transport = FakeTransport()
        val controller = B1BluetoothController(this, { transport })
        controller.scan()
        transport.onEvent?.invoke(B1BluetoothEvent.Disconnected)
        assertEquals(B1ConnectionPhase.FAILED, controller.state.value.phase)
        assertEquals(1, transport.closes)
    }

    @Test fun observedUuidsNeverBecomeVerifiedProtocolConstants() {
        val report = Json.parseToJsonElement(snapshot.evidenceJSON()).jsonObject
        val protocol = report.getValue("b1Protocol").jsonObject
        assertEquals(10, protocol.size)
        assertTrue(protocol.values.all { it is JsonNull })
        assertEquals(JsonNull, report.getValue("observation").jsonObject["negotiatedMtu"])
    }
}
