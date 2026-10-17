import Foundation

@MainActor
private final class FakeBluetoothTransport: B1BluetoothTransport {
    var onEvent: ((B1BluetoothEvent) -> Void)?
    var connections: [String] = []
    var closes = 0
    func startScan() { onEvent?(.scanning) }
    func stopScan() {}
    func connect(deviceID: String) { connections.append(deviceID) }
    func close() { closes += 1 }
}

@main
struct B1BluetoothTests {
    @MainActor
    static func main() async throws {
        precondition(B1BluetoothPermission.notDetermined.canScan, "An explicit scan may request undecided Bluetooth permission")
        precondition(!B1BluetoothPermission.denied.canScan && !B1BluetoothPermission.restricted.canScan,
                     "Denied or restricted Bluetooth permission must direct the user to recovery")
        let device = B1NearbyDevice(id: "selected", name: "User selected device", rssi: -60,
                                    connectable: true, advertisedServices: [])
        let snapshot = B1GattSnapshot(device: device, services: [], writeWithResponseLimit: 182,
                                      writeWithoutResponseLimit: 182, negotiatedMtu: nil, observedAt: "test")
        let first = FakeBluetoothTransport()
        let second = FakeBluetoothTransport()
        var transports = [first, second]
        let controller = B1BluetoothController(factory: { transports.removeFirst() })
        precondition(transports.count == 2, "Opening the screen must not create a Bluetooth central or prompt for access")
        controller.scan()
        first.onEvent?(.availability(.poweredOn))
        precondition(controller.availability == .poweredOn, "Bluetooth radio state must be separate from connection readiness")
        let staleCallback = first.onEvent
        first.onEvent?(.discovered(device))
        first.onEvent?(.discovered(B1NearbyDevice(id: device.id, name: device.name, rssi: -55,
                                                connectable: true, advertisedServices: [], lastSeenAt: "test")))
        precondition(controller.devices.count == 1 && controller.devices[0].rssi == -55,
                     "Repeated advertisements must refresh signal strength without duplicate rows")
        controller.connect(device)
        controller.connect(device)
        precondition(first.connections == [device.id], "Double tap must not create a second connection")
        first.onEvent?(.connected)
        precondition(controller.phase == .discovering, "A BLE connection must not imply B1 readiness")
        first.onEvent?(.gattDiscovered(snapshot))
        precondition(controller.phase == .connectedUnverified, "GATT discovery must remain unverified")
        controller.disconnect()
        controller.scan()
        staleCallback?(.failure("late failure"))
        staleCallback?(.availability(.poweredOff))
        staleCallback?(.connected)
        staleCallback?(.gattDiscovered(snapshot))
        precondition(controller.phase == .scanning && controller.snapshot == nil, "Retired callbacks must not affect a new session")
        precondition(controller.availability == .unknown, "A retired session must not overwrite the new scan's Bluetooth state")
        second.onEvent?(.discovered(device))
        controller.connect(device)
        second.onEvent?(.connected)
        let wrongDevice = B1NearbyDevice(id: "other", name: nil, rssi: nil, connectable: nil, advertisedServices: [])
        second.onEvent?(.gattDiscovered(B1GattSnapshot(device: wrongDevice, services: [], writeWithResponseLimit: nil,
                                                      writeWithoutResponseLimit: nil, negotiatedMtu: nil, observedAt: "test")))
        precondition(controller.snapshot == nil, "Another device's inventory must not complete this connection")
        second.onEvent?(.disconnected)
        precondition(controller.phase == .failed && second.closes == 1, "Remote disconnect must retire the session")

        let scanTransport = FakeBluetoothTransport()
        let scanning = B1BluetoothController(timeoutNanoseconds: 1_000_000, factory: { scanTransport })
        scanning.scan()
        try await Task.sleep(nanoseconds: 20_000_000)
        precondition(scanning.phase == .idle, "Scan must stop after its deadline")
        scanning.disconnect()

        let timeoutTransport = FakeBluetoothTransport()
        let timed = B1BluetoothController(timeoutNanoseconds: 1_000_000, factory: { timeoutTransport })
        timed.scan()
        timeoutTransport.onEvent?(.discovered(device))
        timed.connect(device)
        let lateReply = timeoutTransport.onEvent
        try await Task.sleep(nanoseconds: 20_000_000)
        lateReply?(.connected)
        precondition(timed.phase == .failed && timeoutTransport.closes == 1, "Timeout must retire the connection before any late reply")

        let json = try snapshot.evidenceJSON()
        let report = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        let protocolFields = report["b1Protocol"] as! [String: Any]
        precondition(protocolFields.count == 10 && protocolFields.values.allSatisfy { $0 is NSNull },
                     "Observed GATT must never be promoted to verified protocol constants")
        print("B1 Bluetooth tests passed: permissions, radio state, signal updates, connection isolation, readiness, double taps, disconnects, bounded scan/timeout, evidence nulls")
    }
}
