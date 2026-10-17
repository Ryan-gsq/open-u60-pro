import CoreBluetooth
import Foundation

/// One central/delegate per session isolates canceled callbacks from subsequent scans.
@MainActor
final class B1CoreBluetoothTransport: NSObject, B1BluetoothTransport, @preconcurrency CBCentralManagerDelegate, @preconcurrency CBPeripheralDelegate {
    var onEvent: ((B1BluetoothEvent) -> Void)?
    private var central: CBCentralManager?
    private var peripherals: [String: CBPeripheral] = [:]
    private var observations: [String: B1NearbyDevice] = [:]
    private var lastReportedAt: [String: ContinuousClock.Instant] = [:]
    private var selected: CBPeripheral?
    private var pendingServices: Set<ObjectIdentifier> = []
    private var wantsScan = false
    private var closed = false

    func startScan() {
        guard !closed else { return }
        wantsScan = true
        // Delegate isolation is safe because CoreBluetooth delivers this session on the main queue.
        central = CBCentralManager(delegate: self, queue: .main,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: false])
    }

    func stopScan() {
        wantsScan = false
        central?.stopScan()
    }

    func connect(deviceID: String) {
        guard !closed, let central, central.state == .poweredOn,
              let peripheral = peripherals[deviceID] else {
            onEvent?(.failure("Device is no longer available. Scan again."))
            return
        }
        stopScan()
        selected = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func close() {
        closed = true
        onEvent = nil
        stopScan()
        if let selected {
            selected.delegate = nil
            central?.cancelPeripheralConnection(selected)
        }
        central?.delegate = nil
        selected = nil
        central = nil
        peripherals.removeAll()
        observations.removeAll()
        lastReportedAt.removeAll()
        pendingServices.removeAll()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard !closed, central === self.central else { return }
        switch central.state {
        case .poweredOn:
            onEvent?(.availability(.poweredOn))
            if wantsScan {
                // No B1 UUID or advertising-name filter has been verified.
                // Repeated advertisements update signal readings only during the bounded foreground scan.
                central.scanForPeripherals(withServices: nil,
                                           options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
                onEvent?(.scanning)
            }
        case .poweredOff:
            onEvent?(.availability(.poweredOff))
            onEvent?(.failure("Turn on Bluetooth in Settings and scan again."))
        case .unauthorized:
            onEvent?(.availability(.unauthorized))
            onEvent?(.failure("Allow Bluetooth access for OpenU60 in Settings."))
        case .unsupported:
            onEvent?(.availability(.unsupported))
            onEvent?(.failure("Bluetooth Low Energy is unavailable on this device."))
        case .resetting:
            onEvent?(.availability(.resetting))
            if selected != nil { onEvent?(.failure("Bluetooth reset. Scan again to reconnect.")) }
        case .unknown: onEvent?(.availability(.unknown))
        @unknown default: onEvent?(.failure("Bluetooth is unavailable."))
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard !closed, wantsScan, central === self.central else { return }
        let id = peripheral.identifier.uuidString
        guard peripherals[id] != nil || peripherals.count < 100 else { return }
        let now = ContinuousClock.now
        if let previous = lastReportedAt[id], previous.duration(to: now) < .milliseconds(500) { return }
        lastReportedAt[id] = now
        let advertised = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? [])
            + (advertisementData[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] ?? [])
        let device = B1NearbyDevice(
            id: id, name: advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name,
            rssi: RSSI.intValue == 127 ? nil : RSSI.intValue,
            connectable: (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue,
            advertisedServices: Array(Set(advertised.map(\.uuidString))).sorted(),
            lastSeenAt: ISO8601DateFormatter().string(from: Date()))
        peripherals[id] = peripheral
        observations[id] = device
        onEvent?(.discovered(device))
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard !closed, central === self.central, peripheral === selected else { return }
        onEvent?(.connected)
        peripheral.discoverServices(nil)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard !closed, central === self.central, peripheral === selected else { return }
        onEvent?(.failure("Bluetooth connection failed. Scan again to retry."))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard !closed, central === self.central, peripheral === selected else { return }
        onEvent?(.disconnected)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard !closed, peripheral === selected else { return }
        guard error == nil, let services = peripheral.services, !services.isEmpty else {
            onEvent?(.failure("GATT services could not be discovered. Scan again to retry."))
            return
        }
        pendingServices = Set(services.map { ObjectIdentifier($0) })
        for service in services { peripheral.discoverCharacteristics(nil, for: service) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard !closed, peripheral === selected, pendingServices.contains(ObjectIdentifier(service)) else { return }
        guard error == nil else {
            onEvent?(.failure("GATT characteristic discovery failed. Scan again to retry."))
            return
        }
        pendingServices.remove(ObjectIdentifier(service))
        guard pendingServices.isEmpty, let device = observations[peripheral.identifier.uuidString] else { return }
        let services = (peripheral.services ?? []).enumerated().map { index, service in
            B1GattService(instance: index, uuid: service.uuid.uuidString,
                          characteristics: (service.characteristics ?? []).enumerated().map { index, characteristic in
                B1GattCharacteristic(instance: index, uuid: characteristic.uuid.uuidString,
                                     properties: Self.properties(characteristic.properties))
            })
        }
        onEvent?(.gattDiscovered(B1GattSnapshot(
            device: device, services: services,
            writeWithResponseLimit: peripheral.maximumWriteValueLength(for: .withResponse),
            writeWithoutResponseLimit: peripheral.maximumWriteValueLength(for: .withoutResponse),
            negotiatedMtu: nil, observedAt: ISO8601DateFormatter().string(from: Date()))))
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        guard !closed, peripheral === selected else { return }
        onEvent?(.failure("GATT services changed. Scan again to rediscover the device."))
    }

    private static func properties(_ value: CBCharacteristicProperties) -> [String] {
        let flags: [(CBCharacteristicProperties, String)] = [
            (.read, "read"), (.write, "write"), (.writeWithoutResponse, "writeWithoutResponse"),
            (.notify, "notify"), (.indicate, "indicate"), (.broadcast, "broadcast"),
            (.authenticatedSignedWrites, "signedWrite"), (.extendedProperties, "extended"),
            (.notifyEncryptionRequired, "notifyEncryptionRequired"), (.indicateEncryptionRequired, "indicateEncryptionRequired")
        ]
        return flags.compactMap { value.contains($0.0) ? $0.1 : nil }
    }
}
