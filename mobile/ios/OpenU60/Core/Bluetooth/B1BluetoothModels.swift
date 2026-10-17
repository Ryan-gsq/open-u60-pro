import Foundation

enum B1BluetoothPermission {
    case notDetermined, allowed, denied, restricted, unknown

    var canScan: Bool { self == .notDetermined || self == .allowed }

    var title: String {
        switch self {
        case .notDetermined: return "Bluetooth permission required"
        case .allowed: return "Bluetooth access allowed"
        case .denied: return "Bluetooth access denied"
        case .restricted: return "Bluetooth access restricted"
        case .unknown: return "Bluetooth permission unavailable"
        }
    }

    var guidance: String {
        switch self {
        case .notDetermined: return "Tap Scan to allow OpenU60 to discover nearby Bluetooth LE devices."
        case .allowed: return "Keep this screen open while scanning or connecting to your B1."
        case .denied: return "Open Settings and enable Bluetooth access for OpenU60, then return to scan."
        case .restricted: return "Check this iPhone's device restrictions. Bluetooth access is restricted by iOS."
        case .unknown: return "Check Bluetooth access in Settings before scanning."
        }
    }
}

enum B1BluetoothAvailability {
    case unknown, poweredOn, poweredOff, unauthorized, unsupported, resetting

    var title: String {
        switch self {
        case .unknown: return "Checked when scanning starts"
        case .poweredOn: return "Bluetooth on"
        case .poweredOff: return "Bluetooth off"
        case .unauthorized: return "Bluetooth access unavailable"
        case .unsupported: return "Bluetooth LE unsupported"
        case .resetting: return "Bluetooth resetting"
        }
    }
}

enum B1ConnectionPhase: String {
    case idle, preparing, scanning, connecting, discovering, connectedUnverified, failed

    var title: String {
        switch self {
        case .idle: return "Disconnected"
        case .preparing: return "Checking Bluetooth"
        case .scanning: return "Scanning"
        case .connecting: return "Connecting"
        case .discovering: return "Bluetooth connected · discovering services"
        case .connectedUnverified: return "Bluetooth connected · B1 session unverified"
        case .failed: return "Connection stopped"
        }
    }

    var canScan: Bool { self == .idle || self == .failed }
    var canConnect: Bool { self == .idle || self == .scanning }
}

struct B1NearbyDevice: Identifiable, Codable, Equatable {
    let id: String
    let name: String?
    let rssi: Int?
    let connectable: Bool?
    let advertisedServices: [String]
    var lastSeenAt: String? = nil

    var displayName: String {
        guard let name, !name.isEmpty else { return "Unnamed BLE device" }
        return name
    }
}

struct B1GattCharacteristic: Identifiable, Codable, Equatable {
    let instance: Int
    let uuid: String
    let properties: [String]
    var id: Int { instance }
}

struct B1GattService: Identifiable, Codable, Equatable {
    let instance: Int
    let uuid: String
    let characteristics: [B1GattCharacteristic]
    var id: Int { instance }
}

/// Observations only: UUIDs/properties do not prove B1 identity or command semantics.
struct B1GattSnapshot: Codable, Equatable {
    let device: B1NearbyDevice
    let services: [B1GattService]
    let writeWithResponseLimit: Int?
    let writeWithoutResponseLimit: Int?
    let negotiatedMtu: Int?
    let observedAt: String

    func evidenceJSON() throws -> String {
        var observation = try JSONSerialization.jsonObject(with: JSONEncoder().encode(self)) as? [String: Any] ?? [:]
        let unresolved = NSNull()
        for field in ["writeWithResponseLimit", "writeWithoutResponseLimit", "negotiatedMtu"] where observation[field] == nil {
            observation[field] = unresolved
        }
        let report: [String: Any] = [
            "schemaVersion": 1,
            "platform": "ios",
            "protocolStatus": "unverified",
            "observation": observation,
            "b1Protocol": [
                "discovery": unresolved, "serviceUuid": unresolved,
                "outgoingCharacteristic": unresolved, "incomingCharacteristic": unresolved,
                "authorization": unresolved, "initialization": unresolved,
                "messageFormat": unresolved, "fragmentation": unresolved,
                "responses": unresolved, "sessionBehavior": unresolved
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }
}

enum B1BluetoothEvent {
    case availability(B1BluetoothAvailability)
    case scanning
    case discovered(B1NearbyDevice)
    case connected
    case gattDiscovered(B1GattSnapshot)
    case disconnected
    case failure(String)
}

/// Native BLE boundary. A future verified protocol adapter must own authorization,
/// subscription ordering, framing and serialized commands above this connection layer.
@MainActor
protocol B1BluetoothTransport: AnyObject {
    var onEvent: ((B1BluetoothEvent) -> Void)? { get set }
    func startScan()
    func stopScan()
    func connect(deviceID: String)
    func close()
}
