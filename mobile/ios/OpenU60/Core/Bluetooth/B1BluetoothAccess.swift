import CoreBluetooth
import Observation

/// Reads the existing privacy decision without creating a central or starting a scan.
@Observable
@MainActor
final class B1BluetoothAccess {
    private(set) var permission: B1BluetoothPermission = .unknown

    init() { refresh() }

    func refresh() {
        switch CBManager.authorization {
        case .notDetermined: permission = .notDetermined
        case .allowedAlways: permission = .allowed
        case .denied: permission = .denied
        case .restricted: permission = .restricted
        @unknown default: permission = .unknown
        }
    }
}
