import Foundation
import Observation

@Observable
@MainActor
final class B1BluetoothController {
    private(set) var phase: B1ConnectionPhase = .idle
    private(set) var availability: B1BluetoothAvailability = .unknown
    private(set) var devices: [B1NearbyDevice] = []
    private(set) var selectedDevice: B1NearbyDevice?
    private(set) var snapshot: B1GattSnapshot?
    private(set) var message: String?

    @ObservationIgnored private var transport: (any B1BluetoothTransport)?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var deadline: Task<Void, Never>?
    @ObservationIgnored private let factory: @MainActor () -> any B1BluetoothTransport
    @ObservationIgnored private let timeoutNanoseconds: UInt64

    var sessionGeneration: UInt64 { generation }

    init(timeoutNanoseconds: UInt64 = 20_000_000_000,
         factory: @escaping @MainActor () -> any B1BluetoothTransport = { B1CoreBluetoothTransport() }) {
        self.factory = factory
        self.timeoutNanoseconds = timeoutNanoseconds
    }

    func scan() {
        guard phase.canScan else { return }
        invalidate()
        devices = []
        selectedDevice = nil
        snapshot = nil
        message = nil
        availability = .unknown
        phase = .preparing
        let currentGeneration = generation
        let next = factory()
        transport = next
        next.onEvent = { [weak self] event in
            guard let self, self.generation == currentGeneration, self.transport != nil else { return }
            self.receive(event)
        }
        armDeadline("Bluetooth setup timed out. Check permission and try scanning again.")
        next.startScan()
    }

    func stopScan() {
        guard phase == .scanning || phase == .preparing else { return }
        if phase == .preparing { disconnect(); return }
        deadline?.cancel()
        transport?.stopScan()
        phase = .idle
        message = devices.isEmpty ? "No devices found. Make the B1 discoverable and scan again." : nil
    }

    func connect(_ device: B1NearbyDevice) {
        guard phase.canConnect, device.connectable != false,
              devices.contains(where: { $0.id == device.id }), let transport else { return }
        deadline?.cancel()
        transport.stopScan()
        selectedDevice = device
        snapshot = nil
        message = nil
        phase = .connecting
        armDeadline("Connection timed out. Scan again to reconnect.")
        transport.connect(deviceID: device.id)
    }

    /// Cancels pending work and rejects every callback from the retired transport.
    func disconnect() {
        invalidate()
        devices = []
        selectedDevice = nil
        phase = .idle
    }

    private func invalidate() {
        generation &+= 1
        deadline?.cancel()
        deadline = nil
        let previous = transport
        transport = nil
        previous?.onEvent = nil
        previous?.close()
    }

    private func fail(_ reason: String) {
        invalidate()
        devices = []
        selectedDevice = nil
        phase = .failed
        message = reason
    }

    private func receive(_ event: B1BluetoothEvent) {
        switch event {
        case .availability(let value):
            availability = value
        case .scanning:
            guard phase == .preparing else { return }
            phase = .scanning
            armDeadline(nil)
        case .discovered(let device):
            guard phase == .scanning else { return }
            if let index = devices.firstIndex(where: { $0.id == device.id }) {
                devices[index] = device
            } else if devices.count < 100 {
                devices.append(device)
            }
        case .connected:
            guard phase == .connecting else { return }
            phase = .discovering
            armDeadline("GATT discovery timed out. Scan again to reconnect.")
        case .gattDiscovered(let result):
            guard phase == .discovering, result.device.id == selectedDevice?.id else { return }
            deadline?.cancel()
            snapshot = result
            phase = .connectedUnverified
            message = "Profile management requires the verified B1 protocol. Router Internet has not been verified."
        case .disconnected:
            fail("The Bluetooth device disconnected. Scan again to reconnect.")
        case .failure(let reason):
            fail(reason)
        }
    }

    private func armDeadline(_ failure: String?) {
        deadline?.cancel()
        let expectedGeneration = generation
        let expectedPhase = phase
        deadline = Task { [weak self, timeoutNanoseconds] in
            do { try await Task.sleep(nanoseconds: timeoutNanoseconds) }
            catch { return }
            guard let self, self.generation == expectedGeneration, self.phase == expectedPhase else { return }
            if let failure { self.fail(failure) } else { self.stopScan() }
        }
    }
}
