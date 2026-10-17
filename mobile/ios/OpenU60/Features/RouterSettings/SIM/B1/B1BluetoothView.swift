import SwiftUI
import UIKit

struct B1BluetoothView: View {
    @State private var controller = B1BluetoothController()
    @State private var management = B1ESimController()
    @State private var access = B1BluetoothAccess()
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL

    var body: some View {
        List {
            Section("Bluetooth setup") {
                Label(access.permission.title, systemImage: "antenna.radiowaves.left.and.right")
                Text(access.permission.guidance).font(.footnote).foregroundStyle(.secondary)
                LabeledContent("Last Bluetooth status", value: controller.availability.title)
                if !access.permission.canScan || controller.availability == .poweredOff {
                    Button("Open Settings", systemImage: "gear", action: openSettings)
                }
            }
            Section("Connection") {
                Label(controller.phase.title, systemImage: "antenna.radiowaves.left.and.right")
                if let device = controller.selectedDevice { Text(device.displayName) }
                if let message = controller.message {
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                }
                if controller.phase.canScan {
                    Button("Scan nearby devices", systemImage: "magnifyingglass", action: controller.scan)
                        .disabled(!access.permission.canScan)
                }
                if controller.phase == .scanning || controller.phase == .preparing {
                    Button("Stop scan", action: controller.stopScan)
                }
                if !controller.phase.canScan {
                    Button("Disconnect / cancel", action: controller.disconnect)
                }
            }

            Section {
                Text("Select your B1 from the nearby devices. Device names and service identifiers alone do not verify B1 support.")
                    .font(.footnote).foregroundStyle(.secondary)
                ForEach(controller.devices) { device in
                    Button { controller.connect(device) } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.displayName)
                            Text(device.id).font(.caption).foregroundStyle(.secondary)
                            if let rssi = device.rssi { Text("Signal: \(rssi) dBm").font(.caption) }
                            if let lastSeenAt = device.lastSeenAt {
                                Text("Last detected: \(lastSeenAt)").font(.caption2).foregroundStyle(.secondary)
                            }
                            if !device.advertisedServices.isEmpty {
                                Text("Advertised services: \(device.advertisedServices.joined(separator: ", "))")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            if device.connectable == false { Text("Not connectable").font(.caption) }
                        }
                    }
                    .disabled(!controller.phase.canConnect || device.connectable == false)
                    .accessibilityHint("Connect to inspect Bluetooth services")
                }
            } header: { Text("Nearby BLE devices") }

            if let snapshot = controller.snapshot {
                Section {
                    Text("Captured for \(snapshot.device.displayName) at \(snapshot.observedAt).")
                        .font(.caption).foregroundStyle(.secondary)
                    if let json = try? snapshot.evidenceJSON() {
                        ShareLink("Share GATT report", item: json)
                    }
                    ForEach(snapshot.services) { service in
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Service \(service.uuid)").font(.caption.monospaced())
                            ForEach(service.characteristics) { characteristic in
                                VStack(alignment: .leading) {
                                    Text(characteristic.uuid).font(.caption.monospaced())
                                    Text(characteristic.properties.joined(separator: ", "))
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .textSelection(.enabled)
                    }
                } header: { Text("Observed GATT services") }
            }

            B1ESimManagementView(controller: management)
        }
        .navigationTitle("9eSIM B1 Bluetooth")
        .task { access.refresh() }
        .onDisappear { management.disconnect(); controller.disconnect() }
        .onChange(of: controller.phase) {
            if controller.phase == .connectedUnverified, let snapshot = controller.snapshot {
                let epoch = controller.sessionGeneration
                Task {
                    guard controller.sessionGeneration == epoch,
                          controller.phase == .connectedUnverified, controller.snapshot == snapshot else { return }
                    await management.attach(snapshot)
                }
            } else if controller.phase != .discovering { management.disconnect() }
        }
        .onChange(of: controller.availability) { access.refresh() }
        .onChange(of: scenePhase) {
            if scenePhase == .background { management.disconnect(); controller.disconnect() }
            if scenePhase == .active { access.refresh() }
        }
    }

    private func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        openURL(url)
    }
}
