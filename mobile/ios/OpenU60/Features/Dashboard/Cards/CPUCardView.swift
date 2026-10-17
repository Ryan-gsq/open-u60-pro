import SwiftUI

struct CPUCardView: View, Equatable {
    let systemInfo: SystemInfo
    let thermal: ThermalStatus
    var cpuAvailable: Bool = true

    var body: some View {
        CardView {
            VStack(spacing: 8) {
                Image(systemName: "cpu")
                    .font(.title2)
                    .foregroundStyle(.blue)
                if cpuAvailable {
                    CPUUsageValue(value: systemInfo.cpuUsagePercent, font: .title3.bold())
                } else { Text("—").font(.title3.bold()) }
                TemperatureValueText(value: thermal.cpuTemp)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                Text("CPU")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
        }
    }
}

struct CPUDetailSheet: View {
    var cpuAvailable: Bool = true
    let systemInfo: SystemInfo
    let thermal: ThermalStatus
    let client: AgentClient

    @State private var showProcessList = false
    @State private var bloatSummary: String = ""

    var body: some View {
        NavigationStack {
            List {
                HStack {
                    Label("CPU Usage", systemImage: "cpu")
                    Spacer()
                    if cpuAvailable {
                        CPUUsageValue(value: systemInfo.cpuUsagePercent, font: .body, color: .secondary)
                    } else { Text("—").foregroundStyle(.secondary) }
                }
                if systemInfo.cpuUsagePercent > 0 && systemInfo.cpuUsageIsEstimate {
                    row("Usage Source", icon: "info.circle", value: "Estimated")
                }
                row("CPU Cores", icon: "square.grid.2x2", value: "\(systemInfo.cpuCores)")
                HStack {
                    Label("CPU · hottest sensor", systemImage: "thermometer.medium")
                    Spacer()
                    TemperatureValueText(value: thermal.cpuTemp).foregroundStyle(.secondary)
                }
                row("Uptime", icon: "clock", value: formatUptime(systemInfo.uptime))
                row("Memory Total", icon: "memorychip", value: formatBytes(systemInfo.memTotal))
                row("Memory Free", icon: "memorychip", value: formatBytes(systemInfo.memFree))
                if systemInfo.memTotal > 0 {
                    let used = Double(systemInfo.memTotal - systemInfo.memFree) / Double(systemInfo.memTotal) * 100
                    row("Memory Used", icon: "chart.bar", value: String(format: "%.0f%%", used))
                }

                Button {
                    showProcessList = true
                } label: {
                    HStack {
                        Label("Processes", systemImage: "list.number")
                        Spacer()
                        if !bloatSummary.isEmpty {
                            Text(bloatSummary)
                                .foregroundStyle(.orange)
                                .font(.caption)
                        }
                        Image(systemName: "chevron.right")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .foregroundStyle(.primary)
            }
            .navigationTitle("CPU & Memory")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showProcessList) {
                ProcessListSheet(client: client)
            }
            .task {
                await loadBloatSummary()
            }
        }
    }

    private func loadBloatSummary() async {
        do {
            let result: ProcessListResponse = try await client.get("/api/system/top")
            if result.bloatCount > 0 {
                bloatSummary = "\(result.bloatCount) bloat \(String(format: "%.0f", result.bloatCpuPct))%"
            }
        } catch {
            // Silently ignore — summary is optional
        }
    }

    private func row(_ label: String, icon: String, value: String) -> some View {
        HStack {
            Label(label, systemImage: icon)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
    }

    private func formatUptime(_ seconds: Int) -> String {
        let d = seconds / 86400
        let h = (seconds % 86400) / 3600
        let m = (seconds % 3600) / 60
        if d > 0 { return "\(d)d \(h)h \(m)m" }
        if h > 0 { return "\(h)h \(m)m" }
        return "\(m)m"
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        if bytes >= 1_073_741_824 {
            return String(format: "%.1f GB", Double(bytes) / 1_073_741_824)
        } else if bytes >= 1_048_576 {
            return String(format: "%.0f MB", Double(bytes) / 1_048_576)
        }
        return "\(bytes) B"
    }
}


/// Each row keeps the firmware identity; no inferred case/ambient temperature.
struct TemperatureCardView: View {
    let thermal: ThermalStatus
    let battery: BatteryStatus
    let thermalUpdatedAt: Date?
    let batteryUpdatedAt: Date?
    @State private var showAllSensors = false

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 16) {
                Label("Temperatures", systemImage: "thermometer.medium")
                    .font(.headline)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    VStack(alignment: .leading, spacing: 12) {
                        temperatureRow("CPU · hottest sensor", icon: "cpu",
                            value: thermal.cpuTemp, fresh: isFresh(thermalUpdatedAt, at: context.date))
                        temperatureRow("Battery", icon: "battery.100",
                            value: battery.temperature,
                            fresh: isFresh(batteryUpdatedAt, at: context.date))
                        ForEach(summarySensors) { sensor in
                            temperatureRow(sensor.label, icon: "thermometer.medium", value: sensor.temperatureC,
                                fresh: isFresh(thermalUpdatedAt, at: context.date))
                        }
                        Text(freshnessText(at: context.date))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if !thermal.sensors.isEmpty {
                    DisclosureGroup("All sensors", isExpanded: $showAllSensors) {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(thermal.sensors) { sensor in
                                HStack(alignment: .firstTextBaseline) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(sensor.label).font(.subheadline)
                                        if sensor.label != sensor.name {
                                            Text(sensor.name).font(.caption).foregroundStyle(.secondary)
                                        }
                                    }
                                    Spacer()
                                    if let temperature = sensor.temperatureC {
                                        TemperatureValueText(value: temperature)
                                    } else {
                                        Text("Unavailable").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                .accessibilityElement(children: .combine)
                            }
                        }
                        .padding(.top, 8)
                    }
                    .font(.subheadline)
                }
                Text("CPU shows the hottest CPU zone. Board numbers follow the device’s sensor names. Unavailable means the device is not reporting a valid temperature.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

        }
    }

    private var summarySensors: [TemperatureSensor] {
        thermal.sensors.filter { $0.name == "usb" || $0.name == "pmx75_tz" || $0.name.hasPrefix("sys-therm-") }
    }

    private func isFresh(_ date: Date?, at now: Date) -> Bool {
        date.map { now.timeIntervalSince($0) < 10 } ?? false
    }

    private func freshnessText(at now: Date) -> String {
        guard let thermalUpdatedAt else { return "Temperature readings unavailable · retrying automatically" }
        let seconds = max(0, Int(now.timeIntervalSince(thermalUpdatedAt)))
        return seconds < 10 ? "Updated \(seconds)s ago · refreshes every 2s" : "Last sample \(seconds)s ago · waiting for device"
    }

    private func temperatureRow(_ title: String, icon: String, value: Double?, fresh: Bool) -> some View {
        HStack {
            Label(title, systemImage: icon).font(.subheadline)
            Spacer()
            if fresh && value == nil {
                Text("Unavailable").font(.caption).foregroundStyle(.secondary)
            } else {
                TemperatureValueText(value: fresh ? value : nil).font(.body.weight(.semibold))
            }
        }
        .accessibilityElement(children: .combine)
    }
}


/// Use the same stable digit reels as live traffic, preserving sensor precision.
struct TemperatureValueText: View {
    let value: Double?
    @Environment(\.font) private var font
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if let value {
            AnimatedNumber(value: value, decimalPlaces: 1, font: font ?? .body,
                animationDuration: reduceMotion ? 0 : 0.4, suffix: " °C")
        } else {
            Text("—").monospacedDigit()
        }
    }
}

/// Retain the measured tenths so small CPU changes remain visible between samples.
struct CPUUsageValue: View {
    let value: Double
    var font: Font = .title3.bold()
    var color: Color = .primary
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        AnimatedNumber(value: value, decimalPlaces: 1, font: font, textColor: color,
            animationDuration: reduceMotion ? 0 : 0.4, suffix: "%")
    }
}
