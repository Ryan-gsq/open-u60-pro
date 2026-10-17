import SwiftUI

struct CellularCardView: View, Equatable {
    let wanIPv4: String
    let wanIPv6: String
    let speed: TrafficSpeed
    let trafficStats: TrafficStats
    let isTrafficAvailable: Bool
    let trafficUpdatedAt: Date?
    /// Measured seconds between distinct samples; sizes the odometer roll. See
    /// `DashboardViewModel.trafficSampleInterval`.
    var trafficSampleInterval: TimeInterval = 1
    var compact = false

    private func trafficCaption(at now: Date) -> String {
        guard let trafficUpdatedAt else { return "Live traffic unavailable" }
        let age = max(0, Int(now.timeIntervalSince(trafficUpdatedAt)))
        if !isTrafficAvailable || age >= 5 {
            return "Last traffic sample · \(age)s ago · waiting for device"
        }
        return trafficStats.source == "wwandst" ? "Live cellular traffic · all devices"
            : "Estimated cellular traffic · all devices"
    }

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label(compact ? "Live traffic" : "Cellular Connection", systemImage: "arrow.up.arrow.down")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                    if compact { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary) }
                }

                if !compact && !wanIPv4.isEmpty {
                    HStack {
                        Text("WAN IP")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(wanIPv4)
                            .font(.caption.monospacedDigit())
                    }
                }
                if !compact && !wanIPv6.isEmpty {
                    HStack {
                        Text("WAN IPv6")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(wanIPv6)
                            .font(.caption2.monospacedDigit())
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }

                Divider()

                HStack {
                    VStack(spacing: 4) {
                        Image(systemName: "arrow.down.circle.fill")
                            .foregroundStyle(.blue)
                        LiveTrafficValue(bytesPerSecond: trafficUpdatedAt == nil ? nil : speed.downloadBytesPerSec,
                                         sampleInterval: trafficSampleInterval)
                        Text("Download")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)

                    Divider()

                    VStack(spacing: 4) {
                        Image(systemName: "arrow.up.circle.fill")
                            .foregroundStyle(.blue)
                        LiveTrafficValue(bytesPerSecond: trafficUpdatedAt == nil ? nil : speed.uploadBytesPerSec,
                                         sampleInterval: trafficSampleInterval)
                        Text("Upload")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                }

                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(trafficCaption(at: context.date))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Divider()

                // The totals advance on the same poll as the live values, so they share its
                // measured cadence. `AnimatedNumber` now crossfades the unit itself.
                TrafficTotalRow(label: "Total DL", bytes: trafficStats.rxBytes,
                                sampleInterval: trafficSampleInterval)
                TrafficTotalRow(label: "Total UL", bytes: trafficStats.txBytes,
                                sampleInterval: trafficSampleInterval)
            }
        }
    }
}


private struct TrafficTotalRow: View {
    let label: String
    let bytes: UInt64
    let sampleInterval: TimeInterval
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let total = DeviceParser.bytesComponents(bytes)
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            AnimatedNumber(
                value: total.number,
                decimalPlaces: total.decimalPlaces,
                font: .caption.monospacedDigit(),
                textColor: .primary,
                animationDuration: NumberPresentation.trafficDuration(sampleInterval: sampleInterval,
                                                       reduceMotion: reduceMotion),
                suffix: total.unit
            )
        }
    }
}

private struct LiveTrafficValue: View {
    let bytesPerSecond: Double?
    let sampleInterval: TimeInterval
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if let bytesPerSecond {
                let components = DeviceParser.speedComponents(bytesPerSecond)
                // Keep the same text view across samples and unit changes. Availability is
                // based on having a sample, so a polling pause never recreates these digits.
                AnimatedNumber(
                    value: components.number,
                    decimalPlaces: components.decimalPlaces,
                    font: .title3.weight(.bold).monospacedDigit(),
                    textColor: .primary,
                    animationDuration: NumberPresentation.trafficDuration(sampleInterval: sampleInterval,
                                                           reduceMotion: reduceMotion),
                    suffix: components.unit
                )
            } else {
                Text("—").font(.title3.weight(.bold).monospacedDigit())
            }
        }
        .lineLimit(1)
        .minimumScaleFactor(0.75)
    }
}
