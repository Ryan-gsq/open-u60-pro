import ActivityKit
import SwiftUI
import WidgetKit

@main
struct SignalWidgetBundle: WidgetBundle {
    var body: some Widget { SignalLiveActivity() }
}

struct SignalLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: SignalActivityAttributes.self) { context in
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("U60 Pro · Modem signal", systemImage: "wifi.router.fill").font(.headline)
                    Spacer()
                    if context.isStale { Text("Stale").foregroundStyle(.orange).font(.caption.bold()) }
                }
                signalRow(context.state, stale: context.isStale)
            }
            .padding(16)
            .activityBackgroundTint(Color(.secondarySystemBackground))
            .activitySystemActionForegroundColor(.primary)
        } dynamicIsland: { context in
            DynamicIsland {
                // Keep the whole expanded layout below the camera and inside the curved edges.
                DynamicIslandExpandedRegion(.bottom) {
                    signalRow(context.state, stale: context.isStale)
                        .padding(.horizontal, 16)
                        .padding(.bottom, 12)
                }
            } compactLeading: {
                if context.state.mode == .sa {
                    compactQuality(context.state.nrSinr, stale: context.isStale)
                } else if context.state.mode == .lte || context.state.mode == .lteCA {
                    compactQuality(context.state.lteSinr, stale: context.isStale)
                } else {
                HStack(spacing: 3) {
                    Text(context.state.mode == .lteCA ? "4G+" : "4G").font(.system(size: 9, weight: .bold))
                    compactBars(context.state.lteBars, active: context.state.mode.showsLTE, stale: context.isStale)
                }
                .foregroundStyle(context.isStale ? .orange : .blue)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("4G LTE")
                }
            } compactTrailing: {
                if context.state.mode == .lte || context.state.mode == .lteCA {
                    HStack(spacing: 3) {
                        Text(context.state.mode == .lteCA ? "4G+" : "4G")
                            .font(.system(size: 9, weight: .bold))
                        compactBars(context.state.lteBars, active: true, stale: context.isStale)
                    }
                    .foregroundStyle(context.isStale ? .orange : .blue)
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("4G LTE")
                } else {
                HStack(spacing: 3) {
                    Text("5G").font(.system(size: 9, weight: .bold))
                    compactBars(context.state.nrBars, active: context.state.mode.showsNR, stale: context.isStale)
                }
                .foregroundStyle(context.isStale ? .orange : .blue)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("5G NR")
                }
            } minimal: {
                compactBars(context.state.mode.showsNR ? context.state.nrBars : context.state.lteBars,
                            active: context.state.mode.showsNR || context.state.mode.showsLTE, stale: context.isStale)
            }
        }
    }

    private func signalRow(_ state: SignalActivityAttributes.ContentState, stale: Bool) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Group {
                if state.mode == .sa {
                    quality("5G quality", sinr: state.nrSinr, stale: stale)
                } else if state.mode == .lte || state.mode == .lteCA {
                    quality("LTE quality", sinr: state.lteSinr, stale: stale)
                } else {
                    radio("LTE", bars: state.lteBars, rsrp: state.lteRsrp,
                          sinr: state.mode == .nsa ? state.lteSinr : nil,
                          stale: stale, active: state.mode.showsLTE)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            VStack(spacing: 3) {
                Text(state.mode.label).font(.caption.bold())
                if state.mode.showsLTE, let count = state.lteCarrierCount, count > 1 {
                    Text("LTE CA").font(.system(size: 9))
                }
                Text(stale ? "Stale" : "Sample age")
                    .font(.system(size: 9))
                    .foregroundStyle(stale ? Color.orange : Color.secondary)
                Text(Date(timeIntervalSince1970: Double(state.sampledAt)), style: .timer)
                    .id(state.sampledAt)
                    .font(.caption.monospacedDigit())
                    .multilineTextAlignment(.center)
                    .frame(width: 58)
            }
            .frame(width: 78)
            .lineLimit(1)
            .minimumScaleFactor(0.75)
            .accessibilityElement(children: .combine)
            Group {
                if state.mode == .lte || state.mode == .lteCA {
                    radio("LTE", bars: state.lteBars, rsrp: state.lteRsrp,
                          sinr: nil, stale: stale, active: true)
                } else {
                    radio("5G NR", bars: state.nrBars, rsrp: state.nrRsrp,
                          sinr: state.mode == .nsa ? state.nrSinr : nil,
                          stale: stale, active: state.mode.showsNR)
                }
            }
            .frame(maxWidth: .infinity, alignment: .trailing)
        }
    }

    private func quality(_ title: String, sinr: Double?, stale: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold())
            if let sinr {
                Text("\(sinr, specifier: "%.0f") dB")
                    .font(.title3.bold()).monospacedDigit().contentTransition(.numericText())
            } else {
                Text("Unavailable").font(.caption).foregroundStyle(.secondary)
            }
            Text("SINR").font(.caption2).foregroundStyle(.secondary)
        }
        .lineLimit(1).minimumScaleFactor(0.8)
        .opacity(stale ? 0.45 : 1)
        .accessibilityElement(children: .combine)
    }

    private func compactQuality(_ sinr: Double?, stale: Bool) -> some View {
        HStack(spacing: 2) {
            Text("SINR").font(.system(size: 8, weight: .medium))
            if let sinr {
                Text("\(sinr, specifier: "%.0f")")
                    .font(.caption2.bold()).monospacedDigit().contentTransition(.numericText())
            } else { Text("–").font(.caption2) }
        }
        .foregroundStyle(stale ? Color.orange : (sinr == nil ? Color.secondary : Color.blue))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(sinr.map { "Active radio SINR \(Int($0)) decibels" } ?? "Active radio SINR unavailable")
    }

    @ViewBuilder
    private func compactBars(_ bars: Int?, active: Bool, stale: Bool) -> some View {
        if active { SignalBarsView(bars: bars, stale: stale) }
        else { Text("–").font(.caption).foregroundStyle(.secondary).accessibilityLabel("Not reported active") }
    }

    private func radio(_ name: String, bars: Int?, rsrp: Double?, sinr: Double?, stale: Bool = false, active: Bool = true) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(name).font(.caption.bold())
                compactBars(bars, active: active, stale: stale)
            }
            if !active {
                Text("—").font(.title3.bold()).foregroundStyle(.secondary)
            } else if let rsrp {
                Text("\(rsrp, specifier: "%.0f") dBm")
                    .font(.title3.bold()).monospacedDigit().contentTransition(.numericText())
            } else { Text("Unavailable").font(.caption).foregroundStyle(.secondary) }
            if active, let sinr {
                Text("SINR \(sinr, specifier: "%.0f") dB")
                    .font(.caption2).monospacedDigit().contentTransition(.numericText())
            }
        }.lineLimit(1).minimumScaleFactor(0.8)
        .opacity(stale ? 0.45 : 1)
        .accessibilityElement(children: .combine)
    }
}

private struct SignalBarsView: View {
    let bars: Int?
    let stale: Bool
    var body: some View {
        Image(systemName: "cellularbars", variableValue: Double(min(4, max(0, bars ?? 0))) / 4)
            .symbolRenderingMode(.hierarchical)
            .font(.system(size: 17, weight: .regular))
            .foregroundStyle(stale ? Color.orange : (bars == nil ? Color.secondary : Color.blue))
            .frame(width: 24, height: 20)
        .opacity(stale || bars == nil ? 0.5 : 1)
        .accessibilityLabel(stale ? "Stale modem signal" : bars.map { "Modem signal \($0) of 4 bars" } ?? "Modem signal unavailable")
    }
}
