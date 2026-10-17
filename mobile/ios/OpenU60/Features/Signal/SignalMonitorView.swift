import SwiftUI
import Charts

struct SignalMonitorView<ConnectionDetails: View>: View {
    let viewModel: SignalMonitorViewModel
    @ViewBuilder let connectionDetails: ConnectionDetails

    @Environment(\.scenePhase) private var scenePhase
    @State private var isVisible = false

    /// The sheet can remain alive while network mode is pushed or another tab is selected.
    /// Poll only while both visible and foregrounded.
    private struct PollKey: Equatable {
        let foreground: Bool
        let visible: Bool

        var shouldPoll: Bool { foreground && visible }
    }

    private var pollKey: PollKey {
        PollKey(foreground: scenePhase == .active, visible: isVisible)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                let nr = viewModel.nrSignal
                let lte = viewModel.lteSignal
                let wcdma = viewModel.wcdmaSignal
                let showNR = viewModel.operatorInfo.showNR(nr: nr)
                let showLTE = viewModel.operatorInfo.showLTE(lte: lte)
                let show3G = viewModel.operatorInfo.show3G(nr: nr, lte: lte, wcdma: wcdma)

                OperatorCardView(operatorInfo: viewModel.operatorInfo, nrSignal: nr, lteSignal: lte, padding: 12)
                    .equatable()
                if showNR {
                    CellularPanel(data: .nr(nr)).equatable()
                }
                if showLTE {
                    CellularPanel(data: .lte(lte, isNSAAnchor: showNR)).equatable()
                }
                if show3G {
                    WCDMAPanel(signal: wcdma)
                }
                if let bearer = viewModel.bearer {
                    DataSessionPanel(bearer: bearer, qosLabel: viewModel.qosLabel).equatable()
                }
                SignalHistoryChart(history: viewModel.history, showLTE: showLTE, show3G: show3G)
                connectionDetails
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Connection & signal")
        .refreshable { await viewModel.refresh() }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                LastUpdatedView(date: viewModel.lastUpdated)
            }
        }
        .onAppear { isVisible = true }
        .onDisappear {
            isVisible = false
            // Dismissal can tear down the view before onChange runs.
            viewModel.stopPolling()
        }
        .onChange(of: pollKey, initial: true) { _, key in
            if key.shouldPoll {
                viewModel.startPolling()
            } else {
                viewModel.stopPolling()
            }
        }
    }
}

// MARK: - Data Session

private struct DataSessionPanel: View, Equatable {
    let bearer: BearerInfo
    let qosLabel: String

    var body: some View {
        CardView(padding: 12) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Data Session")
                    .font(.headline)

                if let qci = bearer.qci {
                    MetaRow(label: qosLabel, value: String(qci))
                }
                if let ambrText = bearer.ambrText {
                    MetaRow(label: "AMBR", value: ambrText)
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("Rate cap")
                        .accessibilityValue(ambrAccessibilityValue)

                    Text("Down / up. Operator rate cap, set when the data session started. Not a speed test.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var ambrAccessibilityValue: String {
        let down = bearer.ambrDownlinkMbps.map {
            "\(BearerInfo.formatMbps($0)) megabits per second down"
        } ?? "Down unavailable"
        let up = bearer.ambrUplinkMbps.map {
            "\(BearerInfo.formatMbps($0)) megabits per second up"
        } ?? "Up unavailable"
        return "\(down), \(up)"
    }
}

// MARK: - RSRP History Chart

private struct SignalHistoryChart: View {
    let history: [SignalSnapshot]
    let showLTE: Bool
    let show3G: Bool

    var body: some View {
        CardView(padding: 12) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Signal History")
                    .font(.headline)

                if history.isEmpty {
                    Text("Collecting data...")
                        .foregroundStyle(.secondary)
                        .frame(height: 110)
                        .frame(maxWidth: .infinity)
                } else {
                    chart
                }
            }
        }
    }

    private var chart: some View {
        Chart {
            ForEach(history) { point in
                if let nrRSRP = point.nrRSRP {
                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("dBm", nrRSRP)
                    )
                    .foregroundStyle(by: .value("Type", "NR"))
                    .interpolationMethod(.catmullRom)
                }
                if showLTE, let lteRSRP = point.lteRSRP {
                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("dBm", lteRSRP)
                    )
                    .foregroundStyle(by: .value("Type", "LTE"))
                    .interpolationMethod(.catmullRom)
                }
                if show3G, let wcdmaRSCP = point.wcdmaRSCP {
                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("dBm", wcdmaRSCP)
                    )
                    .foregroundStyle(by: .value("Type", "3G"))
                    .interpolationMethod(.catmullRom)
                }
            }
        }
        .chartForegroundStyleScale([
            "NR": Color.blue,
            "LTE": Color.orange,
            "3G": Color.purple,
        ])
        .chartYScale(domain: -140...(-40))
        .chartYAxis {
            AxisMarks(values: [-140, -120, -100, -80, -60, -40]) { value in
                AxisGridLine()
                AxisValueLabel {
                    if let v = value.as(Int.self) {
                        Text("\(v)")
                    }
                }
            }
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 4)) { _ in
                AxisGridLine()
                AxisValueLabel(format: .dateTime.minute().second())
            }
        }
        .frame(height: 160)
        .accessibilityLabel("Signal strength history")
    }
}

// MARK: - Cellular Panel

/// The NR and LTE panels differ only in labels, accent and two extra rows, so both render
/// through `CellularPanel`. Feeding it one `Equatable` value gives SwiftUI a comparison
/// boundary: a tick that only moves the other radio's numbers skips this panel's body.
private struct CellularPanelData: Equatable {
    let title: String
    let systemImage: String
    let accent: Color
    let isNR: Bool
    let isConnected: Bool
    let rsrp: Double?
    let rsrq: Double?
    let sinr: Double?
    let rssi: Double?
    let band: String
    let pci: String
    let cellID: String
    let channelLabel: String
    let channel: String
    let bandwidth: String
    let caActive: Bool
    let showsNSAAnchor: Bool
    let showsTotalBandwidth: Bool
    let sccCarriers: [LTECarrier]

    var technology: BandTechnology { isNR ? .nr : .lte }

    var numCC: Int { 1 + sccCarriers.count }

    static func nr(_ signal: NRSignal) -> CellularPanelData {
        CellularPanelData(
            title: "5G NR",
            systemImage: "antenna.radiowaves.left.and.right",
            accent: .blue,
            isNR: true,
            isConnected: signal.isConnected,
            rsrp: signal.rsrp,
            rsrq: signal.rsrq,
            sinr: signal.sinr,
            rssi: signal.rssi,
            band: signal.band,
            pci: signal.pci,
            cellID: signal.cellID,
            channelLabel: "Channel",
            channel: signal.channel,
            bandwidth: signal.bandwidth,
            caActive: !signal.sccCarriers.isEmpty,
            showsNSAAnchor: false,
            showsTotalBandwidth: true,
            sccCarriers: signal.sccCarriers
        )
    }

    static func lte(_ signal: LTESignal, isNSAAnchor: Bool) -> CellularPanelData {
        CellularPanelData(
            title: "LTE",
            systemImage: "cellularbars",
            accent: .orange,
            isNR: false,
            isConnected: signal.isConnected,
            rsrp: signal.rsrp,
            rsrq: signal.rsrq,
            sinr: signal.sinr,
            rssi: signal.rssi,
            band: signal.band,
            pci: signal.pci,
            cellID: signal.cellID,
            channelLabel: "EARFCN",
            channel: signal.earfcn,
            bandwidth: signal.bandwidth,
            caActive: signal.caState != "0" && !signal.sccCarriers.isEmpty,
            showsNSAAnchor: isNSAAnchor,
            showsTotalBandwidth: false,
            sccCarriers: signal.sccCarriers
        )
    }
}

private struct CellularPanel: View, Equatable {
    let data: CellularPanelData

    var body: some View {
        CardView(padding: 12) {
            VStack(alignment: .leading, spacing: 8) {
                header

                if data.isConnected {
                    metrics

                    Divider()

                    metadata

                    if !data.sccCarriers.isEmpty {
                        Divider()
                        ForEach(data.sccCarriers) { carrier in
                            SCCCarrierView(carrier: carrier)
                        }
                    }
                }
            }
        }
    }

    private var header: some View {
        HStack {
            Label(data.title, systemImage: data.systemImage)
                .font(.headline)
            if data.showsNSAAnchor {
                badge("NSA Anchor")
            }
            if data.caActive {
                badge("\(data.numCC) CC")
            }
            Spacer()
            if data.isConnected {
                Text(Color.rsrpQuality(data.rsrp))
                    .font(.caption.bold())
                    .foregroundStyle(Color.rsrpColor(data.rsrp))
                    .accessibilityLabel("Signal quality")
                    .accessibilityValue(Color.rsrpQuality(data.rsrp))
            } else {
                Text("Disconnected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func badge(_ text: String) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(data.accent.opacity(0.15), in: Capsule())
            .foregroundStyle(data.accent)
    }

    private var metrics: some View {
        SignalMetricsGrid(rsrp: data.rsrp, rsrq: data.rsrq, sinr: data.sinr, rssi: data.rssi)
    }

    private var metadata: some View {
        VStack(alignment: .leading, spacing: 4) {
            MetaRow(label: "Band", value: SignalFormat.band(data.band, technology: data.technology, isPCC: data.caActive))
            MetaRow(label: "PCI", value: data.pci)
            MetaRow(label: "Cell ID", value: data.cellID)
            MetaRow(label: data.channelLabel, value: data.channel)
            MetaRow(label: "Bandwidth", value: SignalFormat.bandwidth(data.bandwidth, band: data.band, technology: data.technology))
            MetaRow(label: "CA", value: data.caActive ? "Active (\(data.numCC) CC)" : "Inactive")
            if data.showsTotalBandwidth, data.caActive, let total = totalBandwidth {
                MetaRow(label: "Total BW", value: "\(total) MHz")
            }
        }
    }

    /// PCC bandwidth plus every SCC bandwidth, in MHz. Nil when nothing parsed.
    private var totalBandwidth: Int? {
        let sccValues = data.sccCarriers.compactMap { SignalFormat.bandwidthMHz($0.bandwidth) }
        guard let pcc = SignalFormat.bandwidthMHz(data.bandwidth) else {
            return sccValues.isEmpty ? nil : sccValues.reduce(0, +)
        }
        return pcc + sccValues.reduce(0, +)
    }
}

private struct SCCCarrierView: View {
    let carrier: LTECarrier

    var body: some View {
        let technology: BandTechnology = carrier.label.hasPrefix("5G") ? .nr : .lte

        VStack(alignment: .leading, spacing: 4) {
            Text(carrier.label)
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Text(SignalFormat.carrierBand(carrier.band, technology: technology))
                    .font(.caption2.monospacedDigit())
                Text("PCI \(carrier.pci)")
                    .font(.caption2.monospacedDigit())
                Text("BW \(carrier.bandwidth)")
                    .font(.caption2.monospacedDigit())
            }
            .foregroundStyle(.secondary)
            SignalMetricsGrid(rsrp: carrier.rsrp, rsrq: carrier.rsrq,
                              sinr: carrier.sinr, rssi: carrier.rssi)
        }
    }
}

// MARK: - WCDMA Panel

private struct WCDMAPanel: View {
    let signal: WCDMASignal

    var body: some View {
        CardView(padding: 12) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Label("WCDMA", systemImage: "antenna.radiowaves.left.and.right.circle")
                        .font(.headline)
                    Spacer()
                    if signal.isConnected {
                        Text(Color.rscpQuality(signal.rscp))
                            .font(.caption.bold())
                            .foregroundStyle(Color.rscpColor(signal.rscp))
                            .accessibilityLabel("Signal quality")
                            .accessibilityValue(Color.rscpQuality(signal.rscp))
                    }
                }
                HStack(spacing: 8) {
                    SignalMetricView(label: "RSCP", value: signal.rscp, unit: "dBm", color: Color.rscpColor(signal.rscp))
                    SignalMetricView(label: "Ec/Io", value: signal.ecio, unit: "dB", color: Color.ecioColor(signal.ecio))
                }
            }
        }
    }
}

// MARK: - Formatting

/// The one place band and bandwidth strings are built. The three renderings deliberately
/// differ: the metadata rows have room for duplex mode and the PCC marker, the SCC rows only
/// for the common name.
enum SignalFormat {
    /// Firmware may send a number, an existing prefix, or a label such as "LTE BAND 3".
    /// Normalize only for display; the model keeps the original modem value.
    static func bandNumber(_ raw: String) -> String? {
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ":_-"))
        var value = raw.uppercased().trimmingCharacters(in: separators)
        let prefixes = ["NR5G", "LTE", "BAND", "NR", "5G", "4G", "B", "N"]
        while let prefix = prefixes.first(where: { value.hasPrefix($0) }) {
            value.removeFirst(prefix.count)
            value = value.trimmingCharacters(in: separators)
        }
        guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }),
              let number = Int(value), number > 0 else { return nil }
        return String(number)
    }

    static func bandLabel(_ raw: String, technology: BandTechnology) -> String {
        guard let number = bandNumber(raw) else { return "--" }
        return (technology == .nr ? "n" : "B") + number
    }

    static func band(_ band: String, technology: BandTechnology, isPCC: Bool) -> String {
        guard let number = bandNumber(band) else { return "--" }
        let label = bandLabel(number, technology: technology)
        let pccSuffix = isPCC ? " · PCC" : ""
        guard let spec = technology.spec(for: number) else { return "\(label)\(pccSuffix)" }
        return "\(label) (\(spec.commonName), \(spec.duplexMode.rawValue))\(pccSuffix)"
    }

    static func carrierBand(_ band: String, technology: BandTechnology) -> String {
        guard let number = bandNumber(band) else { return "--" }
        let label = bandLabel(number, technology: technology)
        guard let spec = technology.spec(for: number) else { return label }
        return "\(label) (\(spec.commonName))"
    }

    static func bandwidth(_ bandwidth: String, band: String, technology: BandTechnology) -> String {
        if let value = bandwidthMHz(bandwidth), let number = bandNumber(band),
           let spec = technology.spec(for: number) {
            return "\(value) / \(spec.maxBandwidthMHz) MHz max"
        }
        return bandwidth.isEmpty ? "--" : bandwidth
    }

    /// Strips the unit off a firmware bandwidth string ("20 MHz" -> 20).
    static func bandwidthMHz(_ raw: String) -> Int? {
        var slice = raw[...]
        while let first = slice.first, first.isLetter || first.isWhitespace { slice.removeFirst() }
        while let last = slice.last, last.isLetter || last.isWhitespace { slice.removeLast() }
        return Int(slice)
    }
}

// MARK: - Rows

private struct MetaRow: View {
    let label: String
    let value: String

    @ScaledMetric(relativeTo: .caption) private var labelWidth: CGFloat = 80

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: labelWidth, alignment: .leading)
            if let number = Int(value), String(number) == value {
                AnimatedNumber(value: number, font: .caption)
            } else {
                Text(value.isEmpty ? "--" : value)
                    .font(.caption.monospacedDigit())
            }
        }
        .accessibilityElement(children: .combine)
    }
}

private struct SignalMetricsGrid: View {
    let rsrp: Double?
    let rsrq: Double?
    let sinr: Double?
    let rssi: Double?

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let columns = Array(repeating: GridItem(.flexible(), spacing: 8),
                            count: dynamicTypeSize.isAccessibilitySize ? 2 : 4)
        LazyVGrid(columns: columns, spacing: 6) {
            SignalMetricView(label: "RSRP", value: rsrp, unit: "dBm", color: Color.rsrpColor(rsrp))
            SignalMetricView(label: "RSRQ", value: rsrq, unit: "dB", color: Color.rsrqColor(rsrq))
            SignalMetricView(label: "SINR", value: sinr, unit: "dB", color: Color.sinrColor(sinr))
            SignalMetricView(label: "RSSI", value: rssi, unit: "dBm", color: .primary)
        }
    }
}

struct SignalMetricView: View {
    let label: String
    let value: Double?
    let unit: String
    let color: Color

    var body: some View {
        VStack(spacing: 3) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 2) {
                if let value {
                    AnimatedNumber(value: Int(value), font: .title3.bold(), textColor: color)
                } else {
                    Text("--")
                        .font(.title3.monospacedDigit().bold())
                        .foregroundStyle(.secondary)
                }
                Text(unit)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .lineLimit(1)
            .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 2)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value.map { "\(Int($0)) \(unit)" } ?? "Unavailable")
    }
}
