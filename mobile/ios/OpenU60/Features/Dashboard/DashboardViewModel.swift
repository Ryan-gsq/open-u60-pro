import Foundation
import Observation
import os

private let logger = Logger(subsystem: "com.zte.companion", category: "Dashboard")

/// Which cadence groups a single refresh pass should fetch.
///
/// The router serves nearly every endpoint by forking `ubus`/`uci`/`iw` subprocesses, so a flat
/// poll of all 15 endpoints costs ~43 fork+exec per tick on a battery-powered CPE. Values that
/// change once a session (SSIDs, WAN address, SIM state) live in the slower tiers.
private struct PollTiers: OptionSet, Sendable {
    let rawValue: Int

    static let fast = PollTiers(rawValue: 1 << 0)
    static let medium = PollTiers(rawValue: 1 << 1)
    static let slow = PollTiers(rawValue: 1 << 2)

    static let all: PollTiers = [.fast, .medium, .slow]
}

@Observable
@MainActor
final class DashboardViewModel {
    var nrSignal: NRSignal = .empty
    var lteSignal: LTESignal = .empty
    var wcdmaSignal: WCDMASignal = .empty
    var operatorInfo: OperatorInfo = .empty
    var battery: BatteryStatus = .empty
    var thermal: ThermalStatus = .empty
    var thermalUpdatedAt: Date?
    var batteryUpdatedAt: Date?
    var cpuUpdatedAt: Date?
    var speed: TrafficSpeed = .zero
    var isTrafficAvailable = false
    var trafficUpdatedAt: Date?
    var trafficStats: TrafficStats = .empty

    /// Seconds between the last two *distinct* traffic samples.
    ///
    /// `/api/network/speeds` is a passthrough read of `real_rx_speed`, a field the ZTE daemon
    /// refreshes on its own clock. Polling it on an independent ~1 s timer means the two clocks
    /// beat against each other: a run of polls re-reads one publication (nothing to animate, the
    /// number sits frozen), then a poll skips one (a double-size jump). Measuring the gap between
    /// samples that actually changed lets the digit reels roll for as long as the value really
    /// stood still, instead of a fixed duration that is right only at one cadence.
    var trafficSampleInterval: TimeInterval = DashboardViewModel.defaultSampleInterval
    var wanIPv4: String = ""
    var wanIPv6: String = ""
    var wifiStatus: WifiStatus = .empty
    var systemInfo: SystemInfo = .empty
    var connectedDevices: [ConnectedDevice] = []
    var isAirplaneMode: Bool = false
    var isMobileDataOff: Bool = false
    var isLoading: Bool = false
    var lastUpdated: Date?
    var error: String?
    var simPinRequired: Bool = false
    var simPukRequired: Bool = false

    private let client: AgentClient
    private let authManager: AuthManager
    private let poller = PollingLoop()
    private let trafficPoller = PollingLoop()
    private let healthPoller = PollingLoop()
    @ObservationIgnored private var healthInFlight: (id: UUID, task: Task<Bool, Never>)?

    /// Wall-clock cadence of the two slower tiers. Tick counts are derived from these and the
    /// user-configurable poll interval, so changing the interval in Settings keeps 10s/60s.
    private static let mediumCadence: TimeInterval = 10
    private static let slowCadence: TimeInterval = 60

    @ObservationIgnored private var previousTraffic: TrafficStats?
    @ObservationIgnored private var tickCount = 0
    @ObservationIgnored private var mediumEvery = 5
    @ObservationIgnored private var slowEvery = 30
    @ObservationIgnored private var refreshGeneration = 0
    @ObservationIgnored private var inFlight: (tiers: PollTiers, id: Int, task: Task<Bool, Never>)?
    @ObservationIgnored private var trafficGeneration = 0
    @ObservationIgnored private var trafficInFlight: (id: Int, task: Task<Bool, Never>)?
    @ObservationIgnored private var trafficTier: TrafficTier = .wwandst
    @ObservationIgnored private var lastTrafficProbe: Date = .distantPast
    @ObservationIgnored private var lastDistinctTrafficAt: Date?

    /// Assumed cadence before two distinct samples have been seen, matching the poll interval.
    private static let defaultSampleInterval: TimeInterval = 1
    /// Bounds on the measured cadence. The floor rejects a burst of samples arriving back to back;
    /// the ceiling keeps a backed-off poll or a resumed tab from reporting a minutes-long gap.
    private static let sampleIntervalRange: ClosedRange<TimeInterval> = 0.25...8

    /// Non-zero while the Signal Monitor screen is pushed. That screen polls `/api/network/signal`
    /// itself, and the dashboard's own signal cards are hidden behind it, so fetching here too
    /// just doubles the rate on the largest payload and heaviest parse in the app.
    ///
    /// Counted rather than a flag because suspension is owned by the presenting view: overlapping
    /// suspend calls (a push plus a background/foreground cycle) must balance, and nothing else —
    /// including a restart of the poll loop — may resume a fetch that view still owns.
    @ObservationIgnored private var signalFetchSuspensions = 0

    var isSignalFetchSuspended: Bool { signalFetchSuspensions > 0 }

    /// Which traffic endpoint last worked. Re-probing the whole chain every tick can serialize
    /// four 10s timeouts inside one refresh when the router is wedged.
    private enum TrafficTier: Int {
        case wwandst
        case agentSpeed
        case agentTraffic
        case rmnet

        var next: TrafficTier? { TrafficTier(rawValue: rawValue + 1) }
    }

    /// How often the traffic fallback chain restarts from the best tier, so recovery still happens.
    private static let trafficReprobeInterval: TimeInterval = 60

    init(client: AgentClient, authManager: AuthManager) {
        self.client = client
        self.authManager = authManager
    }

    // MARK: - Polling

    func startPolling(interval: TimeInterval = 2.0) {
        // Changing the general refresh interval must not restart the traffic clock.
        poller.stop()
        inFlight?.task.cancel()
        inFlight = nil
        let base = max(0.5, interval)
        mediumEvery = max(1, Int((Self.mediumCadence / base).rounded()))
        slowEvery = max(1, Int((Self.slowCadence / base).rounded()))
        tickCount = 0
        if !trafficPoller.isRunning {
            // A pre-pause baseline must not pair with a sample minutes later.
            previousTraffic = nil
            // Likewise for the cadence: the pause itself is not a measurement interval.
            lastDistinctTrafficAt = nil
            trafficSampleInterval = Self.defaultSampleInterval
            // Follow the modem's approximately one-second publication cadence. Traffic has
            // its own clock; global refresh settings only affect the other dashboard tiers.
            trafficPoller.start(interval: .seconds(1), schedule: .fixedInterval) { [weak self] in
                guard let self else { return .failure }
                return await self.refreshTraffic() ? .success : .failure
            }
        }
        if !healthPoller.isRunning {
            healthPoller.start(interval: .seconds(2), schedule: .fixedInterval) { [weak self] in
                guard let self else { return .failure }
                return await self.refreshHealth() ? .success : .failure
            }
        }
        poller.start(interval: .seconds(base)) { [weak self] in
            guard let self else { return .failure }
            return await self.pollTick()
        }
    }

    func stopPolling() {
        poller.stop()
        trafficPoller.stop()
        healthPoller.stop()
        healthInFlight?.task.cancel()
        healthInFlight = nil
        // Pausing is not a failed read. Preserve the last sample and its age across tabs.
        trafficInFlight?.task.cancel()
        trafficInFlight = nil
        previousTraffic = nil
        lastDistinctTrafficAt = nil
        inFlight?.task.cancel()
        inFlight = nil
    }

    // MARK: - Signal fetch suspension

    /// Suspends the dashboard's own signal fetch while a screen that polls signal itself is up.
    /// Must be balanced with `resumeSignalFetch()`.
    func suspendSignalFetch() {
        signalFetchSuspensions += 1
    }

    func resumeSignalFetch() {
        signalFetchSuspensions = max(0, signalFetchSuspensions - 1)
    }

    private func pollTick() async -> PollingLoop.Outcome {
        let index = tickCount
        tickCount = (tickCount + 1) % (mediumEvery * slowEvery)

        var tiers: PollTiers = .fast
        if index % mediumEvery == 0 { tiers.insert(.medium) }
        if index % slowEvery == 0 { tiers.insert(.slow) }

        let succeeded = await performRefresh(tiers)
        return succeeded ? .success : .failure
    }

    /// Refresh the general dashboard tiers. Live traffic stays on its own modem cadence.
    func refresh() async {
        async let general = performRefresh(.all)
        async let health = refreshHealth()
        _ = await (general, health)
    }

    /// Serializes dashboard passes. A pass already in flight that covers everything the caller wants is that
    /// caller's answer too; anything else queues behind it, so the pull-to-refresh spinner lasts
    /// until its own data actually lands.
    @discardableResult
    private func performRefresh(_ tiers: PollTiers) async -> Bool {
        if let existing = inFlight, existing.tiers.isSuperset(of: tiers) {
            return await existing.task.value
        }

        refreshGeneration += 1
        let id = refreshGeneration
        let previousTask = inFlight?.task
        let task = Task { @MainActor [weak self] in
            if let previousTask { _ = await previousTask.value }
            guard let self else { return false }
            let succeeded = await self.executeRefresh(tiers)
            if self.inFlight?.id == id { self.inFlight = nil }
            return succeeded
        }
        inFlight = (tiers, id, task)
        return await task.value
    }

    private func executeRefresh(_ tiers: PollTiers) async -> Bool {
        if Task.isCancelled { return false }
        logger.debug("refresh start")

        let medium = tiers.contains(.medium)
        let slow = tiers.contains(.slow)

        async let signalResult = fetchSignal()
        async let deviceList = fetchDevices(enabled: medium)
        async let batteryETA = fetchBatteryETA(enabled: medium)

        async let wanResult = fetchWAN(enabled: slow)
        async let wan6Result = fetchWAN6(enabled: slow)
        async let wifiResult = fetchWifi(enabled: slow)
        async let systemResult = fetchSystemInfo(enabled: slow)
        async let simResult = fetchSimStatus(enabled: slow)
        async let modemResult = fetchModemStatus(enabled: slow)
        async let mobileDataResult = fetchMobileDataStatus(enabled: slow)

        let signal = await signalResult
        let devices = await deviceList
        let eta = await batteryETA
        let (wan, wan6, wifi, sys, sim, modemStatus, mobileDataOff) = await (
            wanResult, wan6Result, wifiResult, systemResult, simResult, modemResult, mobileDataResult
        )

        // Tab switch or teardown: leave every value as it was rather than half-applying a pass.
        if Task.isCancelled { return false }

        let reachable = signal != nil || sys != nil || devices != nil

        if let (nr, lte, wcdma, op) = signal {
            if nr != nrSignal { nrSignal = nr }
            if lte != lteSignal { lteSignal = lte }
            if wcdma != wcdmaSignal { wcdmaSignal = wcdma }
            if op != operatorInfo { operatorInfo = op }
        }
        if let opMode = modemStatus {
            let airplane = !opMode.isEmpty && opMode != "ONLINE"
            if airplane != isAirplaneMode {
                isAirplaneMode = airplane
                if airplane {
                    nrSignal = .empty
                    lteSignal = .empty
                    wcdmaSignal = .empty
                    operatorInfo = .empty
                }
            }
        }

        if let eta {
            battery.timeToFull = eta.timeToFull
            battery.timeToEmpty = eta.timeToEmpty
        }
        if let devices, devices != connectedDevices { connectedDevices = devices }

        // Only a landed response may blank an address; a dropped poll must not.
        if wan.didFetch, wan.ip != wanIPv4 { wanIPv4 = wan.ip }
        if wan6.didFetch, wan6.ip != wanIPv6 { wanIPv6 = wan6.ip }

        if let wifi, wifi != wifiStatus { wifiStatus = wifi }

        var newSystemInfo = sys ?? systemInfo
        // CPU usage belongs to the independent health loop, never an older system response.
        newSystemInfo.cpuUsagePercent = systemInfo.cpuUsagePercent
        newSystemInfo.cpuUsageIsEstimate = systemInfo.cpuUsageIsEstimate
        if newSystemInfo != systemInfo { systemInfo = newSystemInfo }

        if let (pin, puk) = sim {
            if pin != simPinRequired { simPinRequired = pin }
            if puk != simPukRequired { simPukRequired = puk }
        }
        if let dataOff = mobileDataOff, dataOff != isMobileDataOff {
            isMobileDataOff = dataOff
        }

        if reachable { lastUpdated = Date() }
        logger.debug("refresh done")
        return reachable
    }

    // MARK: - Fast tier

    private func fetchSignal() async -> (NRSignal, LTESignal, WCDMASignal, OperatorInfo)? {
        guard !isSignalFetchSuspended else { return nil }
        do {
            let data = try await client.getJSON("/api/network/signal")
            if error != nil { error = nil }
            let parsed = SignalParser.parseNetInfo(data)
            return (parsed.0, parsed.1, parsed.2, parsed.3)
        } catch let fetchError {
            if !fetchError.isCancellation {
                let message = fetchError.localizedDescription
                if error != message { error = message }
            }
            return nil
        }
    }

    private func fetchThermal() async -> ThermalStatus? {
        do {
            let data = try await client.getJSON("/api/device/thermal")
            guard data["cpuss_temp"] != nil || data["sensors"] != nil else { return nil }
            return DeviceParser.parseThermal(data)
        } catch { return nil }
    }

    /// Applies traffic on its independent clock, without waiting for SIM/Wi-Fi/system
    /// requests. A cancelled old task cannot publish into a new session.
    private func refreshTraffic() async -> Bool {
        guard !Task.isCancelled else { return false }
        if let existing = trafficInFlight { return await existing.task.value }
        trafficGeneration += 1
        let id = trafficGeneration
        let task = Task { @MainActor [weak self] in
            guard let self else { return false }
            let traffic = await self.fetchTraffic()
            guard !Task.isCancelled else { return false }
            guard let traffic else {
                self.isTrafficAvailable = false
                self.previousTraffic = nil
                self.lastDistinctTrafficAt = nil
                return false
            }
            let now = Date()
            // `TrafficStats.==` ignores the local receive timestamp, so this compares the modem's
            // published measurement rather than the poll that fetched it. Only a changed sample
            // marks real elapsed measurement time; timing re-reads instead would report a
            // spuriously short cadence and shrink the animation back to a snap.
            if self.previousTraffic != traffic {
                if let last = self.lastDistinctTrafficAt {
                    let range = Self.sampleIntervalRange
                    self.trafficSampleInterval =
                        min(max(now.timeIntervalSince(last), range.lowerBound), range.upperBound)
                }
                self.lastDistinctTrafficAt = now
            }
            // A re-read still republishes: for the counter-delta tiers, unchanged byte totals are
            // a genuine idle measurement that has to reach zero rather than hold the last rate.
            let speed = DeviceParser.computeSpeed(
                previous: self.previousTraffic ?? traffic, current: traffic
            )
            if speed != self.speed { self.speed = speed }
            self.previousTraffic = traffic
            self.trafficStats = traffic
            self.trafficUpdatedAt = now
            self.isTrafficAvailable = true
            return true
        }
        trafficInFlight = (id, task)
        let succeeded = await task.value
        if trafficInFlight?.id == id { trafficInFlight = nil }
        return succeeded
    }

    private func fetchTraffic() async -> TrafficStats? {
        let now = Date()
        if now.timeIntervalSince(lastTrafficProbe) >= Self.trafficReprobeInterval {
            lastTrafficProbe = now
            trafficTier = .wwandst
        }

        var tier = trafficTier
        while !Task.isCancelled {
            do {
                if let stats = try await fetchTraffic(from: tier) {
                    guard !Task.isCancelled else { return nil }
                    trafficTier = tier
                    return stats
                }
            } catch let fetchError {
                // Tab switch or teardown: nothing was learned about which tier works.
                if fetchError.isCancellation { return nil }
                // The agent is unreachable, not missing this one endpoint, so the rest of the
                // chain would only serialize more 10s timeouts inside this same pass.
                if Self.isTransportFailure(fetchError) {
                    trafficTier = tier
                    return nil
                }
            }
            // Stay on the tier last tried when the whole chain fails: a wedged router must not
            // re-walk four endpoints every tick. Only `trafficReprobeInterval` rewinds the tier.
            guard let next = tier.next else {
                trafficTier = tier
                return nil
            }
            tier = next
        }
        return nil
    }

    /// True for failures that mean the agent itself is out of reach. A missing endpoint on an
    /// older agent build answers with an HTTP error instead, and must still fall through to the
    /// next tier.
    private static func isTransportFailure(_ error: Error) -> Bool {
        guard let agentError = error as? AgentError else { return false }
        switch agentError {
        case .serverUnreachable, .timeout:
            return true
        default:
            return false
        }
    }

    private func fetchTraffic(from tier: TrafficTier) async throws -> TrafficStats? {
        switch tier {
        case .agentSpeed:
            // Server-computed speed (precise Instant timing on device).
            return try await fetchAgentSpeed()
        case .agentTraffic:
            // Native /api/network/traffic (kernel-level /proc/net/dev via agent).
            return try await fetchAgentTraffic()
        case .wwandst:
            // Native firmware source, including hardware-offloaded traffic. Kernel
            // rmnet counters miss traffic and the legacy agent speed is a ~15s average.
            let data = try await client.getJSON("/api/network/speeds")
            return DeviceParser.parseWwandstTraffic(data)
        case .rmnet:
            // network.device status (rmnet_data0 delta).
            let data = try await client.getJSON("/api/network/rmnet")
            var stats = DeviceParser.parseTraffic(data)
            stats.source = "rmnet_agent"
            return stats
        }
    }

    private func fetchAgentSpeed() async throws -> TrafficStats {
        struct AgentSpeedResponse: Decodable {
            let rx_bytes: UInt64
            let tx_bytes: UInt64
            let rx_speed: Double
            let tx_speed: Double
            let elapsed_ms: UInt64
        }
        let resp: AgentSpeedResponse = try await client.get("/api/network/speed")
        var stats = TrafficStats(
            rxBytes: resp.rx_bytes,
            txBytes: resp.tx_bytes,
            timestamp: Date(),
            source: "agent_speed"
        )
        stats.serverRxSpeed = resp.rx_speed
        stats.serverTxSpeed = resp.tx_speed
        return stats
    }

    private func fetchAgentTraffic() async throws -> TrafficStats? {
        struct NetIface: Decodable {
            let name: String
            let rx_bytes: UInt64
            let tx_bytes: UInt64
        }
        let ifaces: [NetIface] = try await client.get("/api/network/traffic")
        guard let rmnet = ifaces.first(where: { $0.name == "rmnet_data0" }) else { return nil }
        return TrafficStats(rxBytes: rmnet.rx_bytes, txBytes: rmnet.tx_bytes, timestamp: Date(), source: "agent")
    }

    private func fetchCpuUsage() async -> Double? {
        struct CpuUsage: Decodable {
            let cores: [Double]
            let overall: Double
        }
        do {
            let usage: CpuUsage = try await client.get("/api/cpu")
            return usage.overall
        } catch {
            return nil
        }
    }

    /// A separate, deduplicated task prevents slow general requests from blocking health.
    private func refreshHealth() async -> Bool {
        guard !Task.isCancelled else { return false }
        if let existing = healthInFlight { return await existing.task.value }
        let id = UUID()
        let task = Task { @MainActor [weak self] in
            guard let self else { return false }
            async let temperatures = self.updateTemperatures()
            async let cpu = self.updateCPU()
            async let battery = self.updateBattery()
            let results = await (temperatures, cpu, battery)
            return results.0 || results.1 || results.2
        }
        healthInFlight = (id, task)
        let result = await task.value
        if healthInFlight?.id == id { healthInFlight = nil }
        return result
    }

    private func updateTemperatures() async -> Bool {
        let fresh = await fetchThermal()
        guard !Task.isCancelled else { return false }
        thermal = fresh ?? .empty
        thermalUpdatedAt = fresh == nil ? nil : Date()
        return fresh != nil
    }

    private func updateCPU() async -> Bool {
        let usage = await fetchCpuUsage()
        guard !Task.isCancelled else { return false }
        let valid = usage.flatMap { $0.isFinite && (0...100).contains($0) ? $0 : nil }
        systemInfo.cpuUsagePercent = valid ?? 0
        systemInfo.cpuUsageIsEstimate = false
        cpuUpdatedAt = valid == nil ? nil : Date()
        return valid != nil
    }

    private func updateBattery() async -> Bool {
        // Kernel temperature is tenths of a degree; thermal zones are millidegrees.
        // Read current values on every health tick, not the slower firmware battery tier.
        async let batteryResponse = try? client.getJSON("/api/battery")
        async let chargerResponse = try? client.getJSON("/api/device/charger")
        let (info, charger) = await (batteryResponse, chargerResponse)
        guard !Task.isCancelled else { return false }
        var fresh = info.map(DeviceParser.parseKernelBattery) ?? .empty
        fresh.timeToFull = battery.timeToFull
        fresh.timeToEmpty = battery.timeToEmpty
        if info != nil, let charger {
            DeviceParser.parseCharger(charger, into: &fresh)
        }
        // Publish once: kernel Discharging may actually mean firmware Charge Stopped.
        // Publishing both interpretations each tick makes the status blink.
        if battery != fresh { battery = fresh }
        batteryUpdatedAt = info == nil ? nil : Date()
        return info != nil
    }

    // MARK: - Medium tier

    private func fetchBatteryETA(enabled: Bool) async -> BatteryStatus? {
        guard enabled, let data = try? await client.getJSON("/api/device/battery-info") else { return nil }
        return DeviceParser.parseBattery(data)
    }

    private func fetchDevices(enabled: Bool) async -> [ConnectedDevice]? {
        guard enabled else { return nil }
        do {
            let data = try await client.getJSON("/api/network/clients")
            let hostsData = data["hosts"] as? [String: Any] ?? [:]
            var deviceList = DeviceParser.parseHostHints(hostsData)
            if let leases = data["dhcp_leases"] as? [[String: Any]] {
                DeviceParser.enrichWithDHCP(devices: &deviceList, leases: leases)
            }
            return deviceList
        } catch { return nil }
    }

    // MARK: - Slow tier

    private func fetchWAN(enabled: Bool) async -> (didFetch: Bool, ip: String) {
        guard enabled, let data = try? await client.getJSON("/api/network/wan") else {
            return (false, "")
        }
        return (true, DeviceParser.parseWanIPv4(data))
    }

    private func fetchWAN6(enabled: Bool) async -> (didFetch: Bool, ip: String) {
        guard enabled, let data = try? await client.getJSON("/api/network/wan6") else {
            return (false, "")
        }
        return (true, DeviceParser.parseWanIPv6(data))
    }

    private func fetchWifi(enabled: Bool) async -> WifiStatus? {
        guard enabled else { return nil }
        if let data = try? await client.getJSON("/api/wifi/status"),
           data["htmode_2g"] != nil {
            return parseCompanionWifi(data)
        }
        return nil
    }

    private func fetchSystemInfo(enabled: Bool) async -> SystemInfo? {
        guard enabled, let data = try? await client.getJSON("/api/device/system") else { return nil }
        return DeviceParser.parseSystemInfo(data, cpuCores: 4)
    }

    private func fetchSimStatus(enabled: Bool) async -> (pin: Bool, puk: Bool)? {
        guard enabled else { return nil }
        do {
            let data = try await client.getJSON("/api/sim/info")
            let sim = (data["sim_states"] as? String ?? "").lowercased()
            let modem = (data["modem_main_state"] as? String ?? "").lowercased()
            return (
                sim == "wait pin" || modem == "modem_waitpin",
                sim == "wait puk" || modem == "modem_waitpuk"
            )
        } catch {
            return nil
        }
    }

    private func fetchModemStatus(enabled: Bool) async -> String? {
        struct ModemStatusResponse: Decodable {
            let operate_mode: String
        }
        guard enabled else { return nil }
        do {
            let resp: ModemStatusResponse = try await client.get("/api/modem/status")
            return resp.operate_mode
        } catch {
            return nil
        }
    }

    private func fetchMobileDataStatus(enabled: Bool) async -> Bool? {
        guard enabled, let data = try? await client.getJSON("/api/modem/data") else { return nil }
        let wwan = MobileNetworkParser.parseWWAN(data)
        let connected = wwan.connectStatus.contains("connected")
        return wwan.dataEnabled == 0 && !connected
    }

    // MARK: - Parsing

    private func parseCompanionWifi(_ data: [String: Any]) -> WifiStatus {
        let actualCh2g = data["actual_channel_2g"] as? String ?? ""
        let actualCh5g = data["actual_channel_5g"] as? String ?? ""
        let ch2g = !actualCh2g.isEmpty ? actualCh2g : (data["channel_2g"] as? String ?? "")
        let ch5g = !actualCh5g.isEmpty ? actualCh5g : (data["channel_5g"] as? String ?? "")
        let enc2g = data["encryption_2g"] as? String ?? ""
        let enc5g = data["encryption_5g"] as? String ?? ""
        let clientsTotal: Int
        if let n = data["clients_total"] as? Int {
            clientsTotal = n
        } else if let s = data["clients_total"] as? String, let n = Int(s) {
            clientsTotal = n
        } else {
            clientsTotal = 0
        }
        let guestDisabled2g = (data["guest_disabled_2g"] as? String) == "1"
        let guestDisabled5g = (data["guest_disabled_5g"] as? String) == "1"
        let guestEnabled = !guestDisabled2g || !guestDisabled5g
        return WifiStatus(
            wifiOn: (data["wifi_onoff"] as? String) == "1",
            ssid2g: data["ssid_2g"] as? String ?? "",
            ssid5g: data["ssid_5g"] as? String ?? "",
            channel2g: ch2g,
            channel5g: ch5g,
            radio2gDisabled: (data["radio2_disabled"] as? String) == "1",
            radio5gDisabled: (data["radio5_disabled"] as? String) == "1",
            encryption2g: DeviceParser.formatEncryption(enc2g),
            encryption5g: DeviceParser.formatEncryption(enc5g),
            hidden2g: (data["hidden_2g"] as? String) == "1",
            hidden5g: (data["hidden_5g"] as? String) == "1",
            txPower2g: data["txpower_2g"] as? String ?? "",
            txPower5g: data["txpower_5g"] as? String ?? "",
            bandwidth2g: data["htmode_2g"] as? String ?? "",
            bandwidth5g: data["htmode_5g"] as? String ?? "",
            clientsTotal: clientsTotal,
            wifi6: (data["wifi6_switch"] as? String) == "1",
            guestEnabled: guestEnabled,
            guestSsid: data["guest_ssid"] as? String ?? ""
        )
    }
}
