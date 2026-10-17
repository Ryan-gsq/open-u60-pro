import Foundation

// Stand-ins used only by the standalone test executable, never by the iOS target.
@MainActor
final class AgentClient {
    var pending: [CheckedContinuation<[String: Any], Error>] = []
    var paths: [String] = []
    var healthFixtures = false
    var sensorTemperature = 36.8
    var failHealth = false
    var pendingThermals: [CheckedContinuation<[String: Any], Error>] = []
    var suspendThermal = false
    var chargerDelay = false
    var kernelStatus = "Discharging"

    func getJSON(_ path: String) async throws -> [String: Any] {
        paths.append(path)
        if healthFixtures {
            if path == "/api/device/thermal" {
                if suspendThermal { return try await withCheckedThrowingContinuation { pendingThermals.append($0) } }
                if failHealth { throw AgentError.timeout }
                return ["cpuss_temp": sensorTemperature]
            }
            if path == "/api/battery" {
                if failHealth { throw AgentError.timeout }
                return ["capacity": 99, "temperature": 315, "current_ua": -123000,
                        "voltage_uv": 4200000, "status": kernelStatus]
            }
            if path == "/api/device/charger" {
                if chargerDelay { try await Task.sleep(for: .milliseconds(300)) }
                return ["charge_status": 4, "charger_connect": 1, "direct_power_supply_mode": "enable"] }
        }
        if path == "/api/network/speeds" {
            // Deliberately ignore cancellation to simulate a late transport response.
            return try await withCheckedThrowingContinuation { pending.append($0) }
        }
        try await Task.sleep(for: .seconds(3))
        return [:]
    }

    func get<T: Decodable>(_ path: String) async throws -> T {
        paths.append(path)
        if healthFixtures && path == "/api/cpu" {
            if failHealth { throw AgentError.timeout }
            return try JSONDecoder().decode(T.self, from: Data("{\"cores\":[0],\"overall\":0}".utf8))
        }
        try await Task.sleep(for: .seconds(3))
        throw AgentError.serverError("No fixture")
    }

    func answer(_ rate: Int) {
        pending.removeFirst().resume(returning: [
            "real_rx_bytes": 1000, "real_tx_bytes": 2000,
            "real_rx_speed": rate, "real_tx_speed": rate / 2
        ])
    }
}

@MainActor final class AuthManager {}

@main
struct DashboardTrafficTests {
    @MainActor
    static func eventually(_ attempts: Int = 100, _ condition: () -> Bool) async throws {
        for _ in 0..<attempts {
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        preconditionFailure("Traffic did not update independently of slow dashboard requests")
    }

    /// The traffic poller runs on a fixed 1 s clock, so waiting for a *subsequent* tick needs a
    /// budget well past the default 1 s worth of attempts.
    private static let acrossPolls = 400

    @MainActor
    static func measureCadence(_ schedule: PollingLoop.Schedule) async throws -> Double {
        let loop = PollingLoop()
        let clock = ContinuousClock()
        var starts: [ContinuousClock.Instant] = []
        var active = 0
        loop.start(interval: .milliseconds(300), schedule: schedule) {
            active += 1
            precondition(active == 1, "Polling requests must not overlap")
            starts.append(clock.now)
            try? await Task.sleep(for: .milliseconds(200))
            active -= 1
            return .success
        }
        for _ in 0..<200 {
            if starts.count >= 3 { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        loop.stop()
        precondition(starts.count >= 3)
        let span = starts[0].duration(to: starts[2]).components
        return Double(span.seconds) + Double(span.attoseconds) / 1e18
    }

    @MainActor
    static func main() async throws {
        let client = AgentClient()
        let model = DashboardViewModel(client: client, authManager: AuthManager())
        model.startPolling()
        try await eventually { client.pending.count == 1 }
        client.answer(25_000_000)
        try await eventually { model.isTrafficAvailable }
        precondition(model.speed.downloadBytesPerSec == 25_000_000)
        precondition(model.lastUpdated == nil) // Slow dashboard still waiting.
        precondition(!client.paths.contains("/api/network/speed"))
        let requestsBefore = client.paths.filter { $0 == "/api/network/speeds" }.count
        model.startPolling(interval: 0.5)
        let manualRefresh = Task { await model.refresh() }
        try await Task.sleep(for: .milliseconds(100))
        precondition(model.isTrafficAvailable, "General refresh must not reset the live traffic display")
        precondition(client.paths.filter { $0 == "/api/network/speeds" }.count == requestsBefore,
                     "Global refresh and manual refresh must not request additional traffic samples")
        manualRefresh.cancel()
        model.stopPolling()
        precondition(model.isTrafficAvailable && model.speed.downloadBytesPerSec == 25_000_000)

        model.startPolling()
        try await eventually { client.pending.count == 1 }
        model.stopPolling()
        model.startPolling()
        try await eventually { client.pending.count == 2 }
        client.answer(99_000_000) // Cancelled session must never overwrite the new one.
        try await Task.sleep(for: .milliseconds(50))
        precondition(model.isTrafficAvailable && model.speed.downloadBytesPerSec == 25_000_000)
        client.answer(5_000_000)
        try await eventually { model.speed.downloadBytesPerSec == 5_000_000 }
        precondition(model.isTrafficAvailable)
        let lastTrafficDate = model.trafficUpdatedAt
        model.stopPolling()
        model.startPolling()
        try await eventually { client.pending.count == 1 }
        client.pending.removeFirst().resume(throwing: AgentError.timeout)
        try await eventually { !model.isTrafficAvailable }
        precondition(model.speed.downloadBytesPerSec == 5_000_000 && model.trafficUpdatedAt == lastTrafficDate,
                     "A failed read must retain the last sample with its original timestamp")
        model.stopPolling()
        model.startPolling()
        try await eventually { client.pending.count == 1 }
        client.answer(0)
        try await eventually { model.isTrafficAvailable }
        precondition(model.speed.downloadBytesPerSec == 0, "Real zero traffic must still publish")
        model.stopPolling()

        // Sample cadence. `/api/network/speeds` is a passthrough read of a field the modem
        // refreshes on its own clock, so an independent 1 s poll re-reads one publication before
        // a new one lands. Only a changed sample may be timed, or the reels would be sized from
        // the poll rate instead of from how long the value actually stood still.
        let cadenceClient = AgentClient()
        let cadenceModel = DashboardViewModel(client: cadenceClient, authManager: AuthManager())
        cadenceModel.startPolling()
        try await eventually { cadenceClient.pending.count == 1 }
        cadenceClient.answer(7_000_000)
        try await eventually { cadenceModel.isTrafficAvailable }
        precondition(cadenceModel.trafficSampleInterval == 1,
                     "The first sample has no predecessor to measure against")
        try await eventually(acrossPolls) { cadenceClient.pending.count == 1 }
        cadenceClient.answer(7_000_000) // Same publication, re-read by the next poll.
        try await Task.sleep(for: .milliseconds(50))
        precondition(cadenceModel.trafficSampleInterval == 1,
                     "A re-read of an unchanged sample must not be timed as a measurement")
        try await eventually(acrossPolls) { cadenceClient.pending.count == 1 }
        cadenceClient.answer(9_000_000)
        try await eventually { cadenceModel.speed.downloadBytesPerSec == 9_000_000 }
        precondition(cadenceModel.trafficSampleInterval > 1.5,
                     "The measured gap must span the polls that re-read the same sample")
        cadenceModel.stopPolling()
        cadenceModel.startPolling()
        precondition(cadenceModel.trafficSampleInterval == 1,
                     "A tab pause is not a measurement interval")
        cadenceModel.stopPolling()
        while !cadenceClient.pending.isEmpty { cadenceClient.answer(0) }

        let healthClient = AgentClient()
        healthClient.healthFixtures = true
        let healthModel = DashboardViewModel(client: healthClient, authManager: AuthManager())
        healthModel.startPolling()
        try await eventually { healthModel.thermalUpdatedAt != nil && healthModel.battery.charging == "stopped" }
        precondition(healthModel.lastUpdated == nil, "Health must publish before slow general endpoints finish")
        precondition(healthModel.battery.temperature == 31.5)
        precondition(healthModel.cpuUpdatedAt != nil && healthModel.systemInfo.cpuUsagePercent == 0,
                     "Zero CPU utilization is a valid measurement")
        healthClient.chargerDelay = true
        healthClient.kernelStatus = "Charging"
        let consistentRefresh = Task { await healthModel.refresh() }
        try await Task.sleep(for: .milliseconds(100))
        precondition(healthModel.battery.charging == "stopped", "Do not publish the intermediate kernel charge state")
        try await Task.sleep(for: .milliseconds(250))
        precondition(healthModel.battery.charging == "stopped")
        consistentRefresh.cancel()
        healthClient.chargerDelay = false
        healthClient.sensorTemperature = 42.1
        let healthRefresh = Task { await healthModel.refresh() }
        try await eventually { healthModel.thermal.cpuTemp == 42.1 }
        healthRefresh.cancel()
        healthClient.failHealth = true
        let failedRefresh = Task { await healthModel.refresh() }
        try await eventually { healthModel.thermalUpdatedAt == nil && healthModel.batteryUpdatedAt == nil }
        precondition(healthModel.thermal.cpuTemp == nil && healthModel.battery.capacityPercent == nil)
        failedRefresh.cancel()
        healthClient.failHealth = false
        let recovery = Task { await healthModel.refresh() }
        try await eventually { healthModel.thermal.cpuTemp == 42.1 }
        recovery.cancel()
        let retainedBattery = healthModel.battery
        let retainedThermal = healthModel.thermal
        healthModel.stopPolling()
        precondition(healthModel.battery == retainedBattery && healthModel.thermal == retainedThermal,
                     "Tab pauses must retain readings instead of flashing empty values")
        if !healthClient.pending.isEmpty { healthClient.answer(0) }

        healthClient.suspendThermal = true
        healthModel.startPolling()
        try await eventually { healthClient.pendingThermals.count == 1 }
        healthModel.stopPolling()
        healthModel.startPolling()
        try await eventually { healthClient.pendingThermals.count == 2 }
        healthClient.pendingThermals.removeFirst().resume(returning: ["cpuss_temp": 99])
        try await Task.sleep(for: .milliseconds(30))
        precondition(healthModel.thermal.cpuTemp == 42.1, "Cancelled health sample cannot publish into new session")
        healthClient.pendingThermals.removeFirst().resume(returning: ["cpuss_temp": 38])
        try await eventually { healthModel.thermal.cpuTemp == 38 }
        healthModel.stopPolling()
        while !healthClient.pending.isEmpty { healthClient.answer(0) }
        print("Health refresh independence, zero CPU, unit conversion, failure, recovery and cancellation passed")
        let fixed = try await measureCadence(.fixedInterval)
        let afterCompletion = try await measureCadence(.afterCompletion)
        precondition(afterCompletion - fixed > 0.2,
                     "Fixed cadence must subtract request duration instead of accumulating drift")
        print("Dashboard traffic independence, cancellation, and fixed-cadence checks passed")
    }
}
