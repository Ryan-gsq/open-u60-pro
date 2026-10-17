import Foundation

// Compile with Core/Models/DeviceModels.swift and Core/Models/RouterSettingsModels.swift.
@main
struct BatteryStatusTests {
    static func main() {
        var battery = DeviceParser.parseBattery([
            "battery_capacity": 100, "battery_temperature": 41,
            "battery_time_to_full": 0, "battery_time_to_empty": 1166
        ])
        precondition(battery.capacityText == "100%")
        DeviceParser.parseCharger([
            "charger_connect": 1, "charge_status": 4
        ], into: &battery, chargeControl: ["charging_stopped": true])
        precondition(battery.charging == "stopped")
        precondition(battery.capacityText == "100%")

        // The complete percentage stays correct across both sides of a digit-width change.
        for capacity in [99, 100, 99, 9, 10, 0, 100] {
            battery.capacity = capacity
            precondition(battery.capacityText == "\(capacity)%")
        }
        for invalid in [-1, 101, 199] {
            battery.capacity = invalid
            precondition(battery.capacityPercent == nil)
            precondition(battery.capacityText == "—")
        }
        precondition(DeviceParser.parseThermal([:]).cpuTemp == nil)
        precondition(DeviceParser.parseBattery([:]).temperature == nil)
        let zones = DeviceParser.parseThermal(["sensors": [
            ["id": "16", "name": "cpuss-0", "temperature_c": 36.8],
            ["id": "17", "name": "cpuss-1", "temperature_c": 38.4],
            ["id": "33", "name": "sys-therm-5", "temperature_c": -40.96],
            ["id": "39", "name": "battery", "temperature_c": 0.0]
        ]])
        precondition(zones.cpuTemp == 38.4)
        precondition(zones.sensors[2].temperatureC == nil)
        precondition(zones.sensors[3].temperatureC == 0, "Zero Celsius is valid")
        precondition(DeviceParser.validTemperature(Double.nan) == nil)
        precondition(DeviceParser.validTemperature(-273) == nil)
        precondition(DeviceParser.parseKernelBattery(["temperature": 315]).temperature == 31.5)
        print("Thermal parsing, hottest CPU selection and invalid sensor checks passed")
        print("Battery percentage and charge-stopped regression checks passed")
    }
}
