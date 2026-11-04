import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Where a value came from, so the UI can be honest about what it is showing.
public enum MeasurementSource: String, Sendable {
    case measured
    case derived
    case unavailable
}

/// Bounds outside which a reading is garbage rather than data.
public enum BatteryLimits {
    public static let minMilliAmps = 20
    public static let maxMilliAmps = 20_000
    public static let minMilliVolts = 2_000
    /// Wide enough for a phone cell and a MacBook pack; the bound exists to catch
    /// garbage, not to assume a phone.
    public static let maxMilliVolts = 30_000
    public static let minCelsius = -20.0
    public static let maxCelsius = 125.0
}

public struct CurrentReading: Sendable, Equatable {
    /// Signed milliamps: negative = discharging, positive = charging.
    public let milliAmps: Int
    public let source: MeasurementSource
    public let note: String

    public static let unavailable = CurrentReading(
        milliAmps: 0,
        source: .unavailable,
        note: "This device does not report battery current."
    )
}

public struct HeatReading: Sendable, Equatable {
    public let effectiveCelsius: Double?
    public let effectiveSource: MeasurementSource
    public let cellCelsius: Double?
    public let socCelsius: Double?
    public let socLabel: String
    public let heatSource: String
}

/// One reading of the device's battery, in the units every platform shares.
public struct BatterySnapshot: Sendable, Equatable {
    public let platform: String
    public let percent: Int
    public let isCharging: Bool
    public let chargingLabel: String
    public let current: CurrentReading
    public let powerMilliWatts: Int?
    public let heat: HeatReading
    public let voltageMilliVolts: Int?
    public let chargeMilliAmpHours: Int?
    public let energyMilliWattHours: Int?
    public let healthLabel: String
    public let readingAt: Date
}

/// The measurement rules, mirrored from the Android and desktop implementations.
///
/// Kept free of UIKit and of `UIDevice` so it can be compiled and unit-tested on any
/// Apple platform, including a headless CI runner.
public enum BatteryMath {

    /// Normalises a raw current so that negative always means discharging.
    ///
    /// `UIDevice.batteryLevel` has no current at all, so on iOS this is normally fed by
    /// a value the app cannot obtain; when it is `nil` the reading says so rather than
    /// showing a plausible-looking zero.
    public static func normaliseCurrent(_ rawMilliAmps: Int?, isCharging: Bool) -> CurrentReading {
        guard let raw = rawMilliAmps else { return .unavailable }
        let magnitude = abs(raw)
        guard magnitude >= BatteryLimits.minMilliAmps, magnitude <= BatteryLimits.maxMilliAmps else {
            return .unavailable
        }
        // The charging state is ground truth; the sign is corrected to match it.
        let saysDischarging = raw < 0
        let flip = isCharging ? saysDischarging : !saysDischarging
        return CurrentReading(
            milliAmps: flip ? -raw : raw,
            source: .measured,
            note: "Measured (sign normalised to the charging state)"
        )
    }

    /// P = V x I, withheld unless both inputs are usable.
    public static func powerMilliWatts(voltageMilliVolts: Int?, currentMilliAmps: Int, currentIsMeasured: Bool) -> Int? {
        guard currentIsMeasured, let volts = voltageMilliVolts else { return nil }
        guard volts >= BatteryLimits.minMilliVolts, volts <= BatteryLimits.maxMilliVolts else { return nil }
        return Int((Double(volts) * Double(currentMilliAmps) / 1000.0).rounded())
    }

    /// Stored energy in mWh = charge (mAh) x voltage (V).
    public static func energyMilliWattHours(chargeMilliAmpHours: Int?, voltageMilliVolts: Int?) -> Int? {
        guard let charge = chargeMilliAmpHours, let volts = voltageMilliVolts else { return nil }
        guard volts >= BatteryLimits.minMilliVolts, volts <= BatteryLimits.maxMilliVolts else { return nil }
        return Int((Double(charge) * Double(volts) / 1000.0).rounded())
    }

    public static func isPlausible(_ celsius: Double?) -> Bool {
        guard let value = celsius else { return false }
        return value.isFinite && value >= BatteryLimits.minCelsius && value <= BatteryLimits.maxCelsius
    }

    /// Chooses the temperature used for decisions and describes where the heat is.
    public static func resolveHeat(cellCelsius: Double?, socCelsius: Double?, socLabel: String = "") -> HeatReading {
        let cell = isPlausible(cellCelsius) ? cellCelsius : nil
        let soc = isPlausible(socCelsius) ? socCelsius : nil

        let effective = cell ?? soc
        let source: MeasurementSource = cell != nil ? .measured : (soc != nil ? .derived : .unavailable)

        let description: String
        if let cellValue = cell, let socValue = soc {
            let gap = socValue - cellValue
            description = gap >= 5
                ? String(format: "The CPU/SoC is %.1f °C hotter than the battery — this heat is workload, not the cell.", gap)
                : "Heat source: battery cell and SoC are close together."
        } else if cell != nil {
            description = "Heat source: battery cell."
        } else if soc != nil {
            description = "Heat source: \(socLabel.isEmpty ? "SoC sensor" : socLabel) (battery cell not reported)."
        } else {
            description = "No temperature sensor is readable on this device."
        }

        return HeatReading(
            effectiveCelsius: effective,
            effectiveSource: source,
            cellCelsius: cell,
            socCelsius: soc,
            socLabel: socLabel,
            heatSource: description
        )
    }

    /// Builds a snapshot from an adapter's raw values, clamping the same way everywhere.
    public static func snapshot(
        platform: String,
        percent: Double?,
        isCharging: Bool,
        chargingLabel: String? = nil,
        currentMilliAmps: Int? = nil,
        voltageMilliVolts: Int? = nil,
        cellCelsius: Double? = nil,
        socCelsius: Double? = nil,
        socLabel: String = "",
        chargeMilliAmpHours: Int? = nil,
        healthLabel: String = "Not reported",
        readingAt: Date = Date()
    ) -> BatterySnapshot {
        let clampedPercent = min(100, max(0, Int((percent ?? 0).rounded())))
        let current = normaliseCurrent(currentMilliAmps, isCharging: isCharging)
        let measured = current.source == .measured
        let heat = resolveHeat(cellCelsius: cellCelsius, socCelsius: socCelsius, socLabel: socLabel)

        return BatterySnapshot(
            platform: platform,
            percent: clampedPercent,
            isCharging: isCharging,
            chargingLabel: chargingLabel ?? (isCharging ? "Charging" : "Discharging"),
            current: current,
            powerMilliWatts: powerMilliWatts(
                voltageMilliVolts: voltageMilliVolts,
                currentMilliAmps: current.milliAmps,
                currentIsMeasured: measured
            ),
            heat: heat,
            voltageMilliVolts: voltageMilliVolts.flatMap {
                ($0 >= BatteryLimits.minMilliVolts && $0 <= BatteryLimits.maxMilliVolts) ? $0 : nil
            },
            chargeMilliAmpHours: chargeMilliAmpHours,
            energyMilliWattHours: energyMilliWattHours(
                chargeMilliAmpHours: chargeMilliAmpHours,
                voltageMilliVolts: voltageMilliVolts
            ),
            healthLabel: healthLabel,
            readingAt: readingAt
        )
    }

    /// The one-line summary used in notifications. Missing values are stated, never
    /// replaced with a plausible-looking zero.
    public static func summaryLine(_ snapshot: BatterySnapshot) -> String {
        var parts: [String] = ["\(snapshot.percent)%"]

        if snapshot.current.source == .measured && snapshot.current.milliAmps != 0 {
            let magnitude = abs(snapshot.current.milliAmps)
            let sign = snapshot.current.milliAmps > 0 ? "+" : "-"
            let watts = snapshot.powerMilliWatts.map {
                String(format: " (%.1f W)", abs(Double($0)) / 1000.0)
            } ?? ""
            parts.append("\(sign)\(magnitude) mA\(watts)")
        } else {
            parts.append("current not reported")
        }

        if let cell = snapshot.heat.cellCelsius {
            parts.append(String(format: "%.1f°C cell", cell))
        }
        if let soc = snapshot.heat.socCelsius {
            parts.append(String(format: "%.1f°C chip", soc))
        }
        if snapshot.heat.cellCelsius == nil && snapshot.heat.socCelsius == nil {
            parts.append("no temperature sensor readable")
        }
        if let energy = snapshot.energyMilliWattHours {
            parts.append(String(format: "%.1f Wh stored", Double(energy) / 1000.0))
        }

        return parts.joined(separator: " • ")
    }
}
