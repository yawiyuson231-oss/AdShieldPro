import Foundation

/// The four alerts, implemented once for Apple platforms.
///
/// Mirrors `desktop/src/core/alerts.js` and `service/BatteryHealthNotifier.kt`: same
/// thresholds, same suppression windows, same refusal to warn about a value that was
/// never measured.
public enum AlertKind: String, Sendable {
    case lowBattery = "low-battery"
    case chargeComplete = "charge-complete"
    case heat = "heat"
    case heavyDraw = "heavy-draw"
}

public struct BatteryAlert: Sendable, Equatable {
    public let kind: AlertKind
    public let title: String
    public let body: String
}

/// User thresholds. Defaults match the Android and desktop builds.
public struct AlertSettings: Sendable, Equatable {
    public var enabled: Bool
    public var lowPercentThreshold: Int
    public var fullPercentThreshold: Int
    public var tempWarningCelsius: Double
    public var currentAlertMilliAmps: Int
    public var notifyOnChargeComplete: Bool

    public static let `default` = AlertSettings(
        enabled: false,
        lowPercentThreshold: 20,
        fullPercentThreshold: 100,
        tempWarningCelsius: 41,
        currentAlertMilliAmps: 1800,
        notifyOnChargeComplete: true
    )

    /// Clamps thresholds into ranges that are actually useful, and keeps the full-charge
    /// threshold above the low-battery one so the two cannot contradict each other.
    public func clamped() -> AlertSettings {
        let low = min(50, max(5, lowPercentThreshold))
        return AlertSettings(
            enabled: enabled,
            lowPercentThreshold: low,
            fullPercentThreshold: min(100, max(low + 10, fullPercentThreshold)),
            tempWarningCelsius: min(55, max(35, tempWarningCelsius)),
            currentAlertMilliAmps: min(5000, max(500, currentAlertMilliAmps)),
            notifyOnChargeComplete: notifyOnChargeComplete
        )
    }
}

/// What the previous evaluation left behind. `nil` timestamps, not 0, because 0 is a
/// valid clock value and would suppress the first alert.
public struct AlertState: Sendable, Equatable {
    public var lastLowPercent: Int?
    public var lastTempAlertAt: Date?
    public var lastTempAlertValueC: Double
    public var lastCurrentAlertAt: Date?
    public var chargeCompleteSessionMarker: Int?

    public init(
        lastLowPercent: Int? = nil,
        lastTempAlertAt: Date? = nil,
        lastTempAlertValueC: Double = 0,
        lastCurrentAlertAt: Date? = nil,
        chargeCompleteSessionMarker: Int? = nil
    ) {
        self.lastLowPercent = lastLowPercent
        self.lastTempAlertAt = lastTempAlertAt
        self.lastTempAlertValueC = lastTempAlertValueC
        self.lastCurrentAlertAt = lastCurrentAlertAt
        self.chargeCompleteSessionMarker = chargeCompleteSessionMarker
    }
}

public enum BatteryAlerts {
    public static let tempCooldown: TimeInterval = 30 * 60
    public static let currentCooldown: TimeInterval = 45 * 60
    public static let tempRealertDeltaC: Double = 2

    /// Evaluates one snapshot.
    ///
    /// - Parameters:
    ///   - now: injected so tests do not depend on the wall clock.
    ///   - sessionOf: maps a date to a charging-session id; defaults to 12-hour buckets.
    public static func evaluate(
        _ snapshot: BatterySnapshot,
        settings rawSettings: AlertSettings,
        state previous: AlertState = AlertState(),
        now: Date = Date(),
        sessionOf: (Date) -> Int = { Int($0.timeIntervalSince1970 / (12 * 60 * 60)) }
    ) -> (alerts: [BatteryAlert], state: AlertState) {
        let settings = rawSettings.clamped()
        var state = previous
        var alerts: [BatteryAlert] = []

        guard settings.enabled else { return (alerts, state) }

        let charging = snapshot.current.source == .measured
            ? snapshot.current.milliAmps > 0
            : snapshot.isCharging

        // 1. Low battery: once per drop, again every further 5%.
        if !charging && snapshot.percent <= settings.lowPercentThreshold {
            if state.lastLowPercent == nil || snapshot.percent <= (state.lastLowPercent ?? 0) - 5 {
                alerts.append(BatteryAlert(
                    kind: .lowBattery,
                    title: "Battery low — \(snapshot.percent)%",
                    body: "\(snapshot.percent)% • AdShield keeps filtering; consider Battery Saver mode."
                ))
                state.lastLowPercent = snapshot.percent
            }
        } else if charging {
            state.lastLowPercent = nil
        }

        // 2. Charge complete: once per charging session.
        if settings.notifyOnChargeComplete && charging && snapshot.percent >= settings.fullPercentThreshold {
            let marker = sessionOf(now)
            if state.chargeCompleteSessionMarker != marker {
                alerts.append(BatteryAlert(
                    kind: .chargeComplete,
                    title: "Charge complete — \(snapshot.percent)%",
                    body: "Unplugging near 80–90% is easier on cell life."
                ))
                state.chargeCompleteSessionMarker = marker
            }
        }

        // 3. Heat: whichever sensor is readable, preferring the cell.
        if let temp = snapshot.heat.effectiveCelsius, temp >= settings.tempWarningCelsius {
            let cooled: Bool
            if let last = state.lastTempAlertAt {
                cooled = now.timeIntervalSince(last) >= tempCooldown
            } else {
                cooled = true
            }
            let heatingUp = state.lastTempAlertAt != nil && temp >= state.lastTempAlertValueC + tempRealertDeltaC
            if cooled || heatingUp {
                let advice = charging
                    ? "Unplug or slow-charge until it drops below \(Int(settings.tempWarningCelsius))°C."
                    : "Close heavy apps until it drops below \(Int(settings.tempWarningCelsius))°C."
                alerts.append(BatteryAlert(
                    kind: .heat,
                    title: String(format: "Heat alert — %.1f°C", temp),
                    body: "\(snapshot.heat.heatSource) \(advice)"
                ))
                state.lastTempAlertAt = now
                state.lastTempAlertValueC = temp
            }
        }

        // 4. Heavy draw: only from a measured current.
        if !charging,
           snapshot.current.source == .measured,
           snapshot.current.milliAmps < -settings.currentAlertMilliAmps {
            let cooled: Bool
            if let last = state.lastCurrentAlertAt {
                cooled = now.timeIntervalSince(last) >= currentCooldown
            } else {
                cooled = true
            }
            if cooled {
                alerts.append(BatteryAlert(
                    kind: .heavyDraw,
                    title: "Heavy battery draw — \(abs(snapshot.current.milliAmps)) mA",
                    body: "A background app may be working hard."
                ))
                state.lastCurrentAlertAt = now
            }
        }

        return (alerts, state)
    }

    /// Explains what cannot fire on this device, for the settings screen.
    public static func unavailableReasons(for snapshot: BatterySnapshot) -> [String] {
        var reasons: [String] = []
        if snapshot.current.source != .measured {
            reasons.append("Heavy-draw alerts need a measured current; this platform does not expose one.")
        }
        if snapshot.heat.effectiveCelsius == nil {
            reasons.append("Heat alerts need a readable temperature sensor; none was found.")
        }
        return reasons
    }
}
