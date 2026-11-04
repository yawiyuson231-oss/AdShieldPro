import Foundation
#if canImport(UIKit)
import UIKit
#endif

/**
 Reads what iOS actually exposes, and states plainly what it does not.

 This is the file that keeps the iOS build honest. `UIDevice` gives battery level and
 charging state and **nothing else**: no current, no voltage, no temperature. There is
 no public API for any of them, and the private `IOKit` route used by jailbreak tools is
 both App Store-rejected and unavailable to sandboxed apps.

 So on iOS:
  - level and charging state are measured
  - current, power, cell temperature and stored energy are reported as unavailable
  - the heavy-draw and heat alerts therefore cannot fire, and the UI says why

 The upper limit on iOS battery alerts is low-level and charge-complete warnings, which
 are exactly the two that iOS itself does not let a third-party app schedule reliably.
 */
public enum IOSBatteryAdapter {

    /// A snapshot from `UIDevice`. Call on the main actor: `UIDevice` is main-actor
    /// isolated on recent SDKs.
    @MainActor
    public static func readSnapshot(now: Date = Date()) -> BatterySnapshot {
        #if canImport(UIKit)
        let device = UIDevice.current
        let wasEnabled = device.isBatteryMonitoringEnabled
        if !wasEnabled { device.isBatteryMonitoringEnabled = true }
        let level = device.batteryLevel
        let state = device.batteryState
        if !wasEnabled { device.isBatteryMonitoringEnabled = false }

        let charging: Bool
        let label: String
        switch state {
        case .charging:
            charging = true
            label = "Charging"
        case .full:
            charging = true
            label = "Fully charged"
        case .unplugged:
            charging = false
            label = "Discharging"
        default:
            charging = false
            label = "Unknown"
        }

        return BatteryMath.snapshot(
            platform: "ios",
            // -1 means "unknown" in UIKit, which must not become a 0% reading.
            percent: level < 0 ? nil : Double(level) * 100,
            isCharging: charging,
            chargingLabel: label,
            currentMilliAmps: nil,
            voltageMilliVolts: nil,
            cellCelsius: nil,
            socCelsius: nil,
            chargeMilliAmpHours: nil,
            healthLabel: "Not exposed by iOS",
            readingAt: now
        )
        #else
        // Built for a platform without UIKit (CI compiles this package on macOS so the
        // rules can be tested without a device). Same claims as the iOS branch: level
        // unknown, nothing measured.
        return BatteryMath.snapshot(
            platform: "ios",
            percent: nil,
            isCharging: false,
            chargingLabel: "UIKit unavailable",
            healthLabel: "Not exposed by iOS",
            readingAt: now
        )
        #endif
    }

    /// What this platform can and cannot alert on, for the settings screen.
    public static let capabilities = [
        "Low battery and charge-complete alerts work on iOS.",
        "Current (mA), power and battery temperature are not available to third-party iOS apps.",
        "Heat and heavy-draw alerts therefore stay disabled on this platform."
    ]
}
