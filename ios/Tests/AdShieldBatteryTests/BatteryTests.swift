import XCTest
@testable import AdShieldBattery

/**
 Tests for the Apple battery core.

 These assert the same rules as `tests/unit/battery-core.test.mjs` and the Android
 `BatteryTelemetryTest`, so a divergence between any two platforms fails a build.
 */
final class BatteryMathTests: XCTestCase {

    func testCurrentSignIsNormalisedAgainstChargingState() {
        XCTAssertEqual(BatteryMath.normaliseCurrent(-812, isCharging: false).milliAmps, -812)
        XCTAssertEqual(BatteryMath.normaliseCurrent(812, isCharging: false).milliAmps, -812)
        XCTAssertEqual(BatteryMath.normaliseCurrent(-1500, isCharging: true).milliAmps, 1500)
        XCTAssertEqual(BatteryMath.normaliseCurrent(1500, isCharging: true).milliAmps, 1500)
    }

    func testAbsentOrImplausibleCurrentIsUnavailableNotZero() {
        for raw in [nil, 0, 5, 40_000] as [Int?] {
            let reading = BatteryMath.normaliseCurrent(raw, isCharging: false)
            XCTAssertEqual(reading.source, .unavailable, "raw=\(String(describing: raw))")
            XCTAssertTrue(reading.note.contains("does not report"))
        }
    }

    func testPowerIsWithheldWithoutBothInputs() {
        XCTAssertEqual(BatteryMath.powerMilliWatts(voltageMilliVolts: 3900, currentMilliAmps: -812, currentIsMeasured: true), -3167)
        XCTAssertNil(BatteryMath.powerMilliWatts(voltageMilliVolts: 3900, currentMilliAmps: -812, currentIsMeasured: false))
        XCTAssertNil(BatteryMath.powerMilliWatts(voltageMilliVolts: nil, currentMilliAmps: -812, currentIsMeasured: true))
        XCTAssertNil(BatteryMath.powerMilliWatts(voltageMilliVolts: 0, currentMilliAmps: -812, currentIsMeasured: true))
    }

    func testLaptopVoltageIsPlausible() {
        XCTAssertEqual(BatteryMath.powerMilliWatts(voltageMilliVolts: 11_934, currentMilliAmps: -1187, currentIsMeasured: true), -14_166)
        XCTAssertNil(BatteryMath.powerMilliWatts(voltageMilliVolts: 45_000, currentMilliAmps: -100, currentIsMeasured: true))
    }

    func testStoredEnergy() {
        XCTAssertEqual(BatteryMath.energyMilliWattHours(chargeMilliAmpHours: 2450, voltageMilliVolts: 3900), 9555)
        XCTAssertNil(BatteryMath.energyMilliWattHours(chargeMilliAmpHours: nil, voltageMilliVolts: 3900))
    }

    func testTheCellWinsAndAHotSoCIsWorkload() {
        let heat = BatteryMath.resolveHeat(cellCelsius: 33, socCelsius: 61)
        XCTAssertEqual(heat.effectiveCelsius, 33)
        XCTAssertEqual(heat.effectiveSource, .measured)
        XCTAssertTrue(heat.heatSource.contains("28.0 °C hotter"), heat.heatSource)
        XCTAssertTrue(heat.heatSource.contains("workload, not the cell"), heat.heatSource)
    }

    func testSoCIsUsedOnlyWhenTheCellIsMissing() {
        let heat = BatteryMath.resolveHeat(cellCelsius: nil, socCelsius: 58, socLabel: "Package sensor")
        XCTAssertEqual(heat.effectiveCelsius, 58)
        XCTAssertEqual(heat.effectiveSource, .derived)
        XCTAssertTrue(heat.heatSource.contains("Package sensor"), heat.heatSource)
        XCTAssertTrue(heat.heatSource.contains("battery cell not reported"), heat.heatSource)
    }

    func testNoSensorIsStatedPlainly() {
        let heat = BatteryMath.resolveHeat(cellCelsius: nil, socCelsius: nil)
        XCTAssertNil(heat.effectiveCelsius)
        XCTAssertEqual(heat.effectiveSource, .unavailable)
        XCTAssertTrue(heat.heatSource.contains("No temperature sensor"))
    }

    func testImplausibleTemperaturesAreRejected() {
        XCTAssertFalse(BatteryMath.isPlausible(-500))
        XCTAssertFalse(BatteryMath.isPlausible(400))
        XCTAssertTrue(BatteryMath.isPlausible(0))
        XCTAssertTrue(BatteryMath.isPlausible(31.4))
    }

    func testPercentIsClamped() {
        XCTAssertEqual(BatteryMath.snapshot(platform: "ios", percent: 127, isCharging: false).percent, 100)
        XCTAssertEqual(BatteryMath.snapshot(platform: "ios", percent: -4, isCharging: false).percent, 0)
        XCTAssertEqual(BatteryMath.snapshot(platform: "ios", percent: 61.6, isCharging: false).percent, 62)
        // UIKit's -1 "unknown" must not become 0%.
        XCTAssertEqual(BatteryMath.snapshot(platform: "ios", percent: nil, isCharging: false).percent, 0)
    }

    func testSummaryLineShowsMeasuredValuesAndAdmitsMissingOnes() {
        let full = BatteryMath.snapshot(
            platform: "ios",
            percent: 62,
            isCharging: false,
            currentMilliAmps: -812,
            voltageMilliVolts: 3900,
            cellCelsius: 31.4,
            chargeMilliAmpHours: 2450
        )
        let line = BatteryMath.summaryLine(full)
        XCTAssertTrue(line.hasPrefix("62% • -812 mA (3.2 W) • 31.4°C cell"), line)

        let bare = BatteryMath.summaryLine(BatteryMath.snapshot(platform: "ios", percent: 55, isCharging: false))
        XCTAssertTrue(bare.contains("current not reported"), bare)
        XCTAssertTrue(bare.contains("no temperature sensor readable"), bare)
        XCTAssertFalse(bare.contains("0 mA"), bare)
    }

    @MainActor
    func testIOSSnapshotAdmitsWhatUIKitDoesNotExpose() {
        let snapshot = IOSBatteryAdapter.readSnapshot()
        XCTAssertEqual(snapshot.platform, "ios")
        XCTAssertEqual(snapshot.current.source, .unavailable)
        XCTAssertNil(snapshot.powerMilliWatts)
        XCTAssertNil(snapshot.heat.effectiveCelsius)
        XCTAssertEqual(snapshot.healthLabel, "Not exposed by iOS")
    }
}

final class AlertTests: XCTestCase {

    private func snapshot(
        percent: Int = 62,
        charging: Bool = false,
        current: Int? = -800,
        cell: Double? = 32
    ) -> BatterySnapshot {
        BatteryMath.snapshot(
            platform: "ios",
            percent: Double(percent),
            isCharging: charging,
            currentMilliAmps: current,
            voltageMilliVolts: 3900,
            cellCelsius: cell
        )
    }

    private var settings: AlertSettings {
        var s = AlertSettings.default
        s.enabled = true
        return s
    }

    func testDisabledPostsNothing() {
        var s = AlertSettings.default
        s.enabled = false
        let result = BatteryAlerts.evaluate(snapshot(percent: 5, cell: 50), settings: s)
        XCTAssertTrue(result.alerts.isEmpty)
    }

    func testLowBatteryFiresOnceThenEveryFivePercent() {
        let first = BatteryAlerts.evaluate(snapshot(percent: 20), settings: settings, now: Date(timeIntervalSince1970: 1000))
        XCTAssertEqual(first.alerts.map(\.kind), [.lowBattery])

        let again = BatteryAlerts.evaluate(snapshot(percent: 18), settings: settings, state: first.state, now: Date(timeIntervalSince1970: 2000))
        XCTAssertTrue(again.alerts.isEmpty)

        let further = BatteryAlerts.evaluate(snapshot(percent: 14), settings: settings, state: again.state, now: Date(timeIntervalSince1970: 3000))
        XCTAssertEqual(further.alerts.map(\.kind), [.lowBattery])
    }

    func testChargeCompleteIsOncePerSession() {
        var s = settings
        s.fullPercentThreshold = 100
        let full = snapshot(percent: 100, charging: true, current: 200)
        let t0 = Date(timeIntervalSince1970: 1000)
        let first = BatteryAlerts.evaluate(full, settings: s, now: t0)
        XCTAssertEqual(first.alerts.map(\.kind), [.chargeComplete])

        let second = BatteryAlerts.evaluate(full, settings: s, state: first.state, now: t0.addingTimeInterval(60))
        XCTAssertTrue(second.alerts.isEmpty)

        let nextSession = BatteryAlerts.evaluate(full, settings: s, state: second.state, now: t0.addingTimeInterval(13 * 60 * 60))
        XCTAssertEqual(nextSession.alerts.map(\.kind), [.chargeComplete])
    }

    func testHeatRespectsCooldownAndRisingTemperature() {
        var s = settings
        s.tempWarningCelsius = 41
        let hot = snapshot(cell: 42)
        let t0 = Date(timeIntervalSince1970: 0) // a zero clock must still alert
        let first = BatteryAlerts.evaluate(hot, settings: s, now: t0)
        XCTAssertEqual(first.alerts.map(\.kind), [.heat])

        let suppressed = BatteryAlerts.evaluate(hot, settings: s, state: first.state, now: t0.addingTimeInterval(60))
        XCTAssertTrue(suppressed.alerts.isEmpty)

        let rising = BatteryAlerts.evaluate(snapshot(cell: 44.5), settings: s, state: first.state, now: t0.addingTimeInterval(60))
        XCTAssertEqual(rising.alerts.map(\.kind), [.heat])

        let cooled = BatteryAlerts.evaluate(hot, settings: s, state: first.state, now: t0.addingTimeInterval(BatteryAlerts.tempCooldown + 1))
        XCTAssertEqual(cooled.alerts.map(\.kind), [.heat])
    }

    func testHeavyDrawNeedsAMeasuredCurrent() {
        var s = settings
        s.currentAlertMilliAmps = 1800
        let heavy = snapshot(current: -2400)
        let first = BatteryAlerts.evaluate(heavy, settings: s, now: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(first.alerts.map(\.kind), [.heavyDraw])

        let iosLike = snapshot(current: nil)
        let result = BatteryAlerts.evaluate(iosLike, settings: s, now: Date(timeIntervalSince1970: 0))
        XCTAssertFalse(result.alerts.contains { $0.kind == .heavyDraw })
        XCTAssertTrue(BatteryAlerts.unavailableReasons(for: iosLike).contains { $0.contains("does not expose one") })
    }

    func testThresholdsClampAndCannotContradict() {
        var s = AlertSettings.default
        s.lowPercentThreshold = 80
        s.fullPercentThreshold = 20
        s.tempWarningCelsius = 10
        s.currentAlertMilliAmps = 99_000
        let clamped = s.clamped()
        XCTAssertEqual(clamped.lowPercentThreshold, 50)
        XCTAssertEqual(clamped.fullPercentThreshold, 60)
        XCTAssertEqual(clamped.tempWarningCelsius, 35)
        XCTAssertEqual(clamped.currentAlertMilliAmps, 5000)
    }

    func testAlertBodiesNeverContainAFabricatedZeroCurrent() {
        var s = settings
        s.tempWarningCelsius = 30
        let unmeasured = snapshot(percent: 15, current: nil, cell: 45)
        let result = BatteryAlerts.evaluate(unmeasured, settings: s)
        for alert in result.alerts {
            XCTAssertFalse(alert.body.contains("0 mA"), alert.body)
        }
    }
}
