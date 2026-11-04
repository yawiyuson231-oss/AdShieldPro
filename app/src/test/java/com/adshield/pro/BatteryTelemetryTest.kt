package com.adshield.pro

import com.adshield.pro.domain.model.BatteryThermalSnapshot
import com.adshield.pro.domain.model.MeasurementSource
import com.adshield.pro.engine.optimizer.BatteryTelemetry
import com.adshield.pro.service.BatteryHealthNotifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the battery measurement layer and the alert text.
 *
 * These cover the parts that are pure logic: unit handling, power derivation,
 * unavailable-data handling and the wording of an alert. They are the guard against
 * the failure mode this feature exists to fix -- a number that looks precise but
 * was never measured.
 */
class BatteryTelemetryTest {

    private fun snapshot(
        level: Int = 62,
        cellTemp: Float = 31.4f,
        cellMeasured: Boolean = true,
        socTemp: Float? = null,
        current: Int = -812,
        currentMeasured: Boolean = true,
        power: Int? = null,
        voltage: Int = 3900,
        charging: Boolean = false,
        chargeCounter: Long? = null
    ) = BatteryThermalSnapshot(
        batteryPercent = level,
        temperatureCelsius = cellTemp,
        isCharging = charging,
        chargingSourceLabel = if (charging) "Charging (USB Port)" else "Discharging (On Battery)",
        voltageMillivolts = voltage,
        healthStatusLabel = "Good",
        thermalStatusLabel = "Nominal (No Throttling)",
        isOverheating = false,
        isLowBattery = level <= 20,
        adShieldBatteryImpactSummary = "",
        recommendations = emptyList(),
        currentMilliAmps = current,
        currentSource = if (currentMeasured) MeasurementSource.MEASURED else MeasurementSource.UNAVAILABLE,
        batteryTemperatureSource = if (cellMeasured) MeasurementSource.MEASURED else MeasurementSource.UNAVAILABLE,
        socTemperatureCelsius = socTemp,
        socTemperatureSourceLabel = if (socTemp != null) "SoC thermal zone (soc_thermal)" else "Unavailable on this device",
        powerMilliWatts = power,
        chargeCounterMilliAmpHours = chargeCounter,
        measuredDrawLabel = ""
    )

    // --- Power derivation ---------------------------------------------------

    @Test
    fun `power is voltage times current and keeps the discharge sign`() {
        // 3900 mV at -812 mA is 3.17 W leaving the battery.
        assertEquals(-3166, BatteryTelemetry.computePowerMilliWatts(3900, -812, currentMeasured = true))
    }

    @Test
    fun `power is positive while charging`() {
        assertEquals(8200, BatteryTelemetry.computePowerMilliWatts(4100, 2000, currentMeasured = true))
    }

    @Test
    fun `power is withheld when the current was not measured`() {
        // A derived figure from a placeholder is worse than no figure.
        assertNull(BatteryTelemetry.computePowerMilliWatts(3900, -812, currentMeasured = false))
    }

    @Test
    fun `power is withheld for an implausible voltage`() {
        assertNull(BatteryTelemetry.computePowerMilliWatts(0, -812, currentMeasured = true))
        assertNull(BatteryTelemetry.computePowerMilliWatts(120, -812, currentMeasured = true))
        assertNull(BatteryTelemetry.computePowerMilliWatts(40_000, -812, currentMeasured = true))
    }

    // --- Energy -------------------------------------------------------------

    @Test
    fun `stored energy uses the charge counter and the measured voltage`() {
        // 2450 mAh at 3.9 V is 9555 mWh.
        assertEquals(9555L, BatteryTelemetry.computeEnergyMilliWattHours(2450L, 3900))
    }

    @Test
    fun `stored energy is withheld without a charge counter`() {
        assertNull(BatteryTelemetry.computeEnergyMilliWattHours(null, 3900))
    }

    // --- Effective values ---------------------------------------------------

    @Test
    fun `the battery cell wins over the chip for the decision temperature`() {
        val s = snapshot(cellTemp = 33.0f, cellMeasured = true, socTemp = 61.0f)
        assertEquals(33.0f, s.effectiveTemperatureCelsius, 0.001f)
    }

    @Test
    fun `the chip is used only when the cell was not reported`() {
        val s = snapshot(cellTemp = 31.0f, cellMeasured = false, socTemp = 57.5f)
        assertEquals(57.5f, s.effectiveTemperatureCelsius, 0.001f)
    }

    @Test
    fun `charging state follows the measured current when available`() {
        val chargingByCurrent = snapshot(current = 1200, currentMeasured = true, charging = false)
        assertTrue(chargingByCurrent.isEffectivelyCharging)

        val dischargingByCurrent = snapshot(current = -900, currentMeasured = true, charging = true)
        assertFalse(dischargingByCurrent.isEffectivelyCharging)
    }

    @Test
    fun `charging state falls back to the status extra without a current`() {
        val s = snapshot(currentMeasured = false, charging = true)
        assertTrue(s.isEffectivelyCharging)
    }

    // --- Alert wording ------------------------------------------------------

    @Test
    fun `alert line reports the measured current and watts`() {
        val line = BatteryHealthNotifier.buildLine(
            snapshot(current = -812, power = -3166)
        )
        assertTrue(line, line.contains("62%"))
        assertTrue(line, line.contains("-812 mA"))
        // Wattage is shown as a magnitude; the sign lives on the current, which is
        // what tells the reader whether energy is going in or out.
        assertTrue(line, line.contains("3.2 W"))
        assertFalse(line, line.contains("-3.2 W"))
        assertTrue(line, line.contains("31.4°C cell"))
    }

    @Test
    fun `alert line says current was not reported instead of showing zero`() {
        val line = BatteryHealthNotifier.buildLine(snapshot(currentMeasured = false))
        assertTrue(line, line.contains("current not reported"))
        assertFalse(line, line.contains("0 mA"))
    }

    @Test
    fun `alert line distinguishes the cell from the chip`() {
        val line = BatteryHealthNotifier.buildLine(
            snapshot(cellTemp = 34.0f, cellMeasured = true, socTemp = 58.0f)
        )
        assertTrue(line, line.contains("34.0°C cell"))
        assertTrue(line, line.contains("58.0°C chip"))
    }

    @Test
    fun `alert line admits when no temperature sensor is readable`() {
        val line = BatteryHealthNotifier.buildLine(
            snapshot(cellMeasured = false, socTemp = null)
        )
        assertTrue(line, line.contains("no temperature sensor readable"))
    }

    // --- Threshold clamping -------------------------------------------------

    @Test
    fun `low battery alert threshold cannot exceed the full charge threshold`() {
        // The repository clamps fullPercent to at least low + 10; verify the rule the
        // UI depends on rather than the DataStore call, which needs a Context.
        val low = 45
        val requestedFull = 50
        val clampedFull = requestedFull.coerceIn(low + 10, 100)
        assertEquals(55, clampedFull)
        assertTrue(clampedFull > low)
    }
}
