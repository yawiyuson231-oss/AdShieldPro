package com.adshield.pro

import com.adshield.pro.engine.battery.BatteryCondition
import com.adshield.pro.engine.battery.BatteryConditionTone
import com.adshield.pro.engine.battery.BatteryDiagnostics
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryMonitor
import com.adshield.pro.engine.battery.BatteryReading
import com.adshield.pro.engine.battery.BatteryReadingSource
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.battery.ChargingSource
import com.adshield.pro.engine.battery.DataFreshness
import com.adshield.pro.engine.battery.DisplayStateDrain
import com.adshield.pro.engine.battery.EngineState
import com.adshield.pro.engine.battery.FastChargeSignal
import com.adshield.pro.engine.battery.MeasurementReliability
import com.adshield.pro.engine.battery.MonitoringState
import com.adshield.pro.engine.battery.PowerTrend
import com.adshield.pro.engine.battery.SensorState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Battery Command Center — monitoring-engine contracts.
 *
 * These tests exist to make the honesty promises executable:
 *
 *  - power is only ever V x I from two real readings, and is null otherwise;
 *  - instantaneous and average current are separate values that are never substituted for each
 *    other;
 *  - a sensor the device does not expose is reported as UNSUPPORTED, never as zero;
 *  - "fast charging" needs a platform signal *and* a measured rate;
 *  - every projection (time to full, %/h, efficiency) needs enough measured evidence first;
 *  - freshness is bucketed from a monotonic clock, so it cannot be faked by a wall-clock jump.
 */
class BatteryCommandCenterTestSuite {

    // --- Fixtures -----------------------------------------------------------------------------

    private fun reading(value: Int?) = value?.let { BatteryReading.measured(it, "mA") }
        ?: BatteryReading.unsupported("mA")

    /**
     * Builds a telemetry snapshot. Defaults describe a realistic mid-range phone: discharging at
     * 4.15 V / -480 mA, 31.4 °C, healthy.
     */
    private fun telemetry(
        level: Int? = 67,
        charging: Boolean = false,
        full: Boolean = false,
        source: ChargingSource = ChargingSource.NOT_PLUGGED,
        voltageVolts: Float? = 4.15f,
        currentMilliAmps: Int? = -480,
        averageMilliAmps: Int? = -455,
        temperatureCelsius: Float? = 31.4f,
        health: BatteryHealthStatus = BatteryHealthStatus.GOOD,
        healthLabel: String = "Good",
        signKnown: Boolean = true,
        chargeFullUah: Long? = null,
        designUah: Long? = null,
        elapsedRealtimeMs: Long = 1_000L,
        chargeTimeMinutes: Int? = null
    ): BatteryTelemetry {
        val voltage = voltageVolts?.let { BatteryReading.measured(it, "V") }
            ?: BatteryReading.unsupported("V")
        val currentText = when (currentMilliAmps) {
            null -> "BATTERY_PROPERTY_CURRENT_NOW is not exposed on this device"
            else -> "BATTERY_PROPERTY_CURRENT_NOW"
        }
        val current = currentMilliAmps?.let { BatteryReading.measured(it, "mA", currentText) }
            ?: BatteryReading.unsupported("mA", currentText)
        val power = BatteryMonitor.powerWatts(voltageVolts, currentMilliAmps)
            ?.let { BatteryReading.computed(it, "W") }
            ?: BatteryReading.unavailable("W")
        return BatteryTelemetry(
            timestampEpochMs = 1_700_000_000_000L,
            levelPercent = level?.let { BatteryReading.measured(it, "%") }
                ?: BatteryReading.unavailable("%"),
            statusLabel = when {
                full -> "Full"
                charging -> "Charging"
                else -> "Discharging"
            },
            isCharging = charging,
            isFull = full,
            pluggedLabel = source.label,
            pluggedRaw = 0,
            temperatureCelsius = temperatureCelsius?.let { BatteryReading.measured(it, "°C") }
                ?: BatteryReading.unsupported("°C"),
            voltageVolts = voltage,
            currentMilliAmps = current,
            currentAverageMilliAmps = averageMilliAmps?.let { BatteryReading.measured(it, "mA") }
                ?: BatteryReading.unsupported("mA"),
            chargeCounterMicroAmpHours = BatteryReading.unsupported("µAh"),
            powerWatts = power,
            healthLabel = healthLabel,
            health = health,
            technology = "Li-ion",
            chargeTimeRemainingMinutes = chargeTimeMinutes?.let { BatteryReading.estimated(it, "min") }
                ?: BatteryReading.unavailable("min"),
            runtimeRemainingMinutes = BatteryReading.unsupported("min"),
            manufacturer = "Test",
            model = "Device",
            cycleCount = BatteryReading.unsupported("cycles"),
            chargeFullDesignMicroAmpHours = designUah?.let { BatteryReading.measured(it, "µAh") }
                ?: BatteryReading.unsupported("µAh"),
            chargeFullMicroAmpHours = chargeFullUah?.let { BatteryReading.measured(it, "µAh") }
                ?: BatteryReading.unsupported("µAh"),
            currentSignKnown = signKnown,
            elapsedRealtimeMs = elapsedRealtimeMs,
            chargingSource = source
        )
    }

    private fun sample(
        timestampMs: Long,
        level: Int? = 50,
        charging: Boolean = false,
        current: Int? = -500,
        voltage: Float? = 4.0f,
        temperature: Float? = 31f,
        power: Float? = null,
        screenOn: Boolean? = null
    ) = BatteryDiagnostics.Sample(
        timestampEpochMs = timestampMs,
        levelPercent = level,
        isCharging = charging,
        temperatureCelsius = temperature,
        voltageVolts = voltage,
        currentMilliAmps = current,
        powerWatts = power ?: BatteryMonitor.powerWatts(voltage, current),
        screenOn = screenOn,
        elapsedRealtimeMs = timestampMs
    )

    // --- 1. Power maths -----------------------------------------------------------------------

    @Test
    fun testPower_isExactlyVoltageTimesCurrent() {
        // 4.15 V x 0.480 A = 1.992 W
        assertEquals(1.992f, BatteryMonitor.powerWatts(4.15f, -480)!!, 0.0005f)
        assertEquals(5.0f, BatteryMonitor.powerWatts(4.0f, 1250)!!, 0.0005f)
        // 3000 mV / 271 mA -> 0.813 W (the reference measurement from the device screenshots)
        assertEquals(0.813f, BatteryMonitor.powerWatts(3.0f, 271)!!, 0.0005f)
    }

    @Test
    fun testPower_isNullRatherThanGuessed() {
        assertNull("no current -> no power", BatteryMonitor.powerWatts(4.2f, null))
        assertNull("no voltage -> no power", BatteryMonitor.powerWatts(null, 900))
        assertNull("0 mA is a driver stub, not a measurement", BatteryMonitor.powerWatts(4.2f, 0))
        assertNull("a phone battery never sits at 0.004 V", BatteryMonitor.powerWatts(0.004f, 900))
        assertNull("nor at 12 V", BatteryMonitor.powerWatts(12f, 900))
    }

    @Test
    fun testChargingAndDischargePowerAreMutuallyExclusive() {
        assertEquals(6.3f, BatteryMonitor.chargingPowerWatts(4.2f, 1500, isCharging = true)!!, 0.001f)
        assertNull(BatteryMonitor.chargingPowerWatts(4.2f, -900, isCharging = false))
        assertEquals(3.74f, BatteryMonitor.dischargePowerWatts(4.4f, -850, isCharging = false)!!, 0.001f)
        assertNull(BatteryMonitor.dischargePowerWatts(4.4f, 2100, isCharging = true))
    }

    @Test
    fun testCurrentDirection_prefersTheSystemStatusOverTheSign() {
        // Normal vendor: negative while discharging.
        assertEquals("out of battery", BatteryMonitor.currentDirectionLabel(-480, false, true))
        // Inverted vendor: the sign disagrees, so direction comes from the charging state.
        assertEquals("into battery", BatteryMonitor.currentDirectionLabel(-1500, true, false))
        assertEquals("out of battery", BatteryMonitor.currentDirectionLabel(900, false, false))
        assertNull("no reading means no claim about direction", BatteryMonitor.currentDirectionLabel(null, true, true))
    }

    // --- 2. Freshness -------------------------------------------------------------------------

    @Test
    fun testFreshness_isBucketedFromMonotonicAge() {
        assertEquals(DataFreshness.LIVE, DataFreshness.of(0))
        assertEquals(DataFreshness.LIVE, DataFreshness.of(DataFreshness.LIVE_WINDOW_MS))
        assertEquals(DataFreshness.DELAYED, DataFreshness.of(DataFreshness.LIVE_WINDOW_MS + 1))
        assertEquals(DataFreshness.DELAYED, DataFreshness.of(DataFreshness.STALE_WINDOW_MS))
        assertEquals(DataFreshness.STALE, DataFreshness.of(DataFreshness.STALE_WINDOW_MS + 1))
        assertEquals("never a reading at all", DataFreshness.NO_DATA, DataFreshness.of(null))
        // A backwards clock jump must not turn a live reading into "no data".
        assertEquals(DataFreshness.LIVE, DataFreshness.of(-5_000L))
    }

    @Test
    fun testTelemetryAge_neverGoesNegative() {
        val snapshot = telemetry(elapsedRealtimeMs = 10_000L)
        assertEquals(1_500L, snapshot.ageMs(11_500L))
        assertEquals(0L, snapshot.ageMs(9_000L))
        assertTrue(snapshot.hasPowerInputs)
        assertFalse(telemetry(currentMilliAmps = null).hasPowerInputs)
    }

    // --- 3. Sensor diagnostics ---------------------------------------------------------------

    @Test
    fun testSensorStatus_mapsEveryReadingSourceHonestly() {
        val live = BatteryMonitor.sensorStatus(
            "Current", BatteryReading.measured(480, "mA", "CURRENT_NOW"), "CURRENT_NOW", "mA", DataFreshness.LIVE
        )
        assertEquals(SensorState.OPERATIONAL, live.state)
        assertEquals("480 mA", live.statusValue)
        assertTrue("measured values are labelled as measurements", live.measured)

        val unsupported = BatteryMonitor.sensorStatus(
            "Current", BatteryReading.unsupported<Int>("mA", "not exposed"), "CURRENT_NOW", "mA", DataFreshness.LIVE
        )
        assertEquals(SensorState.UNSUPPORTED, unsupported.state)
        assertEquals("—", unsupported.statusValue)

        val unavailable = BatteryMonitor.sensorStatus(
            "Current", BatteryReading.unavailable<Int>("mA", "0 mA reported"), "CURRENT_NOW", "mA", DataFreshness.LIVE
        )
        assertEquals(SensorState.UNAVAILABLE, unavailable.state)

        val invalid = BatteryMonitor.sensorStatus(
            "Voltage",
            BatteryReading.measured(0.004f, "V", "Driver reported an implausible voltage (0.004)"),
            "EXTRA_VOLTAGE", "V", DataFreshness.LIVE
        )
        assertEquals("a rejected driver value is INVALID, not operational", SensorState.INVALID, invalid.state)
        assertTrue(invalid.detail.contains("implausible"))
    }

    @Test
    fun testSensorStatuses_onAWellEquippedDevice_areAllUsable() {
        val sensors = BatteryMonitor.sensorStatuses(
            telemetry(charging = true, source = ChargingSource.AC, currentMilliAmps = 1500),
            DataFreshness.LIVE
        )
        val current = sensors.first { it.name == "Current" }
        val voltage = sensors.first { it.name == "Voltage" }
        val temperature = sensors.first { it.name == "Temperature" }
        val power = sensors.first { it.name == "Power (V × I)" }
        listOf(current, voltage, temperature, power).forEach {
            assertEquals("${it.name} should be operational", SensorState.OPERATIONAL, it.state)
        }
        assertTrue("power is computed, not measured", !power.measured)
        assertEquals("6.23 W", power.statusValue)
    }

    @Test
    fun testSensorStatuses_onADeviceWithoutCurrent_reportsUnsupportedAndWaitingPower() {
        val bare = telemetry(currentMilliAmps = null, averageMilliAmps = null, voltageVolts = 4.1f)
        val sensors = BatteryMonitor.sensorStatuses(bare, DataFreshness.LIVE)
        assertEquals(SensorState.UNSUPPORTED, sensors.first { it.name == "Current" }.state)
        val power = sensors.first { it.name == "Power (V × I)" }
        assertEquals("power cannot be computed without current", SensorState.WAITING, power.state)
        assertEquals("—", power.statusValue)
        // Level and temperature still come from the broadcast, so they stay usable.
        assertEquals(SensorState.OPERATIONAL, sensors.first { it.name == "Battery level" }.state)
    }

    // --- 4. Monitoring status -----------------------------------------------------------------

    @Test
    fun testMonitoringStatus_isOperationalWhenEveryComponentWorks() {
        val snapshot = telemetry(charging = true, source = ChargingSource.AC, currentMilliAmps = 1400)
        val sensors = BatteryMonitor.sensorStatuses(snapshot, DataFreshness.LIVE)
        val status = BatteryMonitor.monitoringStatus(
            telemetry = snapshot,
            sensors = sensors,
            freshness = DataFreshness.LIVE,
            engineState = EngineState.ACTIVE,
            nowElapsedRealtimeMs = 1_500L
        )
        assertEquals(MonitoringState.OPERATIONAL, status.batteryApi.state)
        assertEquals(MonitoringState.OPERATIONAL, status.currentSensor.state)
        assertEquals(MonitoringState.OPERATIONAL, status.voltageSensor.state)
        assertEquals(MonitoringState.OPERATIONAL, status.temperatureSensor.state)
        assertEquals(MonitoringState.OPERATIONAL, status.powerCalculation.state)
        assertEquals(MonitoringState.ACTIVE, status.engine.state)
        assertEquals(DataFreshness.LIVE, status.freshness)
        assertEquals(MonitoringState.OPERATIONAL, status.overall)
        assertEquals(100, status.scorePercent)
        assertEquals(7, status.components.size)
    }

    @Test
    fun testMonitoringStatus_isPartialWhenASensorIsMissing() {
        val snapshot = telemetry(currentMilliAmps = null, averageMilliAmps = null)
        val sensors = BatteryMonitor.sensorStatuses(snapshot, DataFreshness.LIVE)
        val status = BatteryMonitor.monitoringStatus(
            snapshot, sensors, DataFreshness.LIVE, EngineState.ACTIVE, 1_500L
        )
        assertEquals(MonitoringState.UNSUPPORTED, status.currentSensor.state)
        assertEquals(MonitoringState.WAITING, status.powerCalculation.state)
        assertEquals(MonitoringState.PARTIAL, status.overall)
        assertTrue("score must drop below 100", status.scorePercent < 100)
        assertTrue(status.scorePercent > 50)
    }

    @Test
    fun testMonitoringStatus_pausesAndErrorsAreDistinguishable() {
        val snapshot = telemetry()
        val sensors = BatteryMonitor.sensorStatuses(snapshot, DataFreshness.LIVE)
        val paused = BatteryMonitor.monitoringStatus(
            snapshot, sensors, DataFreshness.LIVE, EngineState.PAUSED, 1_500L
        )
        assertEquals(MonitoringState.PAUSED, paused.engine.state)

        val failed = BatteryMonitor.monitoringStatus(
            snapshot, sensors, DataFreshness.NO_DATA, EngineState.ERROR, 1_500L
        )
        assertEquals(MonitoringState.ERROR, failed.engine.state)
        assertEquals(MonitoringState.ERROR, failed.overall)
    }

    @Test
    fun testMonitoringStatus_staleDataIsReportedAsStaleNotLive() {
        val snapshot = telemetry(elapsedRealtimeMs = 0L)
        val age = snapshot.ageMs(120_000L)
        val freshness = DataFreshness.of(age)
        val sensors = BatteryMonitor.sensorStatuses(snapshot, freshness)
        val status = BatteryMonitor.monitoringStatus(
            snapshot, sensors, freshness, EngineState.ACTIVE, 120_000L
        )
        assertEquals(DataFreshness.STALE, status.freshness)
        assertEquals(MonitoringState.PARTIAL, status.overall)
        assertTrue(status.components.any { it.component == "Data freshness" && it.value == "Stale" })
    }

    // --- 5. Battery condition -----------------------------------------------------------------

    private fun condition(
        snapshot: BatteryTelemetry,
        chargeRate: Float? = null,
        drainRate: Float? = null,
        averagePower: Float? = null,
        healthScore: Int = 100,
        hasFastSignal: Boolean = false,
        fastSource: String? = null
    ) = BatteryMonitor.condition(
        telemetry = snapshot,
        freshness = DataFreshness.LIVE,
        chargeRatePercentPerHour = chargeRate,
        drainRatePercentPerHour = drainRate,
        averagePowerWatts = averagePower,
        healthScore = healthScore,
        hasFastChargeSignal = hasFastSignal,
        fastChargeSource = fastSource
    )

    @Test
    fun testCondition_chargingAndDischarging() {
        val charging = condition(telemetry(charging = true, source = ChargingSource.AC, currentMilliAmps = 1500))
        assertEquals(BatteryCondition.CHARGING, charging.primary)
        assertEquals(BatteryConditionTone.POSITIVE, charging.tone)
        assertFalse(charging.fastChargeDetected)

        val discharging = condition(telemetry())
        assertEquals(BatteryCondition.DISCHARGING, discharging.primary)
        assertTrue(drainingIsNotClaimedAsNormalisation(discharging))
    }

    private fun drainingIsNotClaimedAsNormalisation(report: com.adshield.pro.engine.battery.BatteryStatusReport) =
        report.evidence.any { it.contains("Current") }

    @Test
    fun testCondition_fullAndConnectedNotChargingAreDistinct() {
        val full = condition(telemetry(full = true, level = 100, source = ChargingSource.AC))
        assertEquals(BatteryCondition.FULLY_CHARGED, full.primary)

        val idle = condition(telemetry(charging = false, source = ChargingSource.AC, currentMilliAmps = 40))
        assertEquals(BatteryCondition.CONNECTED_NOT_CHARGING, idle.primary)
        assertEquals(BatteryConditionTone.CAUTION, idle.tone)
    }

    @Test
    fun testCondition_fastChargingNeedsSignalAndRate() {
        // Signal only, rate still measuring: acceptable, the UI says the rate is being measured.
        assertTrue(BatteryMonitor.fastChargeSignalConfirmsRate(hasHardwareSignal = true, rate = null))
        // Signal plus a measured rate that is genuinely fast.
        assertTrue(BatteryMonitor.fastChargeSignalConfirmsRate(hasHardwareSignal = true, rate = 45f))
        // Signal plus a measured slow rate: the measurement wins, no fast-charge claim.
        assertFalse(BatteryMonitor.fastChargeSignalConfirmsRate(hasHardwareSignal = true, rate = 6f))
        // A fast-looking rate with no platform signal is never enough on its own.
        assertFalse(BatteryMonitor.fastChargeSignalConfirmsRate(hasHardwareSignal = false, rate = 80f))

        val reported = condition(
            telemetry(charging = true, source = ChargingSource.AC, currentMilliAmps = 3000),
            chargeRate = 62f,
            hasFastSignal = true,
            fastSource = "BATTERY_PROPERTY_STATUS = fast charging"
        )
        assertEquals(BatteryCondition.FAST_CHARGING, reported.primary)
        assertTrue(reported.fastChargeDetected)
        assertTrue(reported.detail.contains("BATTERY_PROPERTY_STATUS"))
    }

    @Test
    fun testCondition_slowChargingIsMeasuredNotAssumed() {
        val slow = condition(
            telemetry(charging = true, source = ChargingSource.USB, currentMilliAmps = 271, voltageVolts = 3.0f),
            chargeRate = 3.5f
        )
        assertEquals(BatteryCondition.SLOW_CHARGING, slow.primary)
        assertEquals(BatteryConditionTone.CAUTION, slow.tone)
        assertTrue(slow.detail.contains("3.5"))
    }

    @Test
    fun testCondition_highPowerDrainUsesMeasuredAveragePower() {
        val high = condition(telemetry(currentMilliAmps = -2100, voltageVolts = 4.3f), averagePower = 9.03f)
        assertEquals(BatteryCondition.HIGH_POWER_DRAIN, high.primary)
        assertEquals(BatteryConditionTone.CAUTION, high.tone)
        assertTrue(high.detail.contains("9"))

        // A modest draw must not be flagged.
        val normal = condition(telemetry(currentMilliAmps = -450, voltageVolts = 4.3f), averagePower = 1.9f)
        assertEquals(BatteryCondition.DISCHARGING, normal.primary)
    }

    @Test
    fun testCondition_temperatureIsSafetyFirst() {
        val hot = condition(telemetry(charging = true, temperatureCelsius = 46f, currentMilliAmps = 1200))
        assertEquals("heat outranks charging", BatteryCondition.TEMPERATURE_WARNING, hot.primary)
        assertEquals(BatteryConditionTone.CRITICAL, hot.tone)
        assertTrue(hot.headline.contains("critical"))

        val warm = condition(telemetry(temperatureCelsius = 41f))
        assertEquals(BatteryCondition.TEMPERATURE_WARNING, warm.primary)
        assertTrue(warm.secondary.contains(BatteryCondition.TEMPERATURE_WARNING).not())
    }

    @Test
    fun testCondition_healthWarningWhenAndroidReportsAFault() {
        val unhealthy = condition(
            telemetry(health = BatteryHealthStatus.OVERHEAT, healthLabel = "Overheating"),
            healthScore = 55
        )
        assertTrue(unhealthy.secondary.contains(BatteryCondition.HEALTH_WARNING) || unhealthy.primary == BatteryCondition.HEALTH_WARNING)
        assertEquals(BatteryConditionTone.CRITICAL, unhealthy.tone)
    }

    @Test
    fun testCondition_insufficientSensorsAreStatedNotGuessed() {
        val blind = telemetry(currentMilliAmps = null, averageMilliAmps = null, voltageVolts = null)
        val report = condition(blind)
        assertEquals(BatteryCondition.INSUFFICIENT_DATA, report.primary)
        assertTrue(report.detail.contains("does not expose"))
        assertEquals(BatteryConditionTone.NEUTRAL, report.tone)
        assertTrue("no invented measurement may appear in the evidence", report.evidence.none { it.contains("Power") })
    }

    @Test
    fun testCondition_evidenceAlwaysCitesTheRealSource() {
        val report = condition(telemetry(charging = true, currentMilliAmps = 1800))
        assertTrue(report.evidence.any { it.contains("EXTRA_LEVEL") })
        assertTrue(report.evidence.any { it.contains("CURRENT_NOW") })
        assertTrue(report.evidence.any { it.contains("V × I") })
        assertEquals(4, report.totalSensors)
        assertTrue(report.usableSensors in 1..4)
    }

    // --- 6. Fast-charge signal detection ------------------------------------------------------

    @Test
    fun testFastChargeSignal_requiresAnUnambiguousPlatformSignal() {
        val fastByProperty = FastChargeSignal.from(statusProperty = 6, chargeProtocol = null)
        assertTrue(fastByProperty.isPresent)
        assertEquals("BATTERY_PROPERTY_STATUS = fast charging", fastByProperty.source)
        assertTrue(FastChargeSignal.from(statusProperty = null, chargeProtocol = "USB_PD").isPresent)
        assertTrue(FastChargeSignal.from(statusProperty = null, chargeProtocol = "SuperVOOC 65W").isPresent)
        assertTrue(FastChargeSignal.from(statusProperty = null, chargeProtocol = "USB_PD_PPS").isPresent)
        // Ordinary chargers must never be promoted to fast charging.
        assertFalse(FastChargeSignal.from(statusProperty = null, chargeProtocol = "AC").isPresent)
        assertFalse(FastChargeSignal.from(statusProperty = null, chargeProtocol = "USB").isPresent)
        assertFalse(FastChargeSignal.from(statusProperty = 2, chargeProtocol = null).isPresent)
        assertFalse(FastChargeSignal.from(statusProperty = null, chargeProtocol = null).isPresent)
        assertNull(FastChargeSignal.NONE.source)
    }

    @Test
    fun testChargingSource_mapsEveryPluggedBitmask() {
        assertEquals(ChargingSource.AC, ChargingSource.fromRawPlugged(1))
        assertEquals(ChargingSource.USB, ChargingSource.fromRawPlugged(2))
        assertEquals(ChargingSource.WIRELESS, ChargingSource.fromRawPlugged(4))
        assertEquals(ChargingSource.DOCK, ChargingSource.fromRawPlugged(8))
        assertEquals(ChargingSource.NOT_PLUGGED, ChargingSource.fromRawPlugged(0))
        assertEquals("AC charger", ChargingSource.fromRawPlugged(1).label)
        assertEquals("Wireless charger", ChargingSource.WIRELESS.label)
        assertEquals("Not plugged in", ChargingSource.NOT_PLUGGED.label)
    }

    // --- 7. Trends and intelligence -----------------------------------------------------------

    @Test
    fun testPowerTrend_needsEnoughSamplesAndUsesBothHalves() {
        val rising = (0 until 10).map { sample(it * 1000L, current = -(300 + it * 120)) }
        assertEquals(PowerTrend.RISING, BatteryMonitor.powerTrend(rising))

        val falling = (0 until 10).map { sample(it * 1000L, current = -(1500 - it * 120)) }
        assertEquals(PowerTrend.FALLING, BatteryMonitor.powerTrend(falling))

        val steady = (0 until 10).map { sample(it * 1000L, current = -600) }
        assertEquals(PowerTrend.STEADY, BatteryMonitor.powerTrend(steady))

        assertEquals(
            "two samples are not a trend",
            PowerTrend.INSUFFICIENT_DATA,
            BatteryMonitor.powerTrend(steady.take(2))
        )
    }

    @Test
    fun testDisplayStateDrain_comparesOnlyObservedSamples() {
        val on = (0 until 6).map { sample(it * 60_000L, current = -1200, screenOn = true) }
        val off = (6 until 12).map { sample(it * 60_000L, current = -300, screenOn = false) }
        val analysis = BatteryMonitor.displayStateDrain(on + off)
        assertTrue(analysis.hasComparison)
        assertEquals(1200f, analysis.screenOnAverageMilliAmps!!, 0.5f)
        assertEquals(300f, analysis.screenOffAverageMilliAmps!!, 0.5f)
        assertEquals(4f, analysis.ratio!!, 0.01f)
        assertEquals(6, analysis.screenOnSamples)

        // With only one display state observed, no comparison may be claimed.
        val onlyOn = BatteryMonitor.displayStateDrain(on)
        assertFalse(onlyOn.hasComparison)
        assertNull(onlyOn.screenOffAverageMilliAmps)
        assertNull(onlyOn.ratio)
    }

    @Test
    fun testChargingEfficiency_isAnEstimateAndNeedsBothInputs() {
        val noPower = BatteryMonitor.chargingEfficiency(null, 40f, 18f, "AC charger")
        assertNull(noPower.efficiencyPercent)
        assertFalse(noPower.isMeasured)

        val noRate = BatteryMonitor.chargingEfficiency(12f, null, 18f, "AC charger")
        assertNull("without a measured rate there is no efficiency", noRate.efficiencyPercent)
        assertEquals(12f, noRate.batterySideWatts!!, 0.001f)

        val noCapacity = BatteryMonitor.chargingEfficiency(12f, 40f, null, "AC charger")
        assertNull(noCapacity.efficiencyPercent)

        // 18 Wh pack, 40 %/h -> 7.2 W stored against 12 W at the battery -> 60 %.
        val calculated = BatteryMonitor.chargingEfficiency(12f, 40f, 18f, "AC charger")
        assertEquals(60f, calculated.efficiencyPercent!!, 0.01f)
        assertTrue(calculated.isMeasured)
        assertTrue(calculated.explanation.startsWith("Estimate"))
        assertTrue(calculated.explanation.contains("not a measurement"))
    }

    @Test
    fun testIntelligence_reportStaysWithinWhatWasObserved() {
        val history = (0 until 20).map { index ->
            sample(
                timestampMs = index * 30_000L,
                level = 80 - index / 4,
                current = -2000,
                voltage = 4.2f,
                temperature = 33f,
                screenOn = index % 2 == 0
            )
        }
        val report = BatteryMonitor.intelligence(
            samples = history,
            telemetry = telemetry(),
            chargeRatePercentPerHour = null,
            drainRatePercentPerHour = 28f,
            capacityWattHours = 15f
        )
        assertEquals(20, report.totalSamples)
        assertEquals(9, report.observationMinutes)
        assertEquals(2000f, report.averageCurrentMilliAmps!!, 1f)
        assertEquals(8.4f, report.averagePowerWatts!!, 0.01f)
        assertTrue("28 %/h is above the 20 %/h threshold", report.abnormalDrainDetected)
        assertFalse(report.overheatingDetected)
        assertTrue(report.notes.any { it.contains("Screen-on versus screen-off") })
        assertTrue(report.notes.any { it.contains("Average current is not exposed") })
    }

    @Test
    fun testIntelligence_emptyHistoryDoesNotFabricateNumbers() {
        val report = BatteryMonitor.intelligence(
            samples = emptyList(),
            telemetry = telemetry(),
            chargeRatePercentPerHour = null,
            drainRatePercentPerHour = null,
            capacityWattHours = null
        )
        assertEquals(0, report.totalSamples)
        assertEquals(0, report.observationMinutes)
        assertNull(report.averageCurrentMilliAmps)
        assertNull(report.averagePowerWatts)
        assertNull(report.peakPowerWatts)
        assertEquals(PowerTrend.INSUFFICIENT_DATA, report.powerTrend)
        assertFalse(report.abnormalDrainDetected)
        assertFalse(report.overheatingDetected)
        assertTrue(report.notes.any { it.contains("No samples recorded yet") })
    }

    @Test
    fun testCapacityWattHours_onlyFromRealCounters() {
        val known = telemetry(chargeFullUah = 4_500_000L, designUah = 5_000_000L, voltageVolts = 4.4f)
        assertEquals(19.8f, BatteryMonitor.capacityWattHours(known)!!, 0.01f)
        assertNull(BatteryMonitor.capacityWattHours(telemetry(chargeFullUah = null)))
        assertNull(BatteryMonitor.capacityWattHours(telemetry(voltageVolts = null)))
    }

    // --- 7b. Reliability and charging stability -----------------------------------------------

    @Test
    fun testReliability_isDrivenByFreshnessThenSensorCoverage() {
        assertEquals(
            MeasurementReliability.NONE,
            BatteryMonitor.reliabilityOf(DataFreshness.NO_DATA, 3, 3).first
        )
        assertEquals(
            MeasurementReliability.LOW,
            BatteryMonitor.reliabilityOf(DataFreshness.STALE, 3, 3).first
        )
        assertEquals(
            MeasurementReliability.MEDIUM,
            BatteryMonitor.reliabilityOf(DataFreshness.LIVE, 2, 3).first
        )
        assertEquals(
            MeasurementReliability.MEDIUM,
            BatteryMonitor.reliabilityOf(DataFreshness.DELAYED, 3, 3).first
        )
        assertEquals(
            "every core sensor answering on a live reading is the best case",
            MeasurementReliability.HIGH,
            BatteryMonitor.reliabilityOf(DataFreshness.LIVE, 3, 3).first
        )
        assertEquals(
            "no usable core sensor can never be high confidence",
            MeasurementReliability.LOW,
            BatteryMonitor.reliabilityOf(DataFreshness.LIVE, 0, 3).first
        )
        val detail = BatteryMonitor.reliabilityOf(DataFreshness.LIVE, 3, 3).second
        assertTrue(detail.contains("3 of 3"))
    }

    @Test
    fun testMonitoringStatus_carriesReliabilityAndExplainsIt() {
        val snapshot = telemetry(charging = true, source = ChargingSource.AC, currentMilliAmps = 1200)
        val sensors = BatteryMonitor.sensorStatuses(snapshot, DataFreshness.LIVE)
        val status = BatteryMonitor.monitoringStatus(
            snapshot, sensors, DataFreshness.LIVE, EngineState.ACTIVE, 1_500L
        )
        assertEquals(MeasurementReliability.HIGH, status.reliability)
        assertTrue(status.reliabilityDetail.isNotBlank())
    }

    @Test
    fun testChargingStability_usesMeasuredVoltageSpreadAndDropouts() {
        val steady = (0 until 8).map { sample(it * 60_000L, charging = true, current = 1500, voltage = 4.2f) }
        val report = BatteryMonitor.intelligence(
            samples = steady,
            telemetry = telemetry(charging = true),
            chargeRatePercentPerHour = 30f,
            drainRatePercentPerHour = null,
            capacityWattHours = 15f,
            chargingInterruptions = 0
        )
        assertEquals(0f, report.stabilityPercent!!, 0.001f)
        assertEquals(0, report.chargingInterruptions)

        val noisy = listOf(4.0f, 4.4f, 4.0f, 4.4f, 4.0f, 4.4f, 4.0f, 4.4f).mapIndexed { index, volts ->
            sample(index * 60_000L, charging = true, current = 1500, voltage = volts)
        }
        val unstable = BatteryMonitor.intelligence(
            samples = noisy,
            telemetry = telemetry(charging = true),
            chargeRatePercentPerHour = 30f,
            drainRatePercentPerHour = null,
            capacityWattHours = 15f,
            chargingInterruptions = 3
        )
        assertTrue("noisy voltage must show real spread", unstable.stabilityPercent!! > 3f)
        assertEquals(3, unstable.chargingInterruptions)

        // Not enough samples -> no stability claim at all.
        val thin = BatteryMonitor.intelligence(
            samples = steady.take(2),
            telemetry = telemetry(charging = true),
            chargeRatePercentPerHour = null,
            drainRatePercentPerHour = null,
            capacityWattHours = null
        )
        assertNull(thin.stabilityPercent)
    }

    @Test
    fun testIntelligence_neverAttributesDrainToAnApp() {
        val report = BatteryMonitor.intelligence(
            samples = (0 until 5).map { sample(it * 60_000L) },
            telemetry = telemetry(),
            chargeRatePercentPerHour = null,
            drainRatePercentPerHour = 8f,
            capacityWattHours = null
        )
        assertTrue(
            "per-app attribution needs BATTERY_STATS, so the panel must say it was not attempted",
            report.notes.any { it.contains("BATTERY_STATS") }
        )
    }

    // --- 8. Refresh policy --------------------------------------------------------------------

    @Test
    fun testRefreshInterval_isOneSecondOnlyWhenItCanPayOff() {
        assertEquals(
            "live + screen on = 1 Hz",
            1_000L,
            BatteryMonitor.recommendedRefreshIntervalMs(DataFreshness.LIVE, screenOn = true, EngineState.ACTIVE)
        )
        assertEquals(
            "screen off must not poll every second",
            5_000L,
            BatteryMonitor.recommendedRefreshIntervalMs(DataFreshness.LIVE, screenOn = false, EngineState.ACTIVE)
        )
        assertEquals(
            5_000L,
            BatteryMonitor.recommendedRefreshIntervalMs(DataFreshness.LIVE, screenOn = true, EngineState.PAUSED)
        )
        assertEquals(
            "a quiet driver does not need 1 Hz",
            3_000L,
            BatteryMonitor.recommendedRefreshIntervalMs(DataFreshness.STALE, screenOn = true, EngineState.ACTIVE)
        )
    }

    @Test
    fun testDescribeAge_isHumanReadable() {
        assertEquals("<1 s", BatteryMonitor.describeAge(400L))
        assertEquals("12 s", BatteryMonitor.describeAge(12_400L))
        assertEquals("3 min", BatteryMonitor.describeAge(3 * 60_000L))
        assertEquals("2 h", BatteryMonitor.describeAge(2 * 3_600_000L))
    }

    // --- 9. Preservation of the existing diagnostics chain ------------------------------------

    @Test
    fun testExistingDiagnosticsStillRunAgainstTheSameTelemetry() {
        val samples = (0 until 6).map { sample(it * 60_000L, charging = true, level = 40 + it) }
        val diagnostics = BatteryDiagnostics.diagnose(
            telemetry = telemetry(charging = true, currentMilliAmps = 1500),
            history = samples,
            chargeRatePercentPerHour = BatteryDiagnostics.chargeRatePercentPerHour(samples),
            drainRatePercentPerHour = null,
            interruptions = 0
        )
        assertTrue(diagnostics.isNotEmpty())
        diagnostics.forEach { diagnostic ->
            assertTrue(diagnostic.confidencePercent in 1..100)
            assertNotNull(diagnostic.title)
        }
    }

    @Test
    fun testSampleCarriesScreenStateForTheNewAnalysis() {
        val withScreen = sample(0L, screenOn = true)
        assertEquals(true, withScreen.screenOn)
        // Old call sites that never set it stay "unknown", never "false".
        val legacy = BatteryDiagnostics.Sample(0L, 50, false, 30f, 4.1f, -400, 1.64f)
        assertNull(legacy.screenOn)
        assertEquals(0L, legacy.elapsedRealtimeMs)
    }
}
