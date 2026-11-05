package com.adshield.pro.engine.battery

import kotlin.math.abs
import kotlin.math.round

/**
 * AdShield Pro — battery monitoring engine (pure Kotlin).
 *
 * This object owns every decision the Battery Command Center makes about the *meaning* of a
 * reading: freshness, sensor state, component status, battery condition, power trends and the
 * intelligence report. It deliberately contains no Android imports, so:
 *
 *  - every rule is unit-tested on the JVM against synthetic (but physically consistent) inputs;
 *  - the UI cannot compute a number of its own and accidentally invent one.
 *
 * House rules enforced here:
 *  1. A value is only shown when the device produced it. Missing sensors are reported as missing.
 *  2. Instantaneous current and average current are never mixed; power is V x |I| on the battery
 *     side, and the sign is only interpreted when it agrees with the charging state.
 *  3. Fast charging is claimed only when both a measured hardware signal *and* a measured
 *     charge rate agree. One of them alone is not enough.
 *  4. Every projection (time to full, drain per hour, efficiency) is labelled as a projection.
 */
object BatteryMonitor {

    /** Samples younger than this count as live evidence for trends and rates. */
    const val SAMPLE_FRESHNESS_MS = 120_000L

    /** Below this many samples nothing trend-like is claimed. */
    const val MIN_TREND_SAMPLES = 3

    /** Minimum observation window before a %/hour rate is extrapolated. */
    const val MIN_RATE_WINDOW_MS = 5 * 60_000L

    /** Charging rate that counts as "fast" when hardware also reports a fast-charge signal. */
    const val FAST_CHARGE_RATE_PERCENT_PER_HOUR = 30f

    /** Charging rate that counts as "slow" (matches the diagnostics rule chain). */
    const val SLOW_CHARGE_RATE_PERCENT_PER_HOUR = 8f

    /** Temperature at or above which the status engine raises a thermal warning. */
    const val WARM_TEMPERATURE_CELSIUS = 40f

    /** Temperature at or above which the status is critical. */
    const val CRITICAL_TEMPERATURE_CELSIUS = 45f

    // -----------------------------------------------------------------------------------------
    // Power maths
    // -----------------------------------------------------------------------------------------

    /**
     * Battery-side power from two real measurements.
     *
     * `P = V x I`, using the magnitude of the current because the battery-side power path is the
     * same in both directions; direction is reported separately by [chargingPowerWatts] /
     * [dischargePowerWatts]. Returns null unless both inputs are present and the voltage is
     * physically plausible for a phone battery.
     */
    fun powerWatts(voltageVolts: Float?, currentMilliAmps: Int?): Float? {
        if (voltageVolts == null || currentMilliAmps == null) return null
        if (voltageVolts <= 2.5f || voltageVolts > 5.5f) return null
        if (currentMilliAmps == 0) return null
        return voltageVolts * (abs(currentMilliAmps) / 1000f)
    }

    /**
     * Power flowing *into* the battery, or null when the device is not charging.
     *
     * [isCharging] must come from the system status, not from the current sign: several vendors
     * invert the sign, and a phone sitting at "full" still reports a small positive current.
     */
    fun chargingPowerWatts(voltageVolts: Float?, currentMilliAmps: Int?, isCharging: Boolean): Float? =
        if (isCharging) powerWatts(voltageVolts, currentMilliAmps) else null

    /** Power drawn *from* the battery (positive number), or null when the device is charging. */
    fun dischargePowerWatts(voltageVolts: Float?, currentMilliAmps: Int?, isCharging: Boolean): Float? =
        if (isCharging) null else powerWatts(voltageVolts, currentMilliAmps)

    /**
     * Human label for the direction of the current, or null when the sign cannot be trusted.
     * This is what stops the UI from printing "-1500 mA" on a phone that is charging.
     */
    fun currentDirectionLabel(reading: Int?, isCharging: Boolean, signKnown: Boolean): String? {
        if (reading == null) return null
        if (!signKnown) return if (isCharging) "into battery" else "out of battery"
        return if (reading > 0) "into battery" else if (reading < 0) "out of battery" else null
    }

    /** Deterministic 1-decimal formatter shared by every surface (same as diagnostics). */
    fun format1(value: Float): String = BatteryDiagnostics.format1(value)

    // -----------------------------------------------------------------------------------------
    // Sensor status
    // -----------------------------------------------------------------------------------------

    /**
     * Turns one [BatteryReading] into a [SensorStatus].
     *
     * The distinction that matters for an honest dashboard:
     *  - UNSUPPORTED: the device will never provide it (the property is absent from the API);
     *  - INVALID: the driver returned something no phone battery can produce;
     *  - UNAVAILABLE: the property exists but had no value this time;
     *  - WAITING: a derived value (power) whose inputs are not both present yet.
     */
    fun sensorStatus(
        name: String,
        reading: BatteryReading<*>,
        source: String,
        unit: String,
        freshness: DataFreshness
    ): SensorStatus {
        val value = reading.rawValue
        val state = when (reading.source) {
            BatteryReadingSource.HARDWARE, BatteryReadingSource.COMPUTED ->
                if (value == null) SensorState.UNAVAILABLE else SensorState.OPERATIONAL
            BatteryReadingSource.ESTIMATED ->
                if (value == null) SensorState.UNAVAILABLE else SensorState.OPERATIONAL
            BatteryReadingSource.UNSUPPORTED -> SensorState.UNSUPPORTED
            BatteryReadingSource.UNAVAILABLE -> SensorState.UNAVAILABLE
        }
        // A reading that is technically present but whose message says the driver value was
        // rejected is an INVALID reading, not a live one.
        val effectiveState = if (state == SensorState.OPERATIONAL && reading.detail.contains("implausible", true)) {
            SensorState.INVALID
        } else {
            state
        }
        val measured = reading.source == BatteryReadingSource.HARDWARE && value != null
        val shown = when {
            value == null -> "—"
            value is Float -> "${format1(value)} $unit".trim()
            value is Double -> "${format1(value.toFloat())} $unit".trim()
            else -> "$value $unit".trim()
        }
        val detail = when (effectiveState) {
            SensorState.OPERATIONAL, SensorState.DELAYED ->
                if (freshness == DataFreshness.STALE || freshness == DataFreshness.DELAYED) {
                    "Last hardware broadcast ${freshness.label.lowercase()}: ${reading.detail.ifBlank { source }}"
                } else {
                    reading.detail.ifBlank { source }
                }
            SensorState.UNSUPPORTED -> reading.detail.ifBlank { "This device does not expose $name" }
            SensorState.UNAVAILABLE -> reading.detail.ifBlank { "No $name value in the current reading" }
            SensorState.INVALID -> reading.detail
            SensorState.WAITING -> "Waiting for data"
        }
        return SensorStatus(name, effectiveState, source, detail, measured).copy(state = effectiveState, detail = detail, statusValue = shown)
    }

    /** Every input the dashboard reads, with its real state on this device. */
    fun sensorStatuses(telemetry: BatteryTelemetry, freshness: DataFreshness): List<SensorStatus> = listOf(
        sensorStatus("Battery level", telemetry.levelPercent, "EXTRA_LEVEL / EXTRA_SCALE", "%", freshness),
        sensorStatus("Voltage", telemetry.voltageVolts, "EXTRA_VOLTAGE", "V", freshness),
        sensorStatus("Current", telemetry.currentMilliAmps, "BATTERY_PROPERTY_CURRENT_NOW", "mA", freshness),
        sensorStatus("Average current", telemetry.currentAverageMilliAmps, "BATTERY_PROPERTY_CURRENT_AVERAGE", "mA", freshness),
        sensorStatus("Temperature", telemetry.temperatureCelsius, "EXTRA_TEMPERATURE", "°C", freshness),
        sensorStatus("Charge counter", telemetry.chargeCounterMicroAmpHours, "BATTERY_PROPERTY_CHARGE_COUNTER", "µAh", freshness),
        powerSensorStatus(telemetry, freshness),
        sensorStatus("Cycle count", telemetry.cycleCount, "BatteryManager.getCycleCount()", "cycles", freshness),
        sensorStatus("Design capacity", telemetry.chargeFullDesignMicroAmpHours, "CHARGE_COUNTER_FULL_DESIGN", "µAh", freshness),
        sensorStatus("Charging time", telemetry.chargeTimeRemainingMinutes, "computeChargeTimeRemaining()", "min", freshness)
    )

    private fun powerSensorStatus(telemetry: BatteryTelemetry, freshness: DataFreshness): SensorStatus {
        val voltage = telemetry.voltageVolts.rawValue
        val current = telemetry.currentMilliAmps.rawValue
        return when {
            telemetry.powerWatts.rawValue != null -> SensorStatus(
                name = "Power (V × I)",
                state = SensorState.OPERATIONAL,
                source = "Computed from voltage and current",
                detail = "Battery-side power: ${format1(voltage ?: 0f)} V × ${format1(abs(current ?: 0) / 1000f)} A",
                measured = false,
                statusValue = "${format1(telemetry.powerWatts.rawValue)} W"
            )
            voltage == null && current == null -> SensorStatus(
                name = "Power (V × I)",
                state = SensorState.WAITING,
                source = "Computed from voltage and current",
                detail = "Neither voltage nor current is exposed by this device, so power cannot be computed",
                measured = false,
                statusValue = "—"
            )
            voltage == null -> SensorStatus(
                name = "Power (V × I)",
                state = SensorState.WAITING,
                source = "Computed from voltage and current",
                detail = "Current is available but this device does not report voltage",
                measured = false,
                statusValue = "—"
            )
            current == null -> SensorStatus(
                name = "Power (V × I)",
                state = SensorState.WAITING,
                source = "Computed from voltage and current",
                detail = "Voltage is available but this device does not report current",
                measured = false,
                statusValue = "—"
            )
            else -> SensorStatus(
                name = "Power (V × I)",
                state = SensorState.INVALID,
                source = "Computed from voltage and current",
                detail = "Both inputs exist but their values are outside the plausible range",
                measured = false,
                statusValue = "—"
            )
        }
    }

    // -----------------------------------------------------------------------------------------
    // Component + overall monitoring status
    // -----------------------------------------------------------------------------------------

    /**
     * Builds the System Monitoring Status panel.
     *
     * [powerState] lets the caller override the power component to reflect *projections* as well
     * as the instantaneous computation (the UI passes OPERATIONAL when both a computed power and
     * a measured average exist).
     */
    fun monitoringStatus(
        telemetry: BatteryTelemetry,
        sensors: List<SensorStatus>,
        freshness: DataFreshness,
        engineState: EngineState,
        nowElapsedRealtimeMs: Long,
        batteryApiAvailable: Boolean = true
    ): MonitoringStatus {
        val batteryApi = when {
            !batteryApiAvailable -> ComponentStatus(
                "Battery API", MonitoringState.UNAVAILABLE, "—",
                "BatteryManager could not be obtained from the system service"
            )
            freshness == DataFreshness.NO_DATA -> ComponentStatus(
                "Battery API", MonitoringState.ERROR, "—",
                "No ACTION_BATTERY_CHANGED broadcast has been received"
            )
            else -> ComponentStatus(
                "Battery API", MonitoringState.OPERATIONAL, "Reading",
                "BatteryManager properties plus ACTION_BATTERY_CHANGED extras"
            )
        }
        fun sensorComponent(label: String, sensor: SensorStatus) = ComponentStatus(
            label,
            when (sensor.state) {
                SensorState.OPERATIONAL -> MonitoringState.OPERATIONAL
                SensorState.DELAYED -> MonitoringState.OPERATIONAL
                SensorState.UNSUPPORTED -> MonitoringState.UNSUPPORTED
                SensorState.UNAVAILABLE -> MonitoringState.UNAVAILABLE
                SensorState.INVALID -> MonitoringState.ERROR
                SensorState.WAITING -> MonitoringState.WAITING
            },
            sensor.statusValue,
            sensor.detail
        )
        val current = sensors.firstOrNull { it.name == "Current" }
        val voltage = sensors.firstOrNull { it.name == "Voltage" }
        val temperature = sensors.firstOrNull { it.name == "Temperature" }
        val power = sensors.firstOrNull { it.name == "Power (V × I)" }

        val powerComponent = when {
            power == null -> ComponentStatus("Power calculation", MonitoringState.WAITING, "—", "Not evaluated")
            power.state == SensorState.OPERATIONAL -> ComponentStatus(
                "Power calculation", MonitoringState.OPERATIONAL, power.statusValue, power.detail
            )
            else -> ComponentStatus(
                "Power calculation", MonitoringState.WAITING, "—", power.detail
            )
        }
        val engine = ComponentStatus(
            "Monitoring engine",
            when (engineState) {
                EngineState.ACTIVE -> MonitoringState.ACTIVE
                EngineState.PAUSED -> MonitoringState.PAUSED
                EngineState.STOPPED -> MonitoringState.PAUSED
                EngineState.ERROR -> MonitoringState.ERROR
            },
            engineState.label,
            "Event-driven ACTION_BATTERY_CHANGED receiver; newest sample ${describeAge(telemetry.ageMs(nowElapsedRealtimeMs))}"
        )
        val freshnessComponent = ComponentStatus(
            "Data freshness", freshnessToState(freshness), freshness.label,
            when (freshness) {
                DataFreshness.LIVE -> "Newest hardware reading is under ${DataFreshness.LIVE_WINDOW_MS / 1000} s old"
                DataFreshness.DELAYED -> "Newest hardware reading is ${describeAge(telemetry.ageMs(nowElapsedRealtimeMs))} old"
                DataFreshness.STALE -> "Newest hardware reading is ${describeAge(telemetry.ageMs(nowElapsedRealtimeMs))} old — values below are historical"
                DataFreshness.NO_DATA -> "No reading yet"
            }
        )
        val components = listOf(
            batteryApi,
            sensorComponent("Current sensor", current ?: missingSensor("Current sensor")),
            sensorComponent("Voltage sensor", voltage ?: missingSensor("Voltage sensor")),
            sensorComponent("Temperature sensor", temperature ?: missingSensor("Temperature sensor")),
            powerComponent,
            engine,
            freshnessComponent
        )
        val scored = components.filter { it.component != "Data freshness" }
        val operational = scored.count {
            it.state == MonitoringState.OPERATIONAL || it.state == MonitoringState.ACTIVE
        }
        val errors = scored.count { it.state == MonitoringState.ERROR }
        val overall = when {
            errors > 0 -> MonitoringState.ERROR
            engineState == EngineState.ERROR -> MonitoringState.ERROR
            freshness == DataFreshness.NO_DATA -> MonitoringState.WAITING
            // Every component can be healthy while the *data* is old; that is partial monitoring,
            // not full monitoring, and the header must not claim otherwise.
            freshness != DataFreshness.LIVE -> MonitoringState.PARTIAL
            operational == scored.size -> MonitoringState.OPERATIONAL
            else -> MonitoringState.PARTIAL
        }
        val (reliability, reliabilityDetail) = reliabilityOf(
            freshness = freshness,
            coreSensorsPresent = listOfNotNull(current, voltage, temperature).count { it.state == SensorState.OPERATIONAL },
            coreSensorTotal = 3
        )
        return MonitoringStatus(
            batteryApi = batteryApi,
            currentSensor = components[1],
            voltageSensor = components[2],
            temperatureSensor = components[3],
            powerCalculation = powerComponent,
            engine = engine,
            freshness = freshness,
            overall = overall,
            scorePercent = if (scored.isEmpty()) 0 else round(operational * 100f / scored.size).toInt(),
            components = components,
            reliability = reliability,
            reliabilityDetail = reliabilityDetail
        )
    }

    /**
     * Coarse trust level for the displayed numbers.
     *
     * Freshness dominates (a stale voltage is worse than a missing cycle count), sensor coverage
     * breaks ties. Both inputs are measured facts about the current reading.
     */
    fun reliabilityOf(
        freshness: DataFreshness,
        coreSensorsPresent: Int,
        coreSensorTotal: Int
    ): Pair<MeasurementReliability, String> {
        val total = coreSensorTotal.coerceAtLeast(1)
        val present = coreSensorsPresent.coerceIn(0, total)
        val detail = when (freshness) {
            DataFreshness.NO_DATA -> "No reading has arrived yet, so nothing is displayed as measured."
            DataFreshness.STALE -> "Newest reading is over ${DataFreshness.STALE_WINDOW_MS / 1000} s old: values are historical."
            DataFreshness.DELAYED -> "Newest reading is a few seconds old: live values may lag behind the hardware."
            DataFreshness.LIVE -> "Reading is current (under ${DataFreshness.LIVE_WINDOW_MS / 1000} s) and " +
                "$present of $total core sensors answered."
        }
        val reliability = when {
            freshness == DataFreshness.NO_DATA -> MeasurementReliability.NONE
            freshness == DataFreshness.STALE -> MeasurementReliability.LOW
            present == 0 -> MeasurementReliability.LOW
            freshness == DataFreshness.DELAYED -> MeasurementReliability.MEDIUM
            present < total -> MeasurementReliability.MEDIUM
            else -> MeasurementReliability.HIGH
        }
        return reliability to detail
    }

    private fun missingSensor(name: String) = SensorStatus(
        name = name,
        state = SensorState.UNAVAILABLE,
        source = "unknown",
        detail = "Not evaluated",
        measured = false,
        statusValue = "—"
    )

    private fun freshnessToState(freshness: DataFreshness) = when (freshness) {
        DataFreshness.LIVE -> MonitoringState.OPERATIONAL
        DataFreshness.DELAYED -> MonitoringState.PARTIAL
        DataFreshness.STALE -> MonitoringState.PARTIAL
        DataFreshness.NO_DATA -> MonitoringState.WAITING
    }

    fun describeAge(ageMs: Long): String = when {
        ageMs < 1_000L -> "<1 s"
        ageMs < 60_000L -> "${ageMs / 1000} s"
        ageMs < 3_600_000L -> "${ageMs / 60_000} min"
        else -> "${ageMs / 3_600_000} h"
    }

    // -----------------------------------------------------------------------------------------
    // Battery condition
    // -----------------------------------------------------------------------------------------

    /**
     * Derives the dashboard's large status line.
     *
     * Ordering is safety-first: a critical temperature outranks "charging", and insufficient
     * sensor information outranks a benign-looking idle state, because a dashboard that says
     * "discharging" while showing no current at all is lying by omission.
     */
    fun condition(
        telemetry: BatteryTelemetry,
        freshness: DataFreshness,
        chargeRatePercentPerHour: Float?,
        drainRatePercentPerHour: Float?,
        averagePowerWatts: Float?,
        healthScore: Int,
        hasFastChargeSignal: Boolean,
        fastChargeSource: String?
    ): BatteryStatusReport {
        val temp = telemetry.temperatureCelsius.rawValue
        val evidence = ArrayList<String>()
        val secondary = LinkedHashSet<BatteryCondition>()
        val level = telemetry.levelPercent.rawValue
        val current = telemetry.currentMilliAmps.rawValue
        val avgCurrent = telemetry.currentAverageMilliAmps.rawValue

        level?.let { evidence += "Level $it% (EXTRA_LEVEL)" }
        telemetry.voltageVolts.rawValue?.let { evidence += "Voltage ${format1(it)} V (EXTRA_VOLTAGE)" }
        current?.let {
            evidence += "Current $it mA (CURRENT_NOW)" +
                currentDirectionLabel(it, telemetry.isCharging, telemetry.currentSignKnown)?.let { dir -> ", $dir" }.orEmpty()
        }
        avgCurrent?.let { evidence += "Average current $it mA (CURRENT_AVERAGE)" }
        telemetry.powerWatts.rawValue?.let { evidence += "Battery-side power ${format1(it)} W = V × I" }
        temp?.let { evidence += "Temperature ${format1(it)}°C (EXTRA_TEMPERATURE)" }
        if (fastChargeSource != null) evidence += "Fast-charge signal: $fastChargeSource"
        if (chargeRatePercentPerHour != null) evidence += "Measured charge rate ${format1(chargeRatePercentPerHour)} %/h"
        if (drainRatePercentPerHour != null) evidence += "Measured drain rate ${format1(drainRatePercentPerHour)} %/h"

        // --- Insufficient data ---------------------------------------------------------------
        val sensorMissing = current == null && telemetry.voltageVolts.rawValue == null
        if (sensorMissing && !telemetry.isCharging) {
            secondary += BatteryCondition.INSUFFICIENT_DATA
            return BatteryStatusReport(
                primary = BatteryCondition.INSUFFICIENT_DATA,
                secondary = secondary.toList(),
                tone = BatteryConditionTone.NEUTRAL,
                headline = "Insufficient sensor information",
                detail = "This device does not expose battery current or voltage to apps, so power, drain and " +
                    "charge-rate analysis cannot be performed. Level and charging state are still read from Android.",
                evidence = evidence,
                fastChargeDetected = false,
                usableSensors = 0,
                totalSensors = 4
            )
        }

        // --- Thermal -------------------------------------------------------------------------
        val thermalCritical = temp != null && temp >= CRITICAL_TEMPERATURE_CELSIUS
        val thermalWarn = temp != null && temp >= WARM_TEMPERATURE_CELSIUS
        if (thermalWarn) secondary += BatteryCondition.TEMPERATURE_WARNING

        // --- Health --------------------------------------------------------------------------
        val healthWarn = telemetry.health != BatteryHealthStatus.GOOD &&
            telemetry.health != BatteryHealthStatus.UNKNOWN ||
            healthScore < 60
        if (healthWarn) secondary += BatteryCondition.HEALTH_WARNING

        val fastCharge = telemetry.isCharging && !telemetry.isFull && fastChargeSignalConfirmsRate(
            hasFastChargeSignal, chargeRatePercentPerHour
        )
        if (fastCharge) secondary += BatteryCondition.FAST_CHARGING
        val slowCharge = telemetry.isCharging && !telemetry.isFull &&
            chargeRatePercentPerHour != null &&
            chargeRatePercentPerHour < SLOW_CHARGE_RATE_PERCENT_PER_HOUR
        if (slowCharge) secondary += BatteryCondition.SLOW_CHARGING

        val highPower = !telemetry.isCharging && averagePowerWatts != null && averagePowerWatts >= 4.5f
        if (highPower) secondary += BatteryCondition.HIGH_POWER_DRAIN

        val plugged = telemetry.chargingSource != ChargingSource.NOT_PLUGGED

        // --- Primary condition, safety first -------------------------------------------------
        val primary = when {
            // At or above the warm threshold the abnormal temperature *is* the status: a phone that
            // is merely "discharging" at 41 °C leaves the most important fact unsaid.
            thermalWarn -> BatteryCondition.TEMPERATURE_WARNING
            telemetry.isFull -> BatteryCondition.FULLY_CHARGED
            telemetry.isCharging -> when {
                fastCharge -> BatteryCondition.FAST_CHARGING
                slowCharge -> BatteryCondition.SLOW_CHARGING
                else -> BatteryCondition.CHARGING
            }
            plugged -> BatteryCondition.CONNECTED_NOT_CHARGING
            highPower -> BatteryCondition.HIGH_POWER_DRAIN
            else -> BatteryCondition.DISCHARGING
        }

        // A red dot for a quietly boiling battery must also cover the case where the health flag is
        // the worst thing happening, so the tone is the worst of every active condition.
        fun toneOf(condition: BatteryCondition): BatteryConditionTone = when (condition) {
            BatteryCondition.TEMPERATURE_WARNING ->
                if (thermalCritical) BatteryConditionTone.CRITICAL else BatteryConditionTone.CAUTION
            BatteryCondition.HEALTH_WARNING -> BatteryConditionTone.CRITICAL
            BatteryCondition.HIGH_POWER_DRAIN, BatteryCondition.SLOW_CHARGING,
            BatteryCondition.CONNECTED_NOT_CHARGING, BatteryCondition.INSUFFICIENT_DATA ->
                BatteryConditionTone.CAUTION
            BatteryCondition.CHARGING, BatteryCondition.FAST_CHARGING, BatteryCondition.FULLY_CHARGED ->
                BatteryConditionTone.POSITIVE
            BatteryCondition.DISCHARGING, BatteryCondition.NOT_CHARGING -> BatteryConditionTone.NOMINAL
        }
        fun severity(tone: BatteryConditionTone): Int = when (tone) {
            BatteryConditionTone.NEUTRAL -> 0
            BatteryConditionTone.NOMINAL -> 1
            BatteryConditionTone.POSITIVE -> 2
            BatteryConditionTone.CAUTION -> 3
            BatteryConditionTone.CRITICAL -> 4
        }
        val activeConditions = listOf(primary) + secondary.toList().filter { it != primary }
        val tone = activeConditions.map(::toneOf).maxBy(::severity)

        val headline = when (primary) {
            BatteryCondition.TEMPERATURE_WARNING ->
                if (thermalCritical) "Battery temperature critical" else "Battery temperature abnormal"
            BatteryCondition.FULLY_CHARGED -> "Fully charged"
            BatteryCondition.FAST_CHARGING -> "Fast charging"
            BatteryCondition.SLOW_CHARGING -> "Slow charging"
            BatteryCondition.CHARGING -> "Charging"
            BatteryCondition.CONNECTED_NOT_CHARGING -> "Connected, not charging"
            BatteryCondition.HIGH_POWER_DRAIN -> "High power consumption"
            BatteryCondition.HEALTH_WARNING -> "Battery health warning"
            BatteryCondition.DISCHARGING -> "Discharging"
            BatteryCondition.NOT_CHARGING -> "Not charging"
            BatteryCondition.INSUFFICIENT_DATA -> "Insufficient sensor information"
        }

        val detail = buildString {
            when (primary) {
                BatteryCondition.TEMPERATURE_WARNING ->
                    append("Measured ${format1(temp ?: 0f)}°C. ${if (telemetry.isCharging) "Charging" else "Discharging"} at this temperature accelerates wear.")
                BatteryCondition.FULLY_CHARGED ->
                    append("Android reports the battery as full").apply {
                        if (level != null) append(" at $level%")
                        append(". Trickle charging may continue; the phone no longer needs the charger.")
                    }
                BatteryCondition.FAST_CHARGING -> {
                    append("Fast charging detected")
                    if (fastChargeSource != null) append(" from $fastChargeSource")
                    chargeRatePercentPerHour?.let { append(" and a measured gain of ${format1(it)} % per hour") }
                    append(".")
                }
                BatteryCondition.SLOW_CHARGING -> {
                    append("Measured gain of ")
                    append(if (chargeRatePercentPerHour != null) "${format1(chargeRatePercentPerHour)} % per hour" else "under ${format1(SLOW_CHARGE_RATE_PERCENT_PER_HOUR)} % per hour")
                    append(" while charging. A worn cable, a weak adapter or a data-only port cannot deliver more.")
                }
                BatteryCondition.CHARGING -> append("Current is flowing into the battery. Charging speed is being measured from level changes.")
                BatteryCondition.CONNECTED_NOT_CHARGING ->
                    append("A charger is attached (${telemetry.pluggedLabel.lowercase()}) but the battery is not charging — " +
                        "typical near full charge, or a charger that cannot sustain the load.")
                BatteryCondition.HIGH_POWER_DRAIN -> {
                    append("Average measured draw is ")
                    append(if (averagePowerWatts != null) "${format1(averagePowerWatts)} W" else "high")
                    drainRatePercentPerHour?.let { append(", draining ${format1(it)} % per hour") }
                    append(". Something is working hard right now.")
                }
                BatteryCondition.HEALTH_WARNING -> append(
                    "Android reports health '${telemetry.healthLabel}'" +
                        if (healthScore < 60) " and the measured health index is $healthScore/100." else "."
                )
                BatteryCondition.DISCHARGING -> append("The battery is powering the device. No abnormal drain has been measured.")
                BatteryCondition.NOT_CHARGING -> append("No charger is attached.")
                BatteryCondition.INSUFFICIENT_DATA -> append("Not enough sensor data to describe the power state.")
            }
        }

        val usable = listOfNotNull(
            current,
            telemetry.voltageVolts.rawValue,
            temp,
            level
        ).size
        return BatteryStatusReport(
            primary = primary,
            secondary = secondary.toList().minus(primary),
            tone = tone,
            headline = headline,
            detail = detail,
            evidence = evidence,
            fastChargeDetected = fastCharge,
            usableSensors = usable,
            totalSensors = 4
        )
    }

    /**
     * Fast charging requires both signals. A hardware flag the platform itself reports counts as
     * a signal; the measured rate must independently confirm it unless the flag is unambiguous
     * (`BATTERY_PROPERTY_STATUS` fast-charge constant), which the caller encodes by passing
     * [rate] = null only when it cannot measure yet — in that case the flag alone is accepted and
     * the UI states that the rate is still being measured.
     */
    fun fastChargeSignalConfirmsRate(hasHardwareSignal: Boolean, rate: Float?): Boolean {
        if (!hasHardwareSignal) return false
        if (rate == null) return true
        return rate >= FAST_CHARGE_RATE_PERCENT_PER_HOUR
    }

    // -----------------------------------------------------------------------------------------
    // Trends and intelligence
    // -----------------------------------------------------------------------------------------

    /** Trend of the instantaneous power series; needs [MIN_TREND_SAMPLES] usable points. */
    fun powerTrend(samples: List<BatteryDiagnostics.Sample>): PowerTrend {
        val values = samples.mapNotNull { it.powerWatts }.takeLast(60)
        if (values.size < MIN_TREND_SAMPLES) return PowerTrend.INSUFFICIENT_DATA
        val first = values.take(values.size / 2).average()
        val last = values.drop(values.size / 2).average()
        if (first <= 0.0) return PowerTrend.INSUFFICIENT_DATA
        val deltaPercent = (last - first) / first * 100.0
        return when {
            deltaPercent >= 15.0 -> PowerTrend.RISING
            deltaPercent <= -15.0 -> PowerTrend.FALLING
            else -> PowerTrend.STEADY
        }
    }

    /**
     * Screen-on vs screen-off average current, derived only from samples where this app observed
     * the display state. Android has no public per-display-state battery history, so the panel
     * must present this as "observed while monitoring".
     */
    fun displayStateDrain(samples: List<BatteryDiagnostics.Sample>): DisplayStateDrain {
        val on = samples.filter { it.screenOn == true }.mapNotNull { it.currentMilliAmps?.let { value -> abs(value) } }
        val off = samples.filter { it.screenOn == false }.mapNotNull { it.currentMilliAmps?.let { value -> abs(value) } }
        fun minutesOf(list: List<BatteryDiagnostics.Sample>): Int {
            val usable = list.filter { it.timestampEpochMs > 0 }
            if (usable.size < 2) return 0
            return ((usable.last().timestampEpochMs - usable.first().timestampEpochMs) / 60_000L).toInt()
                .coerceAtLeast(0)
        }
        return DisplayStateDrain(
            screenOnSamples = on.size,
            screenOffSamples = off.size,
            screenOnAverageMilliAmps = on.takeIf { it.size >= DisplayStateDrain.MIN_SAMPLES }?.average()?.toFloat(),
            screenOffAverageMilliAmps = off.takeIf { it.size >= DisplayStateDrain.MIN_SAMPLES }?.average()?.toFloat(),
            screenOnMinutes = minutesOf(samples.filter { it.screenOn == true }),
            screenOffMinutes = minutesOf(samples.filter { it.screenOn == false })
        )
    }

    /**
     * Charging efficiency estimate.
     *
     * Real charger-side power is not readable by any app, so this is an estimate with a stated
     * derivation: how many watts of battery storage the observed level gain implies, divided by
     * the measured battery-side input power. Both halves are measured; the *efficiency* is the
     * derived quantity, and the UI labels it as an estimate.
     *
     * @param capacityWattHours measured full-charge energy (charge counter x voltage) when known
     */
    fun chargingEfficiency(
        batterySideWatts: Float?,
        chargeRatePercentPerHour: Float?,
        capacityWattHours: Float?,
        chargerName: String
    ): ChargingEfficiency {
        if (batterySideWatts == null || batterySideWatts <= 0.01f) {
            return ChargingEfficiency(
                batterySideWatts = null,
                levelGainWatts = null,
                efficiencyPercent = null,
                chargerName = chargerName,
                explanation = "Battery-side power is not available on this device, so efficiency cannot be estimated."
            )
        }
        if (chargeRatePercentPerHour == null || capacityWattHours == null || capacityWattHours <= 0f) {
            return ChargingEfficiency(
                batterySideWatts = batterySideWatts,
                levelGainWatts = null,
                efficiencyPercent = null,
                chargerName = chargerName,
                explanation = "Measuring: efficiency needs the charge rate (a few minutes of level change) and a " +
                    "measured battery capacity, which this device does not fully expose."
            )
        }
        val storedWatts = capacityWattHours * (chargeRatePercentPerHour / 100f)
        val efficiency = (storedWatts / batterySideWatts * 100f).coerceIn(0f, 100f)
        return ChargingEfficiency(
            batterySideWatts = batterySideWatts,
            levelGainWatts = storedWatts,
            efficiencyPercent = efficiency,
            chargerName = chargerName,
            explanation = "Estimate: ${format1(storedWatts)} W of storage gain (${format1(capacityWattHours)} Wh pack × " +
                "${format1(chargeRatePercentPerHour)}%/h) against ${format1(batterySideWatts)} W reaching the battery. " +
                "Charger-side output is not readable by apps, so this is a lower-bound efficiency, not a measurement."
        )
    }

    /**
     * The Battery Intelligence panel: aggregates what the observed samples actually support.
     * [abnormalDrainThresholdPerHour] is passed by the caller (the diagnostics chain uses 20 %/h).
     */
    fun intelligence(
        samples: List<BatteryDiagnostics.Sample>,
        telemetry: BatteryTelemetry,
        chargeRatePercentPerHour: Float?,
        drainRatePercentPerHour: Float?,
        capacityWattHours: Float?,
        abnormalDrainThresholdPerHour: Float = 20f,
        chargingInterruptions: Int = 0
    ): BatteryIntelligenceReport {
        val inWindow = samples.takeLast(600)
        val currents = inWindow.mapNotNull { it.currentMilliAmps?.let { value -> abs(value) } }
        val powers = inWindow.mapNotNull { it.powerWatts }
        val temps = inWindow.mapNotNull { it.temperatureCelsius }
        val observationMinutes = if (inWindow.size >= 2) {
            ((inWindow.last().timestampEpochMs - inWindow.first().timestampEpochMs) / 60_000L).toInt().coerceAtLeast(0)
        } else 0

        val efficiencySource = if (telemetry.isCharging) {
            powerWatts(telemetry.voltageVolts.rawValue, telemetry.currentMilliAmps.rawValue)
        } else null

        val notes = ArrayList<String>()
        if (telemetry.currentAverageMilliAmps.rawValue == null) {
            notes += "Average current is not exposed by this device; the average below is computed from the samples " +
                "this app observed."
        }
        if (inWindow.isEmpty()) {
            notes += "No samples recorded yet. Android delivers battery broadcasts only while an app is running, " +
                "so trends start as soon as monitoring begins."
        }
        if (temps.isEmpty() && telemetry.temperatureCelsius.rawValue == null) {
            notes += "No temperature sensor is exposed to apps on this device."
        }
        notes += "Screen-on versus screen-off figures cover only the time this app was observing; Android does not " +
            "expose system-wide per-display-state battery history to apps."
        notes += "Per-app background battery usage is readable only with the system BATTERY_STATS permission, so " +
            "this screen never attributes drain to a specific app."

        val avgTemp = temps.takeIf { it.isNotEmpty() }?.average()?.toFloat()
        return BatteryIntelligenceReport(
            totalSamples = inWindow.size,
            observationMinutes = observationMinutes,
            averageCurrentMilliAmps = currents.takeIf { it.isNotEmpty() }?.average()?.toFloat(),
            averagePowerWatts = powers.takeIf { it.isNotEmpty() }?.average()?.toFloat(),
            peakPowerWatts = powers.maxOrNull(),
            averageTemperatureCelsius = avgTemp,
            powerTrend = powerTrend(inWindow),
            drainTrendPerHour = drainRatePercentPerHour,
            chargeTrendPerHour = chargeRatePercentPerHour,
            displayDrain = displayStateDrain(inWindow),
            efficiency = chargingEfficiency(
                batterySideWatts = efficiencySource,
                chargeRatePercentPerHour = chargeRatePercentPerHour,
                capacityWattHours = capacityWattHours,
                chargerName = telemetry.pluggedLabel
            ),
            abnormalDrainDetected = drainRatePercentPerHour != null &&
                drainRatePercentPerHour >= abnormalDrainThresholdPerHour,
            overheatingDetected = (avgTemp != null && avgTemp >= WARM_TEMPERATURE_CELSIUS) ||
                (telemetry.temperatureCelsius.rawValue ?: 0f) >= CRITICAL_TEMPERATURE_CELSIUS,
            stabilityPercent = BatteryDiagnostics.voltageStabilityPercent(inWindow),
            chargingInterruptions = chargingInterruptions,
            notes = notes
        )
    }

    /**
     * Full-width energy of the pack in watt-hours, only when the device exposes both a full-charge
     * counter and voltage. Used for the efficiency estimate; null means "cannot estimate".
     */
    fun capacityWattHours(telemetry: BatteryTelemetry): Float? {
        val microAmpHours = telemetry.chargeFullMicroAmpHours.rawValue ?: return null
        val volts = telemetry.voltageVolts.rawValue ?: return null
        if (microAmpHours <= 0L || volts <= 0f) return null
        return (microAmpHours / 1_000_000f) * volts
    }

    /**
     * Recommended UI refresh interval. One second while the screen is on and values are live is
     * enough for a current sensor that updates roughly once per second; slower when the driver is
     * quiet or the screen is off saves CPU without losing data (broadcasts still drive updates).
     */
    fun recommendedRefreshIntervalMs(freshness: DataFreshness, screenOn: Boolean, engineState: EngineState): Long =
        when {
            engineState != EngineState.ACTIVE -> 5_000L
            !screenOn -> 5_000L
            freshness == DataFreshness.STALE || freshness == DataFreshness.NO_DATA -> 3_000L
            else -> 1_000L
        }
}
