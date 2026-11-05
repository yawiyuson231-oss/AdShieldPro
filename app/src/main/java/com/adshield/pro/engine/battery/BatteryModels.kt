package com.adshield.pro.engine.battery

/**
 * Where a displayed battery value comes from. Every reading surfaced in the UI carries one of
 * these, so the Battery Intelligence screen can never present an estimate as a measurement.
 */
enum class BatteryReadingSource {
    /** Read directly from Android / the battery driver on this device. */
    HARDWARE,
    /** Derived from hardware readings (power = V x I, °F from °C, runtime from measured rate). */
    COMPUTED,
    /** Statistical estimate (e.g. time to full from observed charging rate). */
    ESTIMATED,
    /** The device does not expose this value to apps. */
    UNSUPPORTED,
    /** Supported in principle, but no reading was available at this moment. */
    UNAVAILABLE
}

/**
 * One measured/derived value with its provenance and unit.
 * [rawValue] is null whenever the source is UNSUPPORTED or UNAVAILABLE.
 */
data class BatteryReading<T>(
    val rawValue: T?,
    val source: BatteryReadingSource,
    val unit: String,
    val detail: String = ""
) {
    val isMeasured: Boolean get() = rawValue != null && (source == BatteryReadingSource.HARDWARE || source == BatteryReadingSource.COMPUTED)
    val label: String
        get() = when (source) {
            BatteryReadingSource.HARDWARE -> "Measured"
            BatteryReadingSource.COMPUTED -> "Computed"
            BatteryReadingSource.ESTIMATED -> "Estimated"
            BatteryReadingSource.UNSUPPORTED -> "Not supported on this device"
            BatteryReadingSource.UNAVAILABLE -> "Unavailable right now"
        }

    companion object {
        fun <T> measured(value: T, unit: String, detail: String = "") =
            BatteryReading(value, BatteryReadingSource.HARDWARE, unit, detail)

        fun <T> computed(value: T?, unit: String, detail: String = "") =
            if (value == null) unavailable(unit, detail) else BatteryReading(value, BatteryReadingSource.COMPUTED, unit, detail)

        fun <T> estimated(value: T?, unit: String, detail: String = "") =
            if (value == null) unavailable(unit, detail) else BatteryReading(value, BatteryReadingSource.ESTIMATED, unit, detail)

        fun <T> unsupported(unit: String, detail: String = "") =
            BatteryReading<T>(null, BatteryReadingSource.UNSUPPORTED, unit, detail)

        fun <T> unavailable(unit: String, detail: String = "") =
            BatteryReading<T>(null, BatteryReadingSource.UNAVAILABLE, unit, detail)
    }
}

/**
 * Android's reported battery health status, mapped to an enum so the diagnostics engine stays
 * pure Kotlin (android.os constants are meaningless in JVM unit tests).
 */
enum class BatteryHealthStatus { GOOD, OVERHEAT, DEAD, OVER_VOLTAGE, COLD, FAILURE, UNKNOWN }

/**
 * Charging source, mapped from ACTION_BATTERY_CHANGED's EXTRA_PLUGGED.
 *
 * [DOCK] exists only on API 33+, so it is mapped from the raw extra value rather than a
 * compile-time constant; older platforms simply never produce it.
 */
enum class ChargingSource(val label: String) {
    NOT_PLUGGED("Not plugged in"),
    AC("AC charger"),
    USB("USB port"),
    WIRELESS("Wireless charger"),
    DOCK("Dock"),
    UNKNOWN("Unknown source");

    companion object {
        /**
         * Maps `BatteryManager.EXTRA_PLUGGED` to a source. AC/USB/WIRELESS are documented
         * constants (1/2/4) that have never changed; DOCK is bit 8 (API 33+). Comparing the raw
         * integer avoids referencing a constant that does not exist on API 29.
         */
        fun fromRawPlugged(raw: Int): ChargingSource = when {
            raw and 1 != 0 -> AC
            raw and 2 != 0 -> USB
            raw and 4 != 0 -> WIRELESS
            raw and 8 != 0 -> DOCK
            raw == 0 -> NOT_PLUGGED
            else -> UNKNOWN
        }
    }
}

/** Full, timestamped snapshot of what this device actually reports. */
data class BatteryTelemetry(
    val timestampEpochMs: Long,
    val levelPercent: BatteryReading<Int>,
    val statusLabel: String,
    val isCharging: Boolean,
    val isFull: Boolean,
    val pluggedLabel: String,
    val pluggedRaw: Int,
    val temperatureCelsius: BatteryReading<Float>,
    val voltageVolts: BatteryReading<Float>,
    val currentMilliAmps: BatteryReading<Int>,
    val currentAverageMilliAmps: BatteryReading<Int>,
    val chargeCounterMicroAmpHours: BatteryReading<Long>,
    val powerWatts: BatteryReading<Float>,
    val healthLabel: String,
    val health: BatteryHealthStatus,
    val technology: String,
    val chargeTimeRemainingMinutes: BatteryReading<Int>,
    val runtimeRemainingMinutes: BatteryReading<Int>,
    val manufacturer: String,
    val model: String,
    val cycleCount: BatteryReading<Int>,
    val chargeFullDesignMicroAmpHours: BatteryReading<Long>,
    val chargeFullMicroAmpHours: BatteryReading<Long>,
    /** Current / average current sign convention: positive = charging, negative = discharging. */
    val currentSignKnown: Boolean,
    /**
     * Samples are only recorded while the app process is alive (Android does not let a normal app
     * listen to battery broadcasts while stopped), so rate/temperature history restarts on launch.
     * The UI states this instead of implying continuous background monitoring.
     */
    val historyCoverage: HistoryCoverage = HistoryCoverage.APP_FOREGROUND_ONLY,
    /**
     * Monotonic (SystemClock.elapsedRealtime) stamp of the read. Wall-clock time can jump when
     * the user or the network changes the timezone/NTP, which would make "freshness" lie; the
     * monotonic stamp cannot go backwards while the device is awake.
     */
    val elapsedRealtimeMs: Long = 0L,
    /** Source of charge, mapped from EXTRA_PLUGGED (AC / USB / wireless / dock). */
    val chargingSource: ChargingSource = ChargingSource.UNKNOWN
) {
    val temperatureFahrenheit: Float? get() = temperatureCelsius.rawValue?.let { it * 9f / 5f + 32f }

    /** Age of this snapshot against a monotonic `now`; never negative. */
    fun ageMs(nowElapsedRealtimeMs: Long): Long =
        (nowElapsedRealtimeMs - elapsedRealtimeMs).coerceAtLeast(0L)

    /** True when both halves of V x I are present, i.e. power can be computed at all. */
    val hasPowerInputs: Boolean
        get() = voltageVolts.rawValue != null && currentMilliAmps.rawValue != null

    // Nullable value helpers: the UI needs "is there a number?" without unwrapping each reading.
    val level: Int? get() = levelPercent.rawValue
    val voltage: Float? get() = voltageVolts.rawValue
    val current: Int? get() = currentMilliAmps.rawValue
    val averageCurrent: Int? get() = currentAverageMilliAmps.rawValue
    val temperature: Float? get() = temperatureCelsius.rawValue
    val power: Float? get() = powerWatts.rawValue
    val chargerMinutes: Int? get() = chargeTimeRemainingMinutes.rawValue
    val designCapacity: Long? get() = chargeFullDesignMicroAmpHours.rawValue
    val fullChargeCapacity: Long? get() = chargeFullMicroAmpHours.rawValue
    val cycles: Int? get() = cycleCount.rawValue

    /** Share of the design capacity Android currently believes is stored, when both are exposed. */
    val capacityHealthPercent: Float?
        get() {
            val full = chargeFullMicroAmpHours.rawValue ?: return null
            val design = chargeFullDesignMicroAmpHours.rawValue ?: return null
            if (full <= 0 || design <= 0) return null
            return (full.toFloat() / design.toFloat() * 100f).coerceIn(0f, 150f)
        }
}

/** How much of the device's battery timeline this app can actually observe. */
enum class HistoryCoverage { APP_FOREGROUND_ONLY }

/** Severity used by the diagnostics list. */
enum class BatteryDiagnosticSeverity { INFO, NOTICE, WARNING, CRITICAL }

/**
 * One explainable diagnostic. [confidencePercent] is how sure the rule chain is given the
 * evidence actually present; rules that fire on missing data are scored low on purpose.
 */
data class BatteryDiagnostic(
    val title: String,
    val explanation: String,
    val recommendation: String,
    val severity: BatteryDiagnosticSeverity,
    val confidencePercent: Int,
    val evidence: List<String>
) {
    val confidenceLabel: String
        get() = when {
            confidencePercent >= 85 -> "High confidence"
            confidencePercent >= 60 -> "Medium confidence"
            else -> "Low confidence — limited data"
        }
}

/** Persistent charging/discharging session, stored locally. */
data class BatterySession(
    val id: Long,
    val startedEpochMs: Long,
    val endedEpochMs: Long,
    val startLevelPercent: Int,
    val endLevelPercent: Int,
    val peakTemperatureCelsius: Float?,
    val averageVoltageVolts: Float?,
    val averageCurrentMilliAmps: Float?,
    val peakPowerWatts: Float?,
    val pluggedLabel: String,
    val wasCharging: Boolean,
    val interruptions: Int
) {
    val durationMinutes: Int get() = (((endedEpochMs - startedEpochMs) / 60_000L).toInt()).coerceAtLeast(0)
    val levelDelta: Int get() = endLevelPercent - startLevelPercent
    /** Average charging speed actually observed, %/hour. */
    val levelPercentPerHour: Float?
        get() {
            if (!wasCharging || durationMinutes < 10) return null
            return levelDelta.toFloat() / (durationMinutes / 60f)
        }
}

// ---------------------------------------------------------------------------------------------
// Monitoring engine state (latency-independent: all durations are supplied by the caller so the
// rules can be unit-tested without a clock).
// ---------------------------------------------------------------------------------------------

/** How old the newest hardware broadcast is, bucketed so the UI can colour it. */
enum class DataFreshness(val label: String) {
    /** Something arrived within the live window — the dashboard may call itself live. */
    LIVE("Live"),
    /** Between the live and stale windows: still real, but the driver has gone quiet. */
    DELAYED("Delayed"),
    /** Older than the stale window: values are shown but flagged as historical. */
    STALE("Stale"),
    /** Not a single broadcast has been received since the engine started. */
    NO_DATA("No data");

    companion object {
        /** Live window: 5 s, i.e. five missed one-second reads before we stop saying "live". */
        const val LIVE_WINDOW_MS = 5_000L
        /** Stale window: 30 s. */
        const val STALE_WINDOW_MS = 30_000L

        /**
         * Classifies an age in milliseconds. A negative age (clock moved backwards) is treated
         * as live rather than as an error: monotonic timestamps never go backwards in practice,
         * but the engine must not claim "no data" if a vendor RTC does.
         */
        fun of(ageMs: Long?): DataFreshness = when {
            ageMs == null -> NO_DATA
            ageMs <= LIVE_WINDOW_MS -> LIVE
            ageMs <= STALE_WINDOW_MS -> DELAYED
            else -> STALE
        }
    }
}

/** Condition of one individual hardware input, as this device actually exposes it. */
enum class SensorState(val label: String) {
    OPERATIONAL("Operational"),
    DELAYED("Delayed"),
    UNSUPPORTED("Unsupported"),
    UNAVAILABLE("Unavailable"),
    INVALID("Invalid reading"),
    WAITING("Waiting for data")
}

/** One row of the Sensor Diagnostics panel. */
data class SensorStatus(
    val name: String,
    val state: SensorState,
    /** The API or property behind this sensor; shown verbatim so it can be verified. */
    val source: String,
    val detail: String,
    /** True when the value shown by this sensor is a measurement rather than a computation. */
    val measured: Boolean,
    /** Exactly what the diagnostics table prints for this sensor, e.g. "4.21 V" or "—". */
    val statusValue: String = "—"
) {
    val isUsable: Boolean get() = state == SensorState.OPERATIONAL || state == SensorState.DELAYED
}

/** Real status of each monitoring component (section 8 of the directive). */
enum class MonitoringState(val label: String) {
    OPERATIONAL("Operational"),
    ACTIVE("Active"),
    PAUSED("Paused"),
    PARTIAL("Partial"),
    WAITING("Waiting for data"),
    UNSUPPORTED("Unsupported"),
    ERROR("Error"),
    UNAVAILABLE("Unavailable")
}

/**
 * How much the displayed measurement can be trusted, derived from freshness *and* sensor coverage.
 * Deliberately coarse: a dashboard that prints "97% reliable" would be inventing precision.
 */
enum class MeasurementReliability(val label: String) {
    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low"),
    NONE("None")
}

/** Heartbeat state of the monitoring engine itself. */
enum class EngineState(val label: String) {
    ACTIVE("Active"),
    PAUSED("Paused"),
    STOPPED("Stopped"),
    ERROR("Error")
}

/**
 * A single component's live status. [value] is the human-readable current value or "-" when the
 * component has nothing to show, so the panel never renders an empty cell that looks like a zero.
 */
data class ComponentStatus(
    val component: String,
    val state: MonitoringState,
    val value: String,
    val detail: String
)

/**
 * The whole monitoring-system status block. [scorePercent] counts operational components so the
 * header can show "Monitoring system: 94%" without inventing a health number.
 */
data class MonitoringStatus(
    val batteryApi: ComponentStatus,
    val currentSensor: ComponentStatus,
    val voltageSensor: ComponentStatus,
    val temperatureSensor: ComponentStatus,
    val powerCalculation: ComponentStatus,
    val engine: ComponentStatus,
    val freshness: DataFreshness,
    val overall: MonitoringState,
    val scorePercent: Int,
    val components: List<ComponentStatus>,
    /** Trust level for the numbers on screen, from freshness plus how many sensors answered. */
    val reliability: MeasurementReliability = MeasurementReliability.NONE,
    /** One sentence explaining [reliability], printed under the panel. */
    val reliabilityDetail: String = ""
)

/**
 * High-level battery condition derived only from measured state. This is what the dashboard's
 * large status line renders; [detail] always names the evidence behind it.
 */
enum class BatteryCondition(val label: String) {
    CHARGING("Charging"),
    FAST_CHARGING("Fast charging"),
    SLOW_CHARGING("Slow charging"),
    DISCHARGING("Discharging"),
    FULLY_CHARGED("Fully charged"),
    NOT_CHARGING("Not charging"),
    CONNECTED_NOT_CHARGING("Connected, not charging"),
    HIGH_POWER_DRAIN("High power consumption"),
    TEMPERATURE_WARNING("Abnormal temperature"),
    HEALTH_WARNING("Battery health warning"),
    INSUFFICIENT_DATA("Insufficient sensor information")
}

/** Severity derived from a [BatteryCondition] so the UI can pick an accent without duplicating rules. */
enum class BatteryConditionTone { NOMINAL, POSITIVE, CAUTION, CRITICAL, NEUTRAL }

/**
 * The result of the status engine. [estimatesOnlyFromMeasurements] documents that any projection
 * inside [detail] was extrapolated from measured rates rather than assumed.
 */
data class BatteryStatusReport(
    val primary: BatteryCondition,
    val secondary: List<BatteryCondition>,
    val tone: BatteryConditionTone,
    val headline: String,
    val detail: String,
    val evidence: List<String>,
    val fastChargeDetected: Boolean,
    val usableSensors: Int,
    val totalSensors: Int
)

/** Trend of power consumption over the observed window. */
enum class PowerTrend(val label: String) {
    RISING("Rising"),
    FALLING("Falling"),
    STEADY("Steady"),
    INSUFFICIENT_DATA("Insufficient data")
}

/** Charging efficiency estimate — explicitly an estimate, never a measurement. */
data class ChargingEfficiency(
    val batterySideWatts: Float?,
    val levelGainWatts: Float?,
    val efficiencyPercent: Float?,
    val chargerName: String,
    val explanation: String
) {
    val isMeasured: Boolean get() = efficiencyPercent != null
}

/**
 * Screen-on versus screen-off drain analysis. Android does not expose per-display-state battery
 * history to apps, so the split is derived from samples recorded while this process observed the
 * display state — labelled as observed rather than system-wide.
 */
data class DisplayStateDrain(
    val screenOnSamples: Int,
    val screenOffSamples: Int,
    val screenOnAverageMilliAmps: Float?,
    val screenOffAverageMilliAmps: Float?,
    val screenOnMinutes: Int,
    val screenOffMinutes: Int
) {
    val hasComparison: Boolean
        get() = screenOnAverageMilliAmps != null && screenOffAverageMilliAmps != null &&
            screenOnSamples >= MIN_SAMPLES && screenOffSamples >= MIN_SAMPLES

    /** How much more power the screen-on state draws, as a multiple of screen-off. */
    val ratio: Float?
        get() {
            val on = screenOnAverageMilliAmps ?: return null
            val off = screenOffAverageMilliAmps?.takeIf { it > 1f } ?: return null
            return on / off
        }

    companion object {
        const val MIN_SAMPLES = 5
    }
}

/** What the battery intelligence panel shows; every field is either measured or clearly derived. */
data class BatteryIntelligenceReport(
    val totalSamples: Int,
    val observationMinutes: Int,
    val averageCurrentMilliAmps: Float?,
    val averagePowerWatts: Float?,
    val peakPowerWatts: Float?,
    val averageTemperatureCelsius: Float?,
    val powerTrend: PowerTrend,
    val drainTrendPerHour: Float?,
    val chargeTrendPerHour: Float?,
    val displayDrain: DisplayStateDrain,
    val efficiency: ChargingEfficiency,
    val abnormalDrainDetected: Boolean,
    val overheatingDetected: Boolean,
    /** Voltage-coefficient-of-variation across the observed window; null until 5 samples exist. */
    val stabilityPercent: Float? = null,
    /** Charging dropouts recorded in the current session (from real charging-state transitions). */
    val chargingInterruptions: Int = 0,
    val notes: List<String> = emptyList()
)
