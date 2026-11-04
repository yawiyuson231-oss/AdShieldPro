package com.adshield.pro.engine.optimizer

import android.content.Context
import android.content.Intent
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import com.adshield.pro.domain.model.MeasurementSource
import java.io.File
import java.util.Locale

/**
 * Reads the parts of battery telemetry that Android does not hand over directly.
 *
 * Three things are commonly reported wrong by other battery apps, and each is
 * handled explicitly here instead of being guessed:
 *
 *  1. **Temperature.** `EXTRA_TEMPERATURE` is the *battery cell*, not the SoC. On a
 *     gaming phone the cell can read 34 °C while the chip is at 60 °C. Both are
 *     reported, and each says which sensor it came from.
 *  2. **Current.** `BatteryManager` exposes `BATTERY_PROPERTY_CURRENT_NOW` (instant)
 *     and `BATTERY_PROPERTY_CURRENT_AVERAGE` (window average), and they disagree on
 *     which way the sign points: some devices report positive while discharging.
 *     Each candidate is range-checked against the known charging state and
 *     normalised to the app's convention:
 *     **negative = discharging, positive = charging**.
 *  3. **Power.** Watts are derived as voltage x current and only shown when both
 *     inputs were actually measured; a derived number from a placeholder is worse
 *     than showing nothing.
 *
 * Nothing here is estimated from a "typical" device. When the platform will not
 * report a value, the result says `UNAVAILABLE` rather than inventing one.
 */
object BatteryTelemetry {

    /** Sanity bounds. A phone battery outside these is reporting garbage, not a reading. */
    private const val MIN_PLAUSIBLE_MILLIAMPS = 20
    private const val MAX_PLAUSIBLE_MILLIAMPS = 20_000
    private const val MIN_PLAUSIBLE_MILLIVOLTS = 2_000
    private const val MAX_PLAUSIBLE_MILLIVOLTS = 6_000

    /**
     * Thermal-zone names that report the SoC / skin temperature. Ordered by how
     * useful the reading is. Deliberately excludes `battery` (that is the cell, and
     * is already read from the battery extra) and GPU-only zones.
     */
    private val SOC_ZONE_PRIORITY = listOf(
        "soc_thermal", "soc-thermal", "soc",
        "cpu-0-0", "cpu-0-1", "cpu0", "cpu-0",
        "apc", "cluster", "big", "little",
        "skin", "xo_therm", "quiet_therm", "pa_therm0", "tsens_tz_sensor0"
    )

    data class CurrentReading(val milliAmps: Int, val source: MeasurementSource, val label: String)

    /**
     * Reads the instantaneous current and normalises it so that **negative means
     * discharging**. Returns `UNAVAILABLE` instead of 0 when no extra is plausible,
     * so the UI can say "not reported" rather than showing a fake 0 mA.
     */
    fun readCurrent(context: Context, isCharging: Boolean): CurrentReading {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            ?: return CurrentReading(0, MeasurementSource.UNAVAILABLE, "Not reported by this device")

        val candidates = listOf<Pair<Int, String>>(
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) to "System current_now (instant)",
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE) to "System current_average (window)"
        )

        val chosen = candidates.firstOrNull { (raw, _) ->
            raw != Int.MIN_VALUE && raw != 0 && kotlin.math.abs(raw) in MIN_PLAUSIBLE_MILLIAMPS..MAX_PLAUSIBLE_MILLIAMPS
        } ?: return CurrentReading(0, MeasurementSource.UNAVAILABLE, "Not reported by this device")

        val (raw, label) = chosen
        // Averages can arrive in microamps on a handful of devices; a "15 mA" phone
        // sitting at 3000 mV charging at 1.5 mA is really 1.5 A.
        val milliAmps = if (kotlin.math.abs(raw) < MIN_PLAUSIBLE_MILLIAMPS) raw / 1000 else raw

        // Normalise the sign against the charging state we can trust.
        val discharging = milliAmps < 0
        val signFlipped = if (isCharging) {
            // Charging but the reading says "negative"? This device uses the
            // opposite convention, or it is a momentary dip. Flip to our convention.
            discharging
        } else {
            // Not charging, so the current must be out of the battery.
            !discharging
        }
        val normalised = if (signFlipped) -milliAmps else milliAmps

        return CurrentReading(normalised, MeasurementSource.MEASURED, label)
    }

    /**
     * Reads the SoC / skin temperature from sysfs thermal zones.
     *
     * This is the *only* source of chip temperature available to a normal app; there
     * is no public API for it. Many OEMs restrict `/sys/class/thermal` on newer
     * Android versions, so a null return is normal and is surfaced as
     * "Unavailable on this device" instead of being papered over with the battery
     * temperature.
     */
    fun readSocTemperature(): Pair<Float, String>? {
        val zones = readThermalZones()
        if (zones.isEmpty()) return null

        fun nameScore(name: String): Int {
            val lower = name.lowercase(Locale.US)
            val index = SOC_ZONE_PRIORITY.indexOfFirst { lower == it || lower.contains(it) }
            return if (index >= 0) SOC_ZONE_PRIORITY.size - index else -1
        }

        val best = zones
            .filter { it.second in 1.0f..125.0f } // discard disabled/unreadable zones
            .maxByOrNull { nameScore(it.first) }
            ?: return null

        // A zone that is obviously not a temperature reading (0, or a raw ADC value)
        // must not be shown as one.
        if (nameScore(best.first) < 0) return null
        return best.second to describeZone(best.first)
    }

    /** Thermal zones that the platform exposes, as `name -> degrees Celsius`. */
    private fun readThermalZones(): List<Pair<String, Float>> {
        val root = File("/sys/class/thermal")
        val dirs = runCatching { root.listFiles { f -> f.name.startsWith("thermal_zone") } }
            .getOrNull() ?: return emptyList()

        return dirs.mapNotNull { dir ->
            val raw = runCatching { File(dir, "temp").readText().trim().toLongOrNull() }.getOrNull()
                ?: return@mapNotNull null
            val type = runCatching { File(dir, "type").readText().trim() }.getOrNull()
                ?: dir.name
            // Kernel convention is millidegrees; a few devices report whole degrees.
            val celsius = if (kotlin.math.abs(raw) > 1_000) raw / 1000f else raw.toFloat()
            type to celsius
        }
    }

    /** Turns a kernel zone name into something a person can read. */
    private fun describeZone(zone: String): String {
        val lower = zone.lowercase(Locale.US)
        return when {
            lower.contains("soc") -> "SoC thermal zone ($zone)"
            lower.contains("cpu") || lower.contains("cluster") || lower.contains("big") ||
                lower.contains("little") -> "CPU thermal zone ($zone)"
            lower.contains("skin") -> "Device skin sensor ($zone)"
            lower.contains("gpu") -> "GPU thermal zone ($zone)"
            else -> "Thermal zone $zone"
        }
    }

    /**
     * Instantaneous power in mW, or null when either input is missing.
     *
     * Derived, never guessed: `P = V x I`. This is the number that makes a
     * "mAh added per hour" claim checkable.
     */
    fun computePowerMilliWatts(voltageMillivolts: Int, currentMilliAmps: Int, currentMeasured: Boolean): Int? {
        if (!currentMeasured) return null
        if (voltageMillivolts !in MIN_PLAUSIBLE_MILLIVOLTS..MAX_PLAUSIBLE_MILLIVOLTS) return null
        return ((voltageMillivolts.toLong() * currentMilliAmps) / 1000L).toInt()
    }

    /**
     * Remaining charge in mAh from the platform's charge counter, or null.
     *
     * `BATTERY_PROPERTY_CHARGE_COUNTER` is microamp-hours. It is not implemented on
     * every device and some OEMs return 0, which is indistinguishable from a flat
     * battery, so 0 is treated as unavailable.
     */
    fun readChargeCounterMilliAmpHours(context: Context): Long? {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return null
        val microAmpHours = bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)
        if (microAmpHours <= 0) return null
        return microAmpHours / 1000L
    }

    /** Energy in mWh = charge (mAh) x voltage (V). Null when either side is missing. */
    fun computeEnergyMilliWattHours(chargeMilliAmpHours: Long?, voltageMillivolts: Int): Long? {
        if (chargeMilliAmpHours == null) return null
        if (voltageMillivolts !in MIN_PLAUSIBLE_MILLIVOLTS..MAX_PLAUSIBLE_MILLIVOLTS) return null
        return chargeMilliAmpHours * voltageMillivolts / 1000L
    }

    /** True when the battery extra carried a real temperature rather than the fallback. */
    fun isTemperatureExtraPresent(intent: Intent?): Boolean {
        if (intent == null) return false
        if (!intent.hasExtra(BatteryManager.EXTRA_TEMPERATURE)) return false
        val tenths = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
        return tenths != Int.MIN_VALUE && tenths in 0..800
    }

    /** Coarse platform throttling state, used to sanity-check a sysfs reading. */
    fun thermalStatus(context: Context): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return PowerManager.THERMAL_STATUS_NONE
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return PowerManager.THERMAL_STATUS_NONE
        return runCatching { pm.currentThermalStatus }.getOrDefault(PowerManager.THERMAL_STATUS_NONE)
    }

}
