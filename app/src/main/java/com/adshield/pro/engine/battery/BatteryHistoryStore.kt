package com.adshield.pro.engine.battery

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Rolling history that survives a process restart.
 *
 * [BatteryMonitoringEngine] keeps a high-resolution in-memory ring for the live charts. That ring
 * is lost when Android kills the process, so every [PERSIST_SPACING_MS] the engine also appends a
 * coarser point here. On the next launch the charts start with real, previously measured history
 * instead of an empty graph.
 *
 * Nothing leaves the device; the file lives in app-private SharedPreferences.
 */
@Singleton
class BatteryHistoryStore @Inject constructor(
    @ApplicationContext context: Context
) {
    @Serializable
    data class StoredSample(
        val t: Long,
        val level: Int? = null,
        val charging: Boolean = false,
        val temperature: Float? = null,
        val voltage: Float? = null,
        val current: Int? = null,
        val power: Float? = null,
        val screenOn: Boolean? = null
    )

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = false }
    private val prefs = context.getSharedPreferences("adshield_battery_history", Context.MODE_PRIVATE)

    fun load(): List<BatteryDiagnostics.Sample> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        return runCatching {
            json.decodeFromString<List<StoredSample>>(raw).map {
                BatteryDiagnostics.Sample(
                    timestampEpochMs = it.t,
                    levelPercent = it.level,
                    isCharging = it.charging,
                    temperatureCelsius = it.temperature,
                    voltageVolts = it.voltage,
                    currentMilliAmps = it.current,
                    powerWatts = it.power,
                    screenOn = it.screenOn
                )
            }
        }.getOrDefault(emptyList())
    }

    /** Appends one point, keeping only the newest [MAX_SAMPLES]. */
    fun append(sample: BatteryDiagnostics.Sample, existing: List<BatteryDiagnostics.Sample>): List<BatteryDiagnostics.Sample> {
        val stored = existing.takeLast(MAX_SAMPLES - 1).map { it.toStored() } + sample.toStored()
        runCatching { prefs.edit().putString(KEY, json.encodeToString(stored)).apply() }
        return existing.takeLast(MAX_SAMPLES - 1) + sample
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
    }

    private fun BatteryDiagnostics.Sample.toStored() = StoredSample(
        t = timestampEpochMs,
        level = levelPercent,
        charging = isCharging,
        temperature = temperatureCelsius,
        voltage = voltageVolts,
        current = currentMilliAmps,
        power = powerWatts,
        screenOn = screenOn
    )

    companion object {
        private const val KEY = "history_v1"
        /** 720 points at 30 s spacing = 6 hours of real history across launches. */
        const val MAX_SAMPLES = 720
        const val PERSIST_SPACING_MS = 30_000L
    }
}
