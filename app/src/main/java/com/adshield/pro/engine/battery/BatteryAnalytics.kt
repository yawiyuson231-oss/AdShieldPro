package com.adshield.pro.engine.battery

import kotlin.math.abs

/**
 * OmniShield X Infinity — Battery Intelligence (Pure Kotlin, unit-testable).
 *
 * Real battery science, not fake percentages:
 * - Drain-rate estimation from rolling level samples (linear regression on discharge phase).
 * - Time-to-empty / time-to-full projections from the measured rate, not fixed tables.
 * - Health scoring from cycle count, temperature behavior, and voltage sag.
 * - Actionable power recommendations driven by measured conditions.
 */
object BatteryAnalytics {

    data class BatterySample(
        val timestampEpochMs: Long,
        val levelPercent: Int,
        val isCharging: Boolean,
        val temperatureCelsius: Float
    )

    data class DrainAnalysis(
        val drainPercentPerHour: Float,
        val sampleCount: Int,
        val isReliable: Boolean,
        val estimatedMinutesToEmpty: Int?,
        val projectedScreenOnHours: Float?
    )

    data class HealthReport(
        val healthScore: Int, // 0..100
        val label: String,
        val cycleCount: Int?,
        val findings: List<String>
    )

    /**
     * Estimates battery drain (%/hour) using least-squares regression over discharging samples.
     * Returns an unreliable zero analysis when fewer than 3 discharging samples exist or the
     * window is too short (< 8 minutes).
     */
    fun analyzeDrain(samples: List<BatterySample>): DrainAnalysis {
        val discharging = samples
            .filter { !it.isCharging && it.levelPercent in 0..100 }
            .sortedBy { it.timestampEpochMs }
        if (discharging.size < 3) {
            return DrainAnalysis(0f, discharging.size, isReliable = false, null, null)
        }
        val windowMs = discharging.last().timestampEpochMs - discharging.first().timestampEpochMs
        if (windowMs < 8L * 60 * 1000) {
            return DrainAnalysis(0f, discharging.size, isReliable = false, null, null)
        }

        // Least squares: level = a * hours + b
        val x0 = discharging.first().timestampEpochMs
        var sx = 0.0; var sy = 0.0; var sxx = 0.0; var sxy = 0.0
        val n = discharging.size
        for (s in discharging) {
            val x = (s.timestampEpochMs - x0) / 3_600_000.0
            val y = s.levelPercent.toDouble()
            sx += x; sy += y; sxx += x * x; sxy += x * y
        }
        val denominator = n * sxx - sx * sx
        val slopePerHour = if (abs(denominator) < 1e-9) 0.0 else (n * sxy - sx * sy) / denominator
        val drainPerHour = (-slopePerHour).toFloat().coerceIn(0f, 150f)

        val reliable = drainPerHour > 0.5f
        val currentLevel = discharging.last().levelPercent
        val minutesToEmpty = if (reliable && drainPerHour > 0.2f) {
            ((currentLevel / drainPerHour) * 60f).toInt().coerceIn(0, 24 * 60)
        } else null
        // Typical phone screen-on drain ≈ measured drain while screen on; report measured figure
        val projected = if (reliable) drainPerHour else null

        return DrainAnalysis(
            drainPercentPerHour = drainPerHour,
            sampleCount = n,
            isReliable = reliable,
            estimatedMinutesToEmpty = minutesToEmpty,
            projectedScreenOnHours = projected?.takeIf { it > 0f }?.let { currentLevel / it }
        )
    }

    /**
     * Estimates minutes until fully charged given the current charge rate samples.
     */
    fun estimateMinutesToFull(levelPercent: Int, chargePercentPerHour: Float): Int? {
        if (chargePercentPerHour <= 1f || levelPercent >= 100) return null
        val remaining = (100 - levelPercent).coerceAtLeast(0)
        // Charging slows down past 80% (taper phase) — model it honestly
        val fastPortion = (80 - levelPercent).coerceAtLeast(0)
        val slowPortion = (levelPercent - 80).coerceAtLeast(0).coerceAtMost(20)
        val hours = (fastPortion / chargePercentPerHour) + (slowPortion / (chargePercentPerHour * 0.45f))
        return (hours * 60f).toInt().coerceAtLeast(1)
    }

    /**
     * Battery health score from cycle count, thermal behavior, and voltage.
     */
    fun assessHealth(
        cycleCount: Int?,
        averageTemperatureCelsius: Float?,
        maxObservedTemperatureCelsius: Float?,
        voltageMillivolts: Int?,
        isChargingNow: Boolean
    ): HealthReport {
        var score = 100
        val findings = ArrayList<String>()

        if (cycleCount != null) {
            when {
                cycleCount >= 1000 -> { score -= 30; findings.add("High cycle count ($cycleCount cycles) — expect reduced capacity vs factory rating") }
                cycleCount >= 600 -> { score -= 18; findings.add("Moderate cycle wear ($cycleCount cycles)") }
                cycleCount >= 300 -> { score -= 8; findings.add("Light cycle wear ($cycleCount cycles)") }
                else -> findings.add("Battery has low cycle wear ($cycleCount cycles)")
            }
        }
        if (averageTemperatureCelsius != null && averageTemperatureCelsius >= 40f) {
            score -= 15
            findings.add("Sustained high battery temperature (${averageTemperatureCelsius}°C avg) accelerates aging — avoid charging while gaming")
        } else if (averageTemperatureCelsius != null && averageTemperatureCelsius >= 37f) {
            score -= 6
            findings.add("Elevated battery temperature (${averageTemperatureCelsius}°C avg)")
        }
        if (maxObservedTemperatureCelsius != null && maxObservedTemperatureCelsius >= 45f) {
            score -= 10
            findings.add("Heat spikes up to ${maxObservedTemperatureCelsius}°C detected")
        }
        if (voltageMillivolts != null && voltageMillivolts in 1..9999 && !isChargingNow) {
            if (voltageMillivolts < 3400) {
                score -= 8
                findings.add("Resting voltage ${voltageMillivolts}mV is low — deep discharge habit detected; charge before 20%")
            }
        }
        if (isChargingNow && (averageTemperatureCelsius ?: 0f) >= 42f) {
            findings.add("Charging while hot — this combination degrades lithium cells fastest")
        }
        if (findings.isEmpty()) findings.add("No wear indicators detected — battery is in good condition")

        score = score.coerceIn(5, 100)
        val label = when {
            score >= 85 -> "Excellent"
            score >= 70 -> "Good"
            score >= 50 -> "Fair"
            else -> "Degraded"
        }
        return HealthReport(score, label, cycleCount, findings)
    }

    /**
     * Honest, actionable power-saving recommendations from measured state.
     */
    fun buildPowerRecommendations(
        batteryPercent: Int,
        temperatureCelsius: Float,
        isCharging: Boolean,
        drainPercentPerHour: Float,
        isPowerSaveModeOn: Boolean
    ): List<String> {
        val recs = ArrayList<String>()
        if (isCharging) {
            if (temperatureCelsius >= 40f) {
                recs.add("Unplug until temperature drops below 38°C — charging hot batteries permanently reduces capacity")
            }
            if (batteryPercent >= 80) {
                recs.add("Battery at $batteryPercent% — for longest cell life, unplug now; lithium batteries age fastest held at 100%")
            }
            if (batteryPercent <= 15) {
                recs.add("Deep discharges stress the cell — avoid regularly draining below 20%")
            }
        } else {
            if (batteryPercent <= 20 && !isPowerSaveModeOn) {
                recs.add("Enable Android Battery Saver now — $batteryPercent% remaining")
            }
            if (drainPercentPerHour >= 15f) {
                recs.add("Unusually fast drain measured (${(drainPercentPerHour * 10).toInt() / 10.0f}%/h) — check Background apps in the Security tab and enable Extreme Saver")
            }
            if (temperatureCelsius >= 43f) {
                recs.add("Battery is hot (${temperatureCelsius}°C) — close games and let it cool; heat is the #1 battery killer")
            }
            if (batteryPercent in 81..100) {
                recs.add("Optimal zone: unplug from charger at 80–90% for maximum battery lifespan")
            }
        }
        if (recs.isEmpty()) recs.add("Battery usage is in a healthy range right now")
        return recs
    }
}
