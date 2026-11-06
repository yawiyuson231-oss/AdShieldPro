package com.adshield.pro.engine.location

import java.util.Locale
import kotlin.math.abs
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToLong
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * AdShield Pro — Safe GPS fix model and accuracy analysis.
 *
 * Pure Kotlin: no Android classes. Everything here is a function of the fixes a device actually
 * reported, so the numbers shown on screen can be re-derived and are covered by the JVM suite.
 *
 * WHAT "BETTER ACCURACY" CAN HONESTLY MEAN
 * -----------------------------------------
 * Android reports [android.location.Location.getAccuracy]: the radius (metres, 68 % confidence)
 * the device believes contains the true position. It is the device's own estimate. This module
 * can therefore only do three honest things:
 *
 *  1. keep sampling until the device itself reports a tighter radius (a cold GNSS receiver needs
 *     tens of seconds; one `getCurrentLocation` call is usually the worst fix of the session);
 *  2. prefer the tightest fix and a 1/accuracy^2 weighted centre, instead of one arbitrary reading;
 *  3. say plainly when fixes disagree, when accuracy stopped improving, when the platform flagged
 *     the fix as mocked, and when the reported number is coarse network positioning.
 *
 * It cannot recover precision the hardware never had, and it never guesses a position.
 */
data class GeoPoint(val latitude: Double, val longitude: Double)

/** Where the reading came from, as the platform reports it. */
enum class FixSource { GNSS, NETWORK, FUSED, UNKNOWN }

/**
 * One reading from the platform.
 *
 * @param accuracyMeters device-reported 68 % confidence radius
 * @param elapsedRealtimeMs monotonic timestamp — the only clock safe for movement maths
 * @param wallClockMs wall time, for display only
 * @param mock true when the platform says the fix is simulated (`Location.isMock`)
 */
data class LocationFix(
    val latitude: Double,
    val longitude: Double,
    val accuracyMeters: Double,
    val elapsedRealtimeMs: Long,
    val wallClockMs: Long,
    val altitudeMeters: Double? = null,
    val verticalAccuracyMeters: Double? = null,
    val speedMetersPerSecond: Float? = null,
    val source: FixSource = FixSource.UNKNOWN,
    val mock: Boolean = false
) {
    val point: GeoPoint get() = GeoPoint(latitude, longitude)
}

/** How much the fix set can be trusted, and in what sense. */
enum class LocationQuality { HIGH, MEDIUM, LOW, COARSE, NONE }

/** A pin rounded onto a grid so sharing it does not reveal a doorway. */
data class RoundedFix(
    val point: GeoPoint,
    val gridMeters: Int,
    val displacementMeters: Double,
    val worstCaseMeters: Double
)

data class LocationAnalysis(
    val count: Int = 0,
    val rejected: Int = 0,
    val best: LocationFix? = null,
    val latest: LocationFix? = null,
    val centroid: GeoPoint? = null,
    val median: GeoPoint? = null,
    val spreadMeters: Double? = null,
    val consistent: Boolean = false,
    val quality: LocationQuality = LocationQuality.NONE,
    val targetAccuracyMeters: Double = 10.0,
    val targetMet: Boolean = false,
    val bestAccuracyMeters: Double? = null,
    val firstAccuracyMeters: Double? = null,
    val latestAccuracyMeters: Double? = null,
    val improvementMeters: Double? = null,
    val improvementPercent: Double? = null,
    val averageAccuracyMeters: Double? = null,
    val impliedSpeedMetersPerSecond: Double? = null,
    val implausibleMovement: Boolean = false,
    val anyMocked: Boolean = false,
    val headline: String = "",
    val detail: String = ""
) {
    val hasFix: Boolean get() = best != null
    fun formatAccuracy(): String = LocationAnalyzer.formatMeters(bestAccuracyMeters)
}

object LocationAnalyzer {

    const val EARTH_RADIUS_METERS = 6_371_008.8
    const val MAX_ACCEPTED_ACCURACY_METERS = 20_000.0
    /** Faster than a commercial airliner between two fixes: implausible for a person. */
    const val IMPLAUSIBLE_SPEED_METERS_PER_SECOND = 250.0
    const val METERS_PER_DEGREE_LATITUDE = 111_320.0

    /** A fix is usable only when the numbers are real and inside the globe. */
    fun isUsable(fix: LocationFix?, maxAccuracyMeters: Double = MAX_ACCEPTED_ACCURACY_METERS): Boolean {
        if (fix == null) return false
        if (!fix.latitude.isFinite() || !fix.longitude.isFinite()) return false
        if (fix.latitude < -90.0 || fix.latitude > 90.0) return false
        if (fix.longitude < -180.0 || fix.longitude > 180.0) return false
        if (!fix.accuracyMeters.isFinite() || fix.accuracyMeters <= 0.0) return false
        return fix.accuracyMeters <= maxAccuracyMeters
    }

    fun haversineMeters(a: GeoPoint, b: GeoPoint): Double {
        val lat1 = Math.toRadians(a.latitude)
        val lat2 = Math.toRadians(b.latitude)
        val dLat = lat2 - lat1
        val dLon = Math.toRadians(b.longitude - a.longitude)
        val h = sin(dLat / 2) * sin(dLat / 2) + cos(lat1) * cos(lat2) * sin(dLon / 2) * sin(dLon / 2)
        return 2 * EARTH_RADIUS_METERS * asin(min(1.0, sqrt(h)))
    }

    /** Two accuracy circles can both be true only if they intersect. */
    fun circlesOverlap(a: LocationFix, b: LocationFix, slackMeters: Double = 0.0): Boolean {
        if (!isUsable(a) || !isUsable(b)) return false
        val distance = haversineMeters(a.point, b.point)
        return distance <= a.accuracyMeters + b.accuracyMeters + max(0.0, slackMeters)
    }

    /** 1/accuracy^2 weighting: a 5 m fix counts 100x a 50 m fix. */
    fun weightedCentroid(fixes: List<LocationFix>): GeoPoint? {
        val usable = fixes.filter { isUsable(it) }
        if (usable.isEmpty()) return null
        var weightSum = 0.0
        var latSum = 0.0
        var lonSum = 0.0
        for (fix in usable) {
            val weight = 1.0 / (fix.accuracyMeters * fix.accuracyMeters)
            weightSum += weight
            latSum += fix.latitude * weight
            lonSum += fix.longitude * weight
        }
        if (weightSum <= 0.0) return null
        return GeoPoint(latSum / weightSum, lonSum / weightSum)
    }

    /** The median position: one wild outlier cannot drag it. */
    fun medianPoint(fixes: List<LocationFix>): GeoPoint? {
        val usable = fixes.filter { isUsable(it) }
        if (usable.isEmpty()) return null
        return GeoPoint(median(usable.map { it.latitude }), median(usable.map { it.longitude }))
    }

    fun median(values: List<Double>): Double {
        val sorted = values.filter { it.isFinite() }.sorted()
        if (sorted.isEmpty()) return Double.NaN
        val mid = sorted.size / 2
        return if (sorted.size % 2 == 1) sorted[mid] else (sorted[mid - 1] + sorted[mid]) / 2.0
    }

    /** Tightest fix wins; ties resolve to the newer one. */
    fun bestFix(fixes: List<LocationFix>): LocationFix? {
        var best: LocationFix? = null
        for (fix in fixes) {
            if (!isUsable(fix)) continue
            val current = best
            if (current == null ||
                fix.accuracyMeters < current.accuracyMeters ||
                (fix.accuracyMeters == current.accuracyMeters && fix.elapsedRealtimeMs >= current.elapsedRealtimeMs)
            ) {
                best = fix
            }
        }
        return best
    }

    /** Implied movement between consecutive fixes, used as a plausibility hint only. */
    fun impliedSpeedMetersPerSecond(fixes: List<LocationFix>): Double? {
        if (fixes.size < 2) return null
        var worst: Double? = null
        for (index in 1 until fixes.size) {
            val previous = fixes[index - 1]
            val current = fixes[index]
            if (!isUsable(previous) || !isUsable(current)) continue
            val seconds = abs(current.elapsedRealtimeMs - previous.elapsedRealtimeMs) / 1000.0
            if (seconds < 0.5) continue
            val speed = haversineMeters(previous.point, current.point) / seconds
            if (worst == null || speed > worst) worst = speed
        }
        return worst
    }

    /**
     * Summarises a window of fixes.
     *
     * @param targetAccuracyMeters what the user asked for; only used to report whether it was met
     * @param maxAccuracyMeters fixes coarser than this are discarded, not averaged in
     * @param minSamples how many consistent fixes are needed before the quality can be HIGH
     */
    fun analyse(
        fixes: List<LocationFix>,
        targetAccuracyMeters: Double = 10.0,
        maxAccuracyMeters: Double = MAX_ACCEPTED_ACCURACY_METERS,
        minSamples: Int = 3
    ): LocationAnalysis {
        val usable = fixes.filter { isUsable(it, maxAccuracyMeters) }
        val rejected = fixes.size - usable.size
        if (usable.isEmpty()) {
            return LocationAnalysis(
                count = 0,
                rejected = rejected,
                targetAccuracyMeters = targetAccuracyMeters,
                quality = LocationQuality.NONE,
                headline = "No usable fix yet",
                detail = "The device has not reported a position accuracy it can stand behind."
            )
        }

        val best = bestFix(usable) ?: return LocationAnalysis(rejected = rejected)
        val latest = usable.last()
        val centroid = weightedCentroid(usable)
        val spread = centroid?.let { centre -> usable.maxOf { haversineMeters(centre, it.point) } }
        val consistent = spread == null || spread <= max(25.0, best.accuracyMeters + latest.accuracyMeters)
        val firstAccuracy = usable.first().accuracyMeters
        val improvement = firstAccuracy - best.accuracyMeters
        val improvementPercent = if (firstAccuracy > 0) improvement / firstAccuracy * 100.0 else null
        val speed = impliedSpeedMetersPerSecond(usable)
        val implausible = speed != null && speed > IMPLAUSIBLE_SPEED_METERS_PER_SECOND
        val mocked = usable.any { it.mock }

        val quality = when {
            !consistent -> LocationQuality.LOW
            mocked -> LocationQuality.LOW
            best.accuracyMeters <= 10.0 && usable.size >= minSamples -> LocationQuality.HIGH
            best.accuracyMeters <= 25.0 -> LocationQuality.MEDIUM
            best.accuracyMeters <= 100.0 -> LocationQuality.LOW
            else -> LocationQuality.COARSE
        }

        val headline = when {
            !consistent -> "Fixes disagree — no position trusted"
            mocked -> "Simulated fix reported by the platform"
            quality == LocationQuality.HIGH -> "Converged • ±${formatMeters(best.accuracyMeters)}"
            quality == LocationQuality.MEDIUM -> "Usable • ±${formatMeters(best.accuracyMeters)}"
            quality == LocationQuality.LOW -> "Coarse • ±${formatMeters(best.accuracyMeters)}"
            else -> "Very coarse • ±${formatMeters(best.accuracyMeters)}"
        }

        val detail = when {
            !consistent -> "Fixes disagree by up to ${formatMeters(spread)}. No position is accepted: move away " +
                "from tall buildings or the car park roof and try again."
            mocked -> "Android flagged this fix as simulated (a mock-location app is enabled in developer " +
                "options). Everything below is a test position, not where the phone is."
            implausible -> "Implied movement of ${speed!!.roundToLong()} m/s between fixes is not physically " +
                "plausible. Treat the pin as unverified."
            quality == LocationQuality.HIGH -> "Tight and repeatable across ${usable.size} fixes (target " +
                "±${formatMeters(targetAccuracyMeters)} met)."
            quality == LocationQuality.MEDIUM -> "Consistent. ±${formatMeters(targetAccuracyMeters)} usually needs " +
                "a longer satellite lock outdoors."
            quality == LocationQuality.LOW || quality == LocationQuality.COARSE -> if (best.source == FixSource.NETWORK) {
                "This is network positioning (Wi-Fi/cell), not satellites. Outdoor GNSS is required for a tighter pin."
            } else {
                "The device reports a coarse radius; waiting can still help if the sky view improves."
            }
            else -> "No usable satellite lock. Do not navigate from this pin."
        }

        return LocationAnalysis(
            count = usable.size,
            rejected = rejected,
            best = best,
            latest = latest,
            centroid = centroid,
            median = medianPoint(usable),
            spreadMeters = spread,
            consistent = consistent,
            quality = quality,
            targetAccuracyMeters = targetAccuracyMeters,
            targetMet = best.accuracyMeters <= targetAccuracyMeters,
            bestAccuracyMeters = best.accuracyMeters,
            firstAccuracyMeters = firstAccuracy,
            latestAccuracyMeters = latest.accuracyMeters,
            improvementMeters = improvement,
            improvementPercent = improvementPercent,
            averageAccuracyMeters = usable.map { it.accuracyMeters }.average(),
            impliedSpeedMetersPerSecond = speed,
            implausibleMovement = implausible,
            anyMocked = mocked,
            headline = headline,
            detail = detail
        )
    }

    /**
     * Snaps a position onto a grid of [gridMeters]. The returned displacement is measured, and
     * [RoundedFix.worstCaseMeters] is the geometric bound (half the cell diagonal).
     */
    fun round(fix: LocationFix, gridMeters: Int): RoundedFix? {
        if (!isUsable(fix)) return null
        val step = gridMeters.coerceIn(25, 5_000)
        val latStep = step / METERS_PER_DEGREE_LATITUDE
        val lonStep = step / (METERS_PER_DEGREE_LATITUDE * max(0.05, cos(Math.toRadians(fix.latitude))))
        val rounded = GeoPoint(
            latitude = Math.round(fix.latitude / latStep) * latStep,
            longitude = Math.round(fix.longitude / lonStep) * lonStep
        )
        return RoundedFix(
            point = rounded,
            gridMeters = step,
            displacementMeters = haversineMeters(fix.point, rounded),
            worstCaseMeters = step * sqrt(2.0) / 2.0
        )
    }

    /** "12 m", "1.4 km" — never a false precision. */
    fun formatMeters(meters: Double?): String {
        if (meters == null || !meters.isFinite()) return "—"
        if (meters < 1.0) return "<1 m"
        if (meters < 10.0) return String.format(Locale.US, "%.1f m", meters)
        if (meters < 1_000.0) return String.format(Locale.US, "%.0f m", meters)
        return String.format(Locale.US, "%.1f km", meters / 1_000.0)
    }

    /** Five decimals is about one metre; more would imply accuracy the device does not have. */
    fun formatCoordinates(latitude: Double, longitude: Double): String {
        if (!latitude.isFinite() || !longitude.isFinite()) return "—"
        return String.format(Locale.US, "%.5f, %.5f", latitude, longitude)
    }

    /** A sentence that survives being read aloud over a phone call. */
    fun spokenReference(fix: LocationFix?): String {
        if (fix == null || !isUsable(fix)) return "No position available."
        val northSouth = if (fix.latitude >= 0) "North" else "South"
        val eastWest = if (fix.longitude >= 0) "East" else "West"
        val accuracy = String.format(Locale.US, "%.0f", fix.accuracyMeters)
        return String.format(
            Locale.US,
            "%.5f degrees %s, %.5f degrees %s — accurate to about %s metres.",
            abs(fix.latitude), northSouth, abs(fix.longitude), eastWest, accuracy
        )
    }

    /** Ground distance between two points for display, e.g. "2.4 km". */
    fun formatDistance(a: GeoPoint, b: GeoPoint): String = formatMeters(haversineMeters(a, b))
}
