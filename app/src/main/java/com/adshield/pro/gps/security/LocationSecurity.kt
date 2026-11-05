package com.adshield.pro.gps.security

import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.geo.GeoPoint
import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * AdShield Pro — location security & privacy policy.
 *
 * Two ideas are kept strictly apart here:
 *
 *  1. **Privacy preferences** ([LocationPrivacyPolicy]) — what the user allows. Defaults are the
 *     most restrictive possible: no traffic sharing, no history, no emergency sharing, no export.
 *  2. **Security verdicts** ([MockLocationDetector], [LocationAnalysis]) — what the device reports.
 *
 * Nothing in this file tries to "disable mock locations" (an app cannot) and nothing claims to
 * detect every spoofing technique. It reports Android's own `FLAG_MOCKED` signal, cross-checks the
 * provider names, detects coarse anomalies, and says so plainly.
 */

/** One row of the "who can see my location" audit. */
data class PermissionAudit(
    val fineLocationGranted: Boolean,
    val coarseLocationGranted: Boolean,
    val backgroundLocationGranted: Boolean,
    val notificationPermissionGranted: Boolean,
    val locationEnabled: Boolean,
    val mockLocationApps: List<String>,
    val mockSettingApp: String?,
    val locationProvidersEnabled: List<String>,
    val checkedAtMs: Long = System.currentTimeMillis()
) {
    val anyGranted: Boolean get() = fineLocationGranted || coarseLocationGranted

    /** Score 0..100 where 100 is the most locked down state. */
    val privacyScore: Int
        get() {
            var score = 100
            if (!fineLocationGranted) score += 0 else if (coarseLocationGranted && !fineLocationGranted) score -= 25
            if (!anyGranted) score = 100
            if (locationEnabled) score -= 10
            if (mockLocationApps.isNotEmpty()) score -= 30
            if (mockSettingApp != null) score -= 20
            return score.coerceIn(0, 100)
        }

    fun findings(): List<String> = buildList {
        if (!anyGranted) add("No location permission granted — the GPS module is fully disabled.")
        if (coarseLocationGranted && !fineLocationGranted) {
            add("Only approximate location is granted: GNSS is unavailable, positions come from the network.")
        }
        if (mockLocationApps.isNotEmpty()) {
            add("Mock location is enabled for: ${mockLocationApps.joinToString(", ")}. Positions may be fabricated.")
        }
        if (mockSettingApp != null) {
            add("The developer-options mock-location app is set to ${mockSettingApp}.")
        }
        if (!locationEnabled) add("System location is switched off.")
        if (fineLocationGranted && !notificationPermissionGranted) {
            add("Notification permission is off: the foreground navigation notification cannot be shown.")
        }
        if (isEmpty()) add("No anomalies found in the current permission state.")
    }
}

/**
 * Android reports mock positions in three separate ways; this combines them.
 *
 *  - `Location.isMock()` / the legacy `FLAG_MOCKED` bit on the fix itself;
 *  - the fix arriving from a provider whose name is not a real hardware/network provider;
 *  - `Settings.Secure.ALLOW_MOCK_LOCATION` (pre-API 23) and `AppOpsManager` mock providers.
 *
 * It can be defeated by a rooted device with a system-level spoofing module — that is stated in the
 * UI instead of being hidden behind a green tick.
 */
class MockLocationDetector {

    private val providersSeen = LinkedHashSet<String>()
    private var detections = 0
    private var firstDetectionAtMs: Long? = null

    data class Verdict(
        val mocked: Boolean,
        val reason: String?,
        val detections: Int,
        val firstDetectionAtMs: Long?,
        val providers: List<String>,
        /** Always true: an app-level detector cannot prove a fix is *not* spoofed by the OS. */
        val heuristicOnly: Boolean = true
    )

    fun inspect(
        androidFlagMocked: Boolean,
        provider: String,
        accuracyMeters: Float?,
        nowMs: Long = System.currentTimeMillis()
    ): Verdict {
        providersSeen += provider
        val providerSuspicious = provider.isNotBlank() &&
            !provider.equals("gps", true) &&
            !provider.equals("fused", true) &&
            !provider.equals("network", true) &&
            !provider.equals("passive", true)
        val accuracySuspicious = accuracyMeters != null && accuracyMeters <= 0.5f && providerSuspicious

        val mocked = androidFlagMocked || providerSuspicious || accuracySuspicious
        if (mocked) {
            detections++
            if (firstDetectionAtMs == null) firstDetectionAtMs = nowMs
        }
        val reason = when {
            androidFlagMocked -> "Android flagged this fix as mocked (FLAG_MOCKED)"
            providerSuspicious -> "Fix came from a non-system provider \"$provider\""
            accuracySuspicious -> "Reported accuracy of ${accuracyMeters} m is not physically possible for GNSS"
            else -> null
        }
        return Verdict(
            mocked = mocked,
            reason = reason,
            detections = detections,
            firstDetectionAtMs = firstDetectionAtMs,
            providers = providersSeen.toList()
        )
    }

    fun reset() {
        providersSeen.clear()
        detections = 0
        firstDetectionAtMs = null
    }
}

/**
 * Cross-checks a live fix against the local database of past trips.
 *
 * Three independent signals:
 *  - **teleport**: the position is far from where this device has ever been, and the travelled
 *    distance since the previous fix is implausible for the elapsed time (already computed by
 *    GpsIntegrityMonitor — here it is compared to *history*, which catches a coherent fake track);
 *  - **stationary drift**: a parked device reporting movement;
 *  - **history divergence**: the new fix is many kilometres from every recorded place while the
 *    previous fix was close to one.
 *
 * These are heuristics and are labelled as such. The output is advisory and never silently changes
 * what the map shows — the user sees the flag and decides.
 */
object LocationAnalysis {

    data class HistoryDivergence(
        val flagged: Boolean,
        val nearestRecordedPlaceMeters: Double?,
        val detail: String
    )

    fun compareWithHistory(
        current: GeoPoint,
        previous: GeoPoint?,
        recordedPlaces: List<GeoPoint>,
        elapsedSeconds: Double
    ): HistoryDivergence {
        if (recordedPlaces.isEmpty()) {
            return HistoryDivergence(false, null, "No location history to compare against.")
        }
        val nearest = recordedPlaces.minOf { Geodesy.distanceMeters(it, current) }
        val previousNearest = previous?.let { point -> recordedPlaces.minOf { Geodesy.distanceMeters(it, point) } }

        if (nearest <= 25_000.0) {
            return HistoryDivergence(false, nearest, "Within ${(nearest / 1000).roundToInt()} km of a known place.")
        }
        if (previousNearest != null && previousNearest < 2_000.0 && elapsedSeconds in 0.0..3600.0) {
            return HistoryDivergence(
                true,
                nearest,
                "Jumped ${(nearest / 1000).roundToInt()} km from the nearest known place in " +
                    "${elapsedSeconds.toInt()} s."
            )
        }
        return HistoryDivergence(
            flagged = false,
            nearestRecordedPlaceMeters = nearest,
            detail = "Position is ${(nearest / 1000).roundToInt()} km from the nearest recorded place (new area)."
        )
    }

    /** Stationary drift: a parked device should not wander more than its own accuracy. */
    fun stationaryDrift(distanceMeters: Double, accuracyMeters: Float, speedMps: Float?): Boolean {
        val effectiveSpeed = speedMps ?: 0f
        return distanceMeters > (accuracyMeters * 3.0).coerceAtLeast(30.0) && effectiveSpeed < 0.6f
    }
}

/**
 * The user's privacy switches for the GPS module.
 *
 * Every default is "off": the module is useful as a map/navigator without sharing anything, so
 * sharing must be an explicit act. [TelemetryGate] is the single place that decides whether a
 * sample may leave the device, which keeps the rules auditable in one function and testable.
 */
data class LocationPrivacyPolicy(
    /** Anonymous, aggregated speed samples only. No identifiers, no trip shapes. */
    val contributeTraffic: Boolean = false,
    /** Store trips on this device (encrypted). Off by default. */
    val recordTripHistory: Boolean = false,
    /** Round trip coordinates to ~1 km so history reveals neighbourhoods, not addresses. */
    val coarseHistoryOnly: Boolean = true,
    /** Keep the last N days of history; older entries are deleted. */
    val historyRetentionDays: Int = 30,
    /** Allow sharing a live location link (generated locally; nothing is uploaded unless used). */
    val allowEmergencySharing: Boolean = false,
    /** Hard switch that disables every location-sharing path, including the emergency one. */
    val emergencySharingDisabled: Boolean = false,
    /** Use the foreground service while navigating (keeps GPS alive with the screen off). */
    val backgroundNavigation: Boolean = true,
    /** Speak turn-by-turn instructions. */
    val voiceGuidance: Boolean = true,
    /** Report incidents to the community traffic layer. */
    val allowIncidentReporting: Boolean = false
) {
    /** Effective permission to share an emergency location, honouring the kill switch. */
    val canShareEmergencyLocation: Boolean
        get() = allowEmergencySharing && !emergencySharingDisabled

    fun withEmergencyKillSwitch(disabled: Boolean): LocationPrivacyPolicy =
        copy(emergencySharingDisabled = disabled, allowEmergencySharing = if (disabled) false else allowEmergencySharing)

    /** Short, honest description rendered under the toggle in the UI. */
    fun describe(): List<Pair<String, String>> = listOf(
        "Contribute traffic" to if (contributeTraffic) {
            "Sending anonymous average speed per road segment. No device id, no route shape."
        } else {
            "Off. Traffic map shows only what other opted-in device data is available."
        },
        "Trip history" to if (recordTripHistory) {
            "Storing trips on this device, AES-256-GCM encrypted, kept for ${historyRetentionDays.coerceIn(1, 365)} days" +
                if (coarseHistoryOnly) ", rounded to ~1 km." else " at full precision."
        } else {
            "Off. No trip is written to disk."
        },
        "Emergency sharing" to when {
            emergencySharingDisabled -> "Blocked by the kill switch."
            allowEmergencySharing -> "Allowed — you can generate a location link manually."
            else -> "Off."
        }
    )
}

/**
 * Single decision point for "may this leave the device?".
 *
 * A sample is uploaded only when: the user opted in, the fix is not compromised, the reported
 * accuracy is good, the vehicle really moved, and the sample was not already sent. Anything else is
 * dropped locally and counted in [TelemetryDecision.reason] so the UI can explain the silence.
 */
object TelemetryGate {

    data class TelemetryDecision(
        val allowed: Boolean,
        val reason: String
    )

    fun evaluate(
        policy: LocationPrivacyPolicy,
        integrityCompromised: Boolean,
        mockFlagged: Boolean,
        accuracyMeters: Float?,
        speedKmh: Double?,
        segmentId: String?,
        alreadySentSegment: Boolean
    ): TelemetryDecision {
        if (!policy.contributeTraffic) return TelemetryDecision(false, "Traffic sharing is switched off")
        if (integrityCompromised) return TelemetryDecision(false, "Location integrity check failed")
        if (mockFlagged) return TelemetryDecision(false, "Mock location detected")
        if (accuracyMeters == null || accuracyMeters > 50f) {
            return TelemetryDecision(false, "Fix accuracy ${accuracyMeters?.toInt() ?: 0} m is too coarse")
        }
        if (speedKmh == null || speedKmh < 4.0) return TelemetryDecision(false, "Vehicle is not moving")
        if (segmentId == null) return TelemetryDecision(false, "Position could not be attributed to a road")
        if (alreadySentSegment) return TelemetryDecision(false, "Already uploaded for this segment")
        return TelemetryDecision(true, "Anonymous speed sample queued")
    }
}

/**
 * Builds the text a user can copy when they choose to share a location.
 *
 * The link is an OpenStreetMap permalink: free, no account, no tracking pixel, no expiry server to
 * run. Precision is deliberately reduced for anything but the emergency path.
 */
object EmergencyShareBuilder {

    data class SharePayload(
        val text: String,
        val url: String,
        val precise: Boolean
    )

    fun build(
        position: GeoPoint,
        accuracyMeters: Float?,
        policy: LocationPrivacyPolicy,
        label: String? = null,
        nowMs: Long = System.currentTimeMillis()
    ): Result<SharePayload> {
        if (!policy.canShareEmergencyLocation) {
            return Result.failure(
                IllegalStateException(
                    if (policy.emergencySharingDisabled) {
                        "Emergency location sharing is blocked by the privacy kill switch."
                    } else {
                        "Emergency location sharing is switched off in Location security."
                    }
                )
            )
        }
        val precise = true // The emergency path is the one place full precision is justified.
        val decimals = if (precise) 6 else 3
        val lat = Geodesy.roundToDecimals(position.latitude, decimals)
        val lon = Geodesy.roundToDecimals(position.longitude, decimals)
        val url = "https://www.openstreetmap.org/?mlat=$lat&mlon=$lon#map=17/$lat/$lon"
        val accuracy = accuracyMeters?.let { " (±${it.roundToInt()} m)" } ?: ""
        val time = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
            .format(java.util.Date(nowMs))
        val text = buildString {
            if (!label.isNullOrBlank()) append("$label\n")
            append("My location at $time:\n")
            append("$lat, $lon$accuracy\n")
            append(url)
        }
        return Result.success(SharePayload(text = text, url = url, precise = precise))
    }
}

/**
 * Geo-fence used to stop the app itself from turning location into a tracking tool.
 *
 * If "no history" is selected, the store refuses writes; this guard is intentionally trivial and
 * central so it cannot be forgotten in a new caller.
 */
object HistoryGuard {

    fun mayPersist(policy: LocationPrivacyPolicy): Boolean = policy.recordTripHistory

    fun exportAllowed(policy: LocationPrivacyPolicy): Boolean = policy.recordTripHistory

    /** Points older than the retention window. */
    fun expiredPoints(timestamps: List<Long>, nowMs: Long, policy: LocationPrivacyPolicy): Int {
        val cutoff = nowMs - policy.historyRetentionDays.coerceIn(1, 365).toLong() * 24L * 3600_000L
        return timestamps.count { it < cutoff }
    }

    /** Coordinates as they will be written. */
    fun persistedPoint(point: GeoPoint, policy: LocationPrivacyPolicy): GeoPoint =
        if (policy.coarseHistoryOnly) {
            GeoPoint(
                Geodesy.roundToDecimals(point.latitude, 3),
                Geodesy.roundToDecimals(point.longitude, 3)
            )
        } else {
            point
        }

    /** True when two persisted points are close enough to be stored as one (battery & privacy win). */
    fun isDuplicate(previous: GeoPoint?, next: GeoPoint, policy: LocationPrivacyPolicy): Boolean {
        if (previous == null) return false
        val threshold = if (policy.coarseHistoryOnly) 150.0 else 25.0
        return Geodesy.distanceMeters(previous, next) < threshold
    }

    /** Age of the oldest retained sample, for the "history size" line. */
    fun retentionLabel(policy: LocationPrivacyPolicy): String =
        if (!policy.recordTripHistory) "History off" else "${policy.historyRetentionDays.coerceIn(1, 365)} days"

    /** Human summary of how much precision is kept. */
    fun precisionLabel(policy: LocationPrivacyPolicy): String =
        if (!policy.recordTripHistory) "Nothing stored" else if (policy.coarseHistoryOnly) "~1 km" else "full GPS precision"
}

/** Alert throttling so a jittering fix cannot spam the notification shade. */
class SecurityAlertThrottle(
    private val minimumIntervalMs: Long = 90_000L,
    private val nowMs: () -> Long = System::currentTimeMillis
) {
    private val lastAlertAt = mutableMapOf<String, Long>()

    fun shouldRaise(key: String): Boolean {
        val now = nowMs()
        val previous = lastAlertAt[key]
        if (previous != null && now - previous < minimumIntervalMs) return false
        lastAlertAt[key] = now
        return true
    }

    fun reset() = lastAlertAt.clear()
}

/** Sanity checks applied to anything the module receives from the server. */
object ServerDataValidator {

    fun validObservationSpeed(speedKmh: Double?): Boolean =
        speedKmh != null && speedKmh.isFinite() && speedKmh in 0.0..250.0

    fun validSegmentId(id: String?): Boolean =
        id != null && id.length in 1..96 && id.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == ':' }

    fun validIncidentKind(name: String?): Boolean =
        name != null && IncidentKindNames.names.contains(name)

    fun validTimestamp(ms: Long?, nowMs: Long = System.currentTimeMillis()): Boolean =
        ms != null && abs(nowMs - ms) <= 24L * 3600_000L

    /** Anything above this is a server bug or an attack attempt, not a route. */
    fun validSpeedAggregate(avgKmh: Double?, samples: Int?): Boolean =
        validObservationSpeed(avgKmh) && samples != null && samples in 0..10_000
}

private object IncidentKindNames {
    val names: Set<String> = setOf(
        "ACCIDENT", "HAZARD", "CONSTRUCTION", "ROAD_CLOSED", "POLICE", "WEATHER", "BROKEN_DOWN"
    )
}
