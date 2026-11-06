package com.adshield.pro.gps.engine

import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy

/**
 * AdShield Pro — GPS module, position models.
 *
 * These types describe *measured* values only. Nothing here is simulated: a [GnssFix] is created
 * exclusively from an Android `Location` delivered by a real provider, and an absent value stays
 * `null` (e.g. a device that does not report altitude) instead of being filled with a default.
 */

/** Where a fix came from. The UI must show this so a network fix is never sold as GNSS. */
enum class FixSource(val label: String) {
    GNSS("GNSS"),
    FUSED("Fused"),
    NETWORK("Network"),
    PASSIVE("Passive"),
    LAST_KNOWN("Last known")
}

/** Coarse quality band derived from the measured horizontal accuracy. */
enum class AccuracyBand(val label: String) {
    EXCELLENT("Excellent"),
    GOOD("Good"),
    FAIR("Fair"),
    POOR("Poor"),
    UNUSABLE("Unusable");

    companion object {
        fun fromAccuracy(accuracyMeters: Float?): AccuracyBand = when {
            accuracyMeters == null || !accuracyMeters.isFinite() -> UNUSABLE
            accuracyMeters <= 5f -> EXCELLENT
            accuracyMeters <= 12f -> GOOD
            accuracyMeters <= 30f -> FAIR
            accuracyMeters <= 100f -> POOR
            else -> UNUSABLE
        }
    }
}

/** Immutable sample of one real provider reading, already mapped out of `android.location`. */
data class GnssFix(
    val position: GeoPoint,
    val timeMs: Long,
    val elapsedRealtimeNanos: Long,
    val accuracyMeters: Float,
    val altitudeMeters: Double? = null,
    val verticalAccuracyMeters: Float? = null,
    val speedMps: Float? = null,
    val speedAccuracyMps: Float? = null,
    val bearingDegrees: Float? = null,
    val bearingAccuracyDegrees: Float? = null,
    val source: FixSource = FixSource.GNSS,
    val satellitesUsed: Int? = null,
    val satellitesVisible: Int? = null,
    /** True when Android itself reports the fix as coming from a mock provider. */
    val mockProviderFlag: Boolean = false,
    /** True when the fix was served from the system's last-known cache (possibly old). */
    val isCached: Boolean = false
) {
    val accuracyBand: AccuracyBand get() = AccuracyBand.fromAccuracy(accuracyMeters)
    val speedKmh: Double? get() = speedMps?.takeIf { it.isFinite() && it >= 0f }?.let { it * 3.6 }

    val ageMs: Long get() = System.currentTimeMillis() - timeMs

    /** 0..100 confidence in the fix, driven by accuracy and known-good flags. */
    val confidence: Int
        get() {
            var score = when (accuracyBand) {
                AccuracyBand.EXCELLENT -> 100
                AccuracyBand.GOOD -> 88
                AccuracyBand.FAIR -> 70
                AccuracyBand.POOR -> 45
                AccuracyBand.UNUSABLE -> 15
            }
            if (source == FixSource.GNSS) score += 0 else if (source == FixSource.NETWORK) score -= 20
            if (isCached) score -= 25
            if (mockProviderFlag) score -= 55
            return score.coerceIn(0, 100)
        }
}

/**
 * A compass reading. Kept separate from the GNSS fix because Android delivers it from a different
 * sensor and at a different rate.
 */
data class HeadingSample(
    val degrees: Double,
    val accuracyDegrees: Double? = null,
    val source: HeadingSource = HeadingSource.ROTATION_VECTOR,
    val timestampMs: Long = System.currentTimeMillis()
)

enum class HeadingSource(val label: String) {
    ROTATION_VECTOR("Rotation vector"),
    MAGNETIC("Magnetometer"),
    GYROSCOPE("Gyroscope"),
    GPS_COURSE("GNSS course")
}

/** One satellite as reported by Android's `GnssStatus` (real sky geometry, not simulated). */
data class SatelliteInfo(
    val svid: Int,
    val constellation: String,
    val azimuthDegrees: Float,
    val elevationDegrees: Float,
    val snrDbHz: Float,
    val usedInFix: Boolean,
    val hasAlmanac: Boolean = false,
    val hasEphemeris: Boolean = false
)

/** Satellite diagnostics sourced from `GnssStatus` (and NMEA when the chipset emits it). */
data class SatelliteSnapshot(
    val satellitesVisible: Int,
    val satellitesUsedInFix: Int,
    val averageSnrDbHz: Double?,
    val bestSnrDbHz: Double?,
    val constellations: List<String> = emptyList(),
    val satellites: List<SatelliteInfo> = emptyList(),
    val timestampMs: Long = System.currentTimeMillis()
) {
    val usable: Boolean get() = satellitesUsedInFix >= 4

    /** Share of visible satellites actually contributing to the fix, 0..1. */
    val usedRatio: Double
        get() = if (satellitesVisible <= 0) 0.0 else satellitesUsedInFix.toDouble() / satellitesVisible

    /** Honest quality note for the radar header. */
    fun qualityNote(): String = when {
        satellitesVisible == 0 -> "Receiver reports no satellites — no sky view or no GNSS hardware"
        satellitesUsedInFix < 4 -> "Only $satellitesUsedInFix satellites in fix; 4 are needed for a 3D position"
        averageSnrDbHz == null -> "$satellitesUsedInFix of $satellitesVisible satellites in fix"
        else -> "$satellitesUsedInFix of $satellitesVisible in fix · mean SNR %.0f dBHz".format(averageSnrDbHz)
    }
}

/** What the receiver is doing right now. */
enum class FixState(val label: String) {
    NO_PERMISSION("Permission denied"),
    SEARCHING("Searching for satellites"),
    FIX_ACQUIRED("Fix acquired"),

    /**
     * A fix whose integrity check failed (mock provider or another spoofing signal).
     *
     * The position is still shown — hiding it would leave the user with a frozen map and no
     * explanation — but it is never counted towards track statistics and never recorded.
     */
    COMPROMISED("Position failed integrity check"),
    STALE("Fix is stale"),
    DISABLED("Location services off"),
    UNSUPPORTED("No GNSS hardware")
}

/** Movement classification with hysteresis (see [StationaryDetector]). */
enum class MovementState(val label: String) {
    UNKNOWN("Unknown"),
    STATIONARY("Stationary"),
    MOVING("Moving"),
    DRIVING("Driving")
}

/** Live navigation quality of the current track. */
data class TrackStats(
    val samples: Int = 0,
    val distanceMeters: Double = 0.0,
    val maxSpeedKmh: Double = 0.0,
    val averageSpeedKmh: Double = 0.0,
    val movingSeconds: Long = 0L,
    val acceptedSamples: Int = 0,
    val rejectedSamples: Int = 0
)

/** Everything one frame of the GPS engine exposes to the UI. Never fabricated. */
data class GpsFrame(
    val fix: GnssFix? = null,
    val fixState: FixState = FixState.SEARCHING,
    val heading: HeadingSample? = null,
    /** Heading the UI should rotate the marker to: compass when slow, course-over-ground when fast. */
    val navigationBearingDegrees: Double? = null,
    val movement: MovementState = MovementState.UNKNOWN,
    val satellites: SatelliteSnapshot? = null,
    val trackStats: TrackStats = TrackStats(),
    val accuracyBand: AccuracyBand = AccuracyBand.UNUSABLE,
    val lastFixAgeMs: Long? = null,
    val integrity: IntegrityReport = IntegrityReport.NONE,
    val updatedAtMs: Long = System.currentTimeMillis()
) {
    val hasFix: Boolean get() = fix != null
    val speedKmh: Double? get() = fix?.speedKmh
    val accuracyMeters: Float? get() = fix?.accuracyMeters
    val altitudeMeters: Double? get() = fix?.altitudeMeters

    companion object {
        val EMPTY = GpsFrame()
    }
}

/** Sliding-window stationary/moving classifier with hysteresis, so the UI does not flicker. */
class StationaryDetector(
    private val stationarySpeedThresholdMps: Double = 0.8,
    private val movingSpeedThresholdMps: Double = 1.8,
    private val drivingSpeedThresholdMps: Double = 6.5,
    private val displacementThresholdMeters: Double = 12.0,
    private val stationaryWindowMs: Long = 8_000
) {
    private var anchor: GeoPoint? = null
    private var anchorTimeMs = 0L
    private var current: MovementState = MovementState.UNKNOWN

    fun reset() {
        anchor = null
        anchorTimeMs = 0L
        current = MovementState.UNKNOWN
    }

    fun update(fix: GnssFix): MovementState {
        val speed = fix.speedMps?.takeIf { it.isFinite() }?.toDouble()
        val anchorPoint = anchor
        val now = fix.timeMs

        if (anchorPoint == null || now - anchorTimeMs > stationaryWindowMs) {
            anchor = fix.position
            anchorTimeMs = now
        }

        val displacement = anchorPoint?.let { Geodesy.distanceMeters(it, fix.position) } ?: 0.0
        val speedValue = speed ?: run {
            // No Doppler speed: infer from displacement over the anchor window.
            val elapsed = ((now - anchorTimeMs).coerceAtLeast(1L)) / 1000.0
            displacement / elapsed
        }

        // Vehicle-reported speed (Doppler) is trusted most; displacement is the fallback.
        current = when {
            speedValue >= drivingSpeedThresholdMps -> MovementState.DRIVING
            speedValue >= movingSpeedThresholdMps -> MovementState.MOVING
            speedValue <= stationarySpeedThresholdMps && displacement < displacementThresholdMeters ->
                MovementState.STATIONARY
            current == MovementState.DRIVING && speedValue > stationarySpeedThresholdMps -> MovementState.MOVING
            current == MovementState.MOVING || current == MovementState.DRIVING -> MovementState.MOVING
            else -> MovementState.STATIONARY
        }

        // Re-anchor whenever the device has clearly moved, so displacement is measured from a
        // recent point rather than from a stale one.
        if (displacement >= displacementThresholdMeters) {
            anchor = fix.position
            anchorTimeMs = now
        }
        return current
    }
}

/**
 * Detects the classic GNSS failure modes without pretending to be able to see the sky:
 *
 *  - coordinate jumps: a displacement that cannot be explained by the reported accuracy and the
 *    elapsed time (this is what "GPS drift" looks like when the receiver briefly re-locks);
 *  - impossible speeds: implied velocity above [Geodesy.PHYSICAL_MAX_SPEED_MPS], or an implied
 *    velocity that disagrees with the receiver's own speed reading by more than 4x in either
 *    direction (a fixed device claiming 90 km/h, or a jump the receiver did not report);
 *  - stale fixes: the provider stopped updating;
 *  - clock anomalies: wall-clock going backwards between fixes, or a wall-clock/elapsed-realtime
 *    divergence (a strong signal of a device clock being played with);
 *  - mock providers: flagged by Android itself.
 */
class GpsIntegrityMonitor(
    private val jumpSpeedToleranceMps: Double = 45.0,
    private val jumpAccuracyMultiplier: Double = 4.0,
    private val minJumpDistanceMeters: Double = 40.0,
    private val staleAfterMs: Long = 15_000,
    private val clockDriftToleranceMs: Long = 5_000
) {
    private var previous: GnssFix? = null
    private var lastWallMs = 0L
    private var lastElapsedNanos = 0L
    private var jumpCount = 0
    private var impossibleSpeedCount = 0
    private var clockAnomalyCount = 0
    private var mockDetections = 0
    private val recentJumps = ArrayDeque<Long>()

    fun reset() {
        previous = null
        lastWallMs = 0L
        lastElapsedNanos = 0L
        jumpCount = 0
        impossibleSpeedCount = 0
        clockAnomalyCount = 0
        mockDetections = 0
        recentJumps.clear()
    }

    val statistics: IntegrityStatistics
        get() = IntegrityStatistics(
            jumpsDetected = jumpCount,
            impossibleSpeeds = impossibleSpeedCount,
            clockAnomalies = clockAnomalyCount,
            mockDetections = mockDetections,
            recentJumpCount = recentJumps.size
        )

    fun inspect(fix: GnssFix, nowMs: Long = System.currentTimeMillis()): IntegrityReport {
        val findings = mutableListOf<IntegrityFinding>()
        val previousFix = previous

        if (fix.mockProviderFlag) {
            mockDetections++
            findings += IntegrityFinding(
                kind = IntegrityFindingKind.MOCK_LOCATION,
                severity = IntegritySeverity.CRITICAL,
                detail = "Android reports this fix as coming from a mock location provider."
            )
        }

        if (fix.isCached) {
            findings += IntegrityFinding(
                kind = IntegrityFindingKind.STALE_FIX,
                severity = IntegritySeverity.WARNING,
                detail = "Fix was served from the system last-known cache, not a live update."
            )
        }

        if (nowMs - fix.timeMs > staleAfterMs) {
            findings += IntegrityFinding(
                kind = IntegrityFindingKind.STALE_FIX,
                severity = IntegritySeverity.WARNING,
                detail = "The provider has not delivered a fix for ${(nowMs - fix.timeMs) / 1000} s."
            )
        }

        if (lastWallMs > 0L && fix.timeMs < lastWallMs) {
            clockAnomalyCount++
            findings += IntegrityFinding(
                kind = IntegrityFindingKind.CLOCK_ANOMALY,
                severity = IntegritySeverity.WARNING,
                detail = "Fix timestamp went backwards by ${lastWallMs - fix.timeMs} ms."
            )
        }

        // Wall clock vs monotonic clock: growth of the wall delta relative to the monotonic delta
        // means something changed the system time while we were sampling.
        if (lastWallMs > 0L && lastElapsedNanos > 0L) {
            val wallDelta = fix.timeMs - lastWallMs
            val monoDelta = (fix.elapsedRealtimeNanos - lastElapsedNanos) / 1_000_000L
            if (wallDelta > 0 && monoDelta > 0 && kotlin.math.abs(wallDelta - monoDelta) > clockDriftToleranceMs) {
                clockAnomalyCount++
                findings += IntegrityFinding(
                    kind = IntegrityFindingKind.CLOCK_ANOMALY,
                    severity = IntegritySeverity.WARNING,
                    detail = "System clock moved ${wallDelta - monoDelta} ms relative to the monotonic clock."
                )
            }
        }

        if (previousFix != null) {
            val distance = Geodesy.distanceMeters(previousFix.position, fix.position)
            val deltaSeconds = (fix.timeMs - previousFix.timeMs) / 1000.0
            val tolerableAccuracy = maxOf(fix.accuracyMeters, previousFix.accuracyMeters) * jumpAccuracyMultiplier
            val impliedSpeed = if (deltaSeconds > 0) distance / deltaSeconds else Double.POSITIVE_INFINITY

            val isJump = distance > minJumpDistanceMeters &&
                distance > tolerableAccuracy &&
                (impliedSpeed.isInfinite() || impliedSpeed > jumpSpeedToleranceMps)

            if (isJump) {
                jumpCount++
                recentJumps.addLast(fix.timeMs)
                while (recentJumps.isNotEmpty() && fix.timeMs - recentJumps.first() > 60_000) {
                    recentJumps.removeFirst()
                }
                findings += IntegrityFinding(
                    kind = IntegrityFindingKind.COORDINATE_JUMP,
                    severity = if (distance > 500.0) IntegritySeverity.CRITICAL else IntegritySeverity.WARNING,
                    detail = "Position moved ${distance.toInt()} m in ${"%.1f".format(deltaSeconds.coerceAtLeast(0.0))} s " +
                        "with ±${maxOf(fix.accuracyMeters, previousFix.accuracyMeters).toInt()} m accuracy."
                )
            }

            // Only a disagreement between the receiver's own speed and the observed displacement is
            // an anomaly. A vehicle genuinely doing 105 km/h reports it and is left alone.
            val reportedSpeedMps = fix.speedMps?.let { maxOf(it, previousFix.speedMps ?: it).toDouble() }
            val speedDiscontinuity = reportedSpeedMps == null ||
                impliedSpeed > reportedSpeedMps * jumpAccuracyMultiplier

            if (deltaSeconds > 0) {
                when {
                    // Faster than any road vehicle, whatever the receiver claims.
                    impliedSpeed > Geodesy.PHYSICAL_MAX_SPEED_MPS && speedDiscontinuity -> {
                        impossibleSpeedCount++
                        findings += IntegrityFinding(
                            kind = IntegrityFindingKind.IMPOSSIBLE_SPEED,
                            severity = IntegritySeverity.CRITICAL,
                            detail = "Implied speed ${(impliedSpeed * 3.6).toInt()} km/h exceeds any road vehicle."
                        )
                    }
                    // Within the physical limit, but the position moved several times faster than
                    // the receiver says it is moving (or it moved while reporting zero speed).
                    reportedSpeedMps != null && reportedSpeedMps >= 0.5 &&
                        impliedSpeed > reportedSpeedMps * jumpAccuracyMultiplier &&
                        impliedSpeed - reportedSpeedMps > 5.0 -> {
                        impossibleSpeedCount++
                        findings += IntegrityFinding(
                            kind = IntegrityFindingKind.IMPOSSIBLE_SPEED,
                            severity = IntegritySeverity.WARNING,
                            detail = "Position moved at ${(impliedSpeed * 3.6).toInt()} km/h while the " +
                                "receiver reported ${(reportedSpeedMps * 3.6).toInt()} km/h."
                        )
                    }
                    // The mirror image: the receiver claims motorway speed while the device barely
                    // moved. That is what a stationary spoof or a stuck speed field looks like.
                    reportedSpeedMps != null && reportedSpeedMps > 8.0 &&
                        impliedSpeed < reportedSpeedMps / jumpAccuracyMultiplier &&
                        reportedSpeedMps - impliedSpeed > 5.0 -> {
                        impossibleSpeedCount++
                        findings += IntegrityFinding(
                            kind = IntegrityFindingKind.IMPOSSIBLE_SPEED,
                            severity = IntegritySeverity.WARNING,
                            detail = "Receiver reported ${(reportedSpeedMps * 3.6).toInt()} km/h but the " +
                                "device moved ${impliedSpeed.toInt()} m in this interval."
                        )
                    }
                }
            }

            val courseChange = fix.bearingDegrees?.let { current ->
                previousFix.bearingDegrees?.let { prior ->
                    Geodesy.bearingDifference(prior.toDouble(), current.toDouble())
                }
            }
            if (courseChange != null && courseChange > 120.0 && (fix.speedMps ?: 0f) > 8f) {
                findings += IntegrityFinding(
                    kind = IntegrityFindingKind.COURSE_DISCONTINUITY,
                    severity = IntegritySeverity.INFO,
                    detail = "Course changed ${courseChange.toInt()}° while moving at " +
                        "${((fix.speedMps ?: 0f) * 3.6).toInt()} km/h."
                )
            }
        }

        previous = fix
        lastWallMs = fix.timeMs
        lastElapsedNanos = fix.elapsedRealtimeNanos

        return IntegrityReport(
            verdict = verdictFor(findings),
            findings = findings,
            statistics = statistics,
            evaluatedAtMs = nowMs
        )
    }

    private fun verdictFor(findings: List<IntegrityFinding>): IntegrityVerdict {
        if (findings.any { it.severity == IntegritySeverity.CRITICAL }) return IntegrityVerdict.COMPROMISED
        if (findings.any { it.severity == IntegritySeverity.WARNING }) return IntegrityVerdict.SUSPICIOUS
        if (findings.isNotEmpty()) return IntegrityVerdict.DEGRADED
        return IntegrityVerdict.TRUSTED
    }
}

data class IntegrityStatistics(
    val jumpsDetected: Int = 0,
    val impossibleSpeeds: Int = 0,
    val clockAnomalies: Int = 0,
    val mockDetections: Int = 0,
    val recentJumpCount: Int = 0
)

enum class IntegrityVerdict(val label: String) {
    TRUSTED("Trusted"),
    DEGRADED("Degraded"),
    SUSPICIOUS("Suspicious"),
    COMPROMISED("Compromised")
}

enum class IntegritySeverity { INFO, WARNING, CRITICAL }

enum class IntegrityFindingKind(val label: String) {
    MOCK_LOCATION("Mock location"),
    COORDINATE_JUMP("Coordinate jump"),
    IMPOSSIBLE_SPEED("Impossible speed"),
    STALE_FIX("Stale fix"),
    CLOCK_ANOMALY("Clock anomaly"),
    COURSE_DISCONTINUITY("Course discontinuity"),
    PERMISSION_REVOKED("Permission revoked"),
    LOCATION_DISABLED("Location disabled"),
    TELEMETRY_PAUSED("Telemetry paused"),
    EMERGENCY_SHARING_BLOCKED("Emergency sharing blocked")
}

data class IntegrityFinding(
    val kind: IntegrityFindingKind,
    val severity: IntegritySeverity,
    val detail: String,
    val atMs: Long = System.currentTimeMillis()
)

data class IntegrityReport(
    val verdict: IntegrityVerdict = IntegrityVerdict.TRUSTED,
    val findings: List<IntegrityFinding> = emptyList(),
    val statistics: IntegrityStatistics = IntegrityStatistics(),
    val evaluatedAtMs: Long = 0L
) {
    /** True when the current fix should be excluded from traffic observations and trip history. */
    val shouldRejectObservation: Boolean
        get() = verdict == IntegrityVerdict.COMPROMISED ||
            findings.any { it.kind == IntegrityFindingKind.MOCK_LOCATION }

    companion object {
        val NONE = IntegrityReport()
    }
}

/**
 * Fuses the compass with course-over-ground.
 *
 * Below walking speed the magnetometer/rotation vector is the only source of heading (GNSS course
 * is meaningless when stationary), above the speed gate the GNSS course is more reliable and is
 * blended in with a weight that ramps up with speed. An angular low-pass (with correct wrap-around
 * handling) removes magnetometer chatter and gyro jitter without lagging behind real turns.
 */
class HeadingFusion(
    private val smoothingFactor: Double = 0.22,
    private val courseWeightMaxSpeedMps: Double = 8.0
) {
    private var fused: Double? = null
    private var lastSource: HeadingSource = HeadingSource.ROTATION_VECTOR

    val current: Double? get() = fused
    val source: HeadingSource get() = lastSource

    fun reset() {
        fused = null
        lastSource = HeadingSource.ROTATION_VECTOR
    }

    fun update(compass: HeadingSample?, fix: GnssFix?): HeadingSample? {
        val gnssCourse = fix?.bearingDegrees?.toDouble()
            ?.takeIf { fix.speedMps != null && fix.speedMps >= 2.2f && fix.bearingAccuracyDegrees.let { acc -> acc == null || acc <= 45f } }
        val compassHeading = compass?.degrees

        val target: Double = when {
            gnssCourse != null && compassHeading != null -> {
                val speed = fix.speedMps?.toDouble() ?: 0.0
                val weight = (speed / courseWeightMaxSpeedMps).coerceIn(0.0, 0.85)
                lastSource = HeadingSource.GPS_COURSE
                val delta = Geodesy.bearingDelta(compassHeading, gnssCourse)
                Geodesy.normalizeBearing(compassHeading + delta * weight)
            }
            gnssCourse != null -> {
                lastSource = HeadingSource.GPS_COURSE
                gnssCourse
            }
            compassHeading != null -> {
                lastSource = compass?.source ?: HeadingSource.ROTATION_VECTOR
                compassHeading
            }
            else -> null
        } ?: return null

        val previous = fused
        val next = if (previous == null) {
            target
        } else {
            val delta = Geodesy.bearingDelta(previous, target)
            Geodesy.normalizeBearing(previous + delta * smoothingFactor)
        }
        fused = next
        return HeadingSample(
            degrees = next,
            accuracyDegrees = compass?.accuracyDegrees,
            source = lastSource,
            timestampMs = compass?.timestampMs ?: System.currentTimeMillis()
        )
    }
}

/** Distance/ETA bookkeeping for the active route. */
object EtaMath {
    /**
     * Remaining time in seconds. When the driver is stopped the rolling average is 0 and would
     * divide by zero, so the road-class speed limit of the remaining route is used instead and the
     * result is marked as an estimate by [EtaEstimate.isMeasured].
     */
    fun estimate(remainingMeters: Double, rollingSpeedKmh: Double?, routeSpeedLimitKmh: Double?): EtaEstimate {
        val measured = rollingSpeedKmh?.takeIf { it.isFinite() && it >= 3.0 }
        val fallback = routeSpeedLimitKmh?.takeIf { it.isFinite() && it > 0.0 } ?: 30.0
        val speedKmh = measured ?: fallback
        val seconds = if (speedKmh <= 0.0) Double.POSITIVE_INFINITY else remainingMeters / 1000.0 / speedKmh * 3600.0
        return EtaEstimate(
            remainingMeters = remainingMeters,
            remainingSeconds = seconds,
            arrivalEpochMs = if (seconds.isFinite()) System.currentTimeMillis() + (seconds * 1000).toLong() else null,
            speedKmh = speedKmh,
            isMeasured = measured != null
        )
    }
}

data class EtaEstimate(
    val remainingMeters: Double,
    val remainingSeconds: Double,
    val arrivalEpochMs: Long?,
    val speedKmh: Double,
    val isMeasured: Boolean
)
