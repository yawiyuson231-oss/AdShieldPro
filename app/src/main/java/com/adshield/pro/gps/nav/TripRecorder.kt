package com.adshield.pro.gps.nav

import android.content.Context
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsTripEntity
import com.adshield.pro.gps.data.TripPointEntity
import com.adshield.pro.gps.engine.GnssFix
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.security.HistoryGuard
import com.adshield.pro.gps.security.LocationPrivacyPolicy
import com.adshield.pro.gps.security.SecureLocationStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — trip recorder.
 *
 * Writes a trip only when the user enabled history, and writes it twice on purpose:
 *  - **encrypted track file** in app-private storage (`AES-256-GCM`, key in the Android Keystore),
 *    which is the only artefact containing the shape of the trip;
 *  - **summary row in Room** (start/end, distance, durations) so the history list is fast to render.
 *
 * Points in Room are optional and are stored already down-sampled by [HistoryGuard]; with the
 * default settings the shape never enters the SQL database at all.
 *
 * If the Keystore is unavailable the recorder reports the failure and keeps the trip in memory only,
 * rather than silently writing plaintext coordinates to disk.
 */
@Singleton
class TripRecorder @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: GpsDao
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Encrypted track storage; created lazily so a Keystore failure cannot crash app startup. */
    val secureStore: SecureLocationStore by lazy {
        SecureLocationStore(secureStoreDirectory())
    }
    private val json = Json { prettyPrint = false }

    private var tripId: Long? = null
    private var startedAtMs = 0L
    private var startPoint: GeoPoint? = null
    private var lastPoint: GeoPoint? = null
    private var distanceMeters = 0.0
    private var maxSpeedKmh = 0.0
    private var speedSum = 0.0
    private var speedSamples = 0
    private var movingSeconds = 0L
    private var lastTimestampMs = 0L
    private var pointCount = 0
    private var integrityVerdict = "TRUSTED"
    private val track = ArrayList<TripPointEntity>()
    private var lastPolicy: LocationPrivacyPolicy? = null

    val activeTripId: Long? get() = tripId
    val isRecording: Boolean get() = tripId != null

    data class Snapshot(
        val distanceMeters: Double,
        val maxSpeedKmh: Double,
        val averageSpeedKmh: Double,
        val movingSeconds: Long,
        val points: Int,
        val startedAtMs: Long
    )

    fun snapshot(): Snapshot = Snapshot(
        distanceMeters = distanceMeters,
        maxSpeedKmh = maxSpeedKmh,
        averageSpeedKmh = if (speedSamples > 0) speedSum / speedSamples else 0.0,
        movingSeconds = movingSeconds,
        points = pointCount,
        startedAtMs = startedAtMs
    )

    fun onFix(fix: GnssFix, policy: LocationPrivacyPolicy, compromised: Boolean) {
        lastPolicy = policy
        if (!policy.recordTripHistory) {
            if (tripId != null) finish(policy)
            return
        }
        if (compromised) {
            integrityVerdict = "COMPROMISED"
            return
        }
        val persisted = HistoryGuard.persistedPoint(fix.position, policy)

        if (tripId == null) {
            startPoint = persisted
            lastPoint = persisted
            startedAtMs = fix.timeMs
            lastTimestampMs = fix.timeMs
            movingSeconds = 0L
            speedSum = 0.0
            speedSamples = 0
            maxSpeedKmh = 0.0
            distanceMeters = 0.0
            pointCount = 0
            integrityVerdict = "TRUSTED"
            track.clear()
            track += persisted.toPointEntity(0L, fix)
            pointCount = 1
            val starter = startPoint ?: return
            scope.launch {
                val id = dao.insertTrip(
                    GpsTripEntity(
                        startedAtMs = startedAtMs,
                        endedAtMs = null,
                        distanceMeters = 0.0,
                        maxSpeedKmh = 0.0,
                        averageSpeedKmh = 0.0,
                        movingSeconds = 0L,
                        startLat = starter.latitude,
                        startLon = starter.longitude,
                        endLat = null,
                        endLon = null,
                        encryptedTrackFile = null,
                        pointCount = 1,
                        syncState = "LOCAL_ONLY",
                        integrityVerdict = integrityVerdict
                    )
                )
                tripId = id
            }
            return
        }

        val previous = lastPoint
        if (previous != null) {
            val delta = com.adshield.pro.gps.geo.Geodesy.distanceMeters(previous, persisted)
            val seconds = (fix.timeMs - lastTimestampMs) / 1000.0
            if (seconds > 0 && delta / seconds <= com.adshield.pro.gps.geo.Geodesy.PHYSICAL_MAX_SPEED_MPS) {
                distanceMeters += delta
                if (fix.speedMps?.let { it > 1.8f } == true) movingSeconds += seconds.toLong().coerceAtLeast(0)
            }
        }
        fix.speedKmh?.let {
            speedSum += it
            speedSamples++
            if (it > maxSpeedKmh) maxSpeedKmh = it
        }

        val duplicate = HistoryGuard.isDuplicate(previous, persisted, policy)
        if (!duplicate) {
            lastPoint = persisted
            lastTimestampMs = fix.timeMs
            pointCount++
            track += persisted.toPointEntity(tripId ?: 0L, fix)
            if (track.size > MAX_IN_MEMORY_POINTS) {
                flushTrackToDisk()
            }
        }
    }

    /**
     * Ends the trip: writes the encrypted track, updates the summary row, and clears memory.
     * Safe to call when no trip is active (no-op).
     */
    fun finish(policy: LocationPrivacyPolicy, endFix: GnssFix? = null) {
        val id = tripId ?: return
        val end = endFix?.position?.let { HistoryGuard.persistedPoint(it, policy) } ?: lastPoint
        val endedAt = endFix?.timeMs ?: System.currentTimeMillis()
        val trackFile = writeTrack(id)
        val pointsSnapshot = track.toList()
        val distance = distanceMeters
        val maxSpeed = maxSpeedKmh
        val average = if (speedSamples > 0) speedSum / speedSamples else 0.0
        val moving = movingSeconds
        val count = pointCount
        val verdict = integrityVerdict

        scope.launch {
            runCatching {
                dao.finishTrip(
                    id = id,
                    endedAtMs = endedAt,
                    distance = distance,
                    maxSpeed = maxSpeed,
                    averageSpeed = average,
                    movingSeconds = moving,
                    endLat = end?.latitude,
                    endLon = end?.longitude,
                    pointCount = count,
                    verdict = verdict,
                    trackFile = trackFile
                )
                // The trip *shape* lives only in the encrypted track file. Room keeps the summary
                // row plus, when the user explicitly disabled coarse mode, the point list for the
                // history detail view.
                if (!policy.coarseHistoryOnly && pointsSnapshot.isNotEmpty()) {
                    dao.insertPoints(pointsSnapshot)
                }
            }
        }

        tripId = null
        track.clear()
        pointCount = 0
        startPoint = null
        lastPoint = null
        distanceMeters = 0.0
        maxSpeedKmh = 0.0
        speedSum = 0.0
        speedSamples = 0
        movingSeconds = 0L
        lastTimestampMs = 0L
    }

    private fun flushTrackToDisk() {
        val id = tripId ?: return
        writeTrack(id)
        // Keep the newest points in memory so the tail of the trip is not lost.
        if (track.size > MAX_IN_MEMORY_POINTS) {
            val excess = track.size - MAX_IN_MEMORY_POINTS / 2
            repeat(excess) { track.removeAt(0) }
        }
    }

    private fun writeTrack(id: Long): String? {
        if (track.isEmpty()) return null
        if (lastPolicy?.recordTripHistory != true) return null
        val payload = buildJsonObject {
            put("trip_id", id)
            put("started_at_ms", startedAtMs)
            put("points", kotlinx.serialization.json.JsonArray(
                track.map { point ->
                    buildJsonObject {
                        put("t", point.timestampMs)
                        put("lat", point.latitude)
                        put("lon", point.longitude)
                        put("spd", point.speedKmh ?: 0.0)
                        put("acc", point.accuracyMeters.toDouble())
                        put("brg", point.bearingDegrees ?: 0.0)
                    }
                }
            ))
        }.toString().toByteArray(Charsets.UTF_8)

        val name = "trip_$id.json.enc"
        return if (secureStore.write(name, payload)) {
            name
        } else {
            // Fail loudly in the UI rather than pretending the track was stored.
            lastStorageError = secureStore.lastError ?: "Encrypted storage unavailable"
            null
        }
    }

    var lastStorageError: String? = null
        private set

    /** Deletes the encrypted track file for a trip that is being removed from history. */
    fun deleteTrackFile(name: String?) {
        if (name.isNullOrBlank()) return
        scope.launch { secureStore.delete(name) }
    }

    fun readTrack(name: String): ByteArray? = secureStore.read(name)

    /** Retention sweep; called by the maintenance worker and the privacy screen. */
    fun purgeExpired(policy: LocationPrivacyPolicy) {
        val cutoff = System.currentTimeMillis() - policy.historyRetentionDays.coerceIn(1, 365) * 24L * 3600_000L
        scope.launch {
            runCatching {
                dao.deleteTripsOlderThan(cutoff)
                dao.deletePointsOlderThan(cutoff)
                secureStore.list()
                    .filter { it.startsWith("trip_") && it.endsWith(".json.enc") }
                    .forEach { name ->
                        val file = File(secureStoreDirectory(), name)
                        if (file.isFile && file.lastModified() < cutoff) secureStore.delete(name)
                    }
            }
        }
    }

    /** Full wipe used by "delete all location data". */
    fun wipeAll() {
        tripId = null
        track.clear()
        pointCount = 0
        secureStore.wipe()
        scope.launch {
            runCatching {
                dao.wipeTrips()
                dao.wipePoints()
                dao.deleteAllObservations()
                dao.wipeMyIncidents()
                dao.deleteAllHistory()
                dao.deleteAllSegmentTraffic()
            }
        }
    }

    private fun secureStoreDirectory(): File =
        File(context.filesDir, "gps_tracks")

    private fun GeoPoint.toPointEntity(tripId: Long, fix: GnssFix): TripPointEntity = TripPointEntity(
        tripId = tripId,
        timestampMs = fix.timeMs,
        latitude = latitude,
        longitude = longitude,
        altitudeMeters = fix.altitudeMeters,
        speedKmh = fix.speedKmh,
        bearingDegrees = fix.bearingDegrees?.toDouble(),
        accuracyMeters = fix.accuracyMeters
    )

    companion object {
        /** Keep memory bounded on long trips; the encrypted file is appended in chunks. */
        const val MAX_IN_MEMORY_POINTS = 3_000
    }
}
