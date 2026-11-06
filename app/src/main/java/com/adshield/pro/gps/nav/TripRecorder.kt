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

    /**
     * Time of the newest point already written to the encrypted track archive.
     *
     * [flushTrackToDisk] used to rewrite the whole file from memory after trimming, so `finish()`
     * read back only the newest half of the trip. The archive is now append-only and this watermark
     * says where to continue.
     */
    private var trackArchivedUpToMs = 0L
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
            // A compromised position must not start a trip at an invented origin. Recording it as
            // "the user left from here" is exactly the fabrication this app refuses to do, so the
            // trip simply begins at the next trustworthy fix.
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
            trackArchivedUpToMs = 0L
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
                // Points collected before the row existed were stamped with trip_id = 0. Re-stamp
                // them, otherwise `finish()` inserts rows whose trip_id points at nothing and the
                // history detail view comes up empty.
                val restamped = restampTripId(track, id)
                for (index in restamped.indices) track[index] = restamped[index]
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
        // Every flush trimmed memory down to the newest half, so whatever is still in `track` has
        // not been archived yet. Appending it is what makes the file the complete trip shape.
        trackFileArchiveTail(id)
        val trackFile = if (trackArchivedUpToMs > 0L) "trip_$id.json.enc" else null
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
        trackArchivedUpToMs = 0L
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

    /**
     * Archives the un-written tail of [track] and trims memory.
     *
     * The trim only ever drops points up to [trackArchivedUpToMs], which is what the file already
     * contains. The old version rewrote the file from the whole in-memory list and *then* trimmed,
     * but `finish()` re-read the already-trimmed content, so a trip longer than
     * [MAX_IN_MEMORY_POINTS] lost its first half on disk.
     */
    private fun flushTrackToDisk() {
        val id = tripId ?: return
        trackFileArchiveTail(id)
        if (track.size > MAX_IN_MEMORY_POINTS) {
            // Drop only points that are already archived, oldest first.
            while (track.size > MAX_IN_MEMORY_POINTS && track.first().timestampMs <= trackArchivedUpToMs) {
                track.removeAt(0)
            }
        }
    }

    /**
     * Appends every point newer than [trackArchivedUpToMs] to the encrypted track file.
     *
     * The payload is newline-delimited JSON: one self-contained record per point. Appending a record
     * is inside a single GCM operation, so no point is ever written half-way.
     */
    private fun trackFileArchiveTail(id: Long): Boolean {
        if (lastPolicy?.recordTripHistory != true) return false
        val pending = unarchivedPoints(track, trackArchivedUpToMs)
        if (pending.isEmpty()) return false
        val name = "trip_$id.json.enc"
        val file = File(secureStoreDirectory(), name)
        // An existing file that cannot be decrypted (Keystore reset, corruption) must not be
        // silently replaced by only the newest points: that would look like a complete trip.
        if (file.isFile && secureStore.read(name) == null) {
            lastStorageError = secureStore.lastError ?: "Existing encrypted track could not be read"
            return false
        }
        val payload = pending.joinToString(separator = "\n", postfix = "\n") { point ->
            buildJsonObject {
                put("t", point.timestampMs)
                put("lat", point.latitude)
                put("lon", point.longitude)
                put("spd", point.speedKmh ?: 0.0)
                put("acc", point.accuracyMeters.toDouble())
                put("brg", point.bearingDegrees ?: 0.0)
            }.toString()
        }.toByteArray(Charsets.UTF_8)

        val existing = if (file.isFile) secureStore.read(name) ?: ByteArray(0) else ByteArray(0)
        val merged = ByteArray(existing.size + payload.size).also {
            existing.copyInto(it, 0)
            payload.copyInto(it, existing.size)
        }
        return if (secureStore.write(name, merged)) {
            trackArchivedUpToMs = pending.maxOf { it.timestampMs }
            true
        } else {
            // Fail loudly in the UI rather than pretending the track was stored.
            lastStorageError = secureStore.lastError ?: "Encrypted storage unavailable"
            false
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

        /**
         * Points collected before the Room row existed carry the placeholder `trip_id = 0`.
         *
         * `finish()` writes these rows to the database, so leaving the placeholder makes them
         * orphans: the history detail view queries by real id and shows an empty trip.
         */
        fun restampTripId(points: List<TripPointEntity>, tripId: Long): List<TripPointEntity> =
            if (tripId <= 0L) points else points.map { it.copy(tripId = tripId) }

        /**
         * The part of [points] not yet written to the encrypted archive.
         *
         * The archive watermark is the timestamp of the newest archived point, so this is exactly
         * what has to be appended next. Keeping it pure is what makes the "long trip loses its
         * first half" bug testable without an Android Keystore.
         */
        fun unarchivedPoints(points: List<TripPointEntity>, archivedUpToMs: Long): List<TripPointEntity> =
            points.filter { it.timestampMs > archivedUpToMs }
    }
}
