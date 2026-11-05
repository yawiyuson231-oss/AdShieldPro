package com.adshield.pro.gps.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * AdShield Pro — GPS module database.
 *
 * A dedicated database (`adshield_gps.db`) so the navigation module can be wiped, backed up or
 * disabled without touching the DNS/filter database. Coordinates stored in `trip_points` are
 * already down-sampled by HistoryGuard before they reach Room, and trip tracks are additionally
 * written to the encrypted file store when the user enables history.
 */

@Entity(
    tableName = "gps_trips",
    indices = [Index("started_at_ms"), Index("sync_state")]
)
data class GpsTripEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    @ColumnInfo(name = "started_at_ms") val startedAtMs: Long,
    @ColumnInfo(name = "ended_at_ms") val endedAtMs: Long?,
    @ColumnInfo(name = "distance_meters") val distanceMeters: Double,
    @ColumnInfo(name = "max_speed_kmh") val maxSpeedKmh: Double,
    @ColumnInfo(name = "average_speed_kmh") val averageSpeedKmh: Double,
    @ColumnInfo(name = "moving_seconds") val movingSeconds: Long,
    @ColumnInfo(name = "start_lat") val startLat: Double?,
    @ColumnInfo(name = "start_lon") val startLon: Double?,
    @ColumnInfo(name = "end_lat") val endLat: Double?,
    @ColumnInfo(name = "end_lon") val endLon: Double?,
    @ColumnInfo(name = "encrypted_track_file") val encryptedTrackFile: String?,
    @ColumnInfo(name = "point_count") val pointCount: Int,
    /** PENDING, SYNCED, LOCAL_ONLY (the user chose not to upload) or FAILED. */
    @ColumnInfo(name = "sync_state") val syncState: String = "LOCAL_ONLY",
    @ColumnInfo(name = "integrity_verdict") val integrityVerdict: String = "TRUSTED"
)

@Entity(
    tableName = "trip_points",
    indices = [Index("trip_id"), Index("timestamp_ms")]
)
data class TripPointEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    @ColumnInfo(name = "trip_id") val tripId: Long,
    @ColumnInfo(name = "timestamp_ms") val timestampMs: Long,
    @ColumnInfo(name = "latitude") val latitude: Double,
    @ColumnInfo(name = "longitude") val longitude: Double,
    @ColumnInfo(name = "altitude_m") val altitudeMeters: Double?,
    @ColumnInfo(name = "speed_kmh") val speedKmh: Double?,
    @ColumnInfo(name = "bearing_deg") val bearingDegrees: Double?,
    @ColumnInfo(name = "accuracy_m") val accuracyMeters: Float
)

@Entity(
    tableName = "traffic_observations",
    indices = [Index("segment_id"), Index("captured_at_ms"), Index(value = ["queued_for_upload"])]
)
data class TrafficObservationEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    @ColumnInfo(name = "segment_id") val segmentId: String,
    @ColumnInfo(name = "speed_kmh") val speedKmh: Double,
    @ColumnInfo(name = "captured_at_ms") val capturedAtMs: Long,
    @ColumnInfo(name = "accuracy_m") val accuracyMeters: Float,
    @ColumnInfo(name = "heading_deg") val headingDegrees: Double,
    @ColumnInfo(name = "sample_count") val sampleCount: Int,
    @ColumnInfo(name = "queued_for_upload") val queuedForUpload: Boolean = false,
    @ColumnInfo(name = "upload_attempts") val uploadAttempts: Int = 0
)

@Entity(
    tableName = "traffic_incidents",
    indices = [Index("reported_at_ms"), Index("expires_at_ms"), Index("kind")]
)
data class TrafficIncidentEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "kind") val kind: String,
    @ColumnInfo(name = "latitude") val latitude: Double,
    @ColumnInfo(name = "longitude") val longitude: Double,
    @ColumnInfo(name = "road_name") val roadName: String?,
    @ColumnInfo(name = "segment_id") val segmentId: String?,
    @ColumnInfo(name = "reported_at_ms") val reportedAtMs: Long,
    @ColumnInfo(name = "expires_at_ms") val expiresAtMs: Long,
    @ColumnInfo(name = "reporter_token") val reporterToken: String,
    @ColumnInfo(name = "confirmations") val confirmations: Int,
    @ColumnInfo(name = "notes") val notes: String?,
    @ColumnInfo(name = "reported_by_me") val reportedByMe: Boolean,
    @ColumnInfo(name = "sync_state") val syncState: String
)

@Entity(tableName = "segment_traffic_cache", indices = [Index("segment_id", unique = true), Index("level")])
data class SegmentTrafficEntity(
    @PrimaryKey @ColumnInfo(name = "segment_id") val segmentId: String,
    @ColumnInfo(name = "segment_name") val segmentName: String?,
    @ColumnInfo(name = "level") val level: String,
    @ColumnInfo(name = "average_speed_kmh") val averageSpeedKmh: Double?,
    @ColumnInfo(name = "free_flow_kmh") val freeFlowKmh: Double?,
    @ColumnInfo(name = "sample_count") val sampleCount: Int,
    @ColumnInfo(name = "reporter_count") val reporterCount: Int,
    @ColumnInfo(name = "confidence") val confidence: Double,
    @ColumnInfo(name = "updated_at_ms") val updatedAtMs: Long,
    @ColumnInfo(name = "source") val source: String
)

@Entity(tableName = "offline_map_packs", indices = [Index("created_at_ms")])
data class OfflineMapPackEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "name") val name: String,
    @ColumnInfo(name = "south") val south: Double,
    @ColumnInfo(name = "west") val west: Double,
    @ColumnInfo(name = "north") val north: Double,
    @ColumnInfo(name = "east") val east: Double,
    @ColumnInfo(name = "min_zoom") val minZoom: Int,
    @ColumnInfo(name = "max_zoom") val maxZoom: Int,
    @ColumnInfo(name = "style_url") val styleUrl: String,
    @ColumnInfo(name = "maplibre_region_id") val maplibreRegionId: Long?,
    @ColumnInfo(name = "state") val state: String,
    @ColumnInfo(name = "completed_resources") val completedResources: Long,
    @ColumnInfo(name = "required_resources") val requiredResources: Long,
    @ColumnInfo(name = "bytes_downloaded") val bytesDownloaded: Long,
    @ColumnInfo(name = "created_at_ms") val createdAtMs: Long,
    @ColumnInfo(name = "updated_at_ms") val updatedAtMs: Long,
    @ColumnInfo(name = "error") val error: String? = null,
    /** Routing graph imported for this pack, if the user added one. */
    @ColumnInfo(name = "graph_file") val graphFile: String? = null,
    @ColumnInfo(name = "graph_bytes") val graphBytes: Long = 0L
)

@Entity(tableName = "saved_places", indices = [Index("created_at_ms")])
data class SavedPlaceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    @ColumnInfo(name = "label") val label: String,
    @ColumnInfo(name = "latitude") val latitude: Double,
    @ColumnInfo(name = "longitude") val longitude: Double,
    @ColumnInfo(name = "created_at_ms") val createdAtMs: Long,
    @ColumnInfo(name = "is_home") val isHome: Boolean = false,
    @ColumnInfo(name = "is_work") val isWork: Boolean = false
)

/** Purgeable local copy of a server-side traffic aggregate used offline. */
@Entity(tableName = "traffic_history_buckets", indices = [Index("segment_id"), Index("bucket_start_ms")])
data class TrafficHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    @ColumnInfo(name = "segment_id") val segmentId: String,
    @ColumnInfo(name = "bucket_start_ms") val bucketStartMs: Long,
    @ColumnInfo(name = "average_speed_kmh") val averageSpeedKmh: Double,
    @ColumnInfo(name = "sample_count") val sampleCount: Int
)

@Dao
interface GpsDao {

    // ---------------------------------------------------------------- trips
    @Insert
    suspend fun insertTrip(trip: GpsTripEntity): Long

    @Query("UPDATE gps_trips SET ended_at_ms = :endedAtMs, distance_meters = :distance, max_speed_kmh = :maxSpeed, average_speed_kmh = :averageSpeed, moving_seconds = :movingSeconds, end_lat = :endLat, end_lon = :endLon, point_count = :pointCount, integrity_verdict = :verdict, encrypted_track_file = :trackFile WHERE id = :id")
    suspend fun finishTrip(
        id: Long,
        endedAtMs: Long,
        distance: Double,
        maxSpeed: Double,
        averageSpeed: Double,
        movingSeconds: Long,
        endLat: Double?,
        endLon: Double?,
        pointCount: Int,
        verdict: String,
        trackFile: String?
    )

    @Query("SELECT * FROM gps_trips ORDER BY started_at_ms DESC LIMIT :limit")
    fun observeTrips(limit: Int = 50): Flow<List<GpsTripEntity>>

    @Query("SELECT * FROM gps_trips ORDER BY started_at_ms DESC LIMIT :limit")
    suspend fun recentTrips(limit: Int = 50): List<GpsTripEntity>

    @Query("SELECT * FROM gps_trips WHERE id = :id")
    suspend fun trip(id: Long): GpsTripEntity?

    @Query("DELETE FROM gps_trips WHERE id = :id")
    suspend fun deleteTrip(id: Long)

    @Query("DELETE FROM gps_trips WHERE started_at_ms < :cutoffMs")
    suspend fun deleteTripsOlderThan(cutoffMs: Long)

    @Query("DELETE FROM gps_trips")
    suspend fun deleteAllTrips()

    @Query("SELECT COUNT(*) FROM gps_trips")
    suspend fun tripCount(): Int

    @Query("SELECT SUM(distance_meters) FROM gps_trips")
    suspend fun totalDistanceMeters(): Double?

    @Insert
    suspend fun insertPoints(points: List<TripPointEntity>)

    @Query("SELECT * FROM trip_points WHERE trip_id = :tripId ORDER BY timestamp_ms ASC")
    suspend fun pointsForTrip(tripId: Long): List<TripPointEntity>

    @Query("DELETE FROM trip_points WHERE trip_id = :tripId")
    suspend fun deletePointsForTrip(tripId: Long)

    @Query("DELETE FROM trip_points WHERE timestamp_ms < :cutoffMs")
    suspend fun deletePointsOlderThan(cutoffMs: Long)

    @Query("DELETE FROM trip_points")
    suspend fun deleteAllPoints()

    // ------------------------------------------------------- traffic samples
    @Insert
    suspend fun insertObservation(observation: TrafficObservationEntity): Long

    @Query("SELECT * FROM traffic_observations WHERE captured_at_ms >= :sinceMs ORDER BY captured_at_ms DESC")
    suspend fun observationsSince(sinceMs: Long): List<TrafficObservationEntity>

    @Query("SELECT * FROM traffic_observations WHERE queued_for_upload = 1 ORDER BY captured_at_ms ASC LIMIT :limit")
    suspend fun queuedObservations(limit: Int = 200): List<TrafficObservationEntity>

    @Query("UPDATE traffic_observations SET queued_for_upload = 0 WHERE id IN (:ids)")
    suspend fun markUploaded(ids: List<Long>)

    @Query("UPDATE traffic_observations SET upload_attempts = upload_attempts + 1 WHERE id IN (:ids)")
    suspend fun bumpAttempts(ids: List<Long>)

    @Query("DELETE FROM traffic_observations WHERE captured_at_ms < :cutoffMs")
    suspend fun deleteObservationsOlderThan(cutoffMs: Long)

    @Query("DELETE FROM traffic_observations")
    suspend fun deleteAllObservations()

    @Query("SELECT COUNT(*) FROM traffic_observations WHERE queued_for_upload = 1")
    fun observeQueuedObservationCount(): Flow<Int>

    // ------------------------------------------------------------- incidents
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertIncident(incident: TrafficIncidentEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertIncidents(incidents: List<TrafficIncidentEntity>)

    @Query("SELECT * FROM traffic_incidents WHERE expires_at_ms > :nowMs ORDER BY reported_at_ms DESC LIMIT :limit")
    fun observeActiveIncidents(nowMs: Long, limit: Int = 100): Flow<List<TrafficIncidentEntity>>

    @Query("SELECT * FROM traffic_incidents WHERE expires_at_ms > :nowMs ORDER BY reported_at_ms DESC")
    suspend fun activeIncidents(nowMs: Long): List<TrafficIncidentEntity>

    @Query("SELECT * FROM traffic_incidents WHERE sync_state = 'PENDING'")
    suspend fun pendingIncidents(): List<TrafficIncidentEntity>

    @Query("UPDATE traffic_incidents SET sync_state = :state WHERE id = :id")
    suspend fun setIncidentSyncState(id: String, state: String)

    @Query("UPDATE traffic_incidents SET confirmations = confirmations + 1 WHERE id = :id")
    suspend fun confirmIncident(id: String)

    @Query("DELETE FROM traffic_incidents WHERE id = :id")
    suspend fun deleteIncident(id: String)

    @Query("DELETE FROM traffic_incidents WHERE expires_at_ms < :nowMs - 3600000")
    suspend fun purgeExpiredIncidents(nowMs: Long)

    // ------------------------------------------------------------- segments
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSegmentTraffic(rows: List<SegmentTrafficEntity>)

    @Query("SELECT * FROM segment_traffic_cache")
    suspend fun allSegmentTraffic(): List<SegmentTrafficEntity>

    @Query("SELECT * FROM segment_traffic_cache")
    fun observeSegmentTraffic(): Flow<List<SegmentTrafficEntity>>

    @Query("SELECT * FROM segment_traffic_cache WHERE segment_id IN (:ids)")
    suspend fun segmentTraffic(ids: List<String>): List<SegmentTrafficEntity>

    @Query("DELETE FROM segment_traffic_cache WHERE updated_at_ms < :cutoffMs")
    suspend fun deleteStaleSegmentTraffic(cutoffMs: Long)

    @Query("DELETE FROM segment_traffic_cache")
    suspend fun deleteAllSegmentTraffic()

    // ---------------------------------------------------------- offline pack
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertOfflinePack(pack: OfflineMapPackEntity)

    @Query("SELECT * FROM offline_map_packs ORDER BY created_at_ms DESC")
    fun observeOfflinePacks(): Flow<List<OfflineMapPackEntity>>

    @Query("SELECT * FROM offline_map_packs ORDER BY created_at_ms DESC")
    suspend fun offlinePacks(): List<OfflineMapPackEntity>

    @Query("SELECT * FROM offline_map_packs WHERE id = :id")
    suspend fun offlinePack(id: String): OfflineMapPackEntity?

    @Query("UPDATE offline_map_packs SET state = :state, completed_resources = :completed, required_resources = :required, bytes_downloaded = :bytes, updated_at_ms = :updatedAt, error = :error WHERE id = :id")
    suspend fun updatePackProgress(
        id: String,
        state: String,
        completed: Long,
        required: Long,
        bytes: Long,
        updatedAt: Long,
        error: String?
    )

    @Query("UPDATE offline_map_packs SET graph_file = :graphFile, graph_bytes = :graphBytes WHERE id = :id")
    suspend fun setPackGraph(id: String, graphFile: String?, graphBytes: Long)

    @Query("DELETE FROM offline_map_packs WHERE id = :id")
    suspend fun deleteOfflinePack(id: String)

    @Query("SELECT SUM(bytes_downloaded) FROM offline_map_packs")
    fun observeOfflineBytes(): Flow<Long?>

    // --------------------------------------------------------- saved places
    @Insert
    suspend fun insertSavedPlace(place: SavedPlaceEntity): Long

    @Query("SELECT * FROM saved_places ORDER BY created_at_ms DESC")
    fun observeSavedPlaces(): Flow<List<SavedPlaceEntity>>

    @Query("SELECT * FROM saved_places ORDER BY created_at_ms DESC")
    suspend fun savedPlaces(): List<SavedPlaceEntity>

    @Query("DELETE FROM saved_places WHERE id = :id")
    suspend fun deleteSavedPlace(id: Long)

    // ------------------------------------------------------ traffic history
    @Insert
    suspend fun insertTrafficHistory(rows: List<TrafficHistoryEntity>)

    @Query("SELECT * FROM traffic_history_buckets WHERE segment_id = :segmentId ORDER BY bucket_start_ms DESC LIMIT :limit")
    suspend fun historyForSegment(segmentId: String, limit: Int = 64): List<TrafficHistoryEntity>

    @Query("SELECT * FROM traffic_history_buckets WHERE bucket_start_ms >= :sinceMs")
    suspend fun historySince(sinceMs: Long): List<TrafficHistoryEntity>

    @Query("DELETE FROM traffic_history_buckets WHERE bucket_start_ms < :cutoffMs")
    suspend fun deleteHistoryOlderThan(cutoffMs: Long)

    @Query("DELETE FROM traffic_history_buckets")
    suspend fun deleteAllHistory()

    /** Everything the privacy screen's "delete all location data" button must remove. */
    @Query("DELETE FROM gps_trips")
    suspend fun wipeTrips()

    @Query("DELETE FROM trip_points")
    suspend fun wipePoints()

    @Query("DELETE FROM traffic_observations")
    suspend fun wipeObservations()

    @Query("DELETE FROM traffic_incidents WHERE reported_by_me = 1")
    suspend fun wipeMyIncidents()
}
