package com.adshield.pro.data.local.db

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Persisted intelligence events for the OMNISHIELD X map.
 *
 * The table is bounded by [com.adshield.pro.data.repository.IntelligenceLimits]: the recorder
 * prunes by age and trims by row count, so a long-lived install cannot grow the history without
 * limit. Every column is a plain string/number so Room's schema stays trivially migratable.
 */
@Entity(
    tableName = "intelligence_events",
    indices = [
        Index(value = ["timestamp_epoch_ms"]),
        Index(value = ["module"]),
        Index(value = ["severity"]),
        Index(value = ["module", "timestamp_epoch_ms"])
    ]
)
data class IntelligenceEventEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0L,
    @ColumnInfo(name = "module") val module: String,
    @ColumnInfo(name = "type_code") val typeCode: String,
    @ColumnInfo(name = "severity") val severity: String,
    @ColumnInfo(name = "timestamp_epoch_ms") val timestampEpochMs: Long,
    @ColumnInfo(name = "title") val title: String,
    @ColumnInfo(name = "description") val description: String,
    @ColumnInfo(name = "evidence") val evidence: String,
    @ColumnInfo(name = "evidence_ref") val evidenceRef: String?,
    @ColumnInfo(name = "related_ids") val relatedIdsJson: String,
    @ColumnInfo(name = "metrics") val metricsJson: String,
    @ColumnInfo(name = "actions") val actionsCsv: String
)

@Dao
interface IntelligenceEventDao {

    @Insert
    suspend fun insert(event: IntelligenceEventEntity): Long

    @Query(
        "SELECT * FROM intelligence_events ORDER BY timestamp_epoch_ms DESC, id DESC LIMIT :limit"
    )
    fun observeRecent(limit: Int): Flow<List<IntelligenceEventEntity>>

    @Query(
        "SELECT * FROM intelligence_events WHERE module = :module " +
            "ORDER BY timestamp_epoch_ms DESC, id DESC LIMIT :limit"
    )
    fun observeForModule(module: String, limit: Int): Flow<List<IntelligenceEventEntity>>

    @Query("SELECT COUNT(*) FROM intelligence_events")
    suspend fun count(): Int

    @Query("SELECT COUNT(*) FROM intelligence_events WHERE module = :module")
    suspend fun countForModule(module: String): Int

    @Query("DELETE FROM intelligence_events WHERE timestamp_epoch_ms < :cutoffEpochMs")
    suspend fun pruneBefore(cutoffEpochMs: Long): Int

    @Query(
        "DELETE FROM intelligence_events WHERE id NOT IN (" +
            "SELECT id FROM intelligence_events ORDER BY timestamp_epoch_ms DESC, id DESC LIMIT :maxRows)"
    )
    suspend fun trimToLimit(maxRows: Int): Int

    @Query("DELETE FROM intelligence_events")
    suspend fun clearAll()
}
