package com.adshield.pro.data.local.db

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * Runtime state of one connector. Persisted so a failure survives a restart, and so the UI can
 * never show "CONNECTED" for something that has not actually succeeded since install.
 */
@Entity(tableName = "connector_state")
data class ConnectorStateEntity(
    @PrimaryKey val connectorId: String,
    val status: String,
    val enabled: Boolean,
    val lastAttemptEpochMs: Long? = null,
    val lastSuccessEpochMs: Long? = null,
    val lastError: String? = null,
    val httpCode: Int? = null,
    val indicatorCount: Int = 0,
    val etag: String? = null,
    val lastModified: String? = null,
    val nextAllowedEpochMs: Long? = null,
    val consecutiveFailures: Int = 0,
    val lastSummary: String? = null,
    val latencyMs: Long? = null
)

/**
 * Bounded, deduplicated indicator cache. The unique index on (sourceId, kind, value) means the
 * same IOC fetched twice updates instead of duplicating; the expiry column lets retention delete
 * stale intelligence instead of serving it as current.
 */
@Entity(
    tableName = "threat_indicators",
    indices = [
        Index("kind"),
        Index("value"),
        Index(value = ["sourceId", "kind", "value"], unique = true),
        Index("expiresAtEpochMs")
    ]
)
data class ThreatIndicatorEntity(
    @PrimaryKey(autoGenerate = true) val rowId: Long = 0,
    val kind: String,
    val value: String,
    val sourceId: String,
    val module: String,
    val label: String,
    val confidence: Int,
    val firstSeenEpochMs: Long,
    val expiresAtEpochMs: Long,
    val attribution: String
)

data class IndicatorKindCount(
    val kind: String,
    @ColumnInfo(name = "count") val count: Int
)

@Dao
interface ConnectorDao {

    @Query("SELECT * FROM connector_state")
    fun observeStates(): Flow<List<ConnectorStateEntity>>

    @Query("SELECT * FROM connector_state WHERE connectorId = :connectorId LIMIT 1")
    suspend fun stateFor(connectorId: String): ConnectorStateEntity?

    @Upsert
    suspend fun upsertState(state: ConnectorStateEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertIndicators(indicators: List<ThreatIndicatorEntity>)

    @Query("DELETE FROM threat_indicators WHERE sourceId = :sourceId")
    suspend fun deleteForSource(sourceId: String): Int

    @Query("SELECT COUNT(*) FROM threat_indicators WHERE sourceId = :sourceId")
    suspend fun countForSource(sourceId: String): Int

    @Query("SELECT COUNT(*) FROM threat_indicators")
    suspend fun countAll(): Int

    @Query("SELECT kind, COUNT(*) AS count FROM threat_indicators GROUP BY kind")
    suspend fun countsByKind(): List<IndicatorKindCount>

    @Query(
        "SELECT * FROM threat_indicators WHERE kind = :kind AND value IN (:values) " +
            "AND expiresAtEpochMs > :nowEpochMs ORDER BY confidence DESC LIMIT :limit"
    )
    suspend fun match(kind: String, values: List<String>, nowEpochMs: Long, limit: Int = 12): List<ThreatIndicatorEntity>

    @Query("SELECT * FROM threat_indicators WHERE kind = 'IP_CIDR' AND expiresAtEpochMs > :nowEpochMs")
    suspend fun activeCidrs(nowEpochMs: Long): List<ThreatIndicatorEntity>

    @Query("DELETE FROM threat_indicators WHERE expiresAtEpochMs < :nowEpochMs")
    suspend fun pruneExpired(nowEpochMs: Long): Int

    @Query(
        "DELETE FROM threat_indicators WHERE rowId NOT IN " +
            "(SELECT rowId FROM threat_indicators ORDER BY firstSeenEpochMs DESC LIMIT :keep)"
    )
    suspend fun trimToLimit(keep: Int): Int

    @Query("DELETE FROM threat_indicators")
    suspend fun clearIndicators(): Int

    @Query("SELECT MAX(lastSuccessEpochMs) FROM connector_state")
    fun observeLastSuccess(): Flow<Long?>
}


/**
 * Cache for on-demand lookups (hash/domain/IP/CVE/package).
 *
 * Keyed by connector + canonical value so a repeated query is served from disk without touching
 * the provider. [expiresAtEpochMs] is the freshness boundary; an expired entry may still be shown
 * while offline, but only with an explicit "cached" marker and its real timestamp.
 */
@Entity(
    tableName = "lookup_cache",
    primaryKeys = ["cacheKey"],
    indices = [Index("connectorId"), Index("expiresAtEpochMs")]
)
data class LookupCacheEntity(
    val cacheKey: String,
    val connectorId: String,
    val field: String,
    val query: String,
    val found: Boolean,
    val riskScore: Int,
    val headline: String,
    val evidenceJson: String,
    val attribution: String,
    val fetchedAtEpochMs: Long,
    val expiresAtEpochMs: Long,
    val httpCode: Int?
)

@Dao
interface LookupCacheDao {

    @Query("SELECT * FROM lookup_cache WHERE cacheKey = :key LIMIT 1")
    suspend fun get(key: String): LookupCacheEntity?

    @Upsert
    suspend fun upsert(entry: LookupCacheEntity)

    @Query("DELETE FROM lookup_cache WHERE expiresAtEpochMs < :nowEpochMs")
    suspend fun pruneExpired(nowEpochMs: Long): Int

    @Query("SELECT COUNT(*) FROM lookup_cache")
    suspend fun count(): Int

    @Query("DELETE FROM lookup_cache")
    suspend fun clear(): Int
}
