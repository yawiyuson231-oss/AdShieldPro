package com.adshield.pro.data.local.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "dns_logs",
    indices = [
        Index(value = ["timestamp_epoch_ms"]),
        Index(value = ["domain"]),
        Index(value = ["is_blocked"])
    ]
)
data class DnsLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0L,
    @ColumnInfo(name = "timestamp_epoch_ms")
    val timestampEpochMs: Long,
    @ColumnInfo(name = "domain")
    val domain: String,
    @ColumnInfo(name = "query_type")
    val queryType: String,
    @ColumnInfo(name = "is_blocked")
    val isBlocked: Boolean,
    @ColumnInfo(name = "category")
    val category: String?,
    @ColumnInfo(name = "matched_rule")
    val matchedRule: String?,
    @ColumnInfo(name = "source_list")
    val sourceList: String,
    @ColumnInfo(name = "latency_ms")
    val latencyMs: Int,
    @ColumnInfo(name = "protocol_used")
    val protocolUsed: String
)

@Entity(
    tableName = "custom_rules",
    indices = [
        Index(value = ["normalized_pattern", "rule_type"], unique = false)
    ]
)
data class CustomRuleEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0L,
    @ColumnInfo(name = "raw_pattern")
    val rawPattern: String,
    @ColumnInfo(name = "normalized_pattern")
    val normalizedPattern: String,
    @ColumnInfo(name = "rule_type")
    val ruleType: String,
    @ColumnInfo(name = "match_type")
    val matchType: String,
    @ColumnInfo(name = "category")
    val category: String,
    @ColumnInfo(name = "priority")
    val priority: Int,
    @ColumnInfo(name = "is_enabled")
    val isEnabled: Boolean,
    @ColumnInfo(name = "comment")
    val comment: String,
    @ColumnInfo(name = "created_at_epoch_ms")
    val createdAtEpochMs: Long
)

@Entity(tableName = "filter_sources")
data class FilterSourceEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "name")
    val name: String,
    @ColumnInfo(name = "description")
    val description: String,
    @ColumnInfo(name = "url")
    val url: String,
    @ColumnInfo(name = "license_name")
    val licenseName: String,
    @ColumnInfo(name = "category")
    val category: String,
    @ColumnInfo(name = "is_built_in")
    val isBuiltIn: Boolean,
    @ColumnInfo(name = "is_enabled")
    val isEnabled: Boolean,
    @ColumnInfo(name = "is_premium_only")
    val isPremiumOnly: Boolean,
    @ColumnInfo(name = "rule_count")
    val ruleCount: Int,
    @ColumnInfo(name = "duplicate_count")
    val duplicateCount: Int,
    @ColumnInfo(name = "last_updated_epoch_ms")
    val lastUpdatedEpochMs: Long,
    @ColumnInfo(name = "last_status_message")
    val lastStatusMessage: String,
    @ColumnInfo(name = "etag_or_hash", defaultValue = "")
    val etagOrHash: String = ""
)

@Entity(tableName = "daily_stats")
data class DailyStatEntity(
    @PrimaryKey
    @ColumnInfo(name = "date_epoch_day")
    val dateEpochDay: Long,
    @ColumnInfo(name = "total_queries")
    val totalQueries: Long,
    @ColumnInfo(name = "blocked_queries")
    val blockedQueries: Long,
    @ColumnInfo(name = "allowed_queries")
    val allowedQueries: Long,
    @ColumnInfo(name = "cached_queries")
    val cachedQueries: Long,
    // Severity breakdown of blocked queries (v3). Rows written before v3 keep 0 here; the
    // dashboard labels the difference as "unclassified earlier blocks" instead of hiding it.
    @ColumnInfo(name = "critical_blocks", defaultValue = "0")
    val criticalBlocks: Long = 0L,
    @ColumnInfo(name = "high_blocks", defaultValue = "0")
    val highBlocks: Long = 0L,
    @ColumnInfo(name = "medium_blocks", defaultValue = "0")
    val mediumBlocks: Long = 0L,
    @ColumnInfo(name = "low_blocks", defaultValue = "0")
    val lowBlocks: Long = 0L
)

/**
 * Cached external threat-intelligence indicator (abuse.ch Feodo Tracker / URLhaus).
 * Persisted so the map and lists keep working offline; freshness is tracked per source in
 * [IntelMetaEntity] and always shown with the data.
 */
@Entity(
    tableName = "intel_indicators",
    indices = [
        Index(value = ["source_id"]),
        Index(value = ["country"])
    ]
)
data class IntelIndicatorEntity(
    @PrimaryKey
    @ColumnInfo(name = "key")
    val key: String,
    @ColumnInfo(name = "source_id")
    val sourceId: String,
    @ColumnInfo(name = "kind")
    val kind: String,
    @ColumnInfo(name = "value")
    val value: String,
    @ColumnInfo(name = "host")
    val host: String,
    @ColumnInfo(name = "port")
    val port: Int?,
    @ColumnInfo(name = "country")
    val country: String?,
    @ColumnInfo(name = "malware_family")
    val malwareFamily: String?,
    @ColumnInfo(name = "threat")
    val threat: String?,
    @ColumnInfo(name = "status")
    val status: String?,
    @ColumnInfo(name = "first_seen_utc")
    val firstSeenUtc: String?,
    @ColumnInfo(name = "last_online_utc")
    val lastOnlineUtc: String?,
    @ColumnInfo(name = "reference_url")
    val referenceUrl: String?,
    @ColumnInfo(name = "fetched_at_epoch_ms")
    val fetchedAtEpochMs: Long
)

/** Per-feed sync metadata: when it last succeeded, how many items, and the last real error. */
@Entity(tableName = "intel_meta")
data class IntelMetaEntity(
    @PrimaryKey
    @ColumnInfo(name = "source_id")
    val sourceId: String,
    @ColumnInfo(name = "status")
    val status: String,
    @ColumnInfo(name = "last_fetch_epoch_ms")
    val lastFetchEpochMs: Long,
    @ColumnInfo(name = "last_error")
    val lastError: String?,
    @ColumnInfo(name = "item_count")
    val itemCount: Int
)
