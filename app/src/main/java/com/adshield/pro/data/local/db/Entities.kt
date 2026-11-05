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
    val cachedQueries: Long
)

@Entity(
    tableName = "security_scans",
    indices = [Index(value = ["timestamp_epoch_ms"]), Index(value = ["threat_level"])]
)
data class SecurityScanEntity(
    @PrimaryKey val id: Long,
    @ColumnInfo(name = "kind") val kind: String,
    @ColumnInfo(name = "target") val target: String,
    @ColumnInfo(name = "source_uri") val sourceUri: String?,
    @ColumnInfo(name = "threat_level") val threatLevel: String,
    @ColumnInfo(name = "risk_score") val riskScore: Int,
    @ColumnInfo(name = "threat_name") val threatName: String?,
    @ColumnInfo(name = "findings_json") val findingsJson: String,
    @ColumnInfo(name = "recommendation") val recommendation: String,
    @ColumnInfo(name = "timestamp_epoch_ms") val timestampEpochMs: Long
)

@Entity(
    tableName = "storage_providers",
    indices = [Index(value = ["health"]), Index(value = ["last_checked_epoch_ms"])]
)
data class StorageProviderEntity(
    @PrimaryKey val id: String,
    val name: String,
    val kind: String,
    @ColumnInfo(name = "base_url") val baseUrl: String,
    val username: String,
    val health: String,
    @ColumnInfo(name = "last_checked_epoch_ms") val lastCheckedEpochMs: Long,
    @ColumnInfo(name = "last_error") val lastError: String?,
    @ColumnInfo(name = "total_bytes") val totalBytes: Long?,
    @ColumnInfo(name = "available_bytes") val availableBytes: Long?,
    @ColumnInfo(name = "used_bytes") val usedBytes: Long?
)

@Entity(
    tableName = "direct_downloads",
    indices = [Index(value = ["system_download_id"]), Index(value = ["updated_at_epoch_ms"])]
)
data class DirectDownloadEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "system_download_id") val systemDownloadId: Long?,
    @ColumnInfo(name = "source_url") val sourceUrl: String,
    @ColumnInfo(name = "file_name") val fileName: String,
    @ColumnInfo(name = "mime_type") val mimeType: String,
    @ColumnInfo(name = "destination_uri") val destinationUri: String?,
    val status: String,
    @ColumnInfo(name = "downloaded_bytes") val downloadedBytes: Long,
    @ColumnInfo(name = "total_bytes") val totalBytes: Long?,
    @ColumnInfo(name = "created_at_epoch_ms") val createdAtEpochMs: Long,
    @ColumnInfo(name = "updated_at_epoch_ms") val updatedAtEpochMs: Long,
    val error: String?,
    @ColumnInfo(name = "integrity_status") val integrityStatus: String?
)
