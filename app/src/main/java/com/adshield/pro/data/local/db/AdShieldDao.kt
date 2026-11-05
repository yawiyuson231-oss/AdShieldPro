package com.adshield.pro.data.local.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.adshield.pro.domain.model.DomainBlockCount
import com.adshield.pro.domain.model.SourceEffectiveness
import kotlinx.coroutines.flow.Flow

@Dao
interface AdShieldDao {

    // --- DNS Activity Logs ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDnsLog(log: DnsLogEntity)

    @Query("SELECT * FROM dns_logs ORDER BY timestamp_epoch_ms DESC LIMIT :limit")
    fun observeRecentLogs(limit: Int = 250): Flow<List<DnsLogEntity>>

    @Query("SELECT COUNT(*) FROM dns_logs")
    fun observeTotalLoggedCount(): Flow<Long>

    @Query("SELECT COUNT(*) FROM dns_logs WHERE is_blocked = 1")
    fun observeBlockedLoggedCount(): Flow<Long>

    @Query(
        """
        SELECT domain, category, COUNT(*) AS count 
        FROM dns_logs 
        WHERE is_blocked = 1 
        GROUP BY domain 
        ORDER BY count DESC 
        LIMIT :limit
        """
    )
    fun observeTopBlockedDomains(limit: Int = 15): Flow<List<DomainBlockCount>>

    @Query(
        """
        SELECT source_list AS sourceList, COUNT(*) AS blockedCount 
        FROM dns_logs 
        WHERE is_blocked = 1 
        GROUP BY source_list 
        ORDER BY blockedCount DESC
        """
    )
    fun observeSourceEffectiveness(): Flow<List<SourceEffectiveness>>

    @Query("SELECT COUNT(*) FROM dns_logs WHERE is_blocked = 1 AND category = 'MALWARE'")
    fun observeMalwareBlockCount(): Flow<Long>

    @Query("DELETE FROM dns_logs WHERE timestamp_epoch_ms < :cutoffEpochMs")
    suspend fun pruneLogsOlderThan(cutoffEpochMs: Long): Int

    @Query("DELETE FROM dns_logs")
    suspend fun clearAllDnsLogs()

    // --- Aggregated Daily Stats ---
    @Query("SELECT * FROM daily_stats WHERE date_epoch_day >= :minEpochDay ORDER BY date_epoch_day ASC")
    fun observeDailyStatsSince(minEpochDay: Long): Flow<List<DailyStatEntity>>

    @Query("SELECT COALESCE(SUM(total_queries), 0) FROM daily_stats")
    fun observeAllTimeTotalQueries(): Flow<Long>

    @Query("SELECT COALESCE(SUM(blocked_queries), 0) FROM daily_stats")
    fun observeAllTimeBlockedQueries(): Flow<Long>

    @Query("SELECT COALESCE(SUM(allowed_queries), 0) FROM daily_stats")
    fun observeAllTimeAllowedQueries(): Flow<Long>

    @Query("SELECT * FROM daily_stats WHERE date_epoch_day = :epochDay LIMIT 1")
    suspend fun getDailyStatForDay(epochDay: Long): DailyStatEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDailyStat(stat: DailyStatEntity)

    @Query("DELETE FROM daily_stats WHERE date_epoch_day < :minEpochDay")
    suspend fun pruneDailyStatsOlderThan(minEpochDay: Long)

    @Query("DELETE FROM daily_stats")
    suspend fun clearAllDailyStats()

    // --- Custom Rules ---
    @Query("SELECT * FROM custom_rules ORDER BY priority DESC, created_at_epoch_ms DESC")
    fun observeCustomRules(): Flow<List<CustomRuleEntity>>

    @Query("SELECT * FROM custom_rules ORDER BY priority DESC, created_at_epoch_ms DESC")
    suspend fun getAllCustomRulesNow(): List<CustomRuleEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertCustomRule(rule: CustomRuleEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertCustomRules(rules: List<CustomRuleEntity>)

    @Update
    suspend fun updateCustomRule(rule: CustomRuleEntity)

    @Query("DELETE FROM custom_rules WHERE id = :ruleId")
    suspend fun deleteCustomRuleById(ruleId: Long)

    @Query("DELETE FROM custom_rules")
    suspend fun clearAllCustomRules()

    // --- Filter List Sources ---
    @Query("SELECT * FROM filter_sources ORDER BY is_built_in DESC, name ASC")
    fun observeFilterSources(): Flow<List<FilterSourceEntity>>

    @Query("SELECT * FROM filter_sources ORDER BY is_built_in DESC, name ASC")
    suspend fun getAllFilterSourcesNow(): List<FilterSourceEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFilterSources(sources: List<FilterSourceEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFilterSource(source: FilterSourceEntity)

    @Query("DELETE FROM filter_sources WHERE id = :id AND is_built_in = 0")
    suspend fun deleteCustomFilterSource(id: String)

    // --- Persistent security reports ---
    @Query("SELECT * FROM security_scans ORDER BY timestamp_epoch_ms DESC LIMIT 200")
    fun observeSecurityScans(): Flow<List<SecurityScanEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSecurityScan(scan: SecurityScanEntity)

    @Query("DELETE FROM security_scans WHERE id = :id")
    suspend fun deleteSecurityScan(id: Long)

    @Query("DELETE FROM security_scans")
    suspend fun clearSecurityScans()

    // --- Authorized storage providers ---
    @Query("SELECT * FROM storage_providers ORDER BY name COLLATE NOCASE ASC")
    fun observeStorageProviders(): Flow<List<StorageProviderEntity>>

    @Query("SELECT * FROM storage_providers WHERE id = :id LIMIT 1")
    suspend fun getStorageProvider(id: String): StorageProviderEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertStorageProvider(provider: StorageProviderEntity)

    @Query("DELETE FROM storage_providers WHERE id = :id")
    suspend fun deleteStorageProvider(id: String)

    // --- Direct-media download history ---
    @Query("SELECT * FROM direct_downloads ORDER BY created_at_epoch_ms DESC LIMIT 200")
    fun observeDirectDownloads(): Flow<List<DirectDownloadEntity>>

    @Query("SELECT * FROM direct_downloads WHERE id = :id LIMIT 1")
    suspend fun getDirectDownload(id: String): DirectDownloadEntity?

    @Query("SELECT * FROM direct_downloads WHERE system_download_id IS NOT NULL AND status IN ('QUEUED', 'RUNNING', 'PAUSED_BY_SYSTEM')")
    suspend fun getActiveDirectDownloads(): List<DirectDownloadEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDirectDownload(download: DirectDownloadEntity)

    @Query("DELETE FROM direct_downloads WHERE id = :id")
    suspend fun deleteDirectDownload(id: String)
}
