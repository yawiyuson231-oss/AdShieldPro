package com.adshield.pro.data.local.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        DnsLogEntity::class,
        CustomRuleEntity::class,
        FilterSourceEntity::class,
        DailyStatEntity::class,
        SecurityScanEntity::class,
        StorageProviderEntity::class,
        DirectDownloadEntity::class,
        IntelligenceEventEntity::class
    ],
    version = 4,
    exportSchema = true
)
abstract class AdShieldDatabase : RoomDatabase() {
    abstract fun adShieldDao(): AdShieldDao

    abstract fun intelligenceEventDao(): IntelligenceEventDao

    companion object {
        const val DATABASE_NAME = "adshield_pro_v2.db"

        /**
         * Explicit Room schema migration from v1 to v2 adding `etag_or_hash` to `filter_sources`
         * and creating indices on `dns_logs` for fast query filtering.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE filter_sources ADD COLUMN etag_or_hash TEXT NOT NULL DEFAULT ''"
                )
                // Every index declared on the v2 entities must exist after the migration,
                // otherwise Room's identity-hash validation fails at runtime and the app
                // crashes while opening the database. IF NOT EXISTS keeps this idempotent for
                // databases that already carried some of these indices.
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_dns_logs_timestamp_epoch_ms " +
                        "ON dns_logs(timestamp_epoch_ms)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_dns_logs_domain ON dns_logs(domain)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_dns_logs_is_blocked ON dns_logs(is_blocked)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_custom_rules_normalized_pattern_rule_type " +
                        "ON custom_rules(normalized_pattern, rule_type)"
                )
            }
        }

        /** Adds durable security evidence, provider health/quota, and direct-download history. */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """CREATE TABLE IF NOT EXISTS security_scans (
                        id INTEGER NOT NULL PRIMARY KEY,
                        kind TEXT NOT NULL,
                        target TEXT NOT NULL,
                        source_uri TEXT,
                        threat_level TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        threat_name TEXT,
                        findings_json TEXT NOT NULL,
                        recommendation TEXT NOT NULL,
                        timestamp_epoch_ms INTEGER NOT NULL
                    )"""
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS index_security_scans_timestamp_epoch_ms ON security_scans(timestamp_epoch_ms)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_security_scans_threat_level ON security_scans(threat_level)")
                db.execSQL(
                    """CREATE TABLE IF NOT EXISTS storage_providers (
                        id TEXT NOT NULL PRIMARY KEY,
                        name TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        username TEXT NOT NULL,
                        health TEXT NOT NULL,
                        last_checked_epoch_ms INTEGER NOT NULL,
                        last_error TEXT,
                        total_bytes INTEGER,
                        available_bytes INTEGER,
                        used_bytes INTEGER
                    )"""
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS index_storage_providers_health ON storage_providers(health)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_storage_providers_last_checked_epoch_ms ON storage_providers(last_checked_epoch_ms)")
                db.execSQL(
                    """CREATE TABLE IF NOT EXISTS direct_downloads (
                        id TEXT NOT NULL PRIMARY KEY,
                        system_download_id INTEGER,
                        source_url TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        mime_type TEXT NOT NULL,
                        destination_uri TEXT,
                        status TEXT NOT NULL,
                        downloaded_bytes INTEGER NOT NULL,
                        total_bytes INTEGER,
                        created_at_epoch_ms INTEGER NOT NULL,
                        updated_at_epoch_ms INTEGER NOT NULL,
                        error TEXT,
                        integrity_status TEXT
                    )"""
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS index_direct_downloads_system_download_id ON direct_downloads(system_download_id)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_direct_downloads_updated_at_epoch_ms ON direct_downloads(updated_at_epoch_ms)")
            }
        }

        /**
         * Adds the bounded intelligence-event store that feeds the OMNISHIELD X live map.
         * Index names match Room's generated naming so the identity hash validates after migration.
         */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """CREATE TABLE IF NOT EXISTS intelligence_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        module TEXT NOT NULL,
                        type_code TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        timestamp_epoch_ms INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        evidence_ref TEXT,
                        related_ids TEXT NOT NULL,
                        metrics TEXT NOT NULL,
                        actions TEXT NOT NULL
                    )"""
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intelligence_events_timestamp_epoch_ms " +
                        "ON intelligence_events(timestamp_epoch_ms)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intelligence_events_module " +
                        "ON intelligence_events(module)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intelligence_events_severity " +
                        "ON intelligence_events(severity)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intelligence_events_module_timestamp_epoch_ms " +
                        "ON intelligence_events(module, timestamp_epoch_ms)"
                )
            }
        }
    }
}
