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
        IntelIndicatorEntity::class,
        IntelMetaEntity::class
    ],
    version = 3,
    exportSchema = true
)
abstract class AdShieldDatabase : RoomDatabase() {
    abstract fun adShieldDao(): AdShieldDao

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

        /**
         * v2 → v3: severity breakdown columns on `daily_stats` (existing rows stay 0 and are
         * surfaced as "unclassified earlier blocks"), plus the threat-intel cache tables.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE daily_stats ADD COLUMN critical_blocks INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE daily_stats ADD COLUMN high_blocks INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE daily_stats ADD COLUMN medium_blocks INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE daily_stats ADD COLUMN low_blocks INTEGER NOT NULL DEFAULT 0")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS intel_indicators (" +
                        "`key` TEXT NOT NULL, " +
                        "source_id TEXT NOT NULL, " +
                        "kind TEXT NOT NULL, " +
                        "value TEXT NOT NULL, " +
                        "host TEXT NOT NULL, " +
                        "port INTEGER, " +
                        "country TEXT, " +
                        "malware_family TEXT, " +
                        "threat TEXT, " +
                        "status TEXT, " +
                        "first_seen_utc TEXT, " +
                        "last_online_utc TEXT, " +
                        "reference_url TEXT, " +
                        "fetched_at_epoch_ms INTEGER NOT NULL, " +
                        "PRIMARY KEY(`key`))"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intel_indicators_source_id ON intel_indicators(source_id)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_intel_indicators_country ON intel_indicators(country)"
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS intel_meta (" +
                        "source_id TEXT NOT NULL, " +
                        "status TEXT NOT NULL, " +
                        "last_fetch_epoch_ms INTEGER NOT NULL, " +
                        "last_error TEXT, " +
                        "item_count INTEGER NOT NULL, " +
                        "PRIMARY KEY(source_id))"
                )
            }
        }
    }
}
