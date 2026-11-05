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
        CloudFileEntity::class,
        CloudTransferEntity::class,
        CloudDnsBackupEntity::class
    ],
    version = 3,
    exportSchema = true
)
abstract class AdShieldDatabase : RoomDatabase() {
    abstract fun adShieldDao(): AdShieldDao
    abstract fun cloudDao(): CloudDao

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
         * v2 -> v3 adds the cloud module tables: cached cloud file metadata, the resumable
         * transfer queue and the DNS cloud-backup history.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS cloud_files (" +
                        "id TEXT NOT NULL PRIMARY KEY, " +
                        "name TEXT NOT NULL, " +
                        "folder_path TEXT NOT NULL, " +
                        "size_bytes INTEGER NOT NULL, " +
                        "mime_type TEXT NOT NULL, " +
                        "sha256 TEXT NOT NULL, " +
                        "is_deleted INTEGER NOT NULL, " +
                        "version INTEGER NOT NULL, " +
                        "updated_at_epoch_ms INTEGER NOT NULL)"
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS index_cloud_files_folder_path ON cloud_files(folder_path)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_cloud_files_sha256 ON cloud_files(sha256)")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS cloud_transfers (" +
                        "id TEXT NOT NULL PRIMARY KEY, " +
                        "direction TEXT NOT NULL, " +
                        "file_id TEXT, " +
                        "display_name TEXT NOT NULL, " +
                        "source_uri TEXT NOT NULL, " +
                        "dest_uri TEXT NOT NULL, " +
                        "total_bytes INTEGER NOT NULL, " +
                        "done_bytes INTEGER NOT NULL, " +
                        "state TEXT NOT NULL, " +
                        "sha256 TEXT NOT NULL, " +
                        "error_message TEXT NOT NULL DEFAULT '', " +
                        "updated_at_epoch_ms INTEGER NOT NULL)"
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS index_cloud_transfers_state ON cloud_transfers(state)")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS cloud_dns_backups (" +
                        "id TEXT NOT NULL PRIMARY KEY, " +
                        "label TEXT NOT NULL, " +
                        "cloud_file_id TEXT NOT NULL, " +
                        "sha256 TEXT NOT NULL, " +
                        "created_at_epoch_ms INTEGER NOT NULL, " +
                        "restored_at_epoch_ms INTEGER)"
                )
            }
        }
    }
}
