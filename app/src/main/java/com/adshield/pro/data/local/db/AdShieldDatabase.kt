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
        DailyStatEntity::class
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
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_dns_logs_is_blocked ON dns_logs(is_blocked)"
                )
            }
        }

        /**
         * v2 → v3: per-app attribution on DNS history rows (CyberShield AI
         * threat details / activity feed). Existing rows keep NULL attribution.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE dns_logs ADD COLUMN app_package TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE dns_logs ADD COLUMN app_label TEXT DEFAULT NULL")
            }
        }
    }
}
