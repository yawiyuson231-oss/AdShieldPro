package com.adshield.pro.gps.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * AdShield Pro — GPS module database.
 *
 * Kept separate from [com.adshield.pro.data.local.db.AdShieldDatabase] so that:
 *  - the DNS/filter database schema is untouched by this module (no migration risk to the
 *    existing product);
 *  - "delete all location data" is one file deletion plus one keystore entry deletion;
 *  - a corrupted location database can be dropped without losing filter rules or statistics.
 */
@Database(
    entities = [
        GpsTripEntity::class,
        TripPointEntity::class,
        TrafficObservationEntity::class,
        TrafficIncidentEntity::class,
        SegmentTrafficEntity::class,
        OfflineMapPackEntity::class,
        SavedPlaceEntity::class,
        TrafficHistoryEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class GpsDatabase : RoomDatabase() {

    abstract fun gpsDao(): GpsDao

    companion object {
        const val DATABASE_NAME = "adshield_gps.db"

        fun build(context: Context): GpsDatabase = Room.databaseBuilder(
            context.applicationContext,
            GpsDatabase::class.java,
            DATABASE_NAME
        )
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()
    }
}
