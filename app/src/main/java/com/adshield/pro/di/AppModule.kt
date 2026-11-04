package com.adshield.pro.di

import android.content.Context
import androidx.room.Room
import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.AdShieldDatabase
import com.adshield.pro.engine.downloader.MediaDownloaderEngine
import com.adshield.pro.engine.security.SecurityEngine
import com.adshield.pro.engine.storage.PrivateCloudBoxEngine
import com.adshield.pro.engine.storage.UniversalFileManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.io.File
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAdShieldDatabase(
        @ApplicationContext context: Context
    ): AdShieldDatabase {
        return Room.databaseBuilder(
            context,
            AdShieldDatabase::class.java,
            AdShieldDatabase.DATABASE_NAME
        )
            .addMigrations(AdShieldDatabase.MIGRATION_1_2)
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()
    }

    @Provides
    @Singleton
    fun provideAdShieldDao(database: AdShieldDatabase): AdShieldDao {
        return database.adShieldDao()
    }

    @Provides
    @Singleton
    fun providePrivateCloudBoxEngine(
        @ApplicationContext context: Context
    ): PrivateCloudBoxEngine {
        return PrivateCloudBoxEngine(
            rootDir = File(context.filesDir, "private_cloud_box")
        )
    }

    @Provides
    @Singleton
    fun provideUniversalFileManager(
        @ApplicationContext context: Context
    ): UniversalFileManager {
        return UniversalFileManager(
            workspaceDir = File(context.filesDir, "managed_files")
        )
    }

    @Provides
    @Singleton
    fun provideMediaDownloaderEngine(
        @ApplicationContext context: Context,
        securityEngine: SecurityEngine
    ): MediaDownloaderEngine {
        return MediaDownloaderEngine(
            defaultDownloadDir = File(context.filesDir, "media_downloads"),
            stateStoreFile = File(context.filesDir, "media_download_history.json"),
            isHostMalicious = { host -> securityEngine.isHostOnActiveThreatBlocklist(host) }
        )
    }
}
