package com.adshield.pro.di

import android.content.Context
import androidx.room.Room
import com.adshield.pro.data.worldmonitor.WorldMonitorDao
import com.adshield.pro.data.worldmonitor.WorldMonitorDatabase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.Cache
import okhttp3.OkHttpClient
import java.io.File
import java.util.concurrent.TimeUnit
import javax.inject.Qualifier
import javax.inject.Singleton

@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class WorldMonitorHttpClient

@Module
@InstallIn(SingletonComponent::class)
object WorldMonitorModule {

    @Provides
    @Singleton
    fun provideWorldMonitorDatabase(
        @ApplicationContext context: Context
    ): WorldMonitorDatabase = Room.databaseBuilder(
        context,
        WorldMonitorDatabase::class.java,
        WorldMonitorDatabase.DATABASE_NAME
    )
        .fallbackToDestructiveMigrationOnDowngrade()
        .build()

    @Provides
    @Singleton
    fun provideWorldMonitorDao(
        database: WorldMonitorDatabase
    ): WorldMonitorDao = database.worldMonitorDao()

    @Provides
    @Singleton
    @WorldMonitorHttpClient
    fun provideWorldMonitorOkHttpClient(
        @ApplicationContext context: Context
    ): OkHttpClient {
        val cacheDir = File(context.cacheDir, "worldmonitor_feed_cache_v1")
        return OkHttpClient.Builder()
            .cache(Cache(cacheDir, 24L * 1024L * 1024L))
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(18, TimeUnit.SECONDS)
            .callTimeout(25, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }
}
