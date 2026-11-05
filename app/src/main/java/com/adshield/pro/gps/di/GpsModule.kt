package com.adshield.pro.gps.di

import android.content.Context
import androidx.room.Room
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsDatabase
import com.adshield.pro.gps.data.GpsHttpClientFactory
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.data.GpsHttpClient
import com.adshield.pro.gps.engine.GnssLocationSource
import com.adshield.pro.gps.engine.GpsEngine
import com.adshield.pro.gps.engine.GpsIntegrityMonitor
import com.adshield.pro.gps.engine.HeadingFusion
import com.adshield.pro.gps.engine.HeadingSensor
import com.adshield.pro.gps.engine.StationaryDetector
import com.adshield.pro.gps.nav.TtsVoiceGuidance
import com.adshield.pro.gps.nav.VoiceGuidanceApi
import com.adshield.pro.gps.traffic.SegmentMatcher
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import okhttp3.OkHttpClient
import javax.inject.Singleton

/**
 * AdShield Pro — GPS module dependency graph.
 *
 * Intentionally a *separate* Hilt module from the DNS/VPN/cloud modules: the navigation feature
 * depends on none of them and can be removed again without touching their providers. The only
 * shared objects are the application Context and the OkHttp builder (a fresh client instance).
 */
/** Qualifier for the GPS module's own coroutine scope (see [GpsModule.provideGpsScope]). */
@javax.inject.Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class GpsScope

@Module
@InstallIn(SingletonComponent::class)
object GpsModule {

    @Provides
    @Singleton
    fun provideGpsDatabase(@ApplicationContext context: Context): GpsDatabase =
        Room.databaseBuilder(
            context,
            GpsDatabase::class.java,
            GpsDatabase.DATABASE_NAME
        ).fallbackToDestructiveMigrationOnDowngrade().build()

    @Provides
    @Singleton
    fun provideGpsDao(database: GpsDatabase): GpsDao = database.gpsDao()

    @Provides
    @Singleton
    @GpsScope
    fun provideGpsScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Provides
    @Singleton
    @GpsHttpClient
    fun provideGpsHttpClient(factory: GpsHttpClientFactory): OkHttpClient = factory.create()

    @Provides
    @Singleton
    fun provideGpsPreferences(@ApplicationContext context: Context): GpsPreferences = GpsPreferences(context)

    @Provides
    @Singleton
    fun provideGpsEngine(
        @ApplicationContext context: Context,
        @GpsScope scope: CoroutineScope
    ): GpsEngine = GpsEngine(
        context = context,
        scope = scope,
        locationSource = GnssLocationSource(context),
        headingSensor = HeadingSensor(context),
        integrityMonitor = GpsIntegrityMonitor(),
        stationaryDetector = StationaryDetector(),
        headingFusion = HeadingFusion()
    ).also { GpsEngineHolder.install(it) }

    @Provides
    @Singleton
    fun provideSegmentMatcher(): SegmentMatcher = SegmentMatcher(emptyList())
}

@Module
@InstallIn(SingletonComponent::class)
abstract class GpsBindingsModule {
    @Binds
    @Singleton
    abstract fun bindVoiceGuidance(impl: TtsVoiceGuidance): VoiceGuidanceApi
}

/**
 * Static handle to the singleton [GpsEngine] for the foreground service, which is created by the
 * platform rather than through injection. Set once by [GpsEngine]'s provider.
 */
object GpsEngineHolder {
    @Volatile
    private var engine: GpsEngine? = null

    fun install(engine: GpsEngine) {
        this.engine = engine
    }

    fun get(): GpsEngine? = engine
}
