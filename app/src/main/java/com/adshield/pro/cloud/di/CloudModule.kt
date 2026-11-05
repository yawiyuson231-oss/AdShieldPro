package com.adshield.pro.cloud.di

import android.content.Context
import androidx.room.Room
import com.adshield.pro.cloud.data.CloudConfigRepository
import com.adshield.pro.cloud.data.CloudDao
import com.adshield.pro.cloud.data.CloudDatabase
import com.adshield.pro.cloud.data.ClientSideCipher
import com.adshield.pro.cloud.data.KeystoreBox
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

/**
 * Dependency graph for the cloud module.
 *
 * The HTTP client is shared and tuned for large transfers: no overall call timeout (a 2 GB
 * upload legitimately takes a while), generous write timeout, and automatic retry on
 * connection failure. TLS is enforced by the client itself.
 */
@Module
@InstallIn(SingletonComponent::class)
object CloudModule {

    @Provides
    @Singleton
    fun provideCloudHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .callTimeout(0, TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(true)
        .followSslRedirects(false)
        .build()

    @Provides
    @Singleton
    fun provideCloudJson(): Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    @Provides
    @Singleton
    fun provideKeystoreBox(): KeystoreBox = KeystoreBox()

    @Provides
    @Singleton
    fun provideClientSideCipher(): ClientSideCipher = ClientSideCipher()

    @Provides
    @Singleton
    fun provideCloudDatabase(@ApplicationContext context: Context): CloudDatabase =
        Room.databaseBuilder(context, CloudDatabase::class.java, CloudDatabase.DATABASE_NAME)
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()

    @Provides
    fun provideCloudDao(database: CloudDatabase): CloudDao = database.cloudDao()

    @Provides
    @Singleton
    fun provideCloudConfigRepository(
        @ApplicationContext context: Context
    ): CloudConfigRepository = CloudConfigRepository(context)
}
