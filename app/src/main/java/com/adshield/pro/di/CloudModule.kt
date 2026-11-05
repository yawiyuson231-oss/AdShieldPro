package com.adshield.pro.di

import android.content.Context
import com.adshield.pro.data.cloud.CloudAccountManager
import com.adshield.pro.data.cloud.CloudApi
import com.adshield.pro.data.cloud.CloudApiClient
import com.adshield.pro.data.cloud.CloudUploadEngine
import com.adshield.pro.data.cloud.JsonFileUploadJobStore
import com.adshield.pro.data.cloud.PreferencesVaultStorage
import com.adshield.pro.data.cloud.UploadJobStore
import com.adshield.pro.data.cloud.VaultStorage
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CloudModule {

    /** Used for API calls and for the direct-to-storage transfers the upload engine performs. */
    @Provides
    @Singleton
    fun provideCloudHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .callTimeout(0, TimeUnit.SECONDS)
        .build()

    @Provides
    @Singleton
    fun provideUploadJobStore(@ApplicationContext context: Context): UploadJobStore =
        JsonFileUploadJobStore(context)

    @Provides
    @Singleton
    fun provideVaultStorage(@ApplicationContext context: Context): VaultStorage =
        PreferencesVaultStorage(context)

    @Provides
    @Singleton
    fun provideCloudApi(client: OkHttpClient, accounts: CloudAccountManager): CloudApi =
        CloudApiClient(client, { accounts.endpoints.apiBaseUrl }, accounts)

    @Provides
    @Singleton
    fun provideCloudUploadEngine(
        api: CloudApi,
        client: OkHttpClient,
        store: UploadJobStore
    ): CloudUploadEngine = CloudUploadEngine(api, client, store)
}
