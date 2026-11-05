package com.adshield.pro.cloud.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.pro.BuildConfig
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.cloudDataStore: DataStore<Preferences> by preferencesDataStore(name = "adshield_cloud_preferences")

/**
 * Deployment + behaviour settings for the cloud module.
 *
 * The app ships with **no** cloud endpoint baked in by default, and it never contains a
 * cloud provider credential: only the public Worker URL and the Supabase *publishable*
 * anon key are stored here (both are safe to publish). Users point the app at their own
 * free-tier deployment from Cloud ▸ Settings.
 */
data class CloudConfig(
    val apiBaseUrl: String = BuildConfig.DEFAULT_CLOUD_API_URL,
    val supabaseUrl: String = BuildConfig.DEFAULT_SUPABASE_URL,
    val supabaseAnonKey: String = BuildConfig.DEFAULT_SUPABASE_ANON_KEY,
    val autoBackupEnabled: Boolean = false,
    val autoBackupIntervalHours: Int = 24,
    val autoBackupKinds: Set<String> = setOf("full"),
    val backgroundUploadsEnabled: Boolean = true,
    val wifiOnlyUploads: Boolean = false,
    val clientSideEncryptionDefault: Boolean = true,
    val shareDefaultExpiryHours: Int = 24,
    val shareDefaultPassword: Boolean = false,
    val warnAtPercent: Int = 80,
    val lastSyncEpochMs: Long = 0L
) {
    /** A deployment is usable only when both the API and the auth project are configured. */
    val isConfigured: Boolean
        get() = apiBaseUrl.isNotBlank() && supabaseUrl.isNotBlank() && supabaseAnonKey.isNotBlank()
}

@Singleton
class CloudConfigRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private object Keys {
        val API_URL = stringPreferencesKey("cloud_api_base_url")
        val SUPABASE_URL = stringPreferencesKey("cloud_supabase_url")
        val SUPABASE_ANON = stringPreferencesKey("cloud_supabase_anon_key")
        val AUTO_BACKUP = booleanPreferencesKey("cloud_auto_backup")
        val AUTO_BACKUP_HOURS = intPreferencesKey("cloud_auto_backup_hours")
        val AUTO_BACKUP_KINDS = stringPreferencesKey("cloud_auto_backup_kinds")
        val BACKGROUND_UPLOADS = booleanPreferencesKey("cloud_background_uploads")
        val WIFI_ONLY = booleanPreferencesKey("cloud_wifi_only")
        val CLIENT_ENCRYPTION = booleanPreferencesKey("cloud_client_encryption")
        val SHARE_EXPIRY_HOURS = intPreferencesKey("cloud_share_expiry_hours")
        val SHARE_PASSWORD = booleanPreferencesKey("cloud_share_password")
        val WARN_PERCENT = intPreferencesKey("cloud_warn_percent")
        val LAST_SYNC = longPreferencesKey("cloud_last_sync_ms")
    }

    val configFlow: Flow<CloudConfig> = context.cloudDataStore.data.map { prefs ->
        CloudConfig(
            apiBaseUrl = prefs[Keys.API_URL] ?: BuildConfig.DEFAULT_CLOUD_API_URL,
            supabaseUrl = prefs[Keys.SUPABASE_URL] ?: BuildConfig.DEFAULT_SUPABASE_URL,
            supabaseAnonKey = prefs[Keys.SUPABASE_ANON] ?: BuildConfig.DEFAULT_SUPABASE_ANON_KEY,
            autoBackupEnabled = prefs[Keys.AUTO_BACKUP] ?: false,
            autoBackupIntervalHours = prefs[Keys.AUTO_BACKUP_HOURS] ?: 24,
            autoBackupKinds = prefs[Keys.AUTO_BACKUP_KINDS]?.split(',')?.filter { it.isNotBlank() }?.toSet() ?: setOf("full"),
            backgroundUploadsEnabled = prefs[Keys.BACKGROUND_UPLOADS] ?: true,
            wifiOnlyUploads = prefs[Keys.WIFI_ONLY] ?: false,
            clientSideEncryptionDefault = prefs[Keys.CLIENT_ENCRYPTION] ?: true,
            shareDefaultExpiryHours = prefs[Keys.SHARE_EXPIRY_HOURS] ?: 24,
            shareDefaultPassword = prefs[Keys.SHARE_PASSWORD] ?: false,
            warnAtPercent = prefs[Keys.WARN_PERCENT] ?: 80,
            lastSyncEpochMs = prefs[Keys.LAST_SYNC] ?: 0L
        )
    }

    suspend fun snapshot(): CloudConfig = configFlow.first()

    suspend fun updateDeployment(apiBaseUrl: String, supabaseUrl: String, supabaseAnonKey: String) {
        context.cloudDataStore.edit { prefs ->
            prefs[Keys.API_URL] = apiBaseUrl.trim().trimEnd('/')
            prefs[Keys.SUPABASE_URL] = supabaseUrl.trim().trimEnd('/')
            prefs[Keys.SUPABASE_ANON] = supabaseAnonKey.trim()
        }
    }

    suspend fun setAutoBackup(enabled: Boolean, intervalHours: Int) {
        context.cloudDataStore.edit { prefs ->
            prefs[Keys.AUTO_BACKUP] = enabled
            prefs[Keys.AUTO_BACKUP_HOURS] = intervalHours.coerceIn(1, 168)
        }
    }

    suspend fun setAutoBackupKinds(kinds: Set<String>) {
        context.cloudDataStore.edit { prefs -> prefs[Keys.AUTO_BACKUP_KINDS] = kinds.joinToString(",") }
    }

    suspend fun setBackgroundUploads(enabled: Boolean, wifiOnly: Boolean) {
        context.cloudDataStore.edit { prefs ->
            prefs[Keys.BACKGROUND_UPLOADS] = enabled
            prefs[Keys.WIFI_ONLY] = wifiOnly
        }
    }

    suspend fun setClientEncryptionDefault(enabled: Boolean) {
        context.cloudDataStore.edit { prefs -> prefs[Keys.CLIENT_ENCRYPTION] = enabled }
    }

    suspend fun setShareDefaults(expiryHours: Int, passwordProtected: Boolean) {
        context.cloudDataStore.edit { prefs ->
            prefs[Keys.SHARE_EXPIRY_HOURS] = expiryHours.coerceIn(1, 720)
            prefs[Keys.SHARE_PASSWORD] = passwordProtected
        }
    }

    suspend fun setWarnPercent(percent: Int) {
        context.cloudDataStore.edit { prefs -> prefs[Keys.WARN_PERCENT] = percent.coerceIn(50, 95) }
    }

    suspend fun recordSync() {
        context.cloudDataStore.edit { prefs -> prefs[Keys.LAST_SYNC] = System.currentTimeMillis() }
    }
}
