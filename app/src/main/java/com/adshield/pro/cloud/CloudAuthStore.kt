package com.adshield.pro.cloud

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.cloudAuthDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "adshield_cloud_auth"
)

/**
 * Stores the cloud session (access token + user id) in app-private DataStore.
 *
 * Honesty note (mirrors the "encrypted-prefs" capability row): the file sits in the app-private
 * sandbox protected by the OS, but is not additionally encrypted at rest. The token is a
 * short-lived JWT; the Worker treats it as bearer auth and every object is ownership-checked.
 */
@Singleton
class CloudAuthStore @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val dataStore get() = context.cloudAuthDataStore

    private object Keys {
        val ACCESS_TOKEN = stringPreferencesKey("access_token")
        val REFRESH_TOKEN = stringPreferencesKey("refresh_token")
        val USER_ID = stringPreferencesKey("user_id")
        val EMAIL = stringPreferencesKey("email")
        val EXPIRES_AT = stringPreferencesKey("expires_at_epoch_sec")
        val API_BASE_URL = stringPreferencesKey("api_base_url")
    }

    val sessionFlow: Flow<AuthSession?> = dataStore.data.map { prefs ->
        val token = prefs[Keys.ACCESS_TOKEN] ?: return@map null
        AuthSession(
            accessToken = token,
            refreshToken = prefs[Keys.REFRESH_TOKEN] ?: "",
            userId = prefs[Keys.USER_ID] ?: "",
            email = prefs[Keys.EMAIL] ?: "",
            expiresAtEpochSec = prefs[Keys.EXPIRES_AT]?.toLongOrNull() ?: 0L
        )
    }

    val apiBaseUrlFlow: Flow<String> = dataStore.data.map { it[Keys.API_BASE_URL] ?: CloudConfig.DEFAULT_API_BASE_URL }

    suspend fun currentSession(): AuthSession? = sessionFlow.first()

    suspend fun saveSession(session: AuthSession) {
        dataStore.edit { prefs ->
            prefs[Keys.ACCESS_TOKEN] = session.accessToken
            prefs[Keys.REFRESH_TOKEN] = session.refreshToken
            prefs[Keys.USER_ID] = session.userId
            prefs[Keys.EMAIL] = session.email
            prefs[Keys.EXPIRES_AT] = session.expiresAtEpochSec.toString()
        }
    }

    suspend fun clearSession() {
        dataStore.edit { prefs ->
            prefs.remove(Keys.ACCESS_TOKEN)
            prefs.remove(Keys.REFRESH_TOKEN)
            prefs.remove(Keys.USER_ID)
            prefs.remove(Keys.EMAIL)
            prefs.remove(Keys.EXPIRES_AT)
        }
    }

    suspend fun saveApiBaseUrl(url: String) {
        dataStore.edit { prefs -> prefs[Keys.API_BASE_URL] = url.trim().trimEnd('/') }
    }

    suspend fun currentApiBaseUrl(): String = apiBaseUrlFlow.first()

    /** True when a stored session exists and its expiry is still in the future. */
    fun isSessionUsable(session: AuthSession?, nowEpochMs: Long): Boolean =
        session != null && session.accessToken.isNotBlank() &&
            session.expiresAtEpochSec * 1000L > nowEpochMs
}
