package com.adshield.pro.cloud.data

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class CloudSession(
    val accessToken: String,
    val refreshToken: String,
    val expiresAtMs: Long,
    val userId: String,
    val email: String,
    val issuedAtMs: Long = System.currentTimeMillis()
) {
    /** Refresh five minutes before the token actually expires. */
    val needsRefresh: Boolean get() = expiresAtMs - 5 * 60 * 1000 <= System.currentTimeMillis()

    val isExpired: Boolean get() = expiresAtMs <= System.currentTimeMillis()
}

/**
 * Stores the signed-in session encrypted with an Android Keystore key.
 * Nothing is written to disk in plaintext and no credential is ever logged.
 */
@Singleton
class CloudSessionStore @Inject constructor(
    @ApplicationContext context: Context,
    private val keystoreBox: KeystoreBox
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("adshield_cloud_session", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    private val _sessionFlow = MutableStateFlow(load())
    val sessionFlow: StateFlow<CloudSession?> = _sessionFlow.asStateFlow()

    fun current(): CloudSession? = _sessionFlow.value

    fun save(session: CloudSession) {
        val sealed = keystoreBox.seal(json.encodeToString(CloudSession.serializer(), session))
        prefs.edit().putString(KEY_SESSION, sealed).apply()
        _sessionFlow.value = session
    }

    fun clear() {
        prefs.edit().remove(KEY_SESSION).apply()
        _sessionFlow.value = null
    }

    val isSignedIn: Boolean get() = _sessionFlow.value != null

    private fun load(): CloudSession? {
        val sealed = prefs.getString(KEY_SESSION, null) ?: return null
        val plaintext = keystoreBox.open(sealed) ?: return null
        return runCatching { json.decodeFromString(CloudSession.serializer(), plaintext) }.getOrNull()
    }

    private companion object {
        const val KEY_SESSION = "session_v1"
    }
}
