package com.adshield.pro.data.cloud

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class CloudSession(
    val accessToken: String = "",
    val refreshToken: String = "",
    val expiresAtEpochMs: Long = 0L,
    val userId: String = "",
    val email: String = ""
) {
    val isSignedIn: Boolean get() = accessToken.isNotBlank() && userId.isNotBlank()
    val expiresSoon: Boolean get() = expiresAtEpochMs > 0 && expiresAtEpochMs - System.currentTimeMillis() < 60_000L
}

/**
 * Public, non-secret configuration. These values ship inside the APK by design (a Supabase anon
 * key and a Turnstile site key are meant to be public) — the account password and the storage
 * credentials never leave the device or the API worker.
 */
@Serializable
data class CloudEndpoints(
    val apiBaseUrl: String = "",
    val supabaseUrl: String = "",
    val supabaseAnonKey: String = "",
    val turnstileSiteKey: String = ""
) {
    val isConfigured: Boolean
        get() = apiBaseUrl.startsWith("https://") && supabaseUrl.startsWith("https://") && supabaseAnonKey.isNotBlank()
}

/**
 * Stores the signed-in session as Android-Keystore-backed AES-GCM ciphertext.
 *
 * Tokens are the only thing on the device that grants access to a user's files, so they are
 * never written to plain preferences, logs or backups.
 */
@Singleton
class CloudSessionStore @Inject constructor(
    @ApplicationContext context: Context
) {
    private val preferences: SharedPreferences =
        context.getSharedPreferences("adshield_cloud_session", Context.MODE_PRIVATE)

    fun save(session: CloudSession) {
        preferences.edit().putString(KEY_SESSION, encrypt(defaultCloudJson().encodeToString(session))).apply()
    }

    fun load(): CloudSession? {
        val encoded = preferences.getString(KEY_SESSION, null) ?: return null
        return runCatching {
            defaultCloudJson().decodeFromString<CloudSession>(decrypt(encoded))
        }.getOrNull()
    }

    fun clear() {
        preferences.edit().remove(KEY_SESSION).apply()
    }

    fun saveEndpoints(endpoints: CloudEndpoints) {
        preferences.edit().putString(KEY_ENDPOINTS, defaultCloudJson().encodeToString(endpoints)).apply()
    }

    fun endpoints(): CloudEndpoints {
        val raw = preferences.getString(KEY_ENDPOINTS, null) ?: return CloudEndpoints()
        return runCatching { defaultCloudJson().decodeFromString<CloudEndpoints>(raw) }.getOrDefault(CloudEndpoints())
    }

    fun autoBackupEnabled(): Boolean = preferences.getBoolean(KEY_AUTO_BACKUP, false)

    fun setAutoBackupEnabled(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_AUTO_BACKUP, enabled).apply()
    }

    fun clientSideEncryptionEnabled(): Boolean = preferences.getBoolean(KEY_CLIENT_SIDE_ENCRYPTION, false)

    fun setClientSideEncryptionEnabled(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_CLIENT_SIDE_ENCRYPTION, enabled).apply()
    }

    fun lastAutoBackupEpochMs(): Long = preferences.getLong(KEY_LAST_AUTO_BACKUP, 0L)

    fun setLastAutoBackupEpochMs(value: Long) {
        preferences.edit().putLong(KEY_LAST_AUTO_BACKUP, value).apply()
    }

    // ------------------------------------------------------------------ crypto

    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val payload = Base64.decode(encoded, Base64.NO_WRAP)
        require(payload.size > 13) { "invalid encrypted session" }
        val iv = payload.copyOfRange(0, 12)
        val encrypted = payload.copyOfRange(12, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "adshield_cloud_session_key"
        const val KEY_SESSION = "session"
        const val KEY_ENDPOINTS = "endpoints"
        const val KEY_AUTO_BACKUP = "auto_backup_enabled"
        const val KEY_CLIENT_SIDE_ENCRYPTION = "client_side_encryption_enabled"
        const val KEY_LAST_AUTO_BACKUP = "last_auto_backup_epoch_ms"
    }
}
