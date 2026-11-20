package com.adshield.pro.engine.evolution

import android.content.Context
import java.net.URI
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Properties

/** Packaged configuration only, never downloaded trust roots. No production config is bundled. */
internal object EvolutionPublisherConfiguration {
    private const val PREFERENCES = "evolution_update_consent"
    private const val CONSENT = "reviewed_reputation_downloads"

    fun enabled(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getBoolean(CONSENT, false)

    /** Future settings integration must call this only after an explicit user decision. */
    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        if (enabled && createStager(context) == null) return false
        val saved = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putBoolean(CONSENT, enabled).commit()
        if (saved) {
            EvolutionUpdateWorker.reconcile(context)
            if (enabled) EvolutionUpdateWorker.checkNow(context)
        }
        return saved
    }

    fun recordStatus(context: Context, status: String) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
            .putString("status", status.take(160)).putLong("checkedAt", System.currentTimeMillis()).apply()
    }

    fun lastStatus(context: Context): String {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val checkedAt = preferences.getLong("checkedAt", 0)
        return if (checkedAt == 0L) "No update check recorded" else
            "${preferences.getString("status", "Unknown")}; ${java.util.Date(checkedAt)}"
    }

    fun createStager(context: Context): EvolutionUpdateStager? = runCatching {
        val config = Properties().apply {
            context.assets.open("evolution-publisher.properties").use { load(it) }
        }
        require(config.stringPropertyNames() == setOf("endpoint", "keyId", "publicKeySpkiBase64"))
        val keyId = requireNotNull(config.getProperty("keyId"))
        require(keyId.matches(Regex("[a-zA-Z0-9_-]{1,64}")))
        val encodedKey = requireNotNull(config.getProperty("publicKeySpkiBase64"))
        require(encodedKey.length <= 2048)
        val key = KeyFactory.getInstance("RSA").generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(encodedKey)))
        require(key is java.security.interfaces.RSAPublicKey && key.modulus.bitLength() in 2048..4096)
        EvolutionUpdateStager(
            java.io.File(context.noBackupFilesDir, "evolution-reputation"),
            URI(requireNotNull(config.getProperty("endpoint"))).toURL(), mapOf(keyId to key),
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
        )
    }.getOrNull()
}
