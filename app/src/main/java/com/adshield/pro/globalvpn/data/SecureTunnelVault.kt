package com.adshield.pro.globalvpn.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.StoredTunnel
import com.adshield.pro.globalvpn.model.VpnProtocol
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Encrypted-at-rest storage for imported tunnel configurations (which contain WireGuard private
 * keys). Each config blob is sealed with an AES-256-GCM key that lives in the Android Keystore and
 * never leaves it. Only non-secret metadata is kept in a plaintext index. This vault is exclusive
 * to the Global VPN feature and does not touch the DNS system's storage.
 */
@Singleton
class SecureTunnelVault @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val root: File = File(context.filesDir, "global_vpn").apply { mkdirs() }
    private val indexFile = File(root, "index.json")
    private val tunnelDir = File(root, "tunnels").apply { mkdirs() }

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = cipher.iv
        val sealed = cipher.doFinal(plain)
        return iv + sealed
    }

    private fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_LENGTH) { "Corrupt vault entry" }
        val iv = blob.copyOfRange(0, IV_LENGTH)
        val sealed = blob.copyOfRange(IV_LENGTH, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(sealed)
    }

    private fun readIndex(): MutableList<StoredTunnel> =
        if (indexFile.exists()) {
            runCatching {
                json.decodeFromString<List<StoredTunnel>>(indexFile.readText()).toMutableList()
            }.getOrDefault(mutableListOf())
        } else {
            mutableListOf()
        }

    private fun writeIndex(entries: List<StoredTunnel>) {
        indexFile.writeText(json.encodeToString(entries))
    }

    fun list(): List<StoredTunnel> = readIndex().sortedByDescending { it.addedAtEpochMs }

    @Synchronized
    fun save(meta: StoredTunnel, configText: String) {
        try {
            val blob = encrypt(configText.toByteArray(Charsets.UTF_8))
            File(tunnelDir, "${meta.id}.enc").writeBytes(blob)
            val entries = readIndex().filter { it.id != meta.id }.toMutableList()
            entries.add(meta)
            writeIndex(entries)
        } catch (e: Exception) {
            throw IOException("Could not securely store the tunnel configuration: ${e.message}", e)
        }
    }

    fun readConfig(id: String): String? {
        val file = File(tunnelDir, "$id.enc")
        if (!file.exists()) return null
        return runCatching { String(decrypt(file.readBytes()), Charsets.UTF_8) }.getOrNull()
    }

    @Synchronized
    fun delete(id: String) {
        File(tunnelDir, "$id.enc").delete()
        writeIndex(readIndex().filter { it.id != id })
    }

    @Synchronized
    fun touch(id: String) {
        val entries = readIndex().map {
            if (it.id == id) it.copy(lastUsedEpochMs = System.currentTimeMillis()) else it
        }
        writeIndex(entries)
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "adshield_global_vpn_vault"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12

        fun newId(): String = "wg-" + java.util.UUID.randomUUID().toString().take(12)

        fun guessCountryFromName(name: String): Pair<String, String> {
            val upper = name.uppercase()
            val known = mapOf(
                "US" to "United States", "USA" to "United States", "GB" to "United Kingdom",
                "UK" to "United Kingdom", "DE" to "Germany", "NL" to "Netherlands",
                "JP" to "Japan", "SG" to "Singapore", "FR" to "France", "CA" to "Canada",
                "CH" to "Switzerland", "SE" to "Sweden", "NO" to "Norway", "AU" to "Australia",
                "PH" to "Philippines", "IN" to "India", "BR" to "Brazil", "IT" to "Italy",
                "ES" to "Spain", "PL" to "Poland", "RO" to "Romania", "IS" to "Iceland"
            )
            for ((code, country) in known) {
                if (Regex("(^|[^A-Z])$code([^A-Z]|$)").containsMatchIn(upper)) return code to country
            }
            return "UN" to "Unknown location"
        }

        fun protocolOf(configText: String): VpnProtocol =
            if (configText.contains("[Interface]", ignoreCase = true)) VpnProtocol.WIREGUARD
            else VpnProtocol.OPENVPN

        fun providerForImport(default: ProviderId): ProviderId = default
    }
}
