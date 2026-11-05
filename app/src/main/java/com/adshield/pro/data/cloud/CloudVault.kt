package com.adshield.pro.data.cloud

import android.content.Context
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Optional client-side encryption for cloud backups.
 *
 * The key is derived from a passphrase the user types; the passphrase is never written to disk and
 * the derived key lives only in memory while the vault is unlocked. Backups encrypted this way
 * cannot be read by the storage provider or by anyone who does not know the passphrase — which
 * also means a forgotten passphrase cannot be recovered, and the UI says so.
 *
 * Large file uploads are not encrypted client-side: resumable multipart uploads need to re-read a
 * byte range, which an authenticated AES-GCM stream cannot provide. Those files rely on the
 * provider's encryption at rest instead, and the UI states that plainly.
 */
@Singleton
class CloudVault @Inject constructor(
    @ApplicationContext context: Context
) {
    private val preferences = context.getSharedPreferences("adshield_cloud_vault", Context.MODE_PRIVATE)
    private val random = SecureRandom()

    @Volatile
    private var masterKey: SecretKey? = null

    fun isConfigured(): Boolean =
        preferences.getString(KEY_SALT, null) != null && preferences.getString(KEY_VERIFIER, null) != null

    fun isUnlocked(): Boolean = masterKey != null

    /** Creates the vault with a new passphrase. */
    fun setup(passphrase: CharArray, iterations: Int = PBKDF2_ITERATIONS): Boolean {
        if (passphrase.isEmpty()) return false
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        val key = derive(passphrase, salt, iterations)
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        val verifier = cipher.doFinal(VERIFIER_PLAINTEXT)
        preferences.edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_VERIFIER, Base64.encodeToString(nonce + verifier, Base64.NO_WRAP))
            .putInt(KEY_ITERATIONS, iterations)
            .apply()
        masterKey = key
        return true
    }

    /** Unlocks the vault. Returns false when the passphrase is wrong. */
    fun unlock(passphrase: CharArray): Boolean {
        val salt = preferences.getString(KEY_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val verifier = preferences.getString(KEY_VERIFIER, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
            ?: return false
        if (verifier.size <= NONCE_BYTES) return false
        val iterations = preferences.getInt(KEY_ITERATIONS, PBKDF2_ITERATIONS)
        val key = derive(passphrase, salt, iterations)
        val verified = runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(GCM_TAG_BITS, verifier.copyOfRange(0, NONCE_BYTES))
            )
            val plain = cipher.doFinal(verifier.copyOfRange(NONCE_BYTES, verifier.size))
            MessageDigest.isEqual(plain, VERIFIER_PLAINTEXT)
        }.getOrDefault(false)
        if (verified) masterKey = key
        return verified
    }

    fun lock() {
        masterKey = null
    }

    fun changePassphrase(oldPassphrase: CharArray, newPassphrase: CharArray): Boolean {
        if (!unlock(oldPassphrase)) return false
        preferences.edit().remove(KEY_SALT).remove(KEY_VERIFIER).apply()
        return setup(newPassphrase)
    }

    /** Encrypts with AES-256-GCM. Output layout: 12-byte nonce followed by the ciphertext. */
    fun encrypt(plain: ByteArray): ByteArray {
        val key = masterKey ?: error("vault is locked")
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ciphertext = cipher.doFinal(plain)
        return nonce + ciphertext
    }

    fun decrypt(payload: ByteArray): ByteArray {
        val key = masterKey ?: error("vault is locked")
        require(payload.size > NONCE_BYTES + GCM_TAG_BITS / 8) { "encrypted payload is truncated" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(GCM_TAG_BITS, payload.copyOfRange(0, NONCE_BYTES))
        )
        return cipher.doFinal(payload.copyOfRange(NONCE_BYTES, payload.size))
    }

    private fun derive(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKey {
        val spec = PBEKeySpec(passphrase, salt, iterations, KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derived = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(derived, "AES")
    }

    private companion object {
        const val KEY_SALT = "salt"
        const val KEY_VERIFIER = "verifier"
        const val KEY_ITERATIONS = "iterations"
        const val SALT_BYTES = 16
        const val NONCE_BYTES = 12
        const val KEY_BITS = 256
        const val GCM_TAG_BITS = 128
        const val PBKDF2_ITERATIONS = 120_000
        val VERIFIER_PLAINTEXT = "adshield-cloud-vault-v1".toByteArray(Charsets.UTF_8)
    }
}
