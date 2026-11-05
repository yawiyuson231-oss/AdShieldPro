package com.adshield.pro.cybershield.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AES-GCM credential storage backed by the hardware-backed Android Keystore.
 * Used for optional bearer tokens of custom cloud status endpoints. Ciphertext
 * is stored in a private SharedPreferences file; the key never leaves the
 * Keystore. No third-party dependency required.
 */
@Singleton
class KeystoreSecretStore @Inject constructor() {

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
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

    /** Returns Base64(iv || ciphertext+tag), or null on failure (never plaintext). */
    fun encrypt(plaintext: String): String? = runCatching {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(cipher.iv.size + ct.size)
        System.arraycopy(cipher.iv, 0, combined, 0, cipher.iv.size)
        System.arraycopy(ct, 0, combined, cipher.iv.size, ct.size)
        Base64.encodeToString(combined, Base64.NO_WRAP)
    }.getOrNull()

    fun decrypt(encoded: String): String? = runCatching {
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        require(combined.size > GCM_IV_LENGTH)
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val ct = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        String(cipher.doFinal(ct), Charsets.UTF_8)
    }.getOrNull()

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "cybershield_cloud_token_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
    }
}
