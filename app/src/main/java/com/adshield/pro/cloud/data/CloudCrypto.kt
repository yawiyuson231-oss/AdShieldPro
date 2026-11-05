package com.adshield.pro.cloud.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptography for the cloud module.
 *
 * Two independent concerns:
 *  1. [KeystoreBox] — encrypts API session tokens at rest. The AES-256-GCM key is generated
 *     inside the Android Keystore and never leaves the TEE/StrongBox, so a filesystem dump
 *     of the app's private storage cannot recover a bearer token.
 *  2. [ClientSideCipher] — optional end-to-end encryption of user files and DNS backups.
 *     The passphrase never leaves the device; the derived key is memory-only.
 *
 * Container format (v1):
 *   bytes 0..7   magic "CSHIELDV1"
 *   byte  8      kdf id (1 = PBKDF2-HMAC-SHA256)
 *   bytes 9..12  iteration count (big endian)
 *   bytes 13..28 salt (16 bytes)
 *   bytes 29..40 GCM IV (12 bytes)
 *   bytes 41..   ciphertext + GCM tag
 */
object CloudCryptoFormat {
    const val MAGIC = "CSHIELDV1"
    const val KDF_PBKDF2_SHA256: Byte = 1
    const val DEFAULT_ITERATIONS = 210_000
    const val SALT_BYTES = 16
    const val IV_BYTES = 12
    const val HEADER_BYTES = 8 + 1 + 4 + SALT_BYTES + IV_BYTES
}

class KeystoreBox(private val alias: String = "adshield_cloud_token_key") {

    private val random = SecureRandom()

    private fun keyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun secretKey(): SecretKey {
        val store = keyStore()
        (store.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
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

    /** Returns base64(iv).base64(ciphertext) or null when the value cannot be sealed. */
    fun seal(plaintext: String): String? = runCatching {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        "${b64(cipher.iv)}.${b64(ciphertext)}"
    }.getOrNull()

    fun open(sealed: String): String? = runCatching {
        val (ivPart, dataPart) = sealed.split('.', limit = 2)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, unb64(ivPart)))
        String(cipher.doFinal(unb64(dataPart)), Charsets.UTF_8)
    }.getOrNull()

    fun rotate(): Boolean = runCatching {
        keyStore().deleteEntry(alias)
    }.isSuccess

    private fun b64(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

    private fun unb64(value: String): ByteArray =
        android.util.Base64.decode(value, android.util.Base64.NO_WRAP)

    fun newNonce(bytes: Int): ByteArray = ByteArray(bytes).also { random.nextBytes(it) }
}

/**
 * Passphrase-based AES-256-GCM encryption for file/backup payloads.
 * Encryption happens before the bytes ever reach the upload engine.
 */
class ClientSideCipher {

    class EncryptedPayload(
        val data: ByteArray,
        val sha256OfPlaintext: String,
        val iterations: Int
    )

    fun deriveKey(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKey {
        val spec = PBEKeySpec(passphrase, salt, iterations, 256)
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val derived = factory.generateSecret(spec).encoded
            SecretKeySpec(derived, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    fun encrypt(
        plaintext: ByteArray,
        passphrase: CharArray,
        iterations: Int = CloudCryptoFormat.DEFAULT_ITERATIONS,
        salt: ByteArray? = null
    ): EncryptedPayload {
        val random = SecureRandom()
        val useSalt = salt ?: ByteArray(CloudCryptoFormat.SALT_BYTES).also { random.nextBytes(it) }
        val iv = ByteArray(CloudCryptoFormat.IV_BYTES).also { random.nextBytes(it) }
        val key = deriveKey(passphrase, useSalt, iterations)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext)

        val header = ByteArray(CloudCryptoFormat.HEADER_BYTES)
        CloudCryptoFormat.MAGIC.toByteArray(Charsets.US_ASCII).copyInto(header, 0)
        header[8] = CloudCryptoFormat.KDF_PBKDF2_SHA256
        header[9] = ((iterations ushr 24) and 0xFF).toByte()
        header[10] = ((iterations ushr 16) and 0xFF).toByte()
        header[11] = ((iterations ushr 8) and 0xFF).toByte()
        header[12] = (iterations and 0xFF).toByte()
        useSalt.copyInto(header, 13)
        iv.copyInto(header, 13 + CloudCryptoFormat.SALT_BYTES)

        return EncryptedPayload(
            data = header + ciphertext,
            sha256OfPlaintext = Hashing.sha256Hex(plaintext),
            iterations = iterations
        )
    }

    fun decrypt(container: ByteArray, passphrase: CharArray): ByteArray {
        require(container.size > CloudCryptoFormat.HEADER_BYTES) { "Container is too short to be a CyberShield backup" }
        val magic = String(container, 0, 8, Charsets.US_ASCII)
        require(magic == CloudCryptoFormat.MAGIC) { "Unrecognised container magic: $magic" }
        require(container[8] == CloudCryptoFormat.KDF_PBKDF2_SHA256) { "Unsupported key derivation function" }
        val iterations = ((container[9].toInt() and 0xFF) shl 24) or
            ((container[10].toInt() and 0xFF) shl 16) or
            ((container[11].toInt() and 0xFF) shl 8) or
            (container[12].toInt() and 0xFF)
        val salt = container.copyOfRange(13, 13 + CloudCryptoFormat.SALT_BYTES)
        val ivStart = 13 + CloudCryptoFormat.SALT_BYTES
        val iv = container.copyOfRange(ivStart, ivStart + CloudCryptoFormat.IV_BYTES)
        val ciphertext = container.copyOfRange(CloudCryptoFormat.HEADER_BYTES, container.size)
        val key = deriveKey(passphrase, salt, iterations)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    fun looksEncrypted(bytes: ByteArray): Boolean {
        if (bytes.size < 9) return false
        return String(bytes, 0, 8, Charsets.US_ASCII) == CloudCryptoFormat.MAGIC
    }
}
