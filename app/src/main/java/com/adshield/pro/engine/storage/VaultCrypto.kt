package com.adshield.pro.engine.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * AdShield Pro — Authenticated AES-256-GCM Cryptography & PIN Key Derivation.
 *
 * Used by Private Cloud Storage Box and encrypted configuration protection:
 * - Envelope header: `"ADSV1"` (5 bytes) + 12-byte random GCM IV + ciphertext + 16-byte GCM tag.
 * - On Android devices, master keys live inside `AndroidKeyStore` (hardware-backed where available).
 * - In JVM unit tests (or if AndroidKeyStore is unavailable), callers supply an explicit 256-bit
 *   [SecretKey] or local key file so the exact AES-256-GCM cipher path is verified without mocks.
 * - PIN lock uses PBKDF2WithHmacSHA256 (120,000 iterations + 16-byte random salt) and constant-time
 *   digest comparison.
 */
object VaultCrypto {

    private val MAGIC = byteArrayOf('A'.code.toByte(), 'D'.code.toByte(), 'S'.code.toByte(), 'V'.code.toByte(), '1'.code.toByte())
    private const val IV_LENGTH_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val KEYSTORE_ALIAS = "adshield_private_vault_aes256"
    private const val PBKDF2_ITERATIONS = 120_000

    private val secureRandom = SecureRandom()

    fun generateRandomAes256Key(): SecretKey {
        val gen = KeyGenerator.getInstance("AES")
        gen.init(256, secureRandom)
        return gen.generateKey()
    }

    /**
     * Obtains the AndroidKeyStore-backed AES-256 key on-device, falling back to an app-private
     * 256-bit key file only when running outside AndroidKeyStore (e.g. JVM unit tests).
     */
    fun getOrCreateVaultSecretKey(fallbackKeyFile: File): SecretKey {
        val keystoreKey = runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            val existing = (ks.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            if (existing != null) {
                existing
            } else {
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGen.init(spec)
                keyGen.generateKey()
            }
        }.getOrNull()

        if (keystoreKey != null) return keystoreKey

        synchronized(this) {
            if (fallbackKeyFile.exists() && fallbackKeyFile.length() == 32L) {
                val raw = fallbackKeyFile.readBytes()
                if (raw.size == 32) {
                    return SecretKeySpec(raw, "AES")
                }
            }
            val raw = ByteArray(32)
            secureRandom.nextBytes(raw)
            fallbackKeyFile.parentFile?.mkdirs()
            fallbackKeyFile.writeBytes(raw)
            return SecretKeySpec(raw, "AES")
        }
    }

    fun encryptBytes(plain: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // AndroidKeyStore keys generate their own random IV unless caller-provided IVs are explicitly permitted
        runCatching {
            val iv = ByteArray(IV_LENGTH_BYTES).also { secureRandom.nextBytes(it) }
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        }.getOrElse {
            cipher.init(Cipher.ENCRYPT_MODE, key)
        }
        val actualIv = cipher.iv
        require(actualIv != null && actualIv.size == IV_LENGTH_BYTES) {
            "Unexpected GCM IV size: ${actualIv?.size}"
        }
        val cipherText = cipher.doFinal(plain)
        val out = ByteArray(MAGIC.size + IV_LENGTH_BYTES + cipherText.size)
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
        System.arraycopy(actualIv, 0, out, MAGIC.size, IV_LENGTH_BYTES)
        System.arraycopy(cipherText, 0, out, MAGIC.size + IV_LENGTH_BYTES, cipherText.size)
        return out
    }

    fun decryptBytes(envelope: ByteArray, key: SecretKey): ByteArray {
        require(isEncryptedEnvelope(envelope)) { "Invalid or corrupted vault envelope header" }
        val iv = envelope.copyOfRange(MAGIC.size, MAGIC.size + IV_LENGTH_BYTES)
        val cipherBytes = envelope.copyOfRange(MAGIC.size + IV_LENGTH_BYTES, envelope.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(cipherBytes)
    }

    fun isEncryptedEnvelope(bytes: ByteArray): Boolean {
        if (bytes.size < MAGIC.size + IV_LENGTH_BYTES + 16) return false
        for (i in MAGIC.indices) {
            if (bytes[i] != MAGIC[i]) return false
        }
        return true
    }

    /**
     * Encrypts [sourceFile] into [destEncryptedFile] using AES-256-GCM while computing the
     * plaintext SHA-256 digest in a single pass.
     */
    fun encryptFile(sourceFile: File, destEncryptedFile: File, key: SecretKey): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        runCatching {
            val iv = ByteArray(IV_LENGTH_BYTES).also { secureRandom.nextBytes(it) }
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        }.getOrElse {
            cipher.init(Cipher.ENCRYPT_MODE, key)
        }
        val actualIv = cipher.iv
        require(actualIv != null && actualIv.size == IV_LENGTH_BYTES) {
            "Unexpected GCM IV size: ${actualIv?.size}"
        }

        destEncryptedFile.parentFile?.mkdirs()
        FileInputStream(sourceFile).use { input ->
            FileOutputStream(destEncryptedFile).use { output ->
                output.write(MAGIC)
                output.write(actualIv)
                val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buf)
                    if (read < 0) break
                    if (read > 0) {
                        digest.update(buf, 0, read)
                        val chunk = cipher.update(buf, 0, read)
                        if (chunk != null && chunk.isNotEmpty()) {
                            output.write(chunk)
                        }
                    }
                }
                val finalBlock = cipher.doFinal()
                if (finalBlock.isNotEmpty()) {
                    output.write(finalBlock)
                }
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Decrypts [encryptedFile] to [destPlainFile], verifying the 128-bit GCM authentication tag
     * before finishing. Deletes [destPlainFile] if authentication fails.
     */
    fun decryptFile(encryptedFile: File, destPlainFile: File, key: SecretKey) {
        destPlainFile.parentFile?.mkdirs()
        try {
            FileInputStream(encryptedFile).use { input ->
                val header = ByteArray(MAGIC.size + IV_LENGTH_BYTES)
                var offset = 0
                while (offset < header.size) {
                    val r = input.read(header, offset, header.size - offset)
                    if (r < 0) throw IllegalArgumentException("Truncated encrypted vault file")
                    offset += r
                }
                for (i in MAGIC.indices) {
                    if (header[i] != MAGIC[i]) {
                        throw IllegalArgumentException("Invalid encrypted vault file header")
                    }
                }
                val iv = header.copyOfRange(MAGIC.size, header.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))

                FileOutputStream(destPlainFile).use { output ->
                    val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val read = input.read(buf)
                        if (read < 0) break
                        if (read > 0) {
                            val chunk = cipher.update(buf, 0, read)
                            if (chunk != null && chunk.isNotEmpty()) {
                                output.write(chunk)
                            }
                        }
                    }
                    val finalBlock = cipher.doFinal()
                    if (finalBlock.isNotEmpty()) {
                        output.write(finalBlock)
                    }
                }
            }
        } catch (t: Throwable) {
            destPlainFile.delete()
            throw t
        }
    }

    // --- PIN / Passphrase Derivation (PBKDF2-HMAC-SHA256) ---

    data class PinVerifier(
        val saltBase64: String,
        val hashBase64: String,
        val iterations: Int = PBKDF2_ITERATIONS
    )

    fun createPinVerifier(pinOrPassphrase: String): PinVerifier {
        val normalized = pinOrPassphrase.trim()
        require(normalized.length in 4..64) { "Vault PIN/passphrase must be between 4 and 64 characters." }
        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val derived = pbkdf2(normalized, salt, PBKDF2_ITERATIONS)
        return PinVerifier(
            saltBase64 = Base64.getEncoder().encodeToString(salt),
            hashBase64 = Base64.getEncoder().encodeToString(derived),
            iterations = PBKDF2_ITERATIONS
        )
    }

    fun verifyPin(pinOrPassphrase: String, verifier: PinVerifier): Boolean {
        val salt = runCatching { Base64.getDecoder().decode(verifier.saltBase64) }.getOrNull() ?: return false
        val expected = runCatching { Base64.getDecoder().decode(verifier.hashBase64) }.getOrNull() ?: return false
        val candidate = pbkdf2(pinOrPassphrase.trim(), salt, verifier.iterations.coerceIn(10_000, 500_000))
        return MessageDigest.isEqual(expected, candidate)
    }

    private fun pbkdf2(secret: String, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, 256)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
