package com.adshield.pro.gps.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AdShield Pro — at-rest protection for location history and trip data.
 *
 * Format of every stored file:
 *   "ADSE1" (5 bytes) | iv length (1 byte) | iv (12 bytes) | AES-256-GCM ciphertext
 *
 * The key is generated inside the Android Keystore and never leaves it; on devices with a TEE or
 * StrongBox the key material is hardware-bound. The app cannot read the raw key even with root on a
 * device where the keystore is hardware-backed.
 *
 * Honest scope: AES-GCM protects data at rest against another app or a stolen file. It does not
 * protect against a compromised OS with an unlocked keystore, and [SecureLocationStore] is not a
 * substitute for device encryption. That limitation is recorded in the capability registry.
 *
 * Also contains [LocationCipher], the pure transform used by the JVM tests: it accepts any
 * [SecretKey], so the exact same code path is exercised in unit tests with a software key.
 */

object LocationCipher {

    const val MAGIC = "ADSE1"
    const val GCM_TAG_BITS = 128
    const val IV_BYTES = 12
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    fun encrypt(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.size == IV_BYTES) { "unexpected GCM IV length ${iv.size}" }
        val payload = cipher.doFinal(plaintext)
        val header = MAGIC.toByteArray(Charsets.US_ASCII)
        val output = ByteArray(header.size + 1 + iv.size + payload.size)
        header.copyInto(output, 0)
        output[header.size] = iv.size.toByte()
        iv.copyInto(output, header.size + 1)
        payload.copyInto(output, header.size + 1 + iv.size)
        return output
    }

    /**
     * @throws IllegalArgumentException when the container header is wrong or truncated.
     * @throws javax.crypto.AEADBadTagException when the data was tampered with.
     */
    fun decrypt(key: SecretKey, container: ByteArray): ByteArray {
        val header = MAGIC.toByteArray(Charsets.US_ASCII)
        require(container.size > header.size + 1 + IV_BYTES) { "encrypted container is truncated" }
        require(container.copyOfRange(0, header.size).contentEquals(header)) {
            "not an AdShield encrypted container"
        }
        val ivLength = container[header.size].toInt() and 0xff
        require(ivLength in 1..32) { "invalid IV length $ivLength" }
        require(container.size > header.size + 1 + ivLength) { "encrypted container has no payload" }
        val iv = container.copyOfRange(header.size + 1, header.size + 1 + ivLength)
        val payload = container.copyOfRange(header.size + 1 + ivLength, container.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(payload)
    }

    fun isContainer(bytes: ByteArray): Boolean {
        val header = MAGIC.toByteArray(Charsets.US_ASCII)
        return bytes.size > header.size + 1 + IV_BYTES && bytes.copyOfRange(0, header.size).contentEquals(header)
    }
}

/**
 * Keystore-backed file encryptor. Used for trip history, saved places and the cached traffic queue.
 *
 * If the Keystore is unavailable (an emulator image without a keystore provider, or a device where
 * key generation fails), every operation fails closed: the caller is told the data cannot be
 * protected and the module falls back to not persisting history rather than writing plaintext.
 */
class SecureLocationStore(
    private val directory: File,
    private val keyAlias: String = DEFAULT_KEY_ALIAS
) {

    enum class State { READY, KEYSTORE_UNAVAILABLE }

    var state: State = State.READY
        private set
    var lastError: String? = null
        private set

    private fun secretKey(): SecretKey? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val existing = keyStore.getKey(keyAlias, null) as? SecretKey
            if (existing != null) return existing
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
            generator.generateKey()
        } catch (t: Throwable) {
            state = State.KEYSTORE_UNAVAILABLE
            lastError = t.message ?: t.javaClass.simpleName
            null
        }
    }

    fun write(name: String, plaintext: ByteArray): Boolean {
        val key = secretKey() ?: return false
        return try {
            if (!directory.exists()) directory.mkdirs()
            val container = LocationCipher.encrypt(key, plaintext)
            File(directory, name).outputStream().use { it.write(container) }
            true
        } catch (t: Throwable) {
            lastError = t.message ?: t.javaClass.simpleName
            false
        }
    }

    fun read(name: String): ByteArray? {
        val file = File(directory, name)
        if (!file.isFile) return null
        val key = secretKey() ?: return null
        return try {
            LocationCipher.decrypt(key, file.readBytes())
        } catch (t: Throwable) {
            lastError = t.message ?: t.javaClass.simpleName
            null
        }
    }

    fun delete(name: String): Boolean = File(directory, name).delete()

    fun exists(name: String): Boolean = File(directory, name).isFile

    fun list(): List<String> = directory.listFiles()?.map { it.name }.orEmpty().sorted()

    /** Wipes every stored file and the keystore key. Used by "delete all location data". */
    fun wipe(): Int {
        var deleted = 0
        directory.listFiles()?.forEach { if (it.delete()) deleted++ }
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
        }
        return deleted
    }

    /** Total bytes on disk (encrypted size), shown in the privacy screen. */
    fun sizeBytes(): Long = directory.listFiles()?.filter { it.isFile }?.sumOf { it.length() } ?: 0L

    companion object {
        const val DEFAULT_KEY_ALIAS = "adshield_gps_history_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

/** Streaming variant used when appending to a trip log would otherwise need a full copy. */
object SecureFileStreams {

    fun openEncryptedOutput(file: File, key: SecretKey): CipherOutputStream {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val out = FileOutputStream(file)
        out.write(LocationCipher.MAGIC.toByteArray(Charsets.US_ASCII))
        out.write(byteArrayOf(cipher.iv.size.toByte()))
        out.write(cipher.iv)
        return CipherOutputStream(out, cipher)
    }

    fun openEncryptedInput(file: File, key: SecretKey): CipherInputStream {
        val input = FileInputStream(file)
        val header = ByteArray(LocationCipher.MAGIC.length)
        input.read(header)
        require(header.contentEquals(LocationCipher.MAGIC.toByteArray(Charsets.US_ASCII))) {
            "not an AdShield encrypted file"
        }
        val ivLength = input.read()
        require(ivLength in 1..32) { "invalid IV length $ivLength" }
        val iv = ByteArray(ivLength)
        input.read(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(LocationCipher.GCM_TAG_BITS, iv))
        return CipherInputStream(input, cipher)
    }
}
