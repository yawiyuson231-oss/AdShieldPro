package com.adshield.pro.engine.security

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.adshield.pro.engine.storage.ZeroKnowledgeFileCipher
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.OutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Isolates flagged files in app-private storage with Android-Keystore-wrapped AES-256-GCM
 * streaming encryption (`OSZK` v1).
 *
 * Design rules:
 *  - Quarantine **encrypts** the content into `filesDir/quarantine/<id>.quarantined` using a
 *    256-bit AES Data Encryption Key wrapped by an `AndroidKeyStore` hardware/OS-backed master key.
 *  - Legacy pre-2.12 unencrypted `.quarantined` files remain readable and verifiable via header
 *    detection (`ZeroKnowledgeFileCipher.hasZeroKnowledgeHeader`).
 *  - Every copy is SHA-256 hashed over its original plaintext on ingest and re-verified on
 *    integrity check and restore, so a corrupted or tampered quarantine file is never handed back.
 */
@Singleton
class QuarantineManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val quarantineDir: File
        get() = File(context.filesDir, "quarantine").apply { if (!exists()) mkdirs() }

    @Volatile
    private var cachedDek: SecretKey? = null

    fun storedFile(item: QuarantinedItem): File = File(quarantineDir, item.storedFileName)

    /** Bytes actually on disk (not the index), so the UI cannot over-report usage. */
    fun diskUsageBytes(): Long =
        quarantineDir.listFiles()?.filter { QuarantineNaming.isStoredFileName(it.name) }
            ?.sumOf { it.length().coerceAtLeast(0L) } ?: 0L

    /**
     * Copies and AES-256-GCM encrypts [uri] into quarantine. Returns null when the source could not
     * be read or encrypted — the caller reports that rather than claiming the file was isolated.
     */
    suspend fun isolate(
        uri: Uri,
        displayName: String,
        record: SecurityScanRecord
    ): QuarantinedItem? = withContext(Dispatchers.IO) {
        val target = File(quarantineDir, QuarantineNaming.storedFileName(record.id))
        try {
            val input = context.contentResolver.openInputStream(uri)
            if (input == null) {
                target.delete()
                return@withContext null
            }
            val dek = getOrCreateEnvelopeKey()
            val summary = input.use { source ->
                target.outputStream().use { sink ->
                    ZeroKnowledgeFileCipher.encryptStreamWithKey(source, sink, dek)
                }
            }
            QuarantinedItem(
                id = record.id,
                displayName = QuarantineNaming.safeDisplayName(displayName),
                originalLocation = displayName,
                storedFileName = target.name,
                sha256 = summary.plaintextSha256Hex,
                sizeBytes = summary.plaintextBytes,
                threatLevel = record.threatLevel,
                threatName = record.threatName,
                quarantinedAtEpochMs = System.currentTimeMillis(),
                originalRemoved = false
            )
        } catch (_: Throwable) {
            target.delete()
            null
        }
    }

    /**
     * Attempts to delete the original document. Returns true only when the provider confirmed the
     * deletion. Requires a document URI the user granted write access to.
     */
    suspend fun tryRemoveOriginal(uri: Uri): Boolean = withContext(Dispatchers.IO) {
        runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) }.getOrDefault(false)
    }

    /** Verifies both AES-GCM chunk authentication tags (when encrypted) and the recorded plaintext SHA-256. */
    suspend fun verifyIntegrity(item: QuarantinedItem): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        if (!file.exists()) return@withContext false
        runCatching {
            if (isEncryptedQuarantineFile(file)) {
                val dek = getOrCreateEnvelopeKey()
                val summary = file.inputStream().use { input ->
                    ZeroKnowledgeFileCipher.decryptStreamWithKey(input, NullOutputStream, dek)
                }
                summary.plaintextSha256Hex.equals(item.sha256, ignoreCase = true) &&
                    summary.plaintextBytes == item.sizeBytes
            } else {
                val digest = MessageDigest.getInstance("SHA-256")
                file.inputStream().use { input ->
                    val buffer = ByteArray(1 shl 16)
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        digest.update(buffer, 0, read)
                    }
                }
                digest.digest().toHexLower().equals(item.sha256, ignoreCase = true)
            }
        }.getOrDefault(false)
    }

    /**
     * Decrypts (or streams legacy plaintext) a quarantined file back out to a user-chosen
     * destination, verifying authentication tags and SHA-256 as it streams.
     */
    suspend fun exportTo(item: QuarantinedItem, destination: Uri): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        if (!file.exists()) return@withContext false
        try {
            if (isEncryptedQuarantineFile(file)) {
                // Verify GCM authenticity before touching destination so tampered ciphertext writes nothing
                if (!verifyIntegrity(item)) return@withContext false
                val dek = getOrCreateEnvelopeKey()
                val output = context.contentResolver.openOutputStream(destination, "wt")
                    ?: return@withContext false
                val summary = output.use { sink ->
                    file.inputStream().use { source ->
                        ZeroKnowledgeFileCipher.decryptStreamWithKey(source, sink, dek)
                    }
                }
                summary.plaintextSha256Hex.equals(item.sha256, ignoreCase = true) &&
                    summary.plaintextBytes == item.sizeBytes
            } else {
                val output = context.contentResolver.openOutputStream(destination, "wt")
                    ?: return@withContext false
                val digest = MessageDigest.getInstance("SHA-256")
                var size = 0L
                output.use { sink ->
                    file.inputStream().use { source ->
                        val buffer = ByteArray(1 shl 16)
                        while (true) {
                            val read = source.read(buffer)
                            if (read <= 0) break
                            digest.update(buffer, 0, read)
                            sink.write(buffer, 0, read)
                            size += read
                        }
                    }
                }
                digest.digest().toHexLower().equals(item.sha256, ignoreCase = true) &&
                    size == item.sizeBytes
            }
        } catch (_: Throwable) {
            false
        }
    }

    /** Permanently removes the isolated copy. Only ever called from an explicit user action. */
    suspend fun delete(item: QuarantinedItem): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        !file.exists() || file.delete()
    }

    private fun isEncryptedQuarantineFile(file: File): Boolean {
        if (file.length() < ZeroKnowledgeFileCipher.HEADER_BYTES) return false
        val header = ByteArray(5)
        val read = file.inputStream().use { it.read(header) }
        return read == 5 && ZeroKnowledgeFileCipher.hasZeroKnowledgeHeader(header)
    }

    @Synchronized
    private fun getOrCreateEnvelopeKey(): SecretKey {
        cachedDek?.let { return it }
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val wrappingKey = (ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey) ?: run {
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            gen.init(
                KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            gen.generateKey()
        }

        val existingIvB64 = prefs.getString(KEY_WRAPPED_IV, null)
        val existingCtB64 = prefs.getString(KEY_WRAPPED_CT, null)
        if (existingIvB64 != null && existingCtB64 != null) {
            val unwrapped = runCatching {
                val iv = Base64.decode(existingIvB64, Base64.NO_WRAP)
                val ct = Base64.decode(existingCtB64, Base64.NO_WRAP)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, wrappingKey, GCMParameterSpec(128, iv))
                SecretKeySpec(cipher.doFinal(ct), "AES")
            }.getOrNull()
            if (unwrapped != null) {
                cachedDek = unwrapped
                return unwrapped
            }
        }

        val rawDek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wrapCipher = Cipher.getInstance("AES/GCM/NoPadding")
        wrapCipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        val wrappedCt = wrapCipher.doFinal(rawDek)
        val wrappedIv = wrapCipher.iv
        prefs.edit()
            .putString(KEY_WRAPPED_IV, Base64.encodeToString(wrappedIv, Base64.NO_WRAP))
            .putString(KEY_WRAPPED_CT, Base64.encodeToString(wrappedCt, Base64.NO_WRAP))
            .apply()

        val created = SecretKeySpec(rawDek, "AES")
        cachedDek = created
        return created
    }

    private object NullOutputStream : OutputStream() {
        override fun write(b: Int) = Unit
        override fun write(b: ByteArray, off: Int, len: Int) = Unit
    }

    private fun ByteArray.toHexLower(): String {
        val out = StringBuilder(size * 2)
        for (byte in this) {
            val code = byte.toInt() and 0xFF
            out.append(HEX[code shr 4]).append(HEX[code and 0x0F])
        }
        return out.toString()
    }

    private companion object {
        const val HEX = "0123456789abcdef"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEYSTORE_ALIAS = "adshield_quarantine_envelope_v1"
        const val PREFS_NAME = "adshield_quarantine_keystore"
        const val KEY_WRAPPED_IV = "wrapped_dek_iv"
        const val KEY_WRAPPED_CT = "wrapped_dek_ct"
    }
}
