package com.adshield.pro.engine.security

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Isolates flagged files in app-private storage.
 *
 * Design rules, all of which exist to avoid destroying user data or lying about it:
 *  - Quarantine **copies** the content into `filesDir/quarantine/<id>.quarantined`. The neutral
 *    suffix stops Android from treating the copy as installable/openable.
 *  - The original is only removed when the caller explicitly asks, and the outcome is reported.
 *    Android frequently refuses to delete a document this app does not own; that is surfaced as
 *    "original still present", never silently treated as success.
 *  - Every copy is SHA-256 hashed on the way in and re-verified on the way out, so a corrupted
 *    or tampered quarantine file is never handed back to the user as the original.
 *  - Storage is app-private (OS sandbox). It is not additionally encrypted at rest.
 */
@Singleton
class QuarantineManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val quarantineDir: File
        get() = File(context.filesDir, "quarantine").apply { if (!exists()) mkdirs() }

    fun storedFile(item: QuarantinedItem): File = File(quarantineDir, item.storedFileName)

    /** Bytes actually on disk (not the index), so the UI cannot over-report usage. */
    fun diskUsageBytes(): Long =
        quarantineDir.listFiles()?.filter { QuarantineNaming.isStoredFileName(it.name) }
            ?.sumOf { it.length().coerceAtLeast(0L) } ?: 0L

    /**
     * Copies [uri] into quarantine. Returns null when the source could not be read — the caller
     * must report that rather than claiming the file was isolated.
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
            val digest = MessageDigest.getInstance("SHA-256")
            var size = 0L
            input.use { source ->
                target.outputStream().use { sink ->
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
            QuarantinedItem(
                id = record.id,
                displayName = QuarantineNaming.safeDisplayName(displayName),
                originalLocation = displayName,
                storedFileName = target.name,
                sha256 = digest.digest().toHexLower(),
                sizeBytes = size,
                threatLevel = record.threatLevel,
                threatName = record.threatName,
                quarantinedAtEpochMs = System.currentTimeMillis(),
                originalRemoved = false
            )
        } catch (t: Throwable) {
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

    /** Recomputes the stored file's hash and compares it with the recorded one. */
    suspend fun verifyIntegrity(item: QuarantinedItem): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        if (!file.exists()) return@withContext false
        runCatching {
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
        }.getOrDefault(false)
    }

    /**
     * Writes a quarantined file back out to a user-chosen destination, verifying the hash as it
     * streams. Returns false (and writes nothing further) if the content no longer matches.
     */
    suspend fun exportTo(item: QuarantinedItem, destination: Uri): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        if (!file.exists()) return@withContext false
        try {
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
            val matches = digest.digest().toHexLower().equals(item.sha256, ignoreCase = true) &&
                size == item.sizeBytes
            matches
        } catch (t: Throwable) {
            false
        }
    }

    /** Permanently removes the isolated copy. Only ever called from an explicit user action. */
    suspend fun delete(item: QuarantinedItem): Boolean = withContext(Dispatchers.IO) {
        val file = storedFile(item)
        !file.exists() || file.delete()
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
    }
}
