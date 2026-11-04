package com.adshield.pro.engine.security

import android.content.Context
import android.net.Uri
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/** App-private scan history and quarantine. No file content or history leaves the device. */
@Singleton
class SecurityLocalStore @Inject constructor(
    @ApplicationContext private val context: Context
) {
    @Serializable
    data class QuarantineItem(
        val id: String,
        val originalName: String,
        val sha256: String,
        val sizeBytes: Long,
        val quarantinedAtEpochMs: Long,
        val originalRemoved: Boolean
    )

    data class QuarantineResult(
        val item: QuarantineItem,
        val originalRemovalNote: String
    )

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val prefs = context.getSharedPreferences("omnishield_security_local", Context.MODE_PRIVATE)
    private val quarantineDir = File(context.filesDir, "quarantine").apply { mkdirs() }

    fun loadHistory(): List<SecurityScanRecord> {
        val raw = prefs.getString(KEY_HISTORY, null) ?: return emptyList()
        return runCatching { json.decodeFromString<List<SecurityScanRecord>>(raw) }
            .getOrDefault(emptyList()).take(MAX_HISTORY)
    }

    fun appendHistory(record: SecurityScanRecord): List<SecurityScanRecord> {
        val updated = (listOf(record) + loadHistory().filterNot {
            it.id == record.id && it.target == record.target
        }).take(MAX_HISTORY)
        prefs.edit().putString(KEY_HISTORY, json.encodeToString(updated)).apply()
        return updated
    }

    fun quarantineItems(): List<QuarantineItem> {
        val raw = prefs.getString(KEY_QUARANTINE, null) ?: return emptyList()
        return runCatching { json.decodeFromString<List<QuarantineItem>>(raw) }
            .getOrDefault(emptyList()).filter { File(quarantineDir, it.id).isFile }
    }

    /**
     * Copies a user-selected document into app-private storage, verifies the copy's SHA-256,
     * then attempts to remove the original only after that verification. Some document
     * providers do not grant delete rights; that outcome is reported, never hidden.
     */
    suspend fun quarantine(uri: Uri, displayName: String): QuarantineResult = withContext(Dispatchers.IO) {
        val safeName = displayName.take(80).replace(Regex("[^A-Za-z0-9._-]"), "_")
        val id = "${System.currentTimeMillis()}-$safeName.quarantined"
        val destination = File(quarantineDir, id)
        val partial = File(quarantineDir, "$id.partial")
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Android could not open the selected document")
            input.use { source ->
                partial.outputStream().buffered().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = source.read(buffer)
                        if (read < 0) break
                        size += read
                        if (size > MAX_QUARANTINE_BYTES) {
                            throw IllegalStateException("File exceeds the 128 MiB quarantine safety limit")
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                    }
                }
            }
            if (size == 0L) throw IllegalStateException("Empty files are not quarantined")
            if (!partial.renameTo(destination)) throw IllegalStateException("Could not finalize private quarantine copy")
            val sha = digest.digest().joinToString("") { "%02x".format(it) }
            val originalRemoved = runCatching {
                context.contentResolver.delete(uri, null, null) > 0
            }.getOrDefault(false)
            val item = QuarantineItem(
                id = id,
                originalName = displayName,
                sha256 = sha,
                sizeBytes = size,
                quarantinedAtEpochMs = System.currentTimeMillis(),
                originalRemoved = originalRemoved
            )
            saveQuarantineItems(listOf(item) + quarantineItems())
            QuarantineResult(
                item,
                if (originalRemoved) "Original document removed by its provider."
                else "Original could not be deleted by Android; the verified copy remains isolated in app-private quarantine."
            )
        } catch (error: Throwable) {
            partial.delete()
            destination.delete()
            throw error
        }
    }

    fun deleteQuarantined(item: QuarantineItem): List<QuarantineItem> {
        File(quarantineDir, item.id).delete()
        return quarantineItems().filterNot { it.id == item.id }.also(::saveQuarantineItems)
    }

    private fun saveQuarantineItems(items: List<QuarantineItem>) {
        prefs.edit().putString(KEY_QUARANTINE, json.encodeToString(items.take(MAX_QUARANTINE_ITEMS))).apply()
    }

    private companion object {
        const val KEY_HISTORY = "scan_history_v1"
        const val KEY_QUARANTINE = "quarantine_items_v1"
        const val MAX_HISTORY = 100
        const val MAX_QUARANTINE_ITEMS = 50
        const val MAX_QUARANTINE_BYTES = 128L * 1024L * 1024L
    }
}
