package com.adshield.pro.data.repository

import android.app.DownloadManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.DirectDownloadEntity
import com.adshield.pro.domain.model.DirectDownload
import com.adshield.pro.domain.model.DirectDownloadStatus
import com.adshield.pro.domain.model.InspectedMedia
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DirectDownloadRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: AdShieldDao
) {
    private val manager = context.getSystemService(DownloadManager::class.java)
    val downloads: Flow<List<DirectDownload>> = dao.observeDirectDownloads().map { rows -> rows.map(::toDomain) }

    suspend fun enqueue(media: InspectedMedia, destination: Uri, allowMetered: Boolean): DirectDownload = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val id = UUID.randomUUID().toString()
        val request = DownloadManager.Request(Uri.parse(media.finalUrl))
            .setTitle(media.fileName)
            .setDescription("OmniShield direct media download")
            .setMimeType(media.mimeType)
            .setDestinationUri(destination)
            .setAllowedOverMetered(allowMetered)
            .setAllowedOverRoaming(false)
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
        val systemId = manager.enqueue(request)
        val entity = DirectDownloadEntity(
            id = id,
            systemDownloadId = systemId,
            sourceUrl = media.url,
            fileName = media.fileName,
            mimeType = media.mimeType,
            destinationUri = destination.toString(),
            status = DirectDownloadStatus.QUEUED.name,
            downloadedBytes = 0L,
            totalBytes = media.sizeBytes,
            createdAtEpochMs = now,
            updatedAtEpochMs = now,
            error = null,
            integrityStatus = null
        )
        dao.upsertDirectDownload(entity)
        toDomain(entity)
    }

    suspend fun refreshActive() = withContext(Dispatchers.IO) {
        dao.getActiveDirectDownloads().forEach { record ->
            val systemId = record.systemDownloadId ?: return@forEach
            manager.query(DownloadManager.Query().setFilterById(systemId))?.use { cursor ->
                if (!cursor.moveToFirst()) {
                    dao.upsertDirectDownload(
                        record.copy(status = DirectDownloadStatus.FAILED.name, error = "Android DownloadManager no longer has this job", updatedAtEpochMs = System.currentTimeMillis())
                    )
                    return@forEach
                }
                val status = when (cursor.getInt(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))) {
                    DownloadManager.STATUS_RUNNING -> DirectDownloadStatus.RUNNING
                    DownloadManager.STATUS_PAUSED -> DirectDownloadStatus.PAUSED_BY_SYSTEM
                    DownloadManager.STATUS_SUCCESSFUL -> DirectDownloadStatus.COMPLETED
                    DownloadManager.STATUS_FAILED -> DirectDownloadStatus.FAILED
                    else -> DirectDownloadStatus.QUEUED
                }
                val reason = cursor.getInt(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON))
                val downloaded = cursor.getLong(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR)).coerceAtLeast(0L)
                val total = cursor.getLong(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES)).takeIf { it >= 0L } ?: record.totalBytes
                dao.upsertDirectDownload(
                    record.copy(
                        status = status.name,
                        downloadedBytes = downloaded,
                        totalBytes = total,
                        updatedAtEpochMs = System.currentTimeMillis(),
                        error = if (status == DirectDownloadStatus.FAILED) "Android DownloadManager error code $reason" else null
                    )
                )
            }
        }
    }

    suspend fun cancel(record: DirectDownload) = withContext(Dispatchers.IO) {
        val systemId = record.systemDownloadId ?: error("This download has no active system job")
        val removed = manager.remove(systemId)
        if (removed <= 0) error("Android did not cancel the job; it may already be finished")
        val current = dao.getDirectDownload(record.id) ?: return@withContext
        dao.upsertDirectDownload(
            current.copy(status = DirectDownloadStatus.CANCELLED.name, updatedAtEpochMs = System.currentTimeMillis(), error = null)
        )
    }

    suspend fun deleteHistory(record: DirectDownload) = withContext(Dispatchers.IO) {
        record.systemDownloadId?.let { runCatching { manager.remove(it) } }
        dao.deleteDirectDownload(record.id)
    }

    /** Verifies a supplied reference digest, or reports measured size and a non-reference local digest. */
    suspend fun verifyIntegrity(record: DirectDownload, expectedSha256: String?): String = withContext(Dispatchers.IO) {
        require(record.status == DirectDownloadStatus.COMPLETED) { "Integrity can be checked only after completion" }
        val destination = record.destinationUri?.let(Uri::parse) ?: error("No destination URI was retained")
        val expected = expectedSha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        if (expected != null) require(expected.matches(Regex("[0-9a-f]{64}"))) { "Expected SHA-256 must contain exactly 64 hexadecimal characters" }
        val digest = MessageDigest.getInstance("SHA-256")
        var measured = 0L
        resolverInput(destination).use { input ->
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                measured += read
                digest.update(buffer, 0, read)
            }
        }
        val sha = digest.digest().joinToString("") { "%02x".format(it) }
        val result = when {
            expected != null && !sha.equals(expected, ignoreCase = true) -> "FAILED: SHA-256 does not match the supplied reference. Local digest: $sha"
            expected != null -> "SHA-256 verified against the supplied reference: $sha"
            record.totalBytes != null && measured != record.totalBytes -> "FAILED: measured $measured bytes but the server declared ${record.totalBytes}. Local SHA-256: $sha"
            record.totalBytes != null -> "Size verified ($measured bytes). SHA-256 computed locally (no reference supplied): $sha"
            else -> "Server supplied no reference length/digest. Measured $measured bytes; local SHA-256: $sha"
        }
        val current = dao.getDirectDownload(record.id)
        if (current != null) {
            dao.upsertDirectDownload(current.copy(integrityStatus = result, updatedAtEpochMs = System.currentTimeMillis()))
        }
        result
    }

    private fun resolverInput(uri: Uri) = context.contentResolver.openInputStream(uri)
        ?: error("The downloaded file is no longer accessible")

    private fun toDomain(row: DirectDownloadEntity) = DirectDownload(
        id = row.id,
        systemDownloadId = row.systemDownloadId,
        sourceUrl = row.sourceUrl,
        fileName = row.fileName,
        mimeType = row.mimeType,
        destinationUri = row.destinationUri,
        status = runCatching { DirectDownloadStatus.valueOf(row.status) }.getOrDefault(DirectDownloadStatus.FAILED),
        downloadedBytes = row.downloadedBytes,
        totalBytes = row.totalBytes,
        createdAtEpochMs = row.createdAtEpochMs,
        updatedAtEpochMs = row.updatedAtEpochMs,
        error = row.error,
        integrityStatus = row.integrityStatus
    )
}
