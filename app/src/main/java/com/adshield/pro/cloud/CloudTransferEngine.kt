package com.adshield.pro.cloud

import android.content.Context
import android.net.Uri
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.adshield.pro.data.local.db.CloudDao
import com.adshield.pro.data.local.db.CloudTransferEntity
import com.adshield.pro.worker.CloudTransferWorker
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Resumable transfer engine.
 *
 * Uploads larger than [CloudConfig.UPLOAD_CHUNK_BYTES] go multipart: the Worker issues a
 * short-lived signed URL per chunk, chunks are PUT directly, and the Worker assembles them in
 * R2. Small files use a single signed PUT. Every transfer is persisted in `cloud_transfers`
 * first, so a pause, a kill or a network drop never loses progress — the WorkManager worker
 * resumes queued work in the background.
 */
@Singleton
class CloudTransferEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApiClient,
    private val authStore: CloudAuthStore,
    private val cloudDao: CloudDao
) {

    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .writeTimeout(300, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    // --- queue ---

    suspend fun enqueueUpload(
        uri: Uri, displayName: String, folderPath: String,
        size: Long, mimeType: String, sha256: String
    ): String = withContext(Dispatchers.IO) {
        val id = UUID.randomUUID().toString()
        cloudDao.upsertTransfer(
            CloudTransferEntity(
                id = id, direction = "UPLOAD", fileId = null, displayName = displayName,
                sourceUri = uri.toString(), destUri = folderPath, totalBytes = size,
                doneBytes = 0L, state = "QUEUED", sha256 = sha256,
                updatedAtEpochMs = System.currentTimeMillis()
            )
        )
        scheduleWorker(id)
        id
    }

    suspend fun enqueueDownload(fileId: String, displayName: String, destUri: Uri): Result<String> =
        withContext(Dispatchers.IO) {
            runCatching {
                val id = UUID.randomUUID().toString()
                cloudDao.upsertTransfer(
                    CloudTransferEntity(
                        id = id, direction = "DOWNLOAD", fileId = fileId, displayName = displayName,
                        sourceUri = fileId, destUri = destUri.toString(), totalBytes = 0L,
                        doneBytes = 0L, state = "QUEUED", sha256 = "",
                        updatedAtEpochMs = System.currentTimeMillis()
                    )
                )
                scheduleWorker(id)
                id
            }
        }

    suspend fun pause(id: String) = updateState(id, "PAUSED")
    suspend fun cancel(id: String) = updateState(id, "CANCELLED")

    suspend fun resume(id: String) = withContext(Dispatchers.IO) {
        updateState(id, "QUEUED")
        scheduleWorker(id)
    }

    private suspend fun updateState(id: String, state: String) {
        val row = cloudDao.pendingTransfers().firstOrNull { it.id == id }
            ?: first(cloudDao.observeTransfers()).firstOrNull { it.id == id }
        if (row != null) {
            cloudDao.updateTransfer(row.copy(state = state, updatedAtEpochMs = System.currentTimeMillis()))
        }
    }

    private fun scheduleWorker(transferId: String) {
        val request = OneTimeWorkRequestBuilder<CloudTransferWorker>()
            .setInputData(workDataOf(CloudTransferWorker.KEY_TRANSFER_ID to transferId))
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            )
            .build()
        WorkManager.getInstance(context)
            .enqueueUniqueWork("cloud_transfer_$transferId", ExistingWorkPolicy.REPLACE, request)
    }

    // --- execution (called by CloudTransferWorker) ---

    suspend fun runTransfer(transferId: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val transfer = cloudDao.pendingTransfers().firstOrNull { it.id == transferId }
                ?: error("Transfer $transferId is no longer pending.")
            mark(transfer, "RUNNING", transfer.doneBytes)
            if (transfer.direction == "UPLOAD") runUpload(transfer) else runDownload(transfer)
        }
    }

    private suspend fun runUpload(transfer: CloudTransferEntity) {
        val baseUrl = authStore.currentApiBaseUrl()
        val token = authStore.currentSession()?.accessToken.orEmpty()
        val uri = Uri.parse(transfer.sourceUri)
        val size = transfer.totalBytes
        val record = api.createFileRecord(
            baseUrl, token, transfer.displayName, transfer.destUri,
            size, mimeOf(uri), transfer.sha256, multipart = size > CloudConfig.UPLOAD_CHUNK_BYTES
        )
        if (size > CloudConfig.UPLOAD_CHUNK_BYTES) {
            multipartUpload(baseUrl, token, record.id, uri, size, transfer)
        } else {
            val signed = api.signedUploadUrl(baseUrl, token, record.id, size, transfer.sha256)
            checkSigned(signed)
            putFile(signed, uri, size) { done -> mark(transfer, "RUNNING", done) }
        }
        mark(transfer.copy(fileId = record.id), "DONE", size)
    }

    private suspend fun multipartUpload(
        baseUrl: String, token: String, fileId: String, uri: Uri, size: Long, transfer: CloudTransferEntity
    ) {
        val chunk = CloudConfig.UPLOAD_CHUNK_BYTES
        val partCount = ((size + chunk - 1) / chunk).toInt()
        val parts = mutableListOf<Int>()
        for (part in 1..partCount) {
            val offset = (part - 1) * chunk
            val length = minOf(chunk, size - offset)
            val signed = api.signedChunkUrl(baseUrl, token, fileId, part, uploadId = fileId)
            checkSigned(signed)
            putRange(signed, uri, offset, length) { done ->
                mark(transfer, "RUNNING", (part - 1) * chunk + done)
            }
            parts.add(part)
        }
        api.completeMultipart(baseUrl, token, fileId, fileId, parts)
    }

    private suspend fun runDownload(transfer: CloudTransferEntity) {
        val baseUrl = authStore.currentApiBaseUrl()
        val token = authStore.currentSession()?.accessToken.orEmpty()
        val signed = api.signedDownloadUrl(baseUrl, token, transfer.fileId!!)
        checkSigned(signed)
        val dest = Uri.parse(transfer.destUri)
        context.contentResolver.openOutputStream(dest, "w")?.use { output ->
            http.newCall(Request.Builder().url(signed.url).get().build()).execute().use { response ->
                if (!response.isSuccessful) throw IOException("Download failed: HTTP ${response.code}")
                val body = response.body ?: throw IOException("Empty download body")
                val total = body.contentLength()
                body.byteStream().use { input ->
                    val buffer = ByteArray(64 * 1024)
                    var written = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        written += read
                        if (written % (512 * 1024) == 0L) mark(transfer, "RUNNING", written)
                    }
                    if (total > 0) mark(transfer, "RUNNING", total)
                }
            }
        } ?: throw IOException("Cannot open destination $dest")
        mark(transfer, "DONE", transfer.totalBytes)
    }

    /** Single-shot PUT of raw bytes (used by the DNS backup path). */
    suspend fun putBytes(signed: SignedUrlResponse, bytes: ByteArray) = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(signed.url)
            .put(bytes.toRequestBody("application/octet-stream".toMediaType()))
            .apply { signed.headers.forEach { (k, v) -> header(k, v) } }
            .build()
        http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Upload failed: HTTP ${response.code}")
        }
    }

    suspend fun getString(signed: SignedUrlResponse): String = withContext(Dispatchers.IO) {
        http.newCall(Request.Builder().url(signed.url).get().build()).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Download failed: HTTP ${response.code}")
            response.body?.string() ?: throw IOException("Empty body")
        }
    }

    private suspend fun putFile(
        signed: SignedUrlResponse, uri: Uri, size: Long,
        onProgress: suspend (Long) -> Unit
    ) {
        val body = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun contentLength() = size
            override fun writeTo(sink: BufferedSink) {
                val out = sink.outputStream()
                context.contentResolver.openInputStream(uri)!!.use { input ->
                    val buffer = ByteArray(64 * 1024)
                    var written = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read == -1) break
                        out.write(buffer, 0, read)
                        written += read
                        if (written % (512 * 1024) == 0L) {
                            kotlinx.coroutines.runBlocking { onProgress(written) }
                        }
                    }
                }
            }
        }
        val request = Request.Builder().url(signed.url).put(body)
            .apply { signed.headers.forEach { (k, v) -> header(k, v) } }
            .build()
        http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Upload failed: HTTP ${response.code}")
        }
        onProgress(size)
    }

    private suspend fun putRange(
        signed: SignedUrlResponse, uri: Uri, offset: Long, length: Long,
        onProgress: suspend (Long) -> Unit
    ) {
        val body = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun contentLength() = length
            override fun writeTo(sink: BufferedSink) {
                val out = sink.outputStream()
                context.contentResolver.openInputStream(uri)!!.use { input ->
                    var skipped = 0L
                    while (skipped < offset) {
                        val n = input.skip(offset - skipped)
                        if (n <= 0) throw IOException("Cannot seek to $offset")
                        skipped += n
                    }
                    var remaining = length
                    val buffer = ByteArray(64 * 1024)
                    while (remaining > 0) {
                        val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                        if (read == -1) throw IOException("Unexpected end of file at $offset")
                        out.write(buffer, 0, read)
                        remaining -= read
                        kotlinx.coroutines.runBlocking { onProgress(length - remaining) }
                    }
                }
            }
        }
        val request = Request.Builder().url(signed.url).put(body)
            .apply { signed.headers.forEach { (k, v) -> header(k, v) } }
            .build()
        http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Chunk upload failed: HTTP ${response.code}")
        }
    }

    private fun checkSigned(signed: SignedUrlResponse) {
        require(CloudWire.isSignedUrlValid(signed.url, System.currentTimeMillis())) {
            "Signed URL missing or expired — refusing to transfer."
        }
    }

    private fun mimeOf(uri: Uri): String =
        context.contentResolver.getType(uri) ?: "application/octet-stream"

    private suspend fun mark(transfer: CloudTransferEntity, state: String, doneBytes: Long) {
        cloudDao.updateTransfer(
            transfer.copy(state = state, doneBytes = doneBytes, updatedAtEpochMs = System.currentTimeMillis())
        )
    }
}
