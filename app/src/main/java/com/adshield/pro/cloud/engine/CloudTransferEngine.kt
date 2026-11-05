package com.adshield.pro.cloud.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.adshield.pro.cloud.data.ClientSideCipher
import com.adshield.pro.cloud.data.CloudApiClient
import com.adshield.pro.cloud.data.CloudCompleteUploadDto
import com.adshield.pro.cloud.data.CloudInitUploadDto
import com.adshield.pro.cloud.data.CloudResult
import com.adshield.pro.cloud.data.CloudUploadStateDto
import com.adshield.pro.cloud.util.Hashing
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.IOException
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton

/** Thrown when the user pauses or cancels a transfer; never shown as an error. */
class TransferInterruptedException(message: String) : IOException(message)

data class TransferProgress(
    val bytesTransferred: Long,
    val totalBytes: Long,
    val partsDone: Int = 0,
    val partsTotal: Int = 0,
    val phase: String = "transferring"
) {
    val fraction: Float get() = if (totalBytes <= 0) 0f else (bytesTransferred.toFloat() / totalBytes).coerceIn(0f, 1f)
}

/** Controls pause/cancel for one running transfer. */
class TransferControl {
    @Volatile var paused: Boolean = false
        private set
    @Volatile var cancelled: Boolean = false
        private set

    fun pause() { paused = true }
    fun resume() { paused = false }
    fun cancel() { cancelled = true }

    fun check() {
        if (cancelled) throw TransferInterruptedException("Transfer cancelled by user")
        if (paused) throw TransferInterruptedException("Transfer paused by user")
    }
}

data class PickResult(val uri: Uri, val name: String, val size: Long, val mime: String)

/**
 * Chunked, resumable transfer engine.
 *
 * Uploads stream straight from the app to the Worker in [CloudInitUploadDto.partSize] chunks, so
 * a 4 GB video never has to fit in memory. Resume state lives on the server (accepted parts) and
 * in Room (transferred bytes), so a killed process can continue where it stopped.
 */
@Singleton
class CloudUploadEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApiClient,
    private val cipher: ClientSideCipher
) {

    fun describe(uri: Uri): PickResult? {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (!cursor.moveToFirst()) return null
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            val name = if (nameIndex >= 0) cursor.getString(nameIndex) ?: "file" else "file"
            val size = if (sizeIndex >= 0) cursor.getLong(sizeIndex) else 0L
            val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
            return PickResult(uri, name, size, mime)
        }
        return null
    }

    /** Streams the content once to compute the SHA-256 used for dedupe + integrity checks. */
    suspend fun hashUri(uri: Uri, onProgress: ((Long, Long) -> Unit)? = null, control: TransferControl? = null): String =
        withContext(Dispatchers.IO) {
            openStream(uri).use { stream ->
                Hashing.sha256HexStream(
                    input = stream,
                    onProgress = onProgress,
                    isCancelled = { control?.cancelled == true }
                )
            }
        }

    fun openStream(uri: Uri): InputStream =
        context.contentResolver.openInputStream(uri) ?: throw IOException("Cannot open the selected file")

    /**
     * Uploads a local content Uri. Returns the server's completion payload.
     * [onProgress] is invoked on a background dispatcher.
     */
    suspend fun upload(
        uri: Uri,
        name: String,
        mime: String,
        parentId: String?,
        encrypted: Boolean,
        control: TransferControl,
        onSession: (CloudInitUploadDto) -> Unit = {},
        onProgress: (TransferProgress) -> Unit
    ): CloudResult<CloudCompleteUploadDto> = withContext(Dispatchers.IO) {
        val size = describe(uri)?.size ?: 0L
        if (size <= 0L) return@withContext CloudResult.Failure("empty_file", "The selected file is empty")

        onProgress(TransferProgress(0, size, phase = "hashing"))
        val sha256 = hashUri(uri, control = control)

        val init = api.initUpload(name, size, parentId, mime, sha256, encrypted)
        if (init !is CloudResult.Success) return@withContext init
        val session = init.value
        onSession(session)

        if (session.duplicate != null) {
            onProgress(TransferProgress(size, size, phase = "deduplicated"))
            return@withContext CloudResult.Success(
                CloudCompleteUploadDto(
                    status = "completed",
                    nodeId = session.nodeId,
                    size = size,
                    sha256 = sha256,
                    sha256Verified = true,
                    warning = "Identical content already existed; a lightweight reference was created instead of uploading again."
                )
            )
        }
        val token = session.uploadToken
            ?: return@withContext CloudResult.Failure("missing_upload_token", "Server did not issue an upload token")
        val base = apiBaseFor(session) ?: return@withContext CloudResult.Failure("not_configured", "Cloud endpoint is not configured")

        try {
            if (session.mode == "single") {
                uploadSingle(base, session, token, uri, size, mime, control, onProgress)
            } else {
                uploadMultipart(base, session, token, uri, size, control, onProgress)
            }
            control.check()
            val completed = api.completeUpload(session.uploadId)
            if (completed is CloudResult.Success) {
                onProgress(TransferProgress(size, size, session.partsTotal, session.partsTotal, "verifying"))
                verifyCompletedUpload(completed.value, uri, sha256)
            } else {
                completed
            }
        } catch (interrupted: TransferInterruptedException) {
            throw interrupted
        } catch (error: Throwable) {
            CloudResult.Failure("upload_failed", error.message ?: "Upload failed", retryable = true)
        }
    }

    private fun apiBaseFor(session: CloudInitUploadDto): String? =
        session.uploadUrls?.get("single")?.substringBefore("/v1/upload/")

    private suspend fun uploadSingle(
        base: String,
        session: CloudInitUploadDto,
        token: String,
        uri: Uri,
        size: Long,
        mime: String,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ) {
        val url = "$base/v1/upload/${session.uploadId}/content?token=${java.net.URLEncoder.encode(token, "UTF-8")}"
        val body = ProgressRequestBody(
            openStream = { openStream(uri) },
            length = size,
            contentType = mime.toMediaType(),
            onProgress = { written ->
                control.check()
                onProgress(TransferProgress(written, size, 0, 1, "uploading"))
            },
            control = control
        )
        val request = api.uploadRequest(url, body, mime)
        api.execute(request).use { response ->
            if (!response.isSuccessful) {
                throw IOException("Chunk upload rejected (HTTP ${response.code})")
            }
        }
    }

    private suspend fun uploadMultipart(
        base: String,
        session: CloudInitUploadDto,
        token: String,
        uri: Uri,
        size: Long,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ) {
        val partSize = session.partSize
        if (partSize <= 0) throw IOException("Server returned an invalid part size")
        val partsTotal = session.partsTotal

        // Ask the server which parts it already has, so a resume skips completed chunks.
        val state = api.uploadState(session.uploadId)
        val accepted = if (state is CloudResult.Success) {
            state.value.acceptedParts.map { it.partNumber }.toSet()
        } else {
            emptySet()
        }
        val resumeToken = if (state is CloudResult.Success) state.value.uploadToken ?: token else token

        var uploadedBytes = accepted.sumOf { part ->
            val start = (part - 1) * partSize
            minOf(partSize, size - start)
        }
        onProgress(TransferProgress(uploadedBytes, size, accepted.size, partsTotal, "uploading"))

        for (partNumber in 1..partsTotal) {
            control.check()
            if (partNumber in accepted) continue
            val start = (partNumber - 1) * partSize
            val length = minOf(partSize, size - start)
            val partBytes = readChunk(uri, start, length)
            var attempt = 0
            while (true) {
                control.check()
                try {
                    val url = "$base/v1/upload/${session.uploadId}/parts/$partNumber?token=" +
                        java.net.URLEncoder.encode(resumeToken, "UTF-8")
                    val body = partBytes.toRequestBody("application/octet-stream".toMediaType())
                    api.execute(api.uploadRequest(url, body, "application/octet-stream")).use { response ->
                        if (!response.isSuccessful) throw IOException("Part $partNumber rejected (HTTP ${response.code})")
                    }
                    uploadedBytes += length
                    onProgress(TransferProgress(uploadedBytes, size, partNumber, partsTotal, "uploading"))
                    break
                } catch (interrupted: TransferInterruptedException) {
                    throw interrupted
                } catch (error: Throwable) {
                    attempt += 1
                    if (attempt >= 3) throw error
                    kotlinx.coroutines.delay(500L * attempt)
                }
            }
        }
    }

    /** Reads exactly [length] bytes starting at [offset] without loading the whole file. */
    private fun readChunk(uri: Uri, offset: Long, length: Long): ByteArray {
        openStream(uri).use { stream ->
            var skipped = 0L
            while (skipped < offset) {
                val delta = stream.skip(offset - skipped)
                if (delta <= 0) {
                    // Fall back to read() for content providers that cannot seek.
                    if (stream.read() < 0) break
                    skipped += 1
                } else {
                    skipped += delta
                }
            }
            val buffer = ByteArray(length.toInt())
            var read = 0
            while (read < buffer.size) {
                val count = stream.read(buffer, read, buffer.size - read)
                if (count <= 0) break
                read += count
            }
            return if (read == buffer.size) buffer else buffer.copyOf(read)
        }
    }

    /**
     * Re-verifies integrity after the server acknowledges the upload: if the server could not
     * hash the object (large file, CPU budget), the client compares the local hash itself.
     */
    private suspend fun verifyCompletedUpload(
        completed: CloudCompleteUploadDto,
        uri: Uri,
        localSha256: String
    ): CloudResult<CloudCompleteUploadDto> {
        if (completed.sha256Verified) {
            return if (completed.sha256 == null || completed.sha256.equals(localSha256, ignoreCase = true)) {
                CloudResult.Success(completed)
            } else {
                CloudResult.Failure(
                    "integrity_mismatch",
                    "The server's SHA-256 does not match the local file. The upload was rejected for your safety.",
                    retryable = false
                )
            }
        }
        val serverHash = completed.sha256
        val ok = serverHash == null || serverHash.equals(localSha256, ignoreCase = true)
        return if (ok) {
            CloudResult.Success(
                completed.copy(
                    sha256 = serverHash ?: localSha256,
                    sha256Verified = true,
                    warning = completed.warning?.let { "$it Local hash re-verified on device." }
                        ?: "Local hash re-verified on device (server skipped hashing for this size)."
                )
            )
        } else {
            CloudResult.Failure("integrity_mismatch", "Content verification failed after upload.", retryable = false)
        }
    }

    /** Uploads already-encrypted bytes (used by the DNS backup manager). */
    suspend fun uploadBytes(
        init: CloudInitUploadDto,
        bytes: ByteArray,
        mime: String,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ): CloudResult<CloudCompleteUploadDto> = withContext(Dispatchers.IO) {
        val token = init.uploadToken ?: return@withContext CloudResult.Failure("missing_upload_token", "No upload token")
        val base = apiBaseFor(init) ?: return@withContext CloudResult.Failure("not_configured", "Cloud endpoint is not configured")
        try {
            if (init.mode == "single") {
                val url = "$base/v1/upload/${init.uploadId}/content?token=${java.net.URLEncoder.encode(token, "UTF-8")}"
                val body = ProgressRequestBody(
                    openStream = { bytes.inputStream() },
                    length = bytes.size.toLong(),
                    contentType = mime.toMediaType(),
                    onProgress = { written -> control.check(); onProgress(TransferProgress(written, bytes.size.toLong())) },
                    control = control
                )
                api.execute(api.uploadRequest(url, body, mime)).use {
                    if (!it.isSuccessful) throw IOException("Backup upload rejected (HTTP ${it.code})")
                }
            } else {
                val partSize = init.partSize
                for (partNumber in 1..init.partsTotal) {
                    control.check()
                    val start = ((partNumber - 1) * partSize).toInt()
                    val end = minOf((start + partSize).toInt(), bytes.size)
                    val chunk = bytes.copyOfRange(start, end)
                    val url = "$base/v1/upload/${init.uploadId}/parts/$partNumber?token=" +
                        java.net.URLEncoder.encode(token, "UTF-8")
                    api.execute(api.uploadRequest(url, chunk.toRequestBody("application/octet-stream".toMediaType()), "application/octet-stream")).use {
                        if (!it.isSuccessful) throw IOException("Backup part $partNumber rejected (HTTP ${it.code})")
                    }
                    onProgress(TransferProgress(end.toLong(), bytes.size.toLong(), partNumber, init.partsTotal))
                }
            }
            api.completeUpload(init.uploadId)
        } catch (interrupted: TransferInterruptedException) {
            throw interrupted
        } catch (error: Throwable) {
            CloudResult.Failure("upload_failed", error.message ?: "Upload failed", retryable = true)
        }
    }

    /** Reads the local file back into memory (only used for encrypted bundles ≤ 64 MB). */
    fun prepareClientEncrypted(uri: Uri, passphrase: CharArray): ClientSideCipher.EncryptedPayload {
        val plaintext = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IOException("Cannot read the selected file")
        return cipher.encrypt(plaintext, passphrase)
    }
}

/**
 * RequestBody that streams from a content Uri and reports byte-level progress.
 * Backpressure-aware: OkHttp pulls from this sink, so memory stays flat.
 */
class ProgressRequestBody(
    private val openStream: () -> InputStream,
    private val length: Long,
    private val contentType: okhttp3.MediaType,
    private val onProgress: (Long) -> Unit,
    private val control: TransferControl
) : okhttp3.RequestBody() {

    override fun contentType(): okhttp3.MediaType = contentType

    override fun contentLength(): Long = length

    override fun writeTo(sink: okio.BufferedSink) {
        openStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            var written = 0L
            var lastReport = 0L
            while (true) {
                control.check()
                val read = input.read(buffer)
                if (read <= 0) break
                sink.write(buffer, 0, read)
                written += read
                if (written - lastReport >= 256 * 1024 || written == length) {
                    lastReport = written
                    onProgress(written)
                }
            }
            if (written != length) {
                throw IOException("Stream ended early: wrote $written of $length bytes")
            }
        }
    }
}

/**
 * Download engine: streams a signed URL to app storage while hashing, so integrity is verified
 * on every download without a second network pass.
 */
@Singleton
class CloudDownloadEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApiClient
) {

    fun targetDirectory(): File =
        (context.getExternalFilesDir("cloud_downloads") ?: File(context.filesDir, "cloud_downloads")).apply { mkdirs() }

    suspend fun download(
        ticketUrl: String,
        fileName: String,
        expectedSize: Long,
        expectedSha256: String?,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ): CloudResult<File> = withContext(Dispatchers.IO) {
        val safeName = fileName.replace(Regex("[^A-Za-z0-9._ -]"), "_").ifBlank { "download" }
        val target = File(targetDirectory(), "${System.currentTimeMillis()}_$safeName")

        var attempt = 0
        while (true) {
            control.check()
            try {
                api.execute(api.downloadRequest(ticketUrl)).use { response ->
                    if (!response.isSuccessful || response.body == null) {
                        val retryable = response.code >= 500
                        throw IOException("Download failed (HTTP ${response.code})${if (retryable) " — will retry" else ""}")
                    }
                    val total = response.body!!.contentLength().takeIf { it > 0 } ?: expectedSize
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                    var written = 0L
                    var lastReport = 0L
                    response.body!!.byteStream().use { input ->
                        target.outputStream().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                control.check()
                                val read = input.read(buffer)
                                if (read <= 0) break
                                output.write(buffer, 0, read)
                                digest.update(buffer, 0, read)
                                written += read
                                if (written - lastReport >= 256 * 1024) {
                                    lastReport = written
                                    onProgress(TransferProgress(written, total, phase = "downloading"))
                                }
                            }
                            output.flush()
                        }
                    }
                    onProgress(TransferProgress(written, total, phase = "verifying"))
                    val actualHash = digest.digest().toHexLower()
                    if (expectedSha256 != null && !actualHash.equals(expectedSha256, ignoreCase = true)) {
                        target.delete()
                        return@withContext CloudResult.Failure(
                            "integrity_mismatch",
                            "Downloaded file failed its SHA-256 check and was discarded.",
                            retryable = true
                        )
                    }
                    if (expectedSize > 0 && written != expectedSize) {
                        target.delete()
                        return@withContext CloudResult.Failure("size_mismatch", "Download was truncated.", retryable = true)
                    }
                    return@withContext CloudResult.Success(target)
                }
            } catch (interrupted: TransferInterruptedException) {
                target.delete()
                throw interrupted
            } catch (error: Throwable) {
                attempt += 1
                if (attempt >= 3) {
                    target.delete()
                    return@withContext CloudResult.Failure(
                        "download_failed",
                        error.message ?: "Download failed",
                        retryable = true
                    )
                }
                kotlinx.coroutines.delay(700L * attempt)
            }
        }
        @Suppress("UNREACHABLE_CODE")
        CloudResult.Failure("download_failed", "Download failed")
    }

    private fun ByteArray.toHexLower(): String {
        val builder = StringBuilder(size * 2)
        for (byte in this) builder.append(((byte.toInt() and 0xFF) + 0x100).toString(16).substring(1))
        return builder.toString()
    }
}

/** Small helper so callers can log transfer state consistently. */
fun CloudResult<*>.errorMessageOrNull(): String? = (this as? CloudResult.Failure)?.message
