package com.adshield.pro.data.cloud

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.math.min

enum class UploadState {
    QUEUED,
    UPLOADING,
    RETRYING,
    PAUSED,
    VERIFYING,
    COMPLETED,
    FAILED,
    CANCELLED
}

@Serializable
data class UploadJob(
    val id: String = "",
    val name: String = "",
    val sizeBytes: Long = 0L,
    val contentType: String = "application/octet-stream",
    val parentId: String? = null,
    val sessionId: String? = null,
    val objectKey: String? = null,
    val partSize: Long = 0L,
    val totalParts: Int = 0,
    val multipart: Boolean = false,
    val uploadedParts: List<Int> = emptyList(),
    val uploadedBytes: Long = 0L,
    val state: UploadState = UploadState.QUEUED,
    val attempts: Int = 0,
    val lastError: String? = null,
    val nodeId: String? = null,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L
) {
    val progress: Float
        get() = if (sizeBytes <= 0L) 0f else (uploadedBytes.toFloat() / sizeBytes.toFloat()).coerceIn(0f, 1f)

    val isTerminal: Boolean
        get() = state == UploadState.COMPLETED || state == UploadState.CANCELLED || state == UploadState.FAILED
}

/** Live progress for the UI: committed bytes plus the bytes of the part currently in flight. */
data class UploadProgress(
    val jobId: String = "",
    val uploadedBytes: Long = 0L,
    val totalBytes: Long = 0L,
    val partsDone: Int = 0,
    val partsTotal: Int = 0,
    val state: UploadState = UploadState.QUEUED,
    val lastError: String? = null
) {
    val fraction: Float
        get() = if (totalBytes <= 0L) 0f else (uploadedBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
}

data class UploadRequest(
    val id: String = UUID.randomUUID().toString(),
    val source: UploadSource,
    val name: String,
    val contentType: String = "application/octet-stream",
    val parentId: String? = null
)

/**
 * A byte source the engine can reopen at any offset. Reopening is what makes pause and resume
 * possible without keeping a multi-hundred-megabyte buffer alive.
 */
interface UploadSource {
    val sizeBytes: Long
    fun open(offsetBytes: Long): InputStream
}

class ByteArrayUploadSource(private val bytes: ByteArray) : UploadSource {
    override val sizeBytes: Long get() = bytes.size.toLong()
    override fun open(offsetBytes: Long): InputStream =
        java.io.ByteArrayInputStream(bytes, offsetBytes.toInt(), (bytes.size - offsetBytes.toInt()))
}

class FileUploadSource(private val file: File) : UploadSource {
    override val sizeBytes: Long get() = file.length()
    override fun open(offsetBytes: Long): InputStream {
        val stream = FileInputStream(file)
        if (offsetBytes > 0) skipExactly(stream, offsetBytes)
        return stream
    }
}

class UriUploadSource(
    private val resolver: android.content.ContentResolver,
    private val uri: Uri,
    override val sizeBytes: Long
) : UploadSource {
    override fun open(offsetBytes: Long): InputStream {
        val stream = resolver.openInputStream(uri)
            ?: throw IOException("cannot open $uri")
        if (offsetBytes > 0) skipExactly(stream, offsetBytes)
        return stream
    }

    companion object {
        fun of(resolver: android.content.ContentResolver, uri: Uri): UriUploadSource? {
            val size = querySize(resolver, uri) ?: return null
            return UriUploadSource(resolver, uri, size)
        }

        private fun querySize(resolver: android.content.ContentResolver, uri: Uri): Long? {
            resolver.query(uri, arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val index = cursor.getColumnIndex(android.provider.OpenableColumns.SIZE)
                        if (index >= 0 && !cursor.isNull(index)) return cursor.getLong(index)
                    }
                }
            return null
        }
    }
}

private fun skipExactly(stream: InputStream, bytes: Long) {
    var remaining = bytes
    val buffer = ByteArray(256 * 1024)
    while (remaining > 0) {
        val read = stream.read(buffer, 0, min(remaining, buffer.size.toLong()).toInt())
        if (read < 0) throw IOException("source ended $remaining bytes before the requested offset")
        remaining -= read
    }
}

/** Thrown from inside a request body when the user pauses or cancels mid-part. */
class UploadInterruptedException(val reason: InterruptReason) : IOException(reason.name)

enum class InterruptReason { PAUSED, CANCELLED }

/**
 * Durable record of upload jobs, so a job survives process death and can be resumed.
 */
interface UploadJobStore {
    suspend fun all(): List<UploadJob>
    suspend fun put(job: UploadJob)
    suspend fun remove(id: String)
}

/**
 * Durable job store: a small JSON file inside the app's private storage. Only job metadata is
 * written (never the file bytes), and terminal jobs are removed so the file cannot grow.
 */
class JsonFileUploadJobStore(context: Context) : UploadJobStore {
    private val file = File(context.filesDir, FILE_NAME)
    private val mutex = Mutex()
    private val json = defaultCloudJson()

    override suspend fun all(): List<UploadJob> = mutex.withLock { read() }

    override suspend fun put(job: UploadJob) = mutex.withLock {
        val map = LinkedHashMap(read().associateBy { it.id })
        map[job.id] = job
        write(map.values.toList())
    }

    override suspend fun remove(id: String) = mutex.withLock {
        write(read().filterNot { it.id == id })
    }

    private fun read(): List<UploadJob> = runCatching {
        if (!file.exists()) return emptyList()
        json.decodeFromString<List<UploadJob>>(file.readText())
    }.getOrDefault(emptyList())

    private fun write(jobs: List<UploadJob>) {
        runCatching { file.writeText(json.encodeToString(jobs)) }
    }

    private companion object {
        const val FILE_NAME = "cloud_upload_jobs.json"
    }
}

class InMemoryUploadJobStore : UploadJobStore {
    private val jobs = LinkedHashMap<String, UploadJob>()
    override suspend fun all(): List<UploadJob> = jobs.values.toList()
    override suspend fun put(job: UploadJob) { jobs[job.id] = job }
    override suspend fun remove(id: String) { jobs.remove(id) }
}

/**
 * Multipart upload engine.
 *
 * Contract with the server (see `cloud/src/index.js`):
 *  1. `initUpload` declares the real byte size, so the quota is refused up front rather than
 *     after the bytes have crossed the network.
 *  2. Each part is streamed straight to the storage provider with its real SHA-1; bytes never
 *     transit the API worker.
 *  3. Every completed part is recorded, so a resumed session only re-sends what is missing.
 *  4. `completeUpload` fails loudly if a part is missing — no truncated file is ever stored.
 */
class CloudUploadEngine(
    private val api: CloudApi,
    private val http: OkHttpClient,
    private val store: UploadJobStore,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val requestedPartSizeBytes: Long = DEFAULT_PART_SIZE_BYTES
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val jobs = ConcurrentHashMap<String, UploadJob>()
    private val sources = ConcurrentHashMap<String, UploadSource>()
    private val tickets = ConcurrentHashMap<String, List<UploadPartTicketDto>>()
    private val inFlightBytes = ConcurrentHashMap<String, Long>()
    private val pauseFlags = ConcurrentHashMap<String, Boolean>()
    private val cancelFlags = ConcurrentHashMap<String, Boolean>()
    private val mutableJobs = MutableStateFlow<List<UploadJob>>(emptyList())
    private val mutableProgress = MutableStateFlow<Map<String, UploadProgress>>(emptyMap())

    private val uploadClient: OkHttpClient = http.newBuilder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(180, TimeUnit.SECONDS)
        .readTimeout(180, TimeUnit.SECONDS)
        .build()

    val jobsFlow: StateFlow<List<UploadJob>> = mutableJobs.asStateFlow()
    val progressFlow: StateFlow<Map<String, UploadProgress>> = mutableProgress.asStateFlow()

    // ---------------------------------------------------------------- lifecycle

    /** Reloads persisted jobs (called once at startup). */
    suspend fun restore() {
        val persisted = store.all()
        jobs.clear()
        persisted.forEach { jobs[it.id] = it }
        publish()
    }

    fun snapshot(jobId: String): UploadJob? = jobs[jobId]

    fun jobs(): List<UploadJob> = jobs.values.sortedByDescending { it.updatedAt }

    /** Starts or resumes a job in the background. Returns immediately. */
    fun launch(request: UploadRequest): String {
        sources[request.id] = request.source
        val existing = jobs[request.id]
        val job = (existing ?: newJob(request)).copy(
            state = UploadState.QUEUED,
            lastError = null,
            updatedAt = clock()
        )
        jobs[request.id] = job
        pauseFlags[request.id] = false
        cancelFlags[request.id] = false
        publish()
        scope.launch { runJob(request.id) }
        return request.id
    }

    /** Runs a job on the calling coroutine — used by the background worker. */
    suspend fun run(request: UploadRequest): UploadJob {
        sources[request.id] = request.source
        val existing = jobs[request.id]
        val job = (existing ?: newJob(request)).copy(state = UploadState.QUEUED, lastError = null)
        jobs[request.id] = job
        pauseFlags[request.id] = false
        cancelFlags[request.id] = false
        publish()
        return runJob(request.id)
    }

    fun pause(jobId: String) {
        pauseFlags[jobId] = true
        val job = jobs[jobId] ?: return
        jobs[jobId] = job.copy(state = UploadState.PAUSED, updatedAt = clock())
        publish()
    }

    /** Resumes a persisted job. The caller must re-register its source with [attachSource]. */
    fun resume(jobId: String) {
        val job = jobs[jobId] ?: return
        if (sources[jobId] == null) return
        pauseFlags[jobId] = false
        cancelFlags[jobId] = false
        jobs[jobId] = job.copy(state = UploadState.QUEUED, lastError = null, updatedAt = clock())
        publish()
        scope.launch { runJob(jobId) }
    }

    /** Re-attaches a byte source to a persisted job so it can be resumed after a restart. */
    fun attachSource(jobId: String, source: UploadSource) {
        sources[jobId] = source
    }

    fun cancel(jobId: String) {
        cancelFlags[jobId] = true
        val job = jobs[jobId] ?: return
        jobs[jobId] = job.copy(state = UploadState.CANCELLED, updatedAt = clock())
        publish()
        scope.launch {
            val sessionId = job.sessionId
            if (!sessionId.isNullOrBlank()) {
                runCatching { api.cancelUpload(sessionId) }
            }
            withContext(Dispatchers.IO) { store.remove(jobId) }
        }
    }

    suspend fun forget(jobId: String) {
        jobs.remove(jobId)
        sources.remove(jobId)
        tickets.remove(jobId)
        inFlightBytes.remove(jobId)
        pauseFlags.remove(jobId)
        cancelFlags.remove(jobId)
        store.remove(jobId)
        publish()
    }

    // ---------------------------------------------------------------- execution

    private fun newJob(request: UploadRequest): UploadJob = UploadJob(
        id = request.id,
        name = request.name,
        sizeBytes = request.source.sizeBytes,
        contentType = request.contentType,
        parentId = request.parentId,
        createdAt = clock(),
        updatedAt = clock()
    )

    private suspend fun runJob(jobId: String): UploadJob {
        val source = sources[jobId]
        if (source == null) {
            val missing = jobs[jobId]?.copy(state = UploadState.FAILED, lastError = "source lost", updatedAt = clock())
            if (missing != null) { jobs[jobId] = missing; publish() }
            return missing ?: UploadJob(id = jobId, state = UploadState.FAILED, lastError = "unknown job")
        }
        var job = jobs[jobId] ?: UploadJob(id = jobId)
        var cancelledByUser = false
        return try {
            if (job.sessionId.isNullOrBlank()) {
                val init = api.initUpload(
                    name = job.name,
                    size = source.sizeBytes,
                    parentId = job.parentId,
                    contentType = job.contentType
                )
                tickets[jobId] = init.parts
                job = job.copy(
                    sessionId = init.sessionId,
                    objectKey = init.key,
                    partSize = init.partSize,
                    totalParts = init.totalParts,
                    multipart = init.multipart,
                    nodeId = init.nodeId,
                    updatedAt = clock()
                )
                persist(job)
            }
            job = job.copy(state = UploadState.UPLOADING, lastError = null, updatedAt = clock())
            persist(job)

            while (missingParts(job).isNotEmpty()) {
                if (cancelFlags[jobId] == true) throw UploadInterruptedException(InterruptReason.CANCELLED)
                if (pauseFlags[jobId] == true) throw UploadInterruptedException(InterruptReason.PAUSED)
                val partNumber = missingParts(job).first()
                uploadPart(job, source, partNumber)
                job = jobs[jobId] ?: job
            }

            job = job.copy(state = UploadState.VERIFYING, updatedAt = clock())
            persist(job)
            val completed = api.completeUpload(job.sessionId ?: error("session missing"))
            job = job.copy(state = UploadState.COMPLETED, nodeId = completed.node.id, updatedAt = clock())
            persist(job)
            sources.remove(jobId)
            tickets.remove(jobId)
            job
        } catch (e: UploadInterruptedException) {
            cancelledByUser = e.reason == InterruptReason.CANCELLED
            val state = if (e.reason == InterruptReason.CANCELLED) UploadState.CANCELLED else UploadState.PAUSED
            job = job.copy(state = state, lastError = null, updatedAt = clock())
            persist(job)
            if (cancelledByUser) {
                job.sessionId?.let { runCatching { api.cancelUpload(it) } }
                store.remove(jobId)
            } else {
                // Refresh the durable record so a later resume starts from the recorded parts.
                job.sessionId?.let { runCatching { api.uploadStatus(it) } }
            }
            job
        } catch (e: Throwable) {
            job = job.copy(
                state = UploadState.FAILED,
                lastError = e.message ?: e.javaClass.simpleName,
                attempts = job.attempts + 1,
                updatedAt = clock()
            )
            persist(job)
            job
        } finally {
            inFlightBytes.remove(jobId)
            publish()
        }
    }

    private fun missingParts(job: UploadJob): List<Int> {
        if (job.totalParts <= 0) return listOf(1)
        val done = job.uploadedParts.toSet()
        return (1..job.totalParts).filterNot { done.contains(it) }
    }

    private suspend fun uploadPart(job: UploadJob, source: UploadSource, partNumber: Int) {
        val offset = (partNumber - 1L) * job.partSize
        val length = min(job.partSize, job.sizeBytes - offset)
        // The storage provider rejects a part whose SHA-1 does not match the declared digest, so
        // the exact bytes are hashed first and then streamed with that digest in the header.
        val sha1 = withContext(Dispatchers.IO) { hashRange(source, offset, length) }
        var attempt = 0
        while (true) {
            attempt += 1
            if (cancelFlags[job.id] == true) throw UploadInterruptedException(InterruptReason.CANCELLED)
            if (pauseFlags[job.id] == true) throw UploadInterruptedException(InterruptReason.PAUSED)
            val ticket = ticketFor(job, partNumber)
            var sent = 0L
            val body = object : RequestBody() {
                override fun contentType() = job.contentType.toMediaTypeOrNull()
                override fun contentLength() = length
                override fun isOneShot() = true
                override fun writeTo(sink: BufferedSink) {
                    source.open(offset).use { stream ->
                        val buffer = ByteArray(256 * 1024)
                        var remaining = length
                        while (remaining > 0) {
                            if (cancelFlags[job.id] == true) throw UploadInterruptedException(InterruptReason.CANCELLED)
                            if (pauseFlags[job.id] == true) throw UploadInterruptedException(InterruptReason.PAUSED)
                            val read = stream.read(buffer, 0, min(remaining, buffer.size.toLong()).toInt())
                            if (read < 0) break
                            sink.write(buffer, 0, read)
                            remaining -= read
                            sent += read
                            inFlightBytes[job.id] = sent
                            publishProgressThrottled(job.id)
                        }
                    }
                    sink.flush()
                }
            }
            val request = Request.Builder()
                .url(ticket.uploadUrl)
                .post(body)
                .addHeader("Authorization", ticket.token)
                .addHeader("X-Bz-Content-Sha1", sha1)
                .apply {
                    if (job.multipart) addHeader("X-Bz-Part-Number", partNumber.toString())
                    else addHeader("X-Bz-File-Name", job.objectKey ?: job.name)
                }
                .build()
            val ok = runCatching {
                withContext(Dispatchers.IO) {
                    uploadClient.newCall(request).execute().use { response ->
                        if (!response.isSuccessful) {
                            val code = response.code
                            response.body?.close()
                            throw IOException("part upload failed: http $code")
                        }
                        true
                    }
                }
            }.getOrElse { error ->
                if (error is UploadInterruptedException) throw error
                if (attempt >= MAX_PART_ATTEMPTS) throw error
                tickets.remove(job.id)
                val current = jobs[job.id] ?: job
                jobs[job.id] = current.copy(state = UploadState.RETRYING, lastError = error.message, attempts = attempt)
                publish()
                delay(RETRY_BACKOFF_MS * attempt)
                false
            }
            if (!ok) continue
            val recorded = api.recordPart(job.sessionId ?: error("session missing"), partNumber, length, sha1)
            val current = jobs[job.id] ?: job
            val updated = current.copy(
                uploadedParts = (current.uploadedParts + partNumber).distinct(),
                uploadedBytes = recorded.uploadedBytes,
                attempts = attempt,
                state = UploadState.UPLOADING,
                lastError = null,
                updatedAt = clock()
            )
            jobs[job.id] = updated
            inFlightBytes.remove(job.id)
            persist(updated)
            return
        }
    }

    private fun hashRange(source: UploadSource, offset: Long, length: Long): String {
        val digest = MessageDigest.getInstance("SHA-1")
        source.open(offset).use { stream ->
            val buffer = ByteArray(256 * 1024)
            var remaining = length
            while (remaining > 0) {
                val read = stream.read(buffer, 0, min(remaining, buffer.size.toLong()).toInt())
                if (read < 0) break
                digest.update(buffer, 0, read)
                remaining -= read
            }
        }
        return hex(digest.digest())
    }

    private var lastProgressPublishAt = 0L

    private fun publishProgressThrottled(jobId: String) {
        val now = System.currentTimeMillis()
        if (now - lastProgressPublishAt < 150) return
        lastProgressPublishAt = now
        publish()
    }

    private suspend fun ticketFor(job: UploadJob, partNumber: Int): UploadPartTicketDto {
        val cached = tickets[job.id]?.firstOrNull { it.partNumber == partNumber }
        if (cached != null) return cached
        val status = api.uploadStatus(job.sessionId ?: error("session missing"))
        tickets[job.id] = status.partUrls
        return status.partUrls.firstOrNull { it.partNumber == partNumber }
            ?: error("storage did not issue a URL for part $partNumber")
    }

    private suspend fun persist(job: UploadJob) {
        jobs[job.id] = job
        store.put(job)
        publish()
    }

    private fun publish() {
        mutableJobs.value = jobs.values.sortedByDescending { it.updatedAt }
        val map = HashMap<String, UploadProgress>()
        jobs.values.forEach { job ->
            map[job.id] = UploadProgress(
                jobId = job.id,
                uploadedBytes = job.uploadedBytes + (inFlightBytes[job.id] ?: 0L),
                totalBytes = job.sizeBytes,
                partsDone = job.uploadedParts.size,
                partsTotal = job.totalParts,
                state = job.state,
                lastError = job.lastError
            )
        }
        mutableProgress.value = map
    }

    companion object {
        const val DEFAULT_PART_SIZE_BYTES = 8L * 1024 * 1024
        private const val MAX_PART_ATTEMPTS = 3
        private const val RETRY_BACKOFF_MS = 800L
    }
}

private fun hex(bytes: ByteArray): String {
    val builder = StringBuilder(bytes.size * 2)
    for (b in bytes) builder.append(String.format(Locale.US, "%02x", b))
    return builder.toString()
}
