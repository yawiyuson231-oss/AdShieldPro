package com.adshield.pro.engine.downloader

import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * AdShield Pro — Universal Video & Music Downloader Engine.
 *
 * Strictly enforces copyright, DRM, and website restrictions:
 * - Refuses DRM-protected or Terms-restricted streaming platforms (YouTube, Netflix, Spotify, etc.),
 *   DASH Widevine/PlayReady CENC manifests, SmoothStreaming DRM, and `#EXT-X-KEY` encrypted HLS streams.
 * - Probes legitimate direct media links, unencrypted HLS `.m3u8` playlists, and open HTML5 `<video>` /
 *   `<audio>` / `<source>` / OpenGraph media pages to discover real formats (MP4, WebM, M4A, MP3, OGG,
 *   OPUS, WAV, FLAC, AAC) and resolutions (2160p, 1080p, 720p, 480p, 360p, Audio).
 * - Supports real download progress, HTTP `Range` (`206 Partial Content`) pause & resume, cancel,
 *   SHA-256 verification, lossless MP4 -> M4A audio demuxing on Android, configurable destination,
 *   and persistent JSON download history.
 */
class MediaDownloaderEngine(
    private val defaultDownloadDir: File,
    private val stateStoreFile: File = File(defaultDownloadDir.parentFile ?: defaultDownloadDir, "media_download_history.json"),
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .followRedirects(true)
        .build(),
    private val isHostMalicious: (String) -> Boolean = { false },
    private val allowLoopbackHttpForTesting: Boolean = false
) {

    @Serializable
    enum class MediaKind { VIDEO, AUDIO }

    @Serializable
    enum class DownloadDestinationKind(val label: String) {
        APP_MEDIA_FOLDER("App Media Folder"),
        SYSTEM_MEDIASTORE("Device Downloads / Media Library"),
        CUSTOM_DIRECTORY("Custom Selected Folder")
    }

    @Serializable
    enum class DownloadStatus {
        QUEUED,
        DOWNLOADING,
        PAUSED,
        COMPLETED,
        FAILED,
        CANCELLED
    }

    @Serializable
    data class MediaFormatOption(
        val id: String,
        val label: String,
        val containerFormat: String, // e.g. "MP4", "WEBM", "M4A", "MP3", "OGG", "WAV", "FLAC", "HLS-TS"
        val mimeType: String,
        val mediaKind: MediaKind,
        val qualityLabel: String,    // e.g. "1080p", "720p", "480p", "Audio (Original)", "Audio (M4A Demux)"
        val width: Int? = null,
        val height: Int? = null,
        val bandwidthBps: Long? = null,
        val contentLengthBytes: Long? = null,
        val supportsRangeResume: Boolean = false,
        val resolvedStreamUrl: String,
        val isHlsPlaylist: Boolean = false,
        val extractAudioOnlyFromMp4: Boolean = false
    )

    data class MediaProbeResult(
        val sourceUrl: String,
        val title: String,
        val sourceHost: String,
        val formats: List<MediaFormatOption>,
        val restrictionNotice: String? = null
    )

    @Serializable
    data class MediaDownloadTask(
        val id: String,
        val sourceUrl: String,
        val streamUrl: String,
        val title: String,
        val fileName: String,
        val containerFormat: String,
        val mimeType: String,
        val mediaKind: MediaKind,
        val qualityLabel: String,
        val destinationKind: DownloadDestinationKind,
        val targetDirectoryPath: String,
        val outputFilePath: String,
        val downloadedBytes: Long = 0L,
        val totalBytes: Long = -1L,
        val speedBytesPerSec: Long = 0L,
        val supportsResume: Boolean = false,
        val etagOrValidator: String? = null,
        val isHlsPlaylist: Boolean = false,
        val extractAudioOnlyFromMp4: Boolean = false,
        val completedHlsSegments: Int = 0,
        val totalHlsSegments: Int = 0,
        val status: DownloadStatus = DownloadStatus.QUEUED,
        val sha256: String? = null,
        val errorMessage: String? = null,
        val createdAtEpochMs: Long = System.currentTimeMillis(),
        val updatedAtEpochMs: Long = System.currentTimeMillis()
    ) {
        val progressFraction: Float
            get() = when {
                status == DownloadStatus.COMPLETED -> 1f
                totalBytes > 0L -> (downloadedBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
                totalHlsSegments > 0 -> (completedHlsSegments.toFloat() / totalHlsSegments.toFloat()).coerceIn(0f, 1f)
                else -> 0f
            }
    }

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val activeJobs = ConcurrentHashMap<String, Job>()
    private val activeCalls = ConcurrentHashMap<String, Call>()
    private val pauseFlags = ConcurrentHashMap<String, Boolean>()
    private val cancelFlags = ConcurrentHashMap<String, Boolean>()
    private val persistLock = Any()

    private val _tasks = MutableStateFlow(loadPersistedTasks())
    val tasks: StateFlow<List<MediaDownloadTask>> = _tasks.asStateFlow()

    init {
        defaultDownloadDir.mkdirs()
    }

    /**
     * Probes a user-pasted URL to verify copyright/DRM/policy compliance and discover available
     * video and audio formats and resolutions.
     */
    suspend fun probeUrl(rawUrl: String): Result<MediaProbeResult> = withContext(Dispatchers.IO) {
        runCatching {
            val trimmed = rawUrl.trim()
            require(trimmed.isNotEmpty()) { "Enter a video or audio URL to inspect." }
            val uri = runCatching { URI(trimmed) }.getOrNull()
                ?: throw IllegalArgumentException("Malformed URL structure.")
            val scheme = uri.scheme?.lowercase() ?: ""
            val host = uri.host?.lowercase()?.trimEnd('.')
                ?: throw IllegalArgumentException("URL does not include a valid hostname.")

            if (scheme != "https" && !(allowLoopbackHttpForTesting && scheme == "http" && isLoopback(host))) {
                throw SecurityException("Only secure HTTPS media URLs are permitted.")
            }
            if (!uri.userInfo.isNullOrBlank()) {
                throw SecurityException("URLs containing embedded credentials are rejected.")
            }
            if (isHostMalicious(host)) {
                throw SecurityException("Blocked: '$host' is listed on the active malware/phishing threat blocklist.")
            }
            checkRestrictedPlatformOrExtension(uri, host)?.let { reason ->
                throw IllegalStateException(reason)
            }

            // Probe headers + initial bytes using GET with Range: bytes=0-65535 (more universally supported than HEAD)
            val probeReq = Request.Builder()
                .url(trimmed)
                .header("User-Agent", USER_AGENT)
                .header("Range", "bytes=0-65535")
                .get()
                .build()

            httpClient.newCall(probeReq).execute().use { resp ->
                if (!resp.isSuccessful && resp.code != 206) {
                    throw IllegalStateException("Server refused media probe (HTTP ${resp.code}).")
                }

                // Re-verify final redirected host against restrictions and threat list
                val finalUri = resp.request.url.toUri()
                val finalHost = finalUri.host?.lowercase()?.trimEnd('.') ?: host
                if (isHostMalicious(finalHost)) {
                    throw SecurityException("Redirected host '$finalHost' is on the active threat blocklist.")
                }
                checkRestrictedPlatformOrExtension(finalUri, finalHost)?.let { reason ->
                    throw IllegalStateException(reason)
                }

                // Respect explicit website / robot / DRM restriction headers
                val xRobots = resp.header("X-Robots-Tag")?.lowercase().orEmpty()
                if (xRobots.contains("noai") && xRobots.contains("noarchive") && resp.header("X-Download-Options") == "noopen") {
                    throw IllegalStateException("Website restricts automated media downloading via HTTP policy headers.")
                }

                val contentType = resp.header("Content-Type")?.substringBefore(';')?.trim()?.lowercase().orEmpty()
                val acceptRanges = resp.header("Accept-Ranges")?.contains("bytes", ignoreCase = true) == true ||
                    resp.code == 206
                val totalLength = parseTotalLengthFromHeaders(resp.code, resp.header("Content-Range"), resp.header("Content-Length"))
                val dispositionName = parseContentDispositionFileName(resp.header("Content-Disposition"))
                val sampleBytes = resp.body?.byteStream()?.use { s ->
                    readUpTo(s, 65_536)
                } ?: ByteArray(0)

                val finalUrlStr = finalUri.toString()
                val pathLower = (finalUri.path ?: "").lowercase()

                // 1. DASH MPD / DRM manifest rejection
                if (pathLower.endsWith(".mpd") || contentType.contains("dash+xml")) {
                    val xml = String(sampleBytes, StandardCharsets.UTF_8)
                    if (xml.contains("ContentProtection", ignoreCase = true) || xml.contains("cenc:", ignoreCase = true)) {
                        throw IllegalStateException("DRM-protected DASH stream detected (ContentProtection). Protected streams cannot be downloaded.")
                    }
                    throw IllegalStateException("Segmented DASH (.mpd) manifests are not directly downloadable; provide a direct MP4/WebM/audio link or unencrypted HLS playlist.")
                }

                // 2. HLS (.m3u8) playlist handling
                if (pathLower.endsWith(".m3u8") ||
                    contentType == "application/vnd.apple.mpegurl" ||
                    contentType == "application/x-mpegurl" ||
                    String(sampleBytes.take(16).toByteArray(), StandardCharsets.UTF_8).startsWith("#EXTM3U")
                ) {
                    val fullPlaylist = fetchFullText(finalUrlStr, maxChars = 262_144)
                    return@runCatching parseHlsPlaylist(finalUri, finalHost, fullPlaylist)
                }

                // 3. HTML webpage containing legitimate open <video> / <audio> / <source> elements
                if (contentType.startsWith("text/html") || contentType.contains("xhtml")) {
                    val fullHtml = if (sampleBytes.size < 65_536) {
                        String(sampleBytes, StandardCharsets.UTF_8)
                    } else {
                        fetchFullText(finalUrlStr, maxChars = 350_000)
                    }
                    return@runCatching parseHtmlMediaPage(finalUri, finalHost, fullHtml)
                }

                // 4. Direct video or audio stream
                val detectedFormat = classifyDirectMedia(
                    url = finalUrlStr,
                    fileNameHint = dispositionName ?: deriveTitleFromUri(finalUri),
                    contentType = contentType,
                    sampleBytes = sampleBytes,
                    contentLength = totalLength,
                    supportsRange = acceptRanges
                ) ?: throw IllegalArgumentException(
                    "No downloadable video or audio stream found at this URL (Content-Type: ${contentType.ifBlank { "unknown" }})."
                )

                val baseTitle = (dispositionName ?: deriveTitleFromUri(finalUri)).substringBeforeLast('.')
                    .ifBlank { "media_${System.currentTimeMillis()}" }

                val options = buildList {
                    add(detectedFormat)
                    if (detectedFormat.containerFormat == "MP4" && detectedFormat.mediaKind == MediaKind.VIDEO) {
                        add(
                            detectedFormat.copy(
                                id = "${detectedFormat.id}_m4a_audio",
                                label = "M4A Audio Track (Lossless Demux)",
                                containerFormat = "M4A",
                                mimeType = "audio/mp4",
                                mediaKind = MediaKind.AUDIO,
                                qualityLabel = "Audio Only (M4A)",
                                width = null,
                                height = null,
                                extractAudioOnlyFromMp4 = true
                            )
                        )
                    }
                }

                MediaProbeResult(
                    sourceUrl = trimmed,
                    title = baseTitle,
                    sourceHost = finalHost,
                    formats = options
                )
            }
        }
    }

    /**
     * Enqueues and starts a media download for the chosen [format].
     */
    fun startDownload(
        probe: MediaProbeResult,
        format: MediaFormatOption,
        destinationKind: DownloadDestinationKind = DownloadDestinationKind.APP_MEDIA_FOLDER,
        customTargetDir: File? = null
    ): MediaDownloadTask {
        val targetDir = (customTargetDir ?: defaultDownloadDir).apply { mkdirs() }
        val ext = when (format.containerFormat.uppercase()) {
            "HLS-TS" -> "ts"
            else -> format.containerFormat.lowercase()
        }
        val cleanBase = sanitizeFileName(probe.title).take(72).ifBlank { "media" }
        val qualSuffix = format.qualityLabel
            .lowercase()
            .replace(Regex("[^a-z0-9]+"), "_")
            .trim('_')
            .take(18)
        val fileName = "${cleanBase}_${qualSuffix.ifBlank { ext }}.$ext"
        val finalFile = uniqueDestinationFile(targetDir, fileName)

        val task = MediaDownloadTask(
            id = UUID.randomUUID().toString(),
            sourceUrl = probe.sourceUrl,
            streamUrl = format.resolvedStreamUrl,
            title = probe.title,
            fileName = finalFile.name,
            containerFormat = format.containerFormat,
            mimeType = format.mimeType,
            mediaKind = format.mediaKind,
            qualityLabel = format.qualityLabel,
            destinationKind = destinationKind,
            targetDirectoryPath = targetDir.absolutePath,
            outputFilePath = finalFile.absolutePath,
            totalBytes = format.contentLengthBytes ?: -1L,
            supportsResume = format.supportsRangeResume || format.isHlsPlaylist,
            isHlsPlaylist = format.isHlsPlaylist,
            extractAudioOnlyFromMp4 = format.extractAudioOnlyFromMp4,
            status = DownloadStatus.QUEUED
        )

        upsertTask(task)
        launchWorkerForTask(task.id)
        return task
    }

    fun pauseDownload(taskId: String) {
        pauseFlags[taskId] = true
        activeCalls[taskId]?.cancel()
        activeJobs[taskId]?.cancel()
        updateTask(taskId) { current ->
            if (current.status == DownloadStatus.DOWNLOADING || current.status == DownloadStatus.QUEUED) {
                current.copy(
                    status = DownloadStatus.PAUSED,
                    speedBytesPerSec = 0L,
                    updatedAtEpochMs = System.currentTimeMillis()
                )
            } else current
        }
    }

    fun resumeDownload(taskId: String) {
        val existing = _tasks.value.firstOrNull { it.id == taskId } ?: return
        if (existing.status != DownloadStatus.PAUSED && existing.status != DownloadStatus.FAILED) return
        pauseFlags.remove(taskId)
        cancelFlags.remove(taskId)
        updateTask(taskId) {
            it.copy(
                status = DownloadStatus.QUEUED,
                errorMessage = null,
                updatedAtEpochMs = System.currentTimeMillis()
            )
        }
        launchWorkerForTask(taskId)
    }

    fun cancelDownload(taskId: String) {
        cancelFlags[taskId] = true
        pauseFlags.remove(taskId)
        activeCalls[taskId]?.cancel()
        activeJobs[taskId]?.cancel()
        val task = _tasks.value.firstOrNull { it.id == taskId }
        if (task != null) {
            File("${task.outputFilePath}.part").delete()
            File("${task.outputFilePath}.mp4.tmp").delete()
        }
        updateTask(taskId) {
            it.copy(
                status = DownloadStatus.CANCELLED,
                speedBytesPerSec = 0L,
                updatedAtEpochMs = System.currentTimeMillis()
            )
        }
    }

    fun removeTaskFromHistory(taskId: String, deleteDownloadedFile: Boolean = false) {
        cancelFlags[taskId] = true
        activeCalls[taskId]?.cancel()
        activeJobs[taskId]?.cancel()
        val existing = _tasks.value.firstOrNull { it.id == taskId }
        if (existing != null) {
            File("${existing.outputFilePath}.part").delete()
            if (deleteDownloadedFile) {
                File(existing.outputFilePath).delete()
            }
        }
        _tasks.update { list -> list.filterNot { it.id == taskId } }
        persistTasksSnapshot()
    }

    fun clearCompletedAndCancelledHistory() {
        _tasks.update { list ->
            list.filter { it.status == DownloadStatus.DOWNLOADING || it.status == DownloadStatus.PAUSED || it.status == DownloadStatus.QUEUED }
        }
        persistTasksSnapshot()
    }

    /**
     * Awaits completion or terminal/paused state of [taskId] (useful for deterministic testing
     * and background workers).
     */
    suspend fun awaitTaskSettlement(taskId: String) {
        activeJobs[taskId]?.join()
    }

    private fun launchWorkerForTask(taskId: String) {
        activeJobs[taskId]?.cancel()
        val job = scope.launch {
            executeTask(taskId)
        }
        activeJobs[taskId] = job
    }

    private suspend fun executeTask(taskId: String) {
        val initial = _tasks.value.firstOrNull { it.id == taskId } ?: return
        pauseFlags.remove(taskId)
        cancelFlags.remove(taskId)

        val outFile = File(initial.outputFilePath)
        val partFile = File("${initial.outputFilePath}.part")
        outFile.parentFile?.mkdirs()

        try {
            updateTask(taskId) {
                it.copy(status = DownloadStatus.DOWNLOADING, errorMessage = null, updatedAtEpochMs = System.currentTimeMillis())
            }

            if (initial.isHlsPlaylist) {
                downloadHlsStream(taskId, initial, partFile)
            } else {
                downloadHttpStreamWithResume(taskId, initial, partFile)
            }

            if (pauseFlags[taskId] == true || cancelFlags[taskId] == true) return

            // Optional lossless MP4 -> M4A audio demux on Android
            if (initial.extractAudioOnlyFromMp4) {
                val tempMp4 = File("${initial.outputFilePath}.mp4.tmp")
                if (tempMp4.exists()) tempMp4.delete()
                if (!partFile.renameTo(tempMp4)) {
                    partFile.copyTo(tempMp4, overwrite = true)
                    partFile.delete()
                }
                try {
                    extractAudioTrackToM4a(tempMp4, outFile)
                } finally {
                    tempMp4.delete()
                }
            } else {
                if (outFile.exists()) outFile.delete()
                if (!partFile.renameTo(outFile)) {
                    partFile.copyTo(outFile, overwrite = true)
                    partFile.delete()
                }
            }

            val finalSize = outFile.length()
            val sha = computeSha256(outFile)
            updateTask(taskId) {
                it.copy(
                    downloadedBytes = finalSize,
                    totalBytes = if (it.totalBytes > 0L) finalSize else finalSize,
                    speedBytesPerSec = 0L,
                    status = DownloadStatus.COMPLETED,
                    sha256 = sha,
                    updatedAtEpochMs = System.currentTimeMillis()
                )
            }
        } catch (ce: CancellationException) {
            if (cancelFlags[taskId] == true) {
                partFile.delete()
                updateTask(taskId) {
                    it.copy(status = DownloadStatus.CANCELLED, speedBytesPerSec = 0L, updatedAtEpochMs = System.currentTimeMillis())
                }
            } else {
                updateTask(taskId) {
                    it.copy(status = DownloadStatus.PAUSED, speedBytesPerSec = 0L, updatedAtEpochMs = System.currentTimeMillis())
                }
            }
        } catch (t: Throwable) {
            when {
                cancelFlags[taskId] == true -> {
                    partFile.delete()
                    updateTask(taskId) {
                        it.copy(status = DownloadStatus.CANCELLED, speedBytesPerSec = 0L, updatedAtEpochMs = System.currentTimeMillis())
                    }
                }
                pauseFlags[taskId] == true -> {
                    updateTask(taskId) {
                        it.copy(status = DownloadStatus.PAUSED, speedBytesPerSec = 0L, updatedAtEpochMs = System.currentTimeMillis())
                    }
                }
                else -> {
                    updateTask(taskId) {
                        it.copy(
                            status = DownloadStatus.FAILED,
                            speedBytesPerSec = 0L,
                            errorMessage = t.message ?: "Download interrupted",
                            updatedAtEpochMs = System.currentTimeMillis()
                        )
                    }
                }
            }
        } finally {
            activeCalls.remove(taskId)
        }
    }

    private fun downloadHttpStreamWithResume(
        taskId: String,
        task: MediaDownloadTask,
        partFile: File
    ) {
        val existingOffset = if (partFile.exists()) partFile.length() else 0L
        val reqBuilder = Request.Builder()
            .url(task.streamUrl)
            .header("User-Agent", USER_AGENT)
            .get()

        if (existingOffset > 0L) {
            reqBuilder.header("Range", "bytes=$existingOffset-")
            task.etagOrValidator?.takeIf { it.isNotBlank() }?.let { validator ->
                reqBuilder.header("If-Range", validator)
            }
        }

        val call = httpClient.newCall(reqBuilder.build())
        activeCalls[taskId] = call

        call.execute().use { resp ->
            if (!resp.isSuccessful && resp.code != 206) {
                throw IllegalStateException("HTTP ${resp.code} while downloading media")
            }

            val isPartialAppend = existingOffset > 0L && resp.code == 206
            val startByte = if (isPartialAppend) existingOffset else 0L
            val totalLength = parseTotalLengthFromHeaders(
                resp.code,
                resp.header("Content-Range"),
                resp.header("Content-Length")
            ) ?: if (task.totalBytes > 0L) task.totalBytes else -1L
            val validator = resp.header("ETag") ?: resp.header("Last-Modified") ?: task.etagOrValidator
            val rangeCapable = resp.code == 206 || resp.header("Accept-Ranges")?.contains("bytes", true) == true

            updateTask(taskId) {
                it.copy(
                    downloadedBytes = startByte,
                    totalBytes = totalLength,
                    supportsResume = rangeCapable,
                    etagOrValidator = validator
                )
            }

            val body = resp.body ?: throw IllegalStateException("Empty media response body")
            RandomAccessFile(partFile, "rw").use { raf ->
                if (!isPartialAppend) {
                    raf.setLength(0L)
                }
                raf.seek(startByte)

                val buffer = ByteArray(16 * 1024)
                var writtenTotal = startByte
                var windowStartMs = System.currentTimeMillis()
                var windowBytes = 0L

                body.byteStream().use { input ->
                    while (true) {
                        if (pauseFlags[taskId] == true || cancelFlags[taskId] == true) {
                            throw CancellationException("Stopped by user")
                        }
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count > 0) {
                            if (writtenTotal + count > MAX_DOWNLOAD_BYTES) {
                                throw IllegalStateException("Media exceeds safety size limit (2 GB).")
                            }
                            raf.write(buffer, 0, count)
                            writtenTotal += count
                            windowBytes += count

                            val now = System.currentTimeMillis()
                            val elapsed = now - windowStartMs
                            if (elapsed >= 180L) {
                                val speed = (windowBytes * 1000L) / elapsed.coerceAtLeast(1L)
                                updateTask(taskId, persist = false) {
                                    it.copy(
                                        downloadedBytes = writtenTotal,
                                        speedBytesPerSec = speed,
                                        updatedAtEpochMs = now
                                    )
                                }
                                windowStartMs = now
                                windowBytes = 0L
                            }
                        }
                    }
                }

                updateTask(taskId) {
                    it.copy(
                        downloadedBytes = writtenTotal,
                        updatedAtEpochMs = System.currentTimeMillis()
                    )
                }
            }
        }
    }

    private fun downloadHlsStream(
        taskId: String,
        task: MediaDownloadTask,
        partFile: File
    ) {
        val playlistText = fetchFullText(task.streamUrl, maxChars = 512_000)
        if (playlistText.contains("#EXT-X-KEY", ignoreCase = true) &&
            !playlistText.contains("METHOD=NONE", ignoreCase = true)
        ) {
            throw SecurityException("Encrypted/DRM HLS stream (#EXT-X-KEY) cannot be downloaded.")
        }

        val baseUri = URI(task.streamUrl)
        val segmentUrls = playlistText.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { baseUri.resolve(it).toString() }
            .toList()

        if (segmentUrls.isEmpty()) {
            throw IllegalStateException("HLS media playlist contained zero downloadable segments.")
        }

        val startSegment = task.completedHlsSegments.coerceIn(0, segmentUrls.size)
        var cumulativeBytes = if (startSegment > 0 && partFile.exists()) partFile.length() else 0L

        FileOutputStream(partFile, startSegment > 0 && partFile.exists()).use { out ->
            for (idx in startSegment until segmentUrls.size) {
                if (pauseFlags[taskId] == true || cancelFlags[taskId] == true) {
                    throw CancellationException("Paused/cancelled")
                }
                val segReq = Request.Builder().url(segmentUrls[idx]).header("User-Agent", USER_AGENT).get().build()
                val call = httpClient.newCall(segReq)
                activeCalls[taskId] = call
                call.execute().use { segResp ->
                    if (!segResp.isSuccessful) {
                        throw IllegalStateException("HLS segment ${idx + 1}/${segmentUrls.size} failed (HTTP ${segResp.code})")
                    }
                    val bytes = segResp.body?.bytes() ?: ByteArray(0)
                    out.write(bytes)
                    cumulativeBytes += bytes.size
                }
                updateTask(taskId) {
                    it.copy(
                        downloadedBytes = cumulativeBytes,
                        completedHlsSegments = idx + 1,
                        totalHlsSegments = segmentUrls.size,
                        updatedAtEpochMs = System.currentTimeMillis()
                    )
                }
            }
        }
    }

    private fun extractAudioTrackToM4a(sourceMp4: File, destM4a: File) {
        val extractor = MediaExtractor()
        var muxer: MediaMuxer? = null
        try {
            extractor.setDataSource(sourceMp4.absolutePath)
            var audioTrackIndex = -1
            var audioFormat: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val format = extractor.getTrackFormat(i)
                val mime = format.getString(MediaFormat.KEY_MIME).orEmpty()
                if (mime.startsWith("audio/")) {
                    audioTrackIndex = i
                    audioFormat = format
                    break
                }
            }
            if (audioTrackIndex < 0 || audioFormat == null) {
                throw IllegalStateException("Selected MP4 video does not contain an extractable audio track.")
            }
            extractor.selectTrack(audioTrackIndex)
            if (destM4a.exists()) destM4a.delete()
            muxer = MediaMuxer(destM4a.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
            val dstTrack = muxer.addTrack(audioFormat)
            muxer.start()

            val buffer = ByteBuffer.allocate(256 * 1024)
            val bufferInfo = MediaCodec.BufferInfo()
            while (true) {
                bufferInfo.offset = 0
                bufferInfo.size = extractor.readSampleData(buffer, 0)
                if (bufferInfo.size < 0) break
                bufferInfo.presentationTimeUs = extractor.sampleTime
                bufferInfo.flags = extractor.sampleFlags
                muxer.writeSampleData(dstTrack, buffer, bufferInfo)
                extractor.advance()
            }
            muxer.stop()
        } finally {
            runCatching { muxer?.release() }
            runCatching { extractor.release() }
        }
    }

    private fun parseHlsPlaylist(baseUri: URI, host: String, content: String): MediaProbeResult {
        if (content.contains("#EXT-X-KEY", ignoreCase = true) &&
            !content.contains("METHOD=NONE", ignoreCase = true)
        ) {
            throw IllegalStateException("DRM / AES-encrypted HLS stream detected (#EXT-X-KEY). Protected content cannot be downloaded.")
        }
        val lines = content.lines().map { it.trim() }
        val formats = ArrayList<MediaFormatOption>()

        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            if (line.startsWith("#EXT-X-STREAM-INF:", ignoreCase = true)) {
                val attrs = line.substringAfter(':')
                val res = Regex("""RESOLUTION=(\d+)x(\d+)""", RegexOption.IGNORE_CASE).find(attrs)
                val bw = Regex("""BANDWIDTH=(\d+)""", RegexOption.IGNORE_CASE).find(attrs)?.groupValues?.get(1)?.toLongOrNull()
                val width = res?.groupValues?.get(1)?.toIntOrNull()
                val height = res?.groupValues?.get(2)?.toIntOrNull()
                val nextUriLine = lines.drop(i + 1).firstOrNull { it.isNotEmpty() && !it.startsWith("#") }
                if (nextUriLine != null) {
                    val resolved = baseUri.resolve(nextUriLine).toString()
                    val qLabel = height?.let { "${it}p" } ?: bw?.let { "${it / 1000} kbps" } ?: "HLS Stream"
                    formats.add(
                        MediaFormatOption(
                            id = "hls_v_${formats.size}",
                            label = "HLS Video ($qLabel)",
                            containerFormat = "HLS-TS",
                            mimeType = "video/mp2t",
                            mediaKind = MediaKind.VIDEO,
                            qualityLabel = qLabel,
                            width = width,
                            height = height,
                            bandwidthBps = bw,
                            supportsRangeResume = true,
                            resolvedStreamUrl = resolved,
                            isHlsPlaylist = true
                        )
                    )
                }
            } else if (line.startsWith("#EXT-X-MEDIA:", ignoreCase = true) && line.contains("TYPE=AUDIO", ignoreCase = true)) {
                val uriMatch = Regex("""URI="([^"]+)"""").find(line)?.groupValues?.get(1)
                val nameMatch = Regex("""NAME="([^"]+)"""").find(line)?.groupValues?.get(1) ?: "Audio"
                if (!uriMatch.isNullOrBlank()) {
                    formats.add(
                        MediaFormatOption(
                            id = "hls_a_${formats.size}",
                            label = "HLS Audio ($nameMatch)",
                            containerFormat = "AAC",
                            mimeType = "audio/aac",
                            mediaKind = MediaKind.AUDIO,
                            qualityLabel = "Audio ($nameMatch)",
                            supportsRangeResume = true,
                            resolvedStreamUrl = baseUri.resolve(uriMatch).toString(),
                            isHlsPlaylist = true
                        )
                    )
                }
            }
            i++
        }

        // Single-variant media playlist
        if (formats.isEmpty() && lines.any { !it.startsWith("#") && it.isNotEmpty() }) {
            formats.add(
                MediaFormatOption(
                    id = "hls_single",
                    label = "HLS Stream (Standard)",
                    containerFormat = "HLS-TS",
                    mimeType = "video/mp2t",
                    mediaKind = MediaKind.VIDEO,
                    qualityLabel = "Standard",
                    supportsRangeResume = true,
                    resolvedStreamUrl = baseUri.toString(),
                    isHlsPlaylist = true
                )
            )
        }

        if (formats.isEmpty()) {
            throw IllegalArgumentException("HLS playlist did not expose any playable video or audio streams.")
        }

        val sorted = formats.sortedWith(
            compareBy<MediaFormatOption> { it.mediaKind.ordinal }
                .thenByDescending { it.height ?: 0 }
                .thenByDescending { it.bandwidthBps ?: 0L }
        )

        return MediaProbeResult(
            sourceUrl = baseUri.toString(),
            title = deriveTitleFromUri(baseUri).substringBeforeLast('.').ifBlank { "hls_stream" },
            sourceHost = host,
            formats = sorted
        )
    }

    private fun parseHtmlMediaPage(pageUri: URI, host: String, html: String): MediaProbeResult {
        if (Regex("""<meta[^>]+name=["']adshield-download["'][^>]+content=["']disallow["']""", RegexOption.IGNORE_CASE).containsMatchIn(html) ||
            html.contains("com.widevine.alpha", ignoreCase = true) ||
            html.contains("playready", ignoreCase = true)
        ) {
            throw IllegalStateException("This webpage marks its media as DRM-protected or disallows downloading.")
        }

        val pageTitle = Regex("""<title[^>]*>(.*?)</title>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(html)?.groupValues?.get(1)
            ?.replace(Regex("""\s+"""), " ")
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?: deriveTitleFromUri(pageUri)

        data class CandidateLink(val url: String, val typeAttr: String?, val qualityHint: String?)
        val candidates = LinkedHashMap<String, CandidateLink>()

        // Match <video>, <audio>, <source> tags
        val mediaTagRegex = Regex("""<(video|audio|source)\b([^>]+)>""", RegexOption.IGNORE_CASE)
        for (match in mediaTagRegex.findAll(html)) {
            val attrs = match.groupValues[2]
            val src = extractHtmlAttr(attrs, "src") ?: continue
            if (src.startsWith("blob:", ignoreCase = true) || src.startsWith("data:", ignoreCase = true)) continue
            val resolved = runCatching { pageUri.resolve(decodeHtmlEntities(src)).toString() }.getOrNull() ?: continue
            val typeAttr = extractHtmlAttr(attrs, "type")
            val qualityHint = extractHtmlAttr(attrs, "label")
                ?: extractHtmlAttr(attrs, "data-res")
                ?: extractHtmlAttr(attrs, "res")
                ?: extractHtmlAttr(attrs, "size")?.let { "${it}p" }
            candidates.putIfAbsent(resolved, CandidateLink(resolved, typeAttr, qualityHint))
        }

        // OpenGraph og:video / og:audio & JSON-LD contentUrl
        val ogRegex = Regex("""<meta[^>]+property=["']og:(video|audio)(?::url|:secure_url)?["'][^>]+content=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
        for (m in ogRegex.findAll(html)) {
            val kindType = if (m.groupValues[1].equals("audio", true)) "audio/mpeg" else "video/mp4"
            val resolved = runCatching { pageUri.resolve(decodeHtmlEntities(m.groupValues[2])).toString() }.getOrNull() ?: continue
            candidates.putIfAbsent(resolved, CandidateLink(resolved, kindType, null))
        }

        val jsonLdRegex = Regex(""""contentUrl"\s*:\s*"(https?://[^"]+\.(?:mp4|webm|m4a|mp3|ogg|opus|wav|flac)(?:\?[^"]*)?)"""", RegexOption.IGNORE_CASE)
        for (m in jsonLdRegex.findAll(html)) {
            val raw = m.groupValues[1].replace("\\/", "/")
            candidates.putIfAbsent(raw, CandidateLink(raw, null, null))
        }

        if (candidates.isEmpty()) {
            throw IllegalArgumentException("No open HTML5 <video> or <audio> streams were found on this webpage.")
        }

        val options = ArrayList<MediaFormatOption>()
        for ((idx, entry) in candidates.values.take(12).withIndex()) {
            val opt = probeSingleCandidateUrl(entry.url, entry.typeAttr, entry.qualityHint, idx)
            if (opt != null) options.add(opt)
        }

        if (options.isEmpty()) {
            throw IllegalArgumentException("Media links on this page could not be verified as downloadable audio/video streams.")
        }

        return MediaProbeResult(
            sourceUrl = pageUri.toString(),
            title = pageTitle,
            sourceHost = host,
            formats = options.sortedWith(
                compareBy<MediaFormatOption> { it.mediaKind.ordinal }
                    .thenByDescending { it.height ?: parseHeightFromLabel(it.qualityLabel) }
            )
        )
    }

    private fun probeSingleCandidateUrl(
        url: String,
        declaredType: String?,
        qualityHint: String?,
        index: Int
    ): MediaFormatOption? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val host = uri.host?.lowercase() ?: return null
        if (checkRestrictedPlatformOrExtension(uri, host) != null || isHostMalicious(host)) return null

        val req = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("Range", "bytes=0-2047")
            .get()
            .build()

        return runCatching {
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful && resp.code != 206) return@use null
                val ct = resp.header("Content-Type")?.substringBefore(';')?.trim()?.lowercase()
                    .takeUnless { it.isNullOrBlank() } ?: declaredType?.lowercase().orEmpty()
                val totalLen = parseTotalLengthFromHeaders(resp.code, resp.header("Content-Range"), resp.header("Content-Length"))
                val rangeOk = resp.code == 206 || resp.header("Accept-Ranges")?.contains("bytes", true) == true
                val sample = resp.body?.byteStream()?.use { readUpTo(it, 2048) } ?: ByteArray(0)
                val base = classifyDirectMedia(url, deriveTitleFromUri(uri), ct, sample, totalLen, rangeOk, index)
                if (base != null && !qualityHint.isNullOrBlank()) {
                    val h = parseHeightFromLabel(qualityHint).takeIf { it > 0 } ?: base.height
                    base.copy(
                        label = "${base.containerFormat} (${qualityHint})",
                        qualityLabel = qualityHint,
                        height = h
                    )
                } else base
            }
        }.getOrNull()
    }

    private fun classifyDirectMedia(
        url: String,
        fileNameHint: String,
        contentType: String,
        sampleBytes: ByteArray,
        contentLength: Long?,
        supportsRange: Boolean,
        index: Int = 0
    ): MediaFormatOption? {
        val pathExt = runCatching { URI(url).path ?: "" }.getOrDefault("")
            .substringAfterLast('.', "").lowercase()
        val hintExt = fileNameHint.substringAfterLast('.', "").lowercase()
        val ext = pathExt.ifBlank { hintExt }

        val (container, mime, kind) = when {
            contentType == "video/mp4" || ext in setOf("mp4", "m4v") -> Triple("MP4", "video/mp4", MediaKind.VIDEO)
            contentType == "video/webm" || ext == "webm" -> Triple("WEBM", "video/webm", MediaKind.VIDEO)
            contentType == "video/quicktime" || ext == "mov" -> Triple("MOV", "video/quicktime", MediaKind.VIDEO)
            contentType == "video/x-matroska" || ext == "mkv" -> Triple("MKV", "video/x-matroska", MediaKind.VIDEO)
            contentType in setOf("audio/mp4", "audio/x-m4a") || ext == "m4a" -> Triple("M4A", "audio/mp4", MediaKind.AUDIO)
            contentType in setOf("audio/mpeg", "audio/mp3") || ext == "mp3" -> Triple("MP3", "audio/mpeg", MediaKind.AUDIO)
            contentType in setOf("audio/ogg", "application/ogg") || ext == "ogg" -> Triple("OGG", "audio/ogg", MediaKind.AUDIO)
            contentType == "audio/opus" || ext == "opus" -> Triple("OPUS", "audio/opus", MediaKind.AUDIO)
            contentType in setOf("audio/wav", "audio/x-wav") || ext == "wav" -> Triple("WAV", "audio/wav", MediaKind.AUDIO)
            contentType == "audio/flac" || ext == "flac" -> Triple("FLAC", "audio/flac", MediaKind.AUDIO)
            contentType in setOf("audio/aac", "audio/x-aac") || ext == "aac" -> Triple("AAC", "audio/aac", MediaKind.AUDIO)
            else -> return null
        }

        // Check if MP4 sample carries CENC / DRM protection box ('encv' or 'enca' or 'pssh')
        if ((container == "MP4" || container == "M4A") && containsMp4DrmBox(sampleBytes)) {
            throw IllegalStateException("DRM-encrypted MP4/CENC media detected. Protected streams cannot be downloaded.")
        }

        val dims = if (container == "MP4") extractMp4Dimensions(sampleBytes) else null
        val inferredRes = dims?.second?.let { "${it}p" }
            ?: inferQualityFromUrl(url)
            ?: if (kind == MediaKind.AUDIO) "Original Audio" else "Original Video"

        return MediaFormatOption(
            id = "direct_${container.lowercase()}_$index",
            label = "$container ($inferredRes)",
            containerFormat = container,
            mimeType = mime,
            mediaKind = kind,
            qualityLabel = inferredRes,
            width = dims?.first,
            height = dims?.second,
            contentLengthBytes = contentLength,
            supportsRangeResume = supportsRange,
            resolvedStreamUrl = url
        )
    }

    private fun fetchFullText(url: String, maxChars: Int): String {
        val req = Request.Builder().url(url).header("User-Agent", USER_AGENT).get().build()
        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw IllegalStateException("HTTP ${resp.code} reading playlist/page")
            val bytes = resp.body?.byteStream()?.use { readUpTo(it, maxChars) } ?: ByteArray(0)
            return String(bytes, StandardCharsets.UTF_8)
        }
    }

    private fun upsertTask(task: MediaDownloadTask) {
        _tasks.update { current -> listOf(task) + current.filterNot { it.id == task.id } }
        persistTasksSnapshot()
    }

    private fun updateTask(
        taskId: String,
        persist: Boolean = true,
        transform: (MediaDownloadTask) -> MediaDownloadTask
    ) {
        _tasks.update { list -> list.map { if (it.id == taskId) transform(it) else it } }
        if (persist) persistTasksSnapshot()
    }

    private fun loadPersistedTasks(): List<MediaDownloadTask> = synchronized(persistLock) {
        if (!stateStoreFile.exists()) return emptyList()
        runCatching {
            val decoded = json.decodeFromString<List<MediaDownloadTask>>(
                stateStoreFile.readText(StandardCharsets.UTF_8)
            )
            // Any task that was DOWNLOADING when the process exited becomes PAUSED so the user can resume it
            decoded.map { task ->
                if (task.status == DownloadStatus.DOWNLOADING || task.status == DownloadStatus.QUEUED) {
                    task.copy(status = DownloadStatus.PAUSED, speedBytesPerSec = 0L)
                } else task
            }
        }.getOrDefault(emptyList())
    }

    private fun persistTasksSnapshot() = synchronized(persistLock) {
        runCatching {
            stateStoreFile.parentFile?.mkdirs()
            val tmp = File(stateStoreFile.parentFile, "${stateStoreFile.name}.tmp")
            tmp.writeText(json.encodeToString(_tasks.value.take(100)), StandardCharsets.UTF_8)
            if (!tmp.renameTo(stateStoreFile)) {
                tmp.copyTo(stateStoreFile, overwrite = true)
                tmp.delete()
            }
        }
    }

    companion object {
        private const val USER_AGENT = "AdShieldPro/2.6 (Android; Legitimate-Media-Downloader)"
        private const val MAX_DOWNLOAD_BYTES = 2L * 1024L * 1024L * 1024L // 2 GB safety ceiling

        /**
         * Streaming services whose Terms of Service or DRM prohibit downloading streams.
         */
        val RESTRICTED_STREAMING_DOMAINS = setOf(
            "youtube.com", "youtu.be", "youtube-nocookie.com",
            "netflix.com", "spotify.com", "scdn.co",
            "disneyplus.com", "hulu.com", "primevideo.com",
            "music.apple.com", "tv.apple.com",
            "tidal.com", "deezer.com", "pandora.com",
            "hbomax.com", "max.com", "peacocktv.com", "paramountplus.com",
            "crunchyroll.com", "dazn.com"
        )

        fun checkRestrictedPlatformOrExtension(uri: URI, host: String): String? {
            val normalizedHost = host.lowercase().removePrefix("www.")
            val matchedRestricted = RESTRICTED_STREAMING_DOMAINS.firstOrNull { domain ->
                normalizedHost == domain || normalizedHost.endsWith(".$domain")
            }
            if (matchedRestricted != null) {
                return "Downloads from '$matchedRestricted' are disabled to respect platform Terms of Service, copyright, and DRM protections."
            }
            val pathLower = (uri.path ?: "").lowercase()
            if (pathLower.endsWith(".ism") || pathLower.endsWith(".ism/manifest") || pathLower.endsWith(".wv")) {
                return "DRM-protected stream manifest detected; protected content cannot be downloaded."
            }
            return null
        }

        internal fun parseTotalLengthFromHeaders(
            statusCode: Int,
            contentRange: String?,
            contentLength: String?
        ): Long? {
            if (!contentRange.isNullOrBlank()) {
                val slashTotal = contentRange.substringAfter('/', "").trim()
                val total = slashTotal.toLongOrNull()
                if (total != null && total > 0L) return total
            }
            if (statusCode != 206) {
                val len = contentLength?.trim()?.toLongOrNull()
                if (len != null && len > 0L) return len
            }
            return null
        }

        internal fun extractMp4Dimensions(bytes: ByteArray): Pair<Int, Int>? {
            // Scan for 'tkhd' atom in ISO BMFF header and read fixed-point 16.16 width & height
            val tkhd = byteArrayOf('t'.code.toByte(), 'k'.code.toByte(), 'h'.code.toByte(), 'd'.code.toByte())
            var idx = 0
            while (idx <= bytes.size - 92) {
                if (bytes[idx] == tkhd[0] && bytes[idx + 1] == tkhd[1] &&
                    bytes[idx + 2] == tkhd[2] && bytes[idx + 3] == tkhd[3]
                ) {
                    val version = bytes[idx + 4].toInt() and 0xFF
                    val widthOffset = if (version == 1) idx + 88 else idx + 76
                    if (widthOffset + 8 <= bytes.size) {
                        val widthFixed = readInt32BE(bytes, widthOffset)
                        val heightFixed = readInt32BE(bytes, widthOffset + 4)
                        val w = widthFixed ushr 16
                        val h = heightFixed ushr 16
                        if (w in 64..16384 && h in 64..16384) {
                            return w to h
                        }
                    }
                }
                idx++
            }
            return null
        }

        internal fun containsMp4DrmBox(bytes: ByteArray): Boolean {
            if (bytes.size < 8) return false
            val ascii = String(bytes, StandardCharsets.ISO_8859_1)
            return ascii.contains("encv") || ascii.contains("enca") || ascii.contains("pssh") || ascii.contains("sinf")
        }

        private fun readInt32BE(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 24) or
                ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or
                (b[off + 3].toInt() and 0xFF)

        private fun inferQualityFromUrl(url: String): String? {
            val match = Regex("""(?:^|[_.\-/])(2160p|1440p|1080p|720p|480p|360p|240p)(?:$|[_.\-/?])""", RegexOption.IGNORE_CASE)
                .find(url)
            return match?.groupValues?.get(1)?.lowercase()
        }

        private fun parseHeightFromLabel(label: String): Int =
            Regex("""(\d{3,4})p""", RegexOption.IGNORE_CASE).find(label)?.groupValues?.get(1)?.toIntOrNull() ?: 0

        private fun parseContentDispositionFileName(header: String?): String? {
            if (header.isNullOrBlank()) return null
            val utf8Match = Regex("""filename\*=UTF-8''([^;\s]+)""", RegexOption.IGNORE_CASE).find(header)
            if (utf8Match != null) {
                return runCatching {
                    URLDecoder.decode(utf8Match.groupValues[1], StandardCharsets.UTF_8.name())
                }.getOrNull()
            }
            val basicMatch = Regex("""filename="?([^";]+)"?""", RegexOption.IGNORE_CASE).find(header)
            return basicMatch?.groupValues?.get(1)?.trim()
        }

        private fun deriveTitleFromUri(uri: URI): String {
            val rawPath = uri.path ?: return "media"
            val lastSeg = rawPath.trimEnd('/').substringAfterLast('/')
            return runCatching { URLDecoder.decode(lastSeg, StandardCharsets.UTF_8.name()) }
                .getOrDefault(lastSeg)
                .ifBlank { uri.host ?: "media" }
        }

        private fun extractHtmlAttr(attrs: String, name: String): String? {
            val quoted = Regex("""\b$name\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE).find(attrs)
            if (quoted != null) return quoted.groupValues[1].trim()
            val unquoted = Regex("""\b$name\s*=\s*([^\s>"']+)""", RegexOption.IGNORE_CASE).find(attrs)
            return unquoted?.groupValues?.get(1)?.trim()
        }

        private fun decodeHtmlEntities(s: String): String =
            s.replace("&amp;", "&").replace("&#38;", "&").replace("&quot;", "\"")

        private fun readUpTo(stream: java.io.InputStream, maxBytes: Int): ByteArray {
            val out = java.io.ByteArrayOutputStream(minOf(maxBytes, 16_384))
            val buf = ByteArray(8192)
            var remaining = maxBytes
            while (remaining > 0) {
                val r = stream.read(buf, 0, minOf(buf.size, remaining))
                if (r < 0) break
                if (r > 0) {
                    out.write(buf, 0, r)
                    remaining -= r
                }
            }
            return out.toByteArray()
        }

        private fun uniqueDestinationFile(dir: File, desiredName: String): File {
            val candidate = File(dir, desiredName)
            if (!candidate.exists() && !File("${candidate.absolutePath}.part").exists()) return candidate
            val base = desiredName.substringBeforeLast('.', desiredName)
            val ext = desiredName.substringAfterLast('.', "")
            for (idx in 1..999) {
                val nextName = if (ext.isNotEmpty()) "${base}_$idx.$ext" else "${base}_$idx"
                val next = File(dir, nextName)
                if (!next.exists() && !File("${next.absolutePath}.part").exists()) return next
            }
            return File(dir, "${System.currentTimeMillis()}_$desiredName")
        }

        private fun sanitizeFileName(raw: String): String =
            raw.trim().replace(Regex("""[\u0000-\u001F\\/:*?"<>|]+"""), "_").trim('_')

        private fun computeSha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val r = input.read(buf)
                    if (r < 0) break
                    if (r > 0) digest.update(buf, 0, r)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        private fun isLoopback(host: String): Boolean =
            host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
    }
}
