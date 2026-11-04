package com.adshield.pro.engine.download

import com.adshield.pro.domain.model.InspectedMedia
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DirectMediaInspector @Inject constructor() {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(false)
        .build()

    suspend fun inspect(rawUrl: String): InspectedMedia = withContext(Dispatchers.IO) {
        val initial = httpsUrl(rawUrl)
        val head = Request.Builder().url(initial).head().header("Accept", SUPPORTED_ACCEPT).build()
        client.newCall(head).execute().use { response ->
            if (response.isSuccessful) return@withContext mediaFromResponseUrl(
                initial, response.request.url, response.header("Content-Type"),
                response.header("Content-Length")?.toLongOrNull(), response.header("Content-Disposition")
            )
            if (response.code !in setOf(400, 403, 405, 501)) {
                error("Media inspection failed with HTTP ${response.code}")
            }
        }
        // Some file servers do not implement HEAD. A one-byte request is a bounded, standards-based
        // fallback; authentication and access errors are not bypassed.
        val range = Request.Builder().url(initial).get().header("Range", "bytes=0-0")
            .header("Accept", SUPPORTED_ACCEPT).build()
        client.newCall(range).execute().use { response ->
            if (!response.isSuccessful) error("Media inspection failed with HTTP ${response.code}")
            val fullSize = response.header("Content-Range")?.substringAfter('/', "")?.toLongOrNull()
                ?: response.header("Content-Length")?.toLongOrNull()
            mediaFromResponseUrl(
                initial, response.request.url, response.header("Content-Type"), fullSize,
                response.header("Content-Disposition")
            )
        }
    }

    private fun mediaFromResponseUrl(
        initial: HttpUrl,
        finalUrl: HttpUrl,
        contentType: String?,
        contentLength: Long?,
        contentDisposition: String?
    ): InspectedMedia {
        require(finalUrl.isHttps) { "The server redirected to cleartext HTTP; download refused" }
        val pathName = finalUrl.pathSegments.lastOrNull().orEmpty()
        val headerName = FILENAME_REGEX.find(contentDisposition.orEmpty())?.groupValues?.get(1)
        val fileName = sanitizeFileName(headerName ?: pathName.ifBlank { "media-download" })
        val mime = contentType?.substringBefore(';')?.trim()?.lowercase().orEmpty()
        val extensionMime = EXTENSION_MIME[fileName.substringAfterLast('.', "").lowercase()]
        val resolvedMime = when {
            mime in SUPPORTED_MIME_TYPES -> mime
            mime.isEmpty() || mime == "application/octet-stream" || mime == "binary/octet-stream" -> extensionMime
                ?: error("The server did not identify a supported media format")
            else -> error("Unsupported response type '$mime'. Paste a direct media file URL, not a website page")
        }
        if (mime == "text/html" || mime == "application/xhtml+xml") {
            error("Website pages are not direct media; no site extractor or DRM bypass is included")
        }
        return InspectedMedia(
            url = initial.toString(),
            finalUrl = finalUrl.toString(),
            fileName = fileName,
            mimeType = resolvedMime,
            sizeBytes = contentLength?.takeIf { it >= 0L }
        )
    }

    companion object {
        fun httpsUrl(raw: String): HttpUrl {
            val value = raw.trim()
            require(value.startsWith("https://", ignoreCase = true)) {
                "Only direct HTTPS media URLs are supported"
            }
            val url = runCatching { value.toHttpUrl() }.getOrElse { error("Invalid media URL") }
            require(url.username.isEmpty() && url.password.isEmpty()) { "Embedded URL credentials are not accepted" }
            return url
        }

        fun sanitizeFileName(raw: String): String {
            val cleaned = raw.substringAfterLast('/').substringAfterLast('\\')
                .map { if (it.isISOControl() || it in "<>:\"|?*") '_' else it }.joinToString("")
                .trim().trim('.')
            return cleaned.take(180).ifBlank { "media-download" }
        }

        private val FILENAME_REGEX = Regex("filename\\*?=(?:UTF-8''|\\\")?([^\\\";]+)", RegexOption.IGNORE_CASE)
        private val SUPPORTED_MIME_TYPES = setOf(
            "video/mp4", "video/webm", "video/quicktime", "video/x-matroska",
            "audio/mpeg", "audio/mp4", "audio/aac", "audio/ogg", "audio/opus",
            "audio/wav", "audio/x-wav", "audio/flac", "audio/webm"
        )
        private val EXTENSION_MIME = mapOf(
            "mp4" to "video/mp4", "webm" to "video/webm", "mov" to "video/quicktime",
            "mkv" to "video/x-matroska", "mp3" to "audio/mpeg", "m4a" to "audio/mp4",
            "aac" to "audio/aac", "ogg" to "audio/ogg", "oga" to "audio/ogg",
            "opus" to "audio/opus", "wav" to "audio/wav", "flac" to "audio/flac"
        )
        private const val SUPPORTED_ACCEPT = "video/mp4,video/webm,video/quicktime,audio/*;q=0.9,*/*;q=0.1"
    }
}
