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
            if (response.code !in setOf(400, 405, 501)) {
                error("Media inspection failed with HTTP ${response.code}")
            }
        }
        // Some file servers do not implement HEAD. A one-byte request is a bounded, standards-based
        // fallback; authentication and access errors are not bypassed.
        val range = Request.Builder().url(initial).get().header("Range", "bytes=0-0")
            .header("Accept", SUPPORTED_ACCEPT).build()
        client.newCall(range).execute().use { response ->
            if (!response.isSuccessful) error("Media inspection failed with HTTP ${response.code}")
            // On 206 Partial Content, Content-Length is the 1-byte range size, NOT the full media size.
            val fullSize = response.header("Content-Range")?.substringAfter('/', "")?.trim()?.toLongOrNull()
                ?: if (response.code == 200) response.header("Content-Length")?.toLongOrNull() else null
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
        require(!isPrivateOrLoopbackHost(finalUrl.host)) { "Private and loopback addresses are not accepted" }
        val pathName = finalUrl.pathSegments.lastOrNull().orEmpty()
        val headerName = parseDispositionFileName(contentDisposition)
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
            require(!isPrivateOrLoopbackHost(url.host)) { "Private and loopback addresses are not accepted" }
            return url
        }

        internal fun isPrivateOrLoopbackHost(rawHost: String): Boolean {
            val host = rawHost.trim().trim('[', ']').lowercase()
            if (host.isEmpty() || host == "localhost" || host.endsWith(".localhost") || host == "::1" || host == "::") {
                return true
            }
            if (host.startsWith("fe8") || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb") ||
                host.startsWith("fc") || host.startsWith("fd")
            ) {
                return host.contains(':')
            }
            val octets = host.split('.')
            if (octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 }) {
                val a = octets[0].toInt()
                val b = octets[1].toInt()
                if (a == 0 || a == 10 || a == 127) return true
                if (a == 169 && b == 254) return true
                if (a == 172 && b in 16..31) return true
                if (a == 192 && b == 168) return true
            }
            return false
        }

        internal fun parseDispositionFileName(header: String?): String? {
            if (header.isNullOrBlank()) return null
            FILENAME_STAR_REGEX.find(header)?.groupValues?.get(1)?.trim()?.takeIf { it.isNotEmpty() }?.let { encoded ->
                return percentDecodeUtf8(encoded)
            }
            return FILENAME_PLAIN_REGEX.find(header)?.let { m ->
                (m.groupValues[1].ifEmpty { m.groupValues[2] }).trim().takeIf { it.isNotEmpty() }
            }
        }

        private fun percentDecodeUtf8(raw: String): String {
            val out = java.io.ByteArrayOutputStream(raw.length)
            var i = 0
            while (i < raw.length) {
                val c = raw[i]
                if (c == '%' && i + 2 < raw.length) {
                    val hi = raw[i + 1].digitToIntOrNull(16)
                    val lo = raw[i + 2].digitToIntOrNull(16)
                    if (hi != null && lo != null) {
                        out.write((hi shl 4) or lo)
                        i += 3
                        continue
                    }
                }
                val bytes = c.toString().toByteArray(Charsets.UTF_8)
                out.write(bytes, 0, bytes.size)
                i++
            }
            return String(out.toByteArray(), Charsets.UTF_8)
        }

        fun sanitizeFileName(raw: String): String {
            val cleaned = raw.substringAfterLast('/').substringAfterLast('\\')
                .map { if (it.isISOControl() || it in "<>:\"|?*") '_' else it }.joinToString("")
                .trim().trim('.')
            return cleaned.take(180).ifBlank { "media-download" }
        }

        private val FILENAME_STAR_REGEX = Regex("filename\\*\\s*=\\s*UTF-8'[^']*'([^;\\s]+)", RegexOption.IGNORE_CASE)
        private val FILENAME_PLAIN_REGEX = Regex("filename\\s*=\\s*(?:\"([^\"]+)\"|([^;\\s]+))", RegexOption.IGNORE_CASE)
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
