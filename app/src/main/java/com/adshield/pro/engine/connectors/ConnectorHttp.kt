package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Transport boundary so the sync engine is pure and testable without a network. */
interface ConnectorTransport {
    fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult
}

sealed interface TransportResult {
    data class Response(
        val code: Int,
        val body: String?,
        val etag: String?,
        val lastModified: String?,
        val retryAfterMs: Long?,
        val latencyMs: Long
    ) : TransportResult

    data class Failure(
        val offline: Boolean,
        val reason: String,
        val latencyMs: Long
    ) : TransportResult
}

/**
 * Real HTTPS client for public feeds.
 *
 * Safety choices that matter for untrusted public data:
 *  - only `https://` endpoints are accepted (plain http is rejected before any socket opens);
 *  - the response is read with a hard byte cap and aborted past it, so a hostile/huge body cannot
 *    exhaust memory on a low-RAM phone;
 *  - conditional requests (ETag / If-Modified-Since) keep provider bandwidth low;
 *  - redirects are followed by OkHttp but a redirect to http is refused;
 *  - no cookies, no credentials and no API keys are stored in the APK for these feeds.
 */
class OkHttpConnectorTransport(
    private val client: OkHttpClient = defaultClient()
) : ConnectorTransport {

    override fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult {
        if (!spec.endpoint.startsWith("https://", ignoreCase = true)) {
            return TransportResult.Failure(false, "endpoint is not HTTPS", 0L)
        }
        val started = System.nanoTime()
        val request = Request.Builder()
            .url(spec.endpoint)
            .header("User-Agent", USER_AGENT)
            .header("Accept", acceptFor(spec))
            .apply {
                etag?.let { header("If-None-Match", it) }
                lastModified?.let { header("If-Modified-Since", it) }
            }
            .get()
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                val latency = (System.nanoTime() - started) / 1_000_000L
                val finalUrl = response.request.url.toString()
                if (!finalUrl.startsWith("https://", ignoreCase = true)) {
                    return TransportResult.Failure(false, "redirected to a non-HTTPS URL", latency)
                }
                val body = response.body
                val bytes = if (response.code == 304 || body == null) {
                    null
                } else {
                    readBounded(body.byteStream(), spec.maxBytes, latency)
                        ?: return TransportResult.Failure(false, "response exceeded ${spec.maxBytes} bytes", latency)
                }
                TransportResult.Response(
                    code = response.code,
                    body = bytes,
                    etag = response.header("ETag"),
                    lastModified = response.header("Last-Modified"),
                    retryAfterMs = parseRetryAfter(response.header("Retry-After")),
                    latencyMs = latency
                )
            }
        } catch (io: IOException) {
            val latency = (System.nanoTime() - started) / 1_000_000L
            TransportResult.Failure(offline = true, reason = io.javaClass.simpleName + ": " + (io.message ?: "network error"), latencyMs = latency)
        }
    }

    private fun readBounded(stream: java.io.InputStream, maxBytes: Int, latency: Long): String? {
        stream.use { input ->
            val out = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
            val buffer = ByteArray(16 * 1024)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                total += read
                if (total > maxBytes) return null
                out.write(buffer, 0, read)
            }
            return out.toString(Charsets.UTF_8.name())
        }
    }

    private fun acceptFor(spec: ConnectorSpec): String = when (spec.format) {
        com.adshield.pro.domain.connectors.ConnectorFormat.JSON -> "application/json"
        com.adshield.pro.domain.connectors.ConnectorFormat.RSS -> "application/rss+xml, application/xml, text/xml"
        com.adshield.pro.domain.connectors.ConnectorFormat.CSV -> "text/csv, text/plain"
        else -> "text/plain, */*"
    }

    private fun parseRetryAfter(raw: String?): Long? {
        if (raw.isNullOrBlank()) return null
        raw.trim().toLongOrNull()?.let { seconds -> return seconds.coerceIn(1L, 3600L) * 1_000L }
        return runCatching {
            val format = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", java.util.Locale.US)
            format.timeZone = java.util.TimeZone.getTimeZone("GMT")
            val at = format.parse(raw)?.time ?: return null
            (at - System.currentTimeMillis()).coerceIn(1_000L, 3_600_000L)
        }.getOrNull()
    }

    companion object {
        const val USER_AGENT = "OmniShieldX/2.9 (+https://github.com/yawiyuson231-oss/AdShieldPro)"

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .callTimeout(35, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }
}
