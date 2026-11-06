package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorFormat
import com.adshield.pro.domain.connectors.ConnectorSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Transport boundary so the sync engine is pure and testable without a network. */
interface ConnectorTransport {
    fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult

    /**
     * POST/PUT body support. Providers that publish machine-readable data only through a POST
     * endpoint (OSV, Sonatype OSS Index, the abuse.ch APIs) are unusable otherwise. Transports that
     * cannot send a body return a failure instead of silently issuing a GET.
     */
    fun post(
        spec: ConnectorSpec,
        body: String,
        contentType: String?,
        etag: String? = null,
        lastModified: String? = null
    ): TransportResult = TransportResult.Failure(false, "this transport cannot send a request body", 0L)
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
 * Real HTTPS client for public feeds and lookups.
 *
 * Safety choices that matter for untrusted public data:
 *  - only `https://` endpoints are accepted (plain http is rejected before any socket opens);
 *  - the response is read with a hard byte cap and aborted past it, so a hostile/huge body cannot
 *    exhaust memory on a low-RAM phone;
 *  - conditional requests (ETag / If-Modified-Since) keep provider bandwidth low;
 *  - redirects are followed by OkHttp but a redirect to http is refused;
 *  - no cookies, no credentials and no API keys are stored in the APK for these feeds;
 *  - retries are bounded, idempotent and only used for transport errors / 429 / 5xx. A 404 is an
 *    answer, not a retry candidate.
 */
class OkHttpConnectorTransport(
    private val client: OkHttpClient = defaultClient()
) : ConnectorTransport {

    override fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult =
        send(spec, null, null, etag, lastModified)

    override fun post(
        spec: ConnectorSpec,
        body: String,
        contentType: String?,
        etag: String?,
        lastModified: String?
    ): TransportResult = send(spec, body, contentType, etag, lastModified)

    private fun send(
        spec: ConnectorSpec,
        body: String?,
        contentType: String?,
        etag: String?,
        lastModified: String?
    ): TransportResult {
        if (!spec.endpoint.startsWith("https://", ignoreCase = true)) {
            return TransportResult.Failure(false, "endpoint is not HTTPS", 0L)
        }
        val attempts = spec.maxRetries.coerceIn(0, 3) + 1
        var last: TransportResult? = null
        var totalLatency = 0L
        for (attempt in 0 until attempts) {
            val result = attemptOnce(spec, body, contentType, etag, lastModified)
            totalLatency += when (result) {
                is TransportResult.Response -> result.latencyMs
                is TransportResult.Failure -> result.latencyMs
            }
            last = when (result) {
                is TransportResult.Response -> {
                    if (result.code == 429 || result.code in 500..599) result else return result
                }
                is TransportResult.Failure -> result
            }
            if (attempt == attempts - 1) break
            // Small, bounded pause before a retry; the caller is already on an IO thread.
            try {
                Thread.sleep(250L * (attempt + 1))
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        return when (val final = last) {
            is TransportResult.Response -> final.copy(latencyMs = totalLatency)
            is TransportResult.Failure -> final.copy(latencyMs = totalLatency)
            null -> TransportResult.Failure(false, "no attempt was made", 0L)
        }
    }

    private fun attemptOnce(
        spec: ConnectorSpec,
        body: String?,
        contentType: String?,
        etag: String?,
        lastModified: String?
    ): TransportResult {
        val started = System.nanoTime()
        val builder = Request.Builder()
            .url(spec.endpoint)
            .header("User-Agent", USER_AGENT)
            .header("Accept", acceptFor(spec))
            .apply {
                etag?.let { header("If-None-Match", it) }
                lastModified?.let { header("If-Modified-Since", it) }
            }
        if (body != null) {
            val mediaType = (contentType ?: "application/json").toMediaType()
            builder.post(body.toRequestBody(mediaType))
        } else {
            builder.get()
        }
        val request = builder.build()
        return try {
            client.newCall(request).execute().use { response ->
                val latency = (System.nanoTime() - started) / 1_000_000L
                val finalUrl = response.request.url.toString()
                if (!finalUrl.startsWith("https://", ignoreCase = true)) {
                    return TransportResult.Failure(false, "redirected to a non-HTTPS URL", latency)
                }
                val responseBody = response.body
                val text = if (response.code == 304 || responseBody == null) {
                    null
                } else {
                    readBounded(responseBody.byteStream(), spec.maxBytes)
                        ?: return TransportResult.Failure(
                            false,
                            "response exceeded ${spec.maxBytes} bytes",
                            latency
                        )
                }
                TransportResult.Response(
                    code = response.code,
                    body = text,
                    etag = response.header("ETag"),
                    lastModified = response.header("Last-Modified"),
                    retryAfterMs = parseRetryAfter(response.header("Retry-After"), spec.maxRetryAfterSeconds),
                    latencyMs = latency
                )
            }
        } catch (io: IOException) {
            val latency = (System.nanoTime() - started) / 1_000_000L
            TransportResult.Failure(
                offline = true,
                reason = io.javaClass.simpleName + ": " + (io.message ?: "network error"),
                latencyMs = latency
            )
        }
    }

    private fun readBounded(stream: java.io.InputStream, maxBytes: Int): String? {
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
        ConnectorFormat.JSON -> "application/json"
        ConnectorFormat.RSS -> "application/rss+xml, application/xml, text/xml"
        ConnectorFormat.CSV -> "text/csv, text/plain"
        else -> "text/plain, */*"
    }

    private fun parseRetryAfter(raw: String?, maxSeconds: Long): Long? {
        if (raw.isNullOrBlank()) return null
        val cap = maxSeconds.coerceIn(60L, 86_400L)
        raw.trim().toLongOrNull()?.let { seconds -> return seconds.coerceIn(1L, cap) * 1_000L }
        return runCatching {
            val format = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", java.util.Locale.US)
            format.timeZone = java.util.TimeZone.getTimeZone("GMT")
            val at = format.parse(raw)?.time ?: return null
            (at - System.currentTimeMillis()).coerceIn(1_000L, cap * 1_000L)
        }.getOrNull()
    }

    companion object {
        const val USER_AGENT = "OmniShieldX/2.10 (+https://github.com/yawiyuson231-oss/AdShieldPro)"

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
