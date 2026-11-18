package com.adshield.pro.engine.aether

import com.adshield.pro.engine.aether.AetherOnlineResult.Problem
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSink
import java.io.IOException
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import kotlin.coroutines.resume

/** One reviewed, bounded HTTPS request. No redirects, credential forwarding or automatic replay. */
internal class AetherOnlineHttp(baseClient: OkHttpClient = OkHttpClient()) {
    private val client = baseClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(35, TimeUnit.SECONDS)
        .callTimeout(40, TimeUnit.SECONDS)
        .build()

    suspend fun send(config: AetherOnlineConfig, prompt: AetherOnlinePrompt): AetherOnlineResult {
        val endpoint = config.endpoint
        val payload = AetherOnlineProtocol.requestBody(endpoint, prompt).toByteArray(Charsets.UTF_8)
        val packet = object : RequestBody() {
            override fun contentType() = "application/json; charset=utf-8".toMediaType()
            override fun contentLength() = payload.size.toLong()
            override fun isOneShot() = true // Prevent automatic follow-ups of potentially billed requests.
            override fun writeTo(sink: BufferedSink) { sink.write(payload) }
        }
        val request = Request.Builder()
            .url(endpoint.url)
            .apply {
                when (endpoint.provider) {
                    AetherOnlineProvider.GEMINI -> header("x-goog-api-key", config.token)
                    AetherOnlineProvider.OPENAI, AetherOnlineProvider.COMPATIBLE -> header("Authorization", "Bearer ${config.token}")
                }
            }
            .header("Accept", "application/json")
            .post(packet)
            .build()
        return suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            if (!continuation.isActive) return@suspendCancellableCoroutine
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    continuation.resume(transportFailure(e))
                }

                override fun onResponse(call: Call, response: Response) {
                    val result = try {
                        response.use { read(it, endpoint, prompt) }
                    } catch (failure: IOException) {
                        transportFailure(failure)
                    }
                    continuation.resume(result)
                }
            })
        }
    }

    private fun read(response: Response, endpoint: AetherOnlineEndpoint, prompt: AetherOnlinePrompt): AetherOnlineResult {
        if (!response.isSuccessful) {
            // Only inspect bounded client-error JSON for a recognized code (e.g. Google's 400 API_KEY_INVALID).
            val diagnostic = if (response.code in 400..499) try {
                response.body.boundedText()
            } catch (_: IOException) {
                null // The HTTP status is still useful if a provider's error body fails to arrive.
            } else null
            return AetherOnlineProtocol.httpFailure(response.code, diagnostic)
        }
        val body = response.body.boundedText() ?: return AetherOnlineResult.Failed(Problem.REPLY_TOO_LARGE)
        return AetherOnlineProtocol.parseReply(endpoint, body, prompt)
    }

    private fun ResponseBody.boundedText(): String? {
        val max = AetherOnlineProtocol.MAX_REPLY_BYTES
        if (contentLength() > max) return null
        val source = source()
        if (source.request(max + 1L)) return null
        return source.readUtf8()
    }

    private fun transportFailure(failure: IOException): AetherOnlineResult.Failed {
        // OkHttp can report the first failed address with other route errors attached, e.g. an
        // IPv6 connection refused before the IPv4 route reaches certificate verification.
        val routeErrors = listOfNotNull(failure, failure.cause) + failure.suppressed
        val problem = when {
            failure is InterruptedIOException -> Problem.TIMEOUT
            routeErrors.any { it is SSLException } -> Problem.TLS
            routeErrors.any { it is InterruptedIOException } -> Problem.TIMEOUT
            else -> Problem.NETWORK
        }
        return AetherOnlineResult.Failed(problem)
    }
}
