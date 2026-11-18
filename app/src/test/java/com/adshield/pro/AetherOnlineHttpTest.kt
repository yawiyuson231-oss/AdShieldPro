package com.adshield.pro

import com.adshield.pro.engine.aether.AetherOnlineConfig
import com.adshield.pro.engine.aether.AetherOnlineHttp
import com.adshield.pro.engine.aether.AetherOnlinePrompt
import com.adshield.pro.engine.aether.AetherOnlineProtocol
import com.adshield.pro.engine.aether.AetherOnlineProvider as Provider
import com.adshield.pro.engine.aether.AetherOnlineResult
import com.adshield.pro.engine.aether.AetherOnlineResult.Problem
import com.adshield.pro.engine.aether.AetherSecurityTask
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLHandshakeException

/** Runs the production OkHttp request/callback path against deterministic reply fixtures. */
class AetherOnlineHttpTest {
    private val config = connection(Provider.COMPATIBLE, "https://model.example/v1", "fixture-model")
    private val prompt = requireNotNull(AetherOnlinePrompt.create(AetherOnlinePrompt.CONNECTION_TEST))

    @Test
    fun sendsOneHttpsPostWithBearerAuthenticationAndReturnsOnlyTheTaskId() {
        val attempts = AtomicInteger()
        val observed = AtomicReference<Request>()
        val body = AtomicReference<String>()
        val http = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { chain ->
            attempts.incrementAndGet()
            val request = chain.request()
            observed.set(request)
            body.set(Buffer().apply { requireNotNull(request.body).writeTo(this) }.readUtf8())
            response(request, 200, """{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"AUDIT_APPS"}}]}""")
        }.build())
        val result = runBlocking { http.send(config, prompt) }
        assertEquals(AetherOnlineResult.Suggested(AetherSecurityTask.AUDIT_APPS), result)
        assertEquals(1, attempts.get())
        assertEquals("POST", observed.get().method)
        assertEquals(config.endpoint.url, observed.get().url.toString())
        assertEquals("Bearer fixture-token", observed.get().header("Authorization"))
        assertEquals(AetherOnlineProtocol.requestBody(config.endpoint, prompt), body.get())
        assertTrue(requireNotNull(observed.get().body).isOneShot())
    }

    @Test
    fun mapsTransportAndHttpFailuresAndBoundsReplyReads() {
        val network = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { throw IOException("private provider detail") }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.NETWORK), runBlocking { network.send(config, prompt) })
        val auth = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { response(it.request(), 401, "private error body") }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.AUTH), runBlocking { auth.send(config, prompt) })
        val tooLong = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor {
            response(it.request(), 200, " ".repeat(AetherOnlineProtocol.MAX_REPLY_BYTES.toInt() + 1))
        }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.REPLY_TOO_LARGE), runBlocking { tooLong.send(config, prompt) })
        val tls = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor {
            throw ConnectException("first route failed").apply { addSuppressed(SSLHandshakeException("fixture")) }
        }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.TLS), runBlocking { tls.send(config, prompt) })
        val timeout = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { throw SocketTimeoutException("fixture") }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.TIMEOUT), runBlocking { timeout.send(config, prompt) })
    }

    @Test
    fun rejectsOversizedRepliesWithNoContentLength() {
        val http = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { chain ->
            val unknownLengthBody = object : ResponseBody() {
                val buffer = Buffer().writeUtf8(" ".repeat(AetherOnlineProtocol.MAX_REPLY_BYTES.toInt() + 1))
                override fun contentLength(): Long = -1
                override fun contentType() = "application/json".toMediaType()
                override fun source() = buffer
            }
            response(chain.request(), 200, "").newBuilder().body(unknownLengthBody).build()
        }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.REPLY_TOO_LARGE), runBlocking { http.send(config, prompt) })
    }

    @Test
    fun stoppingTheWaitCancelsTheHttpCallWithoutReturningATask() = runBlocking {
        val started = CompletableDeferred<Call>()
        val reply = CountDownLatch(1)
        val http = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { chain ->
            started.complete(chain.call())
            if (!reply.await(5, TimeUnit.SECONDS)) throw IOException("fixture timed out")
            response(chain.request(), 200,
                """{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"AUDIT_APPS"}}]}""")
        }.build())
        var result: AetherOnlineResult? = null
        val job = launch { result = http.send(config, prompt) }
        try {
            val call = withTimeout(5_000) { started.await() }
            withTimeout(5_000) { job.cancelAndJoin() }
            assertTrue(call.isCanceled())
            assertNull(result)
        } finally {
            reply.countDown()
            job.cancel()
        }
    }

    @Test
    fun sendsGeminiKeyOnlyToPinnedNativeEndpointAndParsesTheReply() {
        val gemini = connection(Provider.GEMINI, "", "gemini-3.5-flash-lite")
        val observed = AtomicReference<Request>()
        val payload = AtomicReference<String>()
        val http = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor { chain ->
            observed.set(chain.request())
            payload.set(Buffer().apply { requireNotNull(chain.request().body).writeTo(this) }.readUtf8())
            response(chain.request(), 200,
                """{"candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":"AUDIT_APPS"}]}}]}""")
        }.build())
        assertEquals(AetherOnlineResult.Suggested(AetherSecurityTask.AUDIT_APPS), runBlocking { http.send(gemini, prompt) })
        val request = observed.get()
        assertEquals("generativelanguage.googleapis.com", request.url.host)
        assertEquals("/v1beta/models/gemini-3.5-flash-lite:generateContent", request.url.encodedPath)
        assertEquals("fixture-token", request.header("x-goog-api-key"))
        assertNull(request.header("Authorization"))
        assertNull(request.url.query)
        assertFalse(request.url.toString().contains("fixture-token"))
        assertEquals(AetherOnlineProtocol.requestBody(gemini.endpoint, prompt), payload.get())
        assertFalse(payload.get().contains("fixture-token"))
        assertTrue(requireNotNull(request.body).isOneShot())
    }

    @Test
    fun turnsGeminiBadRequestForAnInvalidKeyIntoAnAuthError() {
        val gemini = connection(Provider.GEMINI, "", "gemini-3.5-flash-lite")
        val http = AetherOnlineHttp(OkHttpClient.Builder().addInterceptor {
            response(it.request(), 400,
                """{"error":{"code":400,"message":"private provider details","details":[{"reason":"API_KEY_INVALID"}]}}""")
        }.build())
        assertEquals(AetherOnlineResult.Failed(Problem.AUTH), runBlocking { http.send(gemini, prompt) })
    }

    private fun connection(provider: Provider, url: String, model: String): AetherOnlineConfig =
        (AetherOnlineConfig.validate(AetherOnlineConfig.Input(provider, url, model, "fixture-token"))
            as AetherOnlineConfig.Validation.Ready).config

    private fun response(request: Request, status: Int, body: String) = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(status)
        .message("Fixture response")
        .body(body.toResponseBody("application/json".toMediaType()))
        .build()
}
