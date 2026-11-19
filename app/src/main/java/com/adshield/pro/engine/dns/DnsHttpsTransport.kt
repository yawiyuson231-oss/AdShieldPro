package com.adshield.pro.engine.dns

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.ByteArrayOutputStream
import java.io.IOException

/** RFC 8484 transport. Do not follow a redirect to an endpoint the user didn't select. */
internal class DnsHttpsTransport(baseClient: OkHttpClient) {
    private val client = baseClient.newBuilder().followRedirects(false).followSslRedirects(false).build()

    suspend fun query(wire: ByteArray, endpoint: String): ByteArray {
        val url = endpoint.toHttpUrlOrNull()?.takeIf { it.isHttps }
            ?: throw DnsTransportException("DoH requires a valid HTTPS endpoint")
        val request = Request.Builder().url(url)
            .header("Accept", "application/dns-message")
            .post(wire.toRequestBody(DNS_MEDIA_TYPE))
            .build()
        return suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            if (!continuation.isActive) return@suspendCancellableCoroutine
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    continuation.resumeWith(Result.failure(e))
                }

                override fun onResponse(call: Call, response: Response) {
                    continuation.resumeWith(runCatching { response.use(::readReply) })
                }
            })
        }
    }

    private fun readReply(response: Response): ByteArray {
        if (!response.isSuccessful) throw DnsTransportException("DoH HTTP ${response.code}")
        val body = response.body
        val type = body.contentType()
        if (type?.type != "application" || type.subtype != "dns-message") {
            throw DnsTransportException("DoH response was not application/dns-message")
        }
        val max = DnsPacketCodec.MAX_DNS_WIRE_BYTES
        if (body.contentLength() > max) throw DnsTransportException("DoH response is too large")
        val stream = body.byteStream()
        val out = ByteArrayOutputStream(512)
        val chunk = ByteArray(4096)
        while (true) {
            val count = stream.read(chunk)
            if (count < 0) break
            if (count > max - out.size()) throw DnsTransportException("DoH response is too large")
            out.write(chunk, 0, count)
        }
        return out.toByteArray()
    }

    private companion object {
        val DNS_MEDIA_TYPE = "application/dns-message".toMediaType()
    }
}

internal class DnsTransportException(message: String) : IOException(message)
