package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.engine.dns.DnsDiagnosticQueryFactory
import com.adshield.pro.engine.dns.DnsHttpsTransport
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.DnsResponseValidationException
import com.adshield.pro.engine.dns.DnsResponseValidator
import com.adshield.pro.engine.dns.DnsTransportException
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.dns.dnsExchange
import com.adshield.pro.engine.dns.runDiagnostics
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class DnsResolverHardeningTest {
    @Test
    fun matchesCompleteQuestionAndOnlyThenAllowsTruncationRetry() {
        val query = query()
        val tc = DnsPacketCodec.buildNoDataResponse(query).also { it[2] = (it[2].toInt() or 2).toByte() }
        assertTrue(DnsResponseValidator.matchingReplyFlags(query, tc) and 0x0200 != 0)
        val wrongType = tc.copyOf().also { it[query.questionSectionEndOffset - 3] = 28 }
        val wrongName = tc.copyOf().also { it[13] = 'z'.code.toByte() }
        val wrongClass = tc.copyOf().also { it[query.questionSectionEndOffset - 1] = 3 }
        for (other in listOf(wrongType, wrongName, wrongClass)) {
            assertThrows(DnsResponseValidationException::class.java) { DnsResponseValidator.matchingReplyFlags(query, other) }
        }
        assertThrows(DnsResponseValidationException::class.java) { DnsResponseValidator.inspect(query, tc) }
        val upperCase = DnsPacketCodec.buildNoDataResponse(query).also { it[13] = 'E'.code.toByte() }
        assertEquals(0, DnsResponseValidator.validate(query.rawPayload, upperCase).responseCode)
        assertNull(DnsPacketCodec.parseQuery(query.rawPayload.copyOf().also { it[5] = 2 }))
    }

    @Test
    fun rejectsMalformedRecordDataAndInvalidEdnsPlacementOrLength() {
        val query = query()
        val reply = DnsPacketCodec.buildBlockedResponse(query, true)
        val shortA = reply.copyOf(reply.size - 1).also { it[query.questionSectionEndOffset + 11] = 3 }
        val options = opt(options = byteArrayOf(0, 15, 0, 8, 0, 6))
        val duplicate = withOpt(reply, opt() + opt(), count = 2)
        val inAnswer = (reply + opt()).also { it[7] = 2 }
        for (bad in listOf(shortA, withOpt(reply, options), duplicate, inAnswer)) {
            assertThrows(DnsResponseValidationException::class.java) { DnsResponseValidator.validate(query.rawPayload, bad) }
        }
        val supported = DnsResponseValidator.validate(query.rawPayload, withOpt(reply, opt()))
        assertEquals(0, supported.ednsVersion)
        assertTrue(supported.hasRequestedAnswer)
    }

    @Test
    fun usesExtendedRcodeAndReportsOnlyNumericExtendedErrorEvidence() {
        val query = query()
        val reply = DnsPacketCodec.buildNoDataResponse(query)
        val withBadvers = withOpt(reply, opt(extendedRcode = 1, options = ede(6)))
        val error = assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(query.rawPayload, withBadvers)
        }
        assertEquals(16, error.inspection?.responseCode)
        assertEquals(listOf(6), error.inspection?.extendedErrorCodes)
        assertTrue(error.message.orEmpty().contains("BADVERS"))
        assertFalse(error.message.orEmpty().contains("untrusted"))
    }

    @Test
    fun refusalFallsBackToSelectedEncryptedResolverWithDetails() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val calls = mutableListOf<Pair<String, DnsProtocol>>()
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { query, config, endpoint ->
            calls += endpoint.providerId to config.protocol
            if (endpoint.providerId == "cloudflare") {
                withOpt(DnsPacketCodec.buildNoDataResponse(query).also { it[3] = 0x85.toByte() }, opt(options = ede(18)))
            } else DnsPacketCodec.buildBlockedResponse(query, true)
        }
        val report = resolver.runDiagnostics("example.com", failover(DnsProtocol.DOT))
        assertEquals(listOf("cloudflare" to DnsProtocol.DOT, "quad9" to DnsProtocol.DOT), calls)
        assertTrue(report.successful)
        assertTrue(report.transportAndProvider.startsWith("DOT (Quad9"))
        assertEquals("Upstream DNS failure: REFUSED", report.issues.single().reason)
        assertEquals(listOf(18), report.issues.single().extendedErrorCodes)
    }

    @Test
    fun cancelsSlowHedgeWithoutRecordingItsCancellationAsAnOutage() = runBlocking {
        val health = DnsProviderHealthMonitor()
        val resolver = UpstreamDnsResolver(health)
        val cancelled = CompletableDeferred<Unit>()
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { query, config, endpoint ->
            assertEquals(DnsProtocol.DOH, config.protocol)
            if (endpoint.providerId == "cloudflare") {
                try { awaitCancellation() } finally { cancelled.complete(Unit) }
            }
            DnsPacketCodec.buildBlockedResponse(query, true)
        }
        val result = resolver.resolve(query(), failover(DnsProtocol.DOH))
        assertEquals("quad9", result.providerId)
        assertTrue(cancelled.isCompleted)
        assertEquals(0L, health.snapshot("cloudflare", DnsProtocol.DOH).failedQueries)
        assertEquals(1L, health.snapshot("quad9", DnsProtocol.DOH).successfulQueries)
    }

    @Test
    fun closingABlockedExchangeReleasesItsIoOnCancellation() = runBlocking {
        val started = CompletableDeferred<Unit>()
        val closed = CountDownLatch(1)
        val closeCount = AtomicInteger()
        val socket = Closeable { closeCount.incrementAndGet(); closed.countDown() }
        val io = launch(Dispatchers.IO) {
            socket.dnsExchange {
                started.complete(Unit)
                check(closed.await(2, TimeUnit.SECONDS)) { "Blocked exchange was not released" }
            }
        }
        started.await()
        io.cancelAndJoin()
        assertTrue(closeCount.get() > 0)
    }

    @Test
    fun liveDiagnosticsDoNotReadOrChangeTheNormalReplyCache() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val config = DnsResolverConfig()
        val query = query()
        var calls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            if (++calls == 1) DnsPacketCodec.buildBlockedResponse(parsed, true)
            else withOpt(DnsPacketCodec.buildNoDataResponse(parsed), opt(options = ede(3)))
        }
        assertFalse(resolver.resolve(query, config).fromCache)
        val report = resolver.runDiagnostics("Example.COM.", config)
        assertEquals(2, calls)
        assertTrue(report.successful)
        assertTrue(report.outcome.contains("no A record"))
        assertEquals(0, report.answerCount)
        assertEquals(0, report.ednsVersion)
        assertEquals(listOf(3), report.extendedErrorCodes)
        val cached = resolver.resolve(query, config)
        assertTrue(cached.fromCache)
        assertEquals(1, cached.inspection?.answerCount)
        assertEquals(2, calls)
    }

    @Test
    fun strictDnssecRejectionDoesNotBlockLaterAuthenticatedNames() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val config = DnsResolverConfig(dnssecMode = DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS)
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            DnsPacketCodec.buildBlockedResponse(parsed, true).also {
                if (parsed.questionDomain == "authenticated.example") it[3] = (it[3].toInt() or 0x20).toByte()
            }
        }
        repeat(4) { assertFalse(resolver.runDiagnostics("unsigned.example", config).successful) }
        assertTrue(resolver.runDiagnostics("authenticated.example", config).successful)
    }

    @Test
    fun dohRequiresHttpsAndAcceptsOnlyBoundedDnsMessageBodies() = runBlocking {
        var mediaType = "application/dns-message"
        val wire = DnsPacketCodec.buildBlockedResponse(query(), true)
        var payload = wire
        val calls = AtomicInteger()
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            calls.incrementAndGet()
            val request = chain.request()
            assertEquals("POST", request.method)
            assertEquals("application/dns-message", request.header("Accept"))
            Response.Builder().request(request).protocol(Protocol.HTTP_2).code(200).message("Fixture")
                .body(payload.toResponseBody(mediaType.toMediaType())).build()
        }.build()
        val doh = DnsHttpsTransport(client)
        val endpoint = "https://resolver.example/dns-query"
        assertArrayEquals(wire, doh.query(query().rawPayload, endpoint))
        assertTrue(runCatching { doh.query(query().rawPayload, "http://resolver.example/dns-query") }.exceptionOrNull() is DnsTransportException)
        assertEquals(1, calls.get())
        mediaType = "text/html"
        assertTrue(runCatching { doh.query(query().rawPayload, endpoint) }.exceptionOrNull() is DnsTransportException)
        mediaType = "application/dns-message"
        payload = ByteArray(65_536)
        assertTrue(runCatching { doh.query(query().rawPayload, endpoint) }.exceptionOrNull() is DnsTransportException)
        client.dispatcher.executorService.shutdown()
    }

    private fun query() = requireNotNull(DnsPacketCodec.parseQuery(DnsDiagnosticQueryFactory.build("example.com", 42)))

    private fun failover(protocol: DnsProtocol) = DnsResolverConfig(
        preset = DnsProviderPreset.CLOUDFLARE,
        protocol = protocol,
        failoverEnabled = true,
        failoverProviderIds = setOf(DnsProviderPreset.QUAD9.id)
    )

    private fun opt(extendedRcode: Int = 0, options: ByteArray = byteArrayOf()) =
        byteArrayOf(0, 0, 41, 4, 0xd0.toByte(), extendedRcode.toByte(), 0, 0x80.toByte(), 0,
            (options.size ushr 8).toByte(), options.size.toByte()) + options

    private fun ede(code: Int): ByteArray {
        val detail = "untrusted resolver text".encodeToByteArray()
        return byteArrayOf(0, 15, 0, (2 + detail.size).toByte(), 0, code.toByte()) + detail
    }

    private fun withOpt(reply: ByteArray, opt: ByteArray, count: Int = 1) = (reply + opt).also { it[11] = count.toByte() }
}
