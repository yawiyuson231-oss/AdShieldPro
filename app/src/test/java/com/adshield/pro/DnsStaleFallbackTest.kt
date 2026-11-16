package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * RFC 8767: a recently expired answer is better than SERVFAIL while the upstream is unreachable,
 * and it must not masquerade as fresh.
 */
class DnsStaleFallbackTest {

    private val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)

    @Test
    fun testOnlyAnExpiredAnswerInsideTheGraceWindowIsStaleServeable() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = true)
        }
        val query = query("stale.example.com", transactionId = 0x4A2B)
        resolver.resolve(query, config) // TTL 60 on this synthetic answer
        val cacheKey = UpstreamDnsResolver.buildCacheKey(query, config)
        val now = System.currentTimeMillis()

        // Fresh entry: not served as a stale fallback, it is a normal cache hit.
        assertNull(resolver.resolveStale(cacheKey, query, now))

        // Expired 30 s ago: inside the grace window.
        val stale = resolver.resolveStale(cacheKey, query, now + 90_000)
        assertNotNull("an answer that expired a moment ago must still be usable", stale)
        assertTrue(stale!!.protocolUsed.contains("Stale"))
        assertTrue("a stale answer is still a cache answer", stale.fromCache)
        assertEquals("the transaction ID must match the caller", 0x4A2B, transactionIdOf(stale.responseBytes))
        assertEquals(
            "a stale answer must be handed out with a short lifetime",
            UpstreamDnsResolver.STALE_TTL_SECONDS,
            DnsPacketCodec.extractResponseTtlSeconds(stale.responseBytes)
        )

        // Expired beyond the grace window: no stale answer any more.
        assertNull(resolver.resolveStale(cacheKey, query, now + 90_000 + UpstreamDnsResolver.STALE_GRACE_MS))
        // Unknown key: nothing to serve.
        assertNull(resolver.resolveStale("doh@nowhere|missing.example.com:1:1", query, now))
    }

    @Test
    fun testExpiredEntriesSurviveTrimmingOnlyWhileTheyCanStillHelp() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = true)
        }
        val query = query("trim.example.com")
        resolver.resolve(query, config)
        assertEquals(1, resolver.getCacheSize())

        val justExpired = System.currentTimeMillis() + 90_000
        assertEquals(
            "an entry that expired a moment ago must be kept for the stale window",
            0,
            resolver.trimExpiredAndExcessCache(targetSize = 1024, nowMs = justExpired)
        )
        assertEquals(1, resolver.getCacheSize())

        val longExpired = justExpired + UpstreamDnsResolver.STALE_GRACE_MS + 1_000
        assertEquals(
            "past the stale window the entry is purged",
            1,
            resolver.trimExpiredAndExcessCache(targetSize = 1024, nowMs = longExpired)
        )
        assertEquals(0, resolver.getCacheSize())
    }

    private fun query(domain: String, transactionId: Int = 0x4A2B): DnsPacketCodec.ParsedDnsQuery {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(transactionId)
        u16(0x0100)
        u16(1)
        u16(0)
        u16(0)
        u16(0)
        domain.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        u16(DnsPacketCodec.TYPE_A)
        u16(DnsPacketCodec.CLASS_IN)
        return DnsPacketCodec.parseQuery(out.toByteArray()) ?: error("query should parse")
    }

    private fun transactionIdOf(message: ByteArray): Int =
        ((message[0].toInt() and 0xFF) shl 8) or (message[1].toInt() and 0xFF)
}
