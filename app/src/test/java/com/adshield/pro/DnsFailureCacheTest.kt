package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsFailureCache
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * RFC 2308 §7.1: a failure may be remembered, briefly, so a burst of lookups against a dead
 * resolver fails fast instead of re-walking the whole provider plan for every question.
 */
class DnsFailureCacheTest {

    private val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)

    @Test
    fun testAFailureIsRememberedOnlyForItsWindow() {
        var now = 1_000L
        val cache = DnsFailureCache(ttlMs = 15_000L, clock = { now })
        assertFalse(cache.isFailing("key"))
        cache.recordFailure("key")
        assertEquals(15_000L, cache.remainingMs("key"))
        now += 14_999L
        assertTrue(cache.isFailing("key"))
        now += 1L
        assertFalse("the failure expires exactly at its deadline", cache.isFailing("key"))
        assertEquals(0L, cache.remainingMs("key"))
        assertEquals("an expired entry is dropped rather than kept", 0, cache.size())
    }

    @Test
    fun testTheCacheStaysBoundedAndDropsTheOldestFailureFirst() {
        var now = 0L
        val cache = DnsFailureCache(ttlMs = 15_000L, maxEntries = 3, clock = { now })
        repeat(3) { index ->
            now += 1L
            cache.recordFailure("key$index")
        }
        assertEquals(3, cache.size())
        now += 1L
        cache.recordFailure("key-new")
        assertEquals(3, cache.size())
        assertFalse("the failure closest to expiry is evicted", cache.isFailing("key0"))
        assertTrue(cache.isFailing("key1"))
        assertTrue(cache.isFailing("key-new"))
    }

    @Test
    fun testClearRemovesOnlyWhatItIsGiven() {
        val cache = DnsFailureCache(clock = { 0L })
        cache.recordFailure("a")
        cache.recordFailure("b")
        cache.clear("a")
        assertFalse(cache.isFailing("a"))
        assertTrue(cache.isFailing("b"))
        cache.clearAll()
        assertEquals(0, cache.size())
    }

    @Test
    fun testAResolverAnswersFromTheFailureCacheWithoutTouchingTheNetwork() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        var calls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { _, _, _ ->
            calls++
            throw IOException("upstream down")
        }

        val first = resolver.resolve(query("dead.example.com"), config)
        assertTrue("the first lookup must fail closed", first.protocolUsed.startsWith("SERVFAIL"))
        assertFalse("the first lookup really tried the plan", first.protocolUsed.contains("cached failure"))
        assertTrue("the plan must have been attempted", calls > 0)
        val callsAfterFirst = calls

        val second = resolver.resolve(query("dead.example.com"), config)
        assertTrue(second.protocolUsed.contains("cached failure"))
        assertTrue("a remembered failure is still answered from cache", second.fromCache)
        assertEquals("the second lookup must not reach the network", callsAfterFirst, calls)

        resolver.resolve(query("other.example.com"), config)
        assertTrue("a different question must not be suppressed", calls > callsAfterFirst)
    }

    @Test
    fun testClearCacheForgetsRememberedFailuresSoRecoveryIsImmediate() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        var failing = true
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            if (failing) throw IOException("upstream down")
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = true)
        }
        val name = "recovered.example.com"
        assertTrue(resolver.resolve(query(name), config).protocolUsed.startsWith("SERVFAIL"))
        assertTrue("the failure must be remembered", resolver.failureCache.size() > 0)

        resolver.clearCache()
        assertEquals("clearing the cache clears remembered failures too", 0, resolver.failureCache.size())

        failing = false
        val recovered = resolver.resolve(query(name), config)
        assertFalse("a forgotten failure must not block a real answer", recovered.protocolUsed.contains("cached failure"))
        assertTrue("the recovered answer is a normal cache hit", resolver.resolve(query(name), config).fromCache)
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
}
