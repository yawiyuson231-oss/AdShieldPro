package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicInteger

/**
 * The cache is bounded by payload bytes as well as by entry count, so a burst of large answers
 * cannot grow it into device memory, and the entries that survive are the most recently used.
 */
class DnsCacheBudgetTest {

    private val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)

    @Test
    fun testCacheStaysInsideItsByteBudget() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.cacheByteBudget = 300
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = false)
        }

        repeat(20) { index ->
            resolver.resolve(query("budget-$index.example.com"), config)
        }

        assertTrue(
            "cache holds ${resolver.getCacheBytes()} bytes, budget is 300",
            resolver.getCacheBytes() <= 300
        )
        assertTrue("the entry ceiling alone would have kept 20 entries", resolver.getCacheSize() < 20)
        assertTrue("something must survive a burst", resolver.getCacheSize() >= 1)
    }

    @Test
    fun testEvictionDropsTheLeastRecentlyUsedEntryFirst() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.cacheByteBudget = 300
        val calls = AtomicInteger()
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            calls.incrementAndGet()
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = false)
        }

        repeat(20) { index ->
            resolver.resolve(query("lru-$index.example.com"), config)
        }
        val afterBurst = calls.get()
        assertEquals("each new name is one upstream query", 20, afterBurst)

        // The newest entries are still cached...
        resolver.resolve(query("lru-19.example.com"), config)
        assertEquals("the most recent answer must still be a cache hit", afterBurst, calls.get())

        // ...and the oldest ones were evicted, so they are queried again.
        resolver.resolve(query("lru-0.example.com"), config)
        assertEquals("the eldest answer must have been evicted", afterBurst + 1, calls.get())
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
