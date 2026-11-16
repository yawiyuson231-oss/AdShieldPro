package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Single-flight: a burst of lookups for the same name must cost one upstream query, and a
 * coalesced answer must still be correct for the client that receives it.
 */
class DnsQueryCoalescingTest {

    private val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)

    @Test
    fun testABurstOfIdenticalLookupsCostsOneUpstreamQuery() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val calls = AtomicInteger()
        val release = CountDownLatch(1)
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            calls.incrementAndGet()
            release.await(3, TimeUnit.SECONDS)
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = false)
        }

        val query = query("burst.example.com", transactionId = 0x4A2B)
        val jobs = (1..6).map { async(Dispatchers.IO) { resolver.resolve(query, config) } }
        delay(200) // let the leader reach the transport before the followers arrive
        release.countDown()
        val results = jobs.awaitAll()

        assertEquals("six identical lookups must cost one upstream query", 1, calls.get())
        assertTrue("every caller must receive an answer", results.all { it.responseBytes.size > 12 })
        assertTrue("followers must be marked as coalesced", results.count { it.coalesced } >= 1)
    }

    @Test
    fun testCoalescedAnswerIsRewrittenForTheRequestingTransaction() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val release = CountDownLatch(1)
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            release.await(3, TimeUnit.SECONDS)
            DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = false)
        }

        val leaderQuery = query("shared.example.com", transactionId = 0x1111)
        val followerQuery = query("shared.example.com", transactionId = 0x2222)
        val leader = async(Dispatchers.IO) { resolver.resolve(leaderQuery, config) }
        delay(150)
        val follower = async(Dispatchers.IO) { resolver.resolve(followerQuery, config) }
        delay(150)
        release.countDown()

        leader.await()
        val followerResult = follower.await()
        assertEquals(0x2222, transactionIdOf(followerResult.responseBytes))
    }

    @Test
    fun testAFailedUpstreamIsSharedInsteadOfRetriedByEveryCaller() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        val calls = AtomicInteger()
        val release = CountDownLatch(1)
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { _, _, _ ->
            calls.incrementAndGet()
            release.await(3, TimeUnit.SECONDS)
            throw java.io.IOException("upstream down")
        }

        val query = query("down.example.com")
        val jobs = (1..3).map { async(Dispatchers.IO) { resolver.resolve(query, config) } }
        delay(200)
        release.countDown()
        val results = jobs.awaitAll()

        assertEquals("the fail-closed SERVFAIL is shared, not re-queried", 1, calls.get())
        assertTrue("a SERVFAIL answer is still a response", results.all { it.responseBytes.size >= 12 })
        assertTrue("the failure is reported as SERVFAIL", results.all { it.protocolUsed.startsWith("SERVFAIL") })
    }

    private fun query(domain: String, transactionId: Int = 0x4A2B): DnsPacketCodec.ParsedDnsQuery {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(transactionId)
        u16(0x0100) // RD
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
