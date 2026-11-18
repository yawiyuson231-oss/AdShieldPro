package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.DnssecStatus
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

class DnsCacheLifetimeTest {
    @Test
    fun shortTtlIsNotExtendedAndNoLifetimeMeansNoCache() {
        val query = query()
        val short = DnsPacketCodec.buildBlockedResponse(query, true, ttlSeconds = 5)
        assertEquals(5, DnsPacketCodec.extractResponseTtlSeconds(short))
        assertNull(DnsPacketCodec.prepareCachedResponse(DnsPacketCodec.buildBlockedResponse(query, true, ttlSeconds = 0)))
        assertNull(DnsPacketCodec.prepareCachedResponse(DnsPacketCodec.buildBlockedResponse(query, false)))
        assertNull(DnsPacketCodec.prepareCachedResponse(DnsPacketCodec.buildNoDataResponse(query)))
        assertNull(DnsPacketCodec.prepareCachedResponse(short.copyOf(short.size - 1)))
    }

    @Test
    fun replayAgesRealTtlFieldsWithoutTouchingOptOrOriginalWire() {
        val query = query()
        val opt = byteArrayOf(0, 0, 41, 4, 0xd0.toByte(), 0, 0, 0x80.toByte(), 0, 0, 0)
        val answer = (DnsPacketCodec.buildBlockedResponse(query, true, ttlSeconds = 10) + opt).also { it[11] = 1 }
        val cached = requireNotNull(DnsPacketCodec.prepareCachedResponse(answer))
        val replay = cached.forQuery(transactionId = 0xabcd, ageMs = 2_050)
        assertEquals(0xabcd, UpstreamDnsResolver.transactionIdOf(replay))
        assertEquals(7, unsignedTtlAt(replay, query.questionSectionEndOffset + 6))
        assertEquals(10, unsignedTtlAt(answer, query.questionSectionEndOffset + 6))
        assertArrayEquals(opt, replay.takeLast(opt.size).toByteArray())
        assertFalse(cached.isExpired(9_999))
        assertTrue(cached.isExpired(10_000))
    }

    @Test
    fun negativeLifetimeComesFromSoaAndIsAgedBeforeReplay() {
        val query = query()
        val negative = DnsPacketCodec.buildBlockedResponse(query, false).also { it[9] = 1 }
        val soa = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                writeShort(0xc00c) // owner
                writeShort(DnsPacketCodec.TYPE_SOA)
                writeShort(DnsPacketCodec.CLASS_IN)
                writeInt(40) // SOA RR TTL
                writeShort(24)
                writeShort(0xc00c) // MNAME
                writeShort(0xc00c) // RNAME
                for (field in intArrayOf(1, 60, 60, 300, 7)) writeInt(field)
            }
        }.toByteArray()
        val answer = negative + soa
        val cached = requireNotNull(DnsPacketCodec.prepareCachedResponse(answer))
        assertEquals(7, cached.lifetimeSeconds)
        val reply = cached.forQuery(transactionId = 8, ageMs = 3_000)
        assertEquals(4, unsignedTtlAt(reply, query.questionSectionEndOffset + 6))
        assertEquals(7, unsignedTtlAt(reply, reply.size - 4)) // SOA.MINIMUM, not the RR header TTL
        assertTrue(cached.isExpired(7_000))
        assertNull(DnsPacketCodec.prepareCachedResponse(answer.copyOf().also { it[it.lastIndex] = 0 }))
    }

    @Test
    fun resolverReusesOnlyRemainingLifetimeAndPreservesDnssecEvidence() = runBlocking {
        val time = AtomicLong(100_000)
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.cacheClockMs = time::get
        var upstreamCalls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            upstreamCalls++
            DnsPacketCodec.buildBlockedResponse(parsed, true, ttlSeconds = 5).also {
                it[3] = (it[3].toInt() or 0x20).toByte() // AD from the fixture upstream
            }
        }
        val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)
        val first = resolver.resolve(query(1), config)
        time.addAndGet(1_200)
        val nextQuery = query(2)
        val cached = resolver.resolve(nextQuery, config)
        assertFalse(first.fromCache)
        assertTrue(cached.fromCache)
        assertEquals(1, upstreamCalls)
        assertEquals(2, UpstreamDnsResolver.transactionIdOf(cached.responseBytes))
        assertEquals(3, unsignedTtlAt(cached.responseBytes, nextQuery.questionSectionEndOffset + 6))
        assertEquals(first.providerId, cached.providerId)
        assertEquals(DnssecStatus.UPSTREAM_AUTHENTICATED, cached.dnssecStatus)
        time.addAndGet(3_800)
        assertFalse(resolver.resolve(query(3), config).fromCache)
        assertEquals(2, upstreamCalls)
        assertEquals(0, resolver.trimExpiredAndExcessCache()) // newly received replacement
        time.addAndGet(5_000)
        assertEquals(1, resolver.trimExpiredAndExcessCache())
        assertEquals(0, resolver.getCacheSize())
    }

    @Test
    fun customDohPathsAndQueriesWithDifferentCaseDoNotShareCacheKeys() {
        val original = DnsResolverConfig(preset = DnsProviderPreset.CUSTOM, protocol = DnsProtocol.DOH,
            customDohUrl = "https://resolver.example/Private?profile=GroupA")
        val other = original.copy(customDohUrl = "https://resolver.example/private?profile=groupa")
        assertNotEquals(UpstreamDnsResolver.buildCacheKey(query(), original), UpstreamDnsResolver.buildCacheKey(query(), other))
    }

    @Test
    fun resolverDoesNotReplayAcrossCheckingDisabledOrEdnsDoFlags() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.cacheClockMs = { 100_000L }
        var upstreamCalls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            upstreamCalls++
            DnsPacketCodec.buildBlockedResponse(parsed, true, ttlSeconds = 5)
        }
        val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)
        assertFalse(resolver.resolve(query(1, dnssecOk = false), config).fromCache)
        assertFalse(resolver.resolve(query(2, checkingDisabled = true, dnssecOk = false), config).fromCache)
        assertFalse(resolver.resolve(query(3, dnssecOk = true), config).fromCache)
        assertTrue(resolver.resolve(query(4, dnssecOk = false), config).fromCache)
        assertTrue(resolver.resolve(query(5, checkingDisabled = true, dnssecOk = false), config).fromCache)
        assertTrue(resolver.resolve(query(6, dnssecOk = true), config).fromCache)
        assertEquals(3, upstreamCalls)
    }

    private fun query(id: Int = 1, checkingDisabled: Boolean = false, dnssecOk: Boolean? = null): DnsPacketCodec.ParsedDnsQuery {
        val bytes = byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, if (checkingDisabled) 0x10 else 0,
            0, 1, 0, 0, 0, 0, 0, if (dnssecOk == null) 0 else 1,
            1, 'a'.code.toByte(), 4, 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), 0,
            0, 1, 0, 1)
        val wire = if (dnssecOk == null) bytes else bytes +
            byteArrayOf(0, 0, 41, 4, 0xd0.toByte(), 0, 0, if (dnssecOk) 0x80.toByte() else 0, 0, 0, 0)
        return requireNotNull(DnsPacketCodec.parseQuery(wire))
    }

    private fun unsignedTtlAt(wire: ByteArray, offset: Int): Int = ByteBuffer.wrap(wire, offset, 4).int
}
