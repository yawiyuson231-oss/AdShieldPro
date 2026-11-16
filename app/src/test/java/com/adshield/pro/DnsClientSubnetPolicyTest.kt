package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * EDNS Client Subnet hygiene: the app only forwards a client subnet for streaming hosts the
 * user opted into, and normalises every other outgoing query.
 */
class DnsClientSubnetPolicyTest {

    @Test
    fun testClientSubnetOptionIsRemovedAndOtherOptionsSurvive() {
        val cookie = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00.toByte())
        val query = buildEdnsQuery(includeClientSubnet = true, cookie = cookie)
        val expected = buildEdnsQuery(includeClientSubnet = false, cookie = cookie)

        val stripped = DnsPacketCodec.stripEdnsClientSubnet(query) ?: error("query should be walkable")

        assertTrue(expected.contentEquals(stripped))
        // Header flags stay identical, and the OPT record keeps its UDP payload size (1232) and
        // its DNSSEC OK bit; only the client-subnet option is gone.
        assertTrue(query[2] == stripped[2] && query[3] == stripped[3])
        assertTrue(stripped[38].toInt() == 0x04 && stripped[39].toInt() == 0xD0)
        assertTrue(stripped[42].toInt() == 0x80)
        assertTrue(stripped.size < query.size)
    }

    @Test
    fun testQueryWithoutClientSubnetIsReturnedUntouched() {
        val query = buildEdnsQuery(includeClientSubnet = false, cookie = null)
        val stripped = DnsPacketCodec.stripEdnsClientSubnet(query) ?: error("query should be walkable")
        assertTrue(query === stripped)
    }

    @Test
    fun testMalformedQueryIsRejectedInsteadOfHalfRewritten() {
        val query = buildEdnsQuery(includeClientSubnet = true, cookie = null)
        assertNull(DnsPacketCodec.stripEdnsClientSubnet(query.copyOf(query.size - 2)))
        assertNull(DnsPacketCodec.stripEdnsClientSubnet(ByteArray(6)))
    }

    @Test
    fun testClientSubnetIsForwardedOnlyForOptedInStreamingHosts() {
        val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)
        assertTrue(UpstreamDnsResolver.forwardsClientSubnet("rr1---sn-abc123.googlevideo.com", config))
        assertFalse(UpstreamDnsResolver.forwardsClientSubnet("www.example.com", config))
        assertFalse(
            UpstreamDnsResolver.forwardsClientSubnet(
                "rr1---sn-abc123.googlevideo.com",
                config.copy(preferGeoAccurateMediaDns = false)
            )
        )
    }

    /** A minimal query: one A question plus an EDNS0 OPT record carrying optional options. */
    private fun buildEdnsQuery(includeClientSubnet: Boolean, cookie: ByteArray?): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(0x4321) // transaction id
        u16(0x0100) // RD
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(0) // NSCOUNT
        u16(1) // ARCOUNT
        listOf("media", "example", "com").forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        u16(DnsPacketCodec.TYPE_A)
        u16(DnsPacketCodec.CLASS_IN)

        val options = ByteArrayOutputStream()
        if (includeClientSubnet) {
            // RFC 7871: family 1 (IPv4), source prefix 24, scope 0, three address bytes.
            u16(DnsPacketCodec.EDNS_OPTION_CLIENT_SUBNET)
            u16(7) // option length: family(2) + source(1) + scope(1) + 3 address bytes
            u16(1) // address family: IPv4
            options.write(24)  // source prefix length
            options.write(0)   // scope prefix length
            options.write(203)
            options.write(0)
            options.write(113)
        }
        if (cookie != null) {
            u16(10) // COOKIE option code
            u16(cookie.size)
            options.write(cookie)
        }
        val optionBytes = options.toByteArray()

        out.write(0) // root owner name for OPT
        u16(DnsPacketCodec.TYPE_OPT)
        u16(1232) // requester UDP payload size
        out.write(0); out.write(0); out.write(0x80); out.write(0) // DO bit, ext RCODE/version 0
        u16(optionBytes.size)
        out.write(optionBytes)
        return out.toByteArray()
    }
}
