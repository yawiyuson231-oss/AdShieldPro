package com.adshield.pro

import com.adshield.pro.engine.dns.DnsPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * RFC 2308: a negative answer is cached for `min(SOA TTL, SOA MINIMUM)`, clamped to the same
 * bounds as a positive answer, and falls back to a short lifetime when no SOA is present.
 */
class DnsNegativeCacheTtlTest {

    @Test
    fun testNxdomainUsesTheSmallerOfSoaTtlAndMinimum() {
        val response = buildNegativeResponse(rcode = 3, soaTtl = 600, soaMinimum = 300)
        assertEquals(300, DnsPacketCodec.extractResponseTtlSeconds(response))
    }

    @Test
    fun testNothingNegativeIsCachedLongerThanThePositiveCeiling() {
        val response = buildNegativeResponse(rcode = 3, soaTtl = 86_400, soaMinimum = 86_400)
        assertEquals(1800, DnsPacketCodec.extractResponseTtlSeconds(response))
    }

    @Test
    fun testNodataUsesTheSoaLifetimeToo() {
        val response = buildNegativeResponse(rcode = 0, soaTtl = 900, soaMinimum = 120)
        assertEquals(120, DnsPacketCodec.extractResponseTtlSeconds(response))
    }

    @Test
    fun testNegativeAnswersWithoutSoaFallBackToAShortLifetime() {
        val withoutSoa = buildNegativeResponse(rcode = 3, soaTtl = 0, soaMinimum = 0, includeSoa = false)
        assertEquals(30, DnsPacketCodec.extractResponseTtlSeconds(withoutSoa))
        // Truncated authority section: never guess, fall back.
        val truncated = buildNegativeResponse(rcode = 3, soaTtl = 600, soaMinimum = 300)
        assertEquals(30, DnsPacketCodec.extractResponseTtlSeconds(truncated.copyOf(truncated.size - 6)))
    }

    /** One question plus (optionally) one authority SOA record. */
    private fun buildNegativeResponse(
        rcode: Int,
        soaTtl: Int,
        soaMinimum: Int,
        includeSoa: Boolean = true
    ): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        fun u32(value: Long) {
            out.write(((value ushr 24) and 0xFF).toInt())
            out.write(((value ushr 16) and 0xFF).toInt())
            out.write(((value ushr 8) and 0xFF).toInt())
            out.write((value and 0xFF).toInt())
        }
        fun domain(name: String) {
            name.split('.').forEach { label ->
                val bytes = label.toByteArray(Charsets.US_ASCII)
                out.write(bytes.size)
                out.write(bytes)
            }
            out.write(0)
        }

        u16(0x5151)
        u16(0x8180 or rcode) // QR, RD, RA and the response code
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(if (includeSoa) 1 else 0) // NSCOUNT
        u16(0) // ARCOUNT
        domain("missing.example.com")
        u16(DnsPacketCodec.TYPE_A)
        u16(DnsPacketCodec.CLASS_IN)

        if (includeSoa) {
            domain("example.com") // zone owner
            u16(DnsPacketCodec.TYPE_SOA)
            u16(DnsPacketCodec.CLASS_IN)
            u32(soaTtl.toLong())
            val rdata = ByteArrayOutputStream()
            fun rdomain(name: String) {
                name.split('.').forEach { label ->
                    val bytes = label.toByteArray(Charsets.US_ASCII)
                    rdata.write(bytes.size)
                    rdata.write(bytes)
                }
                rdata.write(0)
            }
            fun r32(value: Long) {
                rdata.write(((value ushr 24) and 0xFF).toInt())
                rdata.write(((value ushr 16) and 0xFF).toInt())
                rdata.write(((value ushr 8) and 0xFF).toInt())
                rdata.write((value and 0xFF).toInt())
            }
            rdomain("ns1.example.com")   // MNAME
            rdomain("hostmaster.example.com") // RNAME
            r32(2026010101L) // serial
            r32(7200)        // refresh
            r32(3600)        // retry
            r32(1_209_600)   // expire
            r32(soaMinimum.toLong()) // MINIMUM
            val rdataBytes = rdata.toByteArray()
            // The RDLENGTH belongs to the record header in the message, not to the RDATA itself.
            u16(rdataBytes.size)
            out.write(rdataBytes)
        }
        return out.toByteArray()
    }
}
