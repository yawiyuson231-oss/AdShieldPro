package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsRebindingGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * A public name answering with a private address is the shape of a rebinding attack. The guard
 * has to catch every private range the device can reach, and stay out of the way of the answers
 * that are legitimately private.
 */
class DnsRebindingGuardTest {

    @Test
    fun testPrivateIpv4AnswersAreDetected() {
        mapOf(
            byteArrayOf(192.toByte(), 168.toByte(), 1, 1) to "private (RFC 1918)",
            byteArrayOf(10, 0, 0, 5) to "private (RFC 1918)",
            byteArrayOf(172.toByte(), 16, 5, 4) to "private (RFC 1918)",
            byteArrayOf(127, 0, 0, 1) to "loopback",
            byteArrayOf(169.toByte(), 254.toByte(), 1, 1) to "link-local",
            byteArrayOf(100, 64, 0, 7) to "carrier-grade NAT",
            byteArrayOf(0xFF.toByte(), 2, 0, 1) to "multicast or reserved"
        ).forEach { (bytes, expectedRange) ->
            val finding = DnsRebindingGuard.firstPrivateAnswer(
                buildResponse(DnsPacketCodec.TYPE_A, bytes)
            )
            assertNotNull("expected a finding for ${bytes.toList()}", finding)
            assertEquals(expectedRange, finding!!.range)
            assertEquals("IPv4", finding.family)
        }
    }

    @Test
    fun testPublicIpv4AnswersAreLeftAlone() {
        listOf(
            byteArrayOf(93, 184.toByte(), 216.toByte(), 34),
            byteArrayOf(8, 8, 8, 8),
            byteArrayOf(172.toByte(), 32, 0, 1) // just outside 172.16/12
        ).forEach { bytes ->
            assertNull(
                "public ${bytes.toList()} must not be flagged",
                DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_A, bytes))
            )
        }
    }

    @Test
    fun testPrivateIpv6AnswersAreDetected() {
        val loopback = ByteArray(16).also { it[15] = 1 }
        val linkLocal = ByteArray(16).also { it[0] = 0xFE.toByte(); it[1] = 0x80.toByte() }
        val uniqueLocal = ByteArray(16).also { it[0] = 0xFD.toByte() }
        val multicast = ByteArray(16).also { it[0] = 0xFF.toByte() }
        val public = byteArrayOf(
            0x26, 0x06, 0x47, 0x00,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0x11, 0x11
        )

        assertEquals("loopback", DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_AAAA, loopback))?.range)
        assertEquals("link-local", DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_AAAA, linkLocal))?.range)
        assertEquals("unique local (RFC 4193)", DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_AAAA, uniqueLocal))?.range)
        assertEquals("multicast", DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_AAAA, multicast))?.range)
        assertNull(DnsRebindingGuard.firstPrivateAnswer(buildResponse(DnsPacketCodec.TYPE_AAAA, public)))
    }

    @Test
    fun testLocalNamesAreExempt() {
        listOf("router.local", "nas.lan", "printer.home.arpa", "db.internal", "myhost", "1.0.0.127.in-addr.arpa")
            .forEach { assertTrue("$it must be treated as local", DnsRebindingGuard.isLocalName(it)) }
        listOf("example.com", "cdn.example.net", "attacker.example")
            .forEach { assertFalse("$it must not be treated as local", DnsRebindingGuard.isLocalName(it)) }
    }

    @Test
    fun testOnlyTheAggressiveModesEnforceTheGuard() {
        assertTrue(ProtectionMode.STRICT.enforceRebindingGuard)
        assertTrue(ProtectionMode.CUSTOM.enforceRebindingGuard)
        assertFalse(ProtectionMode.STANDARD.enforceRebindingGuard)
        assertFalse(ProtectionMode.PRIVACY.enforceRebindingGuard)
    }

    @Test
    fun testUnwalkableAnswersAreNeverJudged() {
        val response = buildResponse(DnsPacketCodec.TYPE_A, byteArrayOf(10, 0, 0, 5))
        assertNull("truncated responses must not be judged", DnsRebindingGuard.firstPrivateAnswer(response.copyOf(response.size - 3)))
        assertNull(
            "an answer with no address records carries nothing to judge",
            DnsRebindingGuard.firstPrivateAnswer(buildResponseWithNoAnswers())
        )
    }

    /** One A or AAAA answer for `public.example`. */
    private fun buildResponse(type: Int, rdata: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(0x6161)
        u16(0x8180)
        u16(1)
        u16(1)
        u16(0)
        u16(0)
        domain(out, "public.example")
        u16(type)
        u16(DnsPacketCodec.CLASS_IN)
        domain(out, "public.example")
        u16(type)
        u16(DnsPacketCodec.CLASS_IN)
        out.write(0); out.write(0); out.write(0x00); out.write(60)
        u16(rdata.size)
        out.write(rdata)
        return out.toByteArray()
    }

    private fun buildResponseWithNoAnswers(): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(0x6161)
        u16(0x8180)
        u16(1)
        u16(0)
        u16(0)
        u16(0)
        domain(out, "public.example")
        u16(DnsPacketCodec.TYPE_A)
        u16(DnsPacketCodec.CLASS_IN)
        return out.toByteArray()
    }

    private fun domain(out: ByteArrayOutputStream, name: String) {
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }
}
