package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.engine.dns.DnsCnameGuard
import com.adshield.pro.engine.dns.DnsPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * CNAME-cloaking enforcement contracts.
 *
 * The filter engine only judges the queried name, so a first-party host that CNAMEs to a blocked
 * tracker would otherwise resolve. These tests pin the wire-format walk, the "never decide on
 * malformed data" rule, and the fact that only the aggressive protection modes enforce it.
 */
class DnsCnameGuardTest {

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        name.trim('.').split('.').filter { it.isNotEmpty() }.forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun resourceRecord(type: Int, rdata: ByteArray, ttl: Int = 60): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, 0xC00C) // owner name: compression pointer to the question at offset 12
        writeU16(out, type)
        writeU16(out, 1) // IN
        out.write(0); out.write(0); out.write((ttl ushr 8) and 0xFF); out.write(ttl and 0xFF)
        writeU16(out, rdata.size)
        out.write(rdata)
        return out.toByteArray()
    }

    private fun response(question: String, answers: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x12); out.write(0x34) // transaction id
        out.write(0x81); out.write(0x80) // QR=1, RD=1, RA=1, RCODE=0
        writeU16(out, 1) // QDCOUNT
        writeU16(out, answers.size) // ANCOUNT
        writeU16(out, 0) // NSCOUNT
        writeU16(out, 0) // ARCOUNT
        out.write(encodeName(question))
        writeU16(out, DnsPacketCodec.TYPE_A)
        writeU16(out, DnsPacketCodec.CLASS_IN)
        answers.forEach { out.write(it) }
        return out.toByteArray()
    }

    private fun aRecord(ip: ByteArray = byteArrayOf(203.toByte(), 0, 113, 10)) =
        resourceRecord(DnsPacketCodec.TYPE_A, ip)

    private fun cnameRecord(target: String) =
        resourceRecord(DnsPacketCodec.TYPE_CNAME, encodeName(target))

    @Test
    fun testExtractsCnameTargetsFromWireResponse() {
        val message = response(
            "metrics.shop.example",
            listOf(cnameRecord("Shop-Account.Tracker.Example"), aRecord())
        )
        val targets = DnsPacketCodec.extractCnameTargets(message)
        assertEquals(listOf("shop-account.tracker.example"), targets)

        assertNull(
            "unparseable data must never yield a target",
            DnsPacketCodec.extractCnameTargets(message + byteArrayOf(0))
        )
    }

    @Test
    fun testReturnsEmptyListWhenAnswerHasNoCname() {
        val message = response("shop.example", listOf(aRecord()))
        assertEquals(emptyList<String>(), DnsPacketCodec.extractCnameTargets(message))
    }

    @Test
    fun testRejectsMalformedAndNonResponseMessages() {
        val valid = response("metrics.shop.example", listOf(cnameRecord("tracker.example"), aRecord()))
        assertNull("truncated RDATA must be rejected", DnsPacketCodec.extractCnameTargets(valid.copyOf(valid.size - 3)))

        val notAResponse = valid.copyOf()
        notAResponse[2] = 0x01 // clear the QR bit
        assertNull("a query must not be treated as an answer", DnsPacketCodec.extractCnameTargets(notAResponse))

        assertNull("short buffers must be rejected", DnsPacketCodec.extractCnameTargets(ByteArray(8)))

        val zeroQuestions = valid.copyOf()
        zeroQuestions[4] = 0
        zeroQuestions[5] = 0
        assertNull("an answer without its question cannot be judged", DnsPacketCodec.extractCnameTargets(zeroQuestions))
    }

    @Test
    fun testGuardBlocksOnlyBlockedHopsAndRespectsHopCap() {
        val blocked = response(
            "metrics.shop.example",
            listOf(cnameRecord("tracker.example"), aRecord())
        )
        assertEquals(
            "tracker.example",
            DnsCnameGuard.firstBlockedTarget(blocked) { it == "tracker.example" }
        )
        assertNull(
            "an unblocked hop must not be reported",
            DnsCnameGuard.firstBlockedTarget(blocked) { it == "someone-else.example" }
        )

        val twoHops = response(
            "a.example",
            listOf(cnameRecord("clean.example"), cnameRecord("tracker.example"), aRecord())
        )
        assertEquals(
            "tracker.example",
            DnsCnameGuard.firstBlockedTarget(twoHops, maxTargets = 2) { it.startsWith("tracker") }
        )
        assertNull(
            "hops beyond the cap must not be trusted",
            DnsCnameGuard.firstBlockedTarget(twoHops, maxTargets = 1) { it == "tracker.example" }
        )
        assertNull(
            "garbage must never produce a block",
            DnsCnameGuard.firstBlockedTarget(byteArrayOf(1, 2, 3)) { true }
        )
    }

    @Test
    fun testOnlyAggressiveModesEnforceCloaking() {
        assertTrue(ProtectionMode.STRICT.enforceCnameCloaking)
        assertTrue(ProtectionMode.CUSTOM.enforceCnameCloaking)
        assertTrue(
            "balanced modes must not break hosts that depend on a third party",
            !ProtectionMode.STANDARD.enforceCnameCloaking && !ProtectionMode.PRIVACY.enforceCnameCloaking
        )
        // Cloaking enforcement must not change which modes sinkhole to 0.0.0.0.
        assertTrue(ProtectionMode.STRICT.blockSinkholeZeroIp && ProtectionMode.CUSTOM.blockSinkholeZeroIp)
        assertTrue(!ProtectionMode.STANDARD.blockSinkholeZeroIp && !ProtectionMode.PRIVACY.blockSinkholeZeroIp)
    }
}
