package com.adshield.pro

import com.adshield.pro.engine.dns.DnsPacketCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Cache-hit TTL ageing.
 *
 * A DNS client honours the TTL it is handed. If a cache hit replayed the original lifetime, every
 * device behind this resolver would keep a stale answer for longer than the upstream allowed, so a
 * hit must report the seconds the entry has left. EDNS0 OPT records must never be touched: their
 * TTL field is not a lifetime.
 */
class DnsResponseCacheTest {

    private class BuiltMessage(
        val bytes: ByteArray,
        val ttlOffsets: List<Int>,
        val optTtlOffset: Int
    )

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }

    private fun encodeName(out: ByteArrayOutputStream, name: String) {
        name.trim('.').split('.').filter { it.isNotEmpty() }.forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    /** Builds a response with one A answer, one CNAME answer, and one EDNS0 OPT record. */
    private fun build(): BuiltMessage {
        val out = ByteArrayOutputStream()
        out.write(0x12); out.write(0x34)
        out.write(0x81); out.write(0x80)
        writeU16(out, 1) // QDCOUNT
        writeU16(out, 2) // ANCOUNT
        writeU16(out, 0) // NSCOUNT
        writeU16(out, 1) // ARCOUNT (the OPT record)
        encodeName(out, "shop.example")
        writeU16(out, 1) // A
        writeU16(out, 1) // IN

        val ttlOffsets = mutableListOf<Int>()

        // Answer 1: A 203.0.113.10, TTL 300
        writeU16(out, 0xC00C)
        writeU16(out, 1)
        writeU16(out, 1)
        ttlOffsets += out.size()
        writeU32(out, 300)
        writeU16(out, 4)
        out.write(byteArrayOf(203.toByte(), 0, 113, 10))

        // Answer 2: CNAME tracker.example, TTL 300
        writeU16(out, 0xC00C)
        writeU16(out, 5)
        writeU16(out, 1)
        ttlOffsets += out.size()
        writeU32(out, 300)
        val target = ByteArrayOutputStream().also { encodeName(it, "tracker.example") }.toByteArray()
        writeU16(out, target.size)
        out.write(target)

        // Additional: OPT, root owner, class 4096, TTL carries flags (0x00008000 = DO bit)
        out.write(0)
        writeU16(out, 41)
        writeU16(out, 4096)
        val optTtlOffset = out.size()
        writeU32(out, 0x8000)
        writeU16(out, 0)

        return BuiltMessage(out.toByteArray(), ttlOffsets, optTtlOffset)
    }

    private fun readU32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xFF) shl 24) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
            (bytes[offset + 3].toLong() and 0xFF)

    @Test
    fun testCachedTtlsAreRewrittenToRemainingLifetime() {
        val built = build()
        val aged = DnsPacketCodec.rewriteResponseTtls(built.bytes, 42) ?: error("rewrite rejected a valid message")

        assertEquals("rewriting must not resize the message", built.bytes.size, aged.size)
        built.ttlOffsets.forEach { offset ->
            assertEquals("every answer TTL must age", 42L, readU32(aged, offset))
        }
        assertEquals(
            "the stored response must not be mutated in place",
            300L,
            readU32(built.bytes, built.ttlOffsets.first())
        )
    }

    @Test
    fun testOptRecordTtlIsLeftAlone() {
        val built = build()
        val aged = DnsPacketCodec.rewriteResponseTtls(built.bytes, 15) ?: error("rewrite rejected a valid message")
        assertEquals(
            "an OPT TTL carries flags, not a lifetime",
            0x8000L,
            readU32(aged, built.optTtlOffset)
        )
    }

    @Test
    fun testTtlIsClampedToAtLeastOneSecond() {
        val built = build()
        listOf(0, -5).forEach { requested ->
            val aged = DnsPacketCodec.rewriteResponseTtls(built.bytes, requested)
                ?: error("rewrite rejected a valid message")
            assertEquals("a zero or negative lifetime is not servable", 1L, readU32(aged, built.ttlOffsets.first()))
        }
    }

    @Test
    fun testRewriterRejectsMalformedMessages() {
        val built = build()
        val original = built.bytes.copyOf()
        assertNull("truncated records must not be half-rewritten", DnsPacketCodec.rewriteResponseTtls(built.bytes.copyOf(built.bytes.size - 2), 60))
        assertNull("trailing bytes are not a DNS message", DnsPacketCodec.rewriteResponseTtls(built.bytes + byteArrayOf(0), 60))
        assertNull("a header-only buffer is not a message", DnsPacketCodec.rewriteResponseTtls(ByteArray(12), 60))
        assertArrayEquals(
            "rejected rewrites must not touch the stored bytes",
            original,
            built.bytes
        )
    }
}
