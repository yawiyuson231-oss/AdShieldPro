package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnssecMode
import java.io.IOException

/** DNSSEC evidence visible in a response. The AD bit is not local cryptographic validation. */
enum class DnssecStatus(val label: String) {
    UPSTREAM_AUTHENTICATED("Upstream resolver reports authenticated data (AD)"),
    SIGNATURES_PRESENT_UNVALIDATED("DNSSEC signatures present; not locally validated"),
    NOT_AUTHENTICATED("No authenticated DNSSEC status")
}

data class DnsResponseInspection(
    val responseCode: Int,
    val authenticatedData: Boolean,
    val checkingDisabled: Boolean,
    val answerCount: Int,
    val hasRequestedAnswer: Boolean,
    val dnssecStatus: DnssecStatus,
    val ednsVersion: Int?,
    val extendedErrorCodes: List<Int>
)

class DnsResponseValidationException(
    message: String,
    val inspection: DnsResponseInspection? = null,
    internal val healthFailure: Boolean = true
) : IOException(message)

/** Strict wire-level response validation before a packet can enter cache or reach an application. */
object DnsResponseValidator {
    fun validate(queryBytes: ByteArray, responseBytes: ByteArray, mode: DnssecMode = DnssecMode.REPORT_ONLY): DnsResponseInspection {
        val query = DnsPacketCodec.parseQuery(queryBytes) ?: fail("Original DNS question is invalid")
        return accept(inspect(query, responseBytes), mode)
    }

    /** Match the question *before* trusting TC; a retry is never triggered by an unrelated UDP reply. */
    internal fun matchingReplyFlags(query: DnsPacketCodec.ParsedDnsQuery, response: ByteArray): Int {
        if (response.size !in 12..DnsPacketCodec.MAX_DNS_WIRE_BYTES) fail("Invalid DNS message length")
        if (u16(response, 0) != query.transactionId) fail("Transaction ID mismatch")
        val flags = u16(response, 2)
        if (flags and 0x8000 == 0) fail("Upstream packet is not a response")
        if ((flags and 0x7800) != (query.flags and 0x7800)) fail("DNS opcode mismatch")
        if (flags and 0x0040 != 0) fail("Reserved DNS Z bit is set")
        if (u16(response, 4) != 1) fail("Response question count does not match query")

        // With one question there is no earlier name to compress. Compare complete wire labels
        // with ASCII case folding, not flattened strings that can confuse literal dots with separators.
        val expected = query.rawPayload
        val end = query.questionSectionEndOffset
        if (response.size < end) fail("Incomplete upstream question")
        for (i in 12 until end - 4) {
            if (foldAscii(response[i]) != foldAscii(expected[i])) fail("Response question does not match original query")
        }
        for (i in end - 4 until end) {
            if (response[i] != expected[i]) fail("Response question type or class does not match original query")
        }
        return flags
    }

    internal fun inspect(query: DnsPacketCodec.ParsedDnsQuery, response: ByteArray): DnsResponseInspection {
        val flags = matchingReplyFlags(query, response)
        if (flags and 0x0200 != 0) fail("Upstream response is truncated")
        val records = DnsPacketCodec.inspectResponseRecords(response, query.qType)
            ?: fail("Malformed DNS records, EDNS options or trailing data")
        val ad = flags and 0x0020 != 0
        return DnsResponseInspection(
            responseCode = (records.extendedRcode shl 4) or (flags and 0xF),
            authenticatedData = ad,
            checkingDisabled = flags and 0x0010 != 0,
            answerCount = u16(response, 6),
            hasRequestedAnswer = records.hasRequestedAnswer,
            dnssecStatus = when {
                ad -> DnssecStatus.UPSTREAM_AUTHENTICATED
                records.hasRrsig -> DnssecStatus.SIGNATURES_PRESENT_UNVALIDATED
                else -> DnssecStatus.NOT_AUTHENTICATED
            },
            ednsVersion = records.ednsVersion,
            extendedErrorCodes = records.extendedErrorCodes
        )
    }

    internal fun accept(reply: DnsResponseInspection, mode: DnssecMode): DnsResponseInspection {
        val rcode = reply.responseCode
        // NOERROR (including NODATA) and NXDOMAIN are usable DNS answers. Others may resolve
        // via another *configured* provider; they must not be recorded as healthy cache hits.
        if (rcode != 0 && rcode != 3) throw DnsResponseValidationException("Upstream DNS failure: ${rcodeLabel(rcode)}", reply)
        if (reply.ednsVersion != null && reply.ednsVersion != 0) {
            throw DnsResponseValidationException("Unsupported EDNS version ${reply.ednsVersion}", reply)
        }
        if (mode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS && rcode == 0 && reply.answerCount > 0 && !reply.authenticatedData) {
            throw DnsResponseValidationException("Strict DNSSEC policy rejected an answer without AD", reply, healthFailure = false)
        }
        return reply
    }

    internal fun rcodeLabel(code: Int): String = when (code) {
        0 -> "NOERROR"
        1 -> "FORMERR"
        2 -> "SERVFAIL"
        3 -> "NXDOMAIN"
        4 -> "NOTIMP"
        5 -> "REFUSED"
        16 -> "BADVERS"
        else -> "RCODE $code"
    }

    private fun foldAscii(b: Byte): Int = (b.toInt() and 0xFF).let { if (it in 'A'.code..'Z'.code) it + 32 else it }

    private fun u16(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun fail(message: String): Nothing = throw DnsResponseValidationException(message)
}
