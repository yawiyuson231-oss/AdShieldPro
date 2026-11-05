package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnssecMode
import java.io.IOException

/** DNSSEC evidence visible in a response. AD is upstream validation evidence, not local chain validation. */
enum class DnssecStatus(val label: String) {
    UPSTREAM_AUTHENTICATED("Authenticated by upstream resolver (AD)"),
    SIGNATURES_PRESENT_UNVALIDATED("DNSSEC signatures present; not locally validated"),
    NOT_AUTHENTICATED("No authenticated DNSSEC status")
}

data class DnsResponseInspection(
    val responseCode: Int,
    val authenticatedData: Boolean,
    val checkingDisabled: Boolean,
    val truncated: Boolean,
    val answerCount: Int,
    val dnssecStatus: DnssecStatus
)

class DnsResponseValidationException(message: String) : IOException(message)

/** Strict wire-level response validation before a packet can enter cache or reach an application. */
object DnsResponseValidator {
    fun validate(queryBytes: ByteArray, responseBytes: ByteArray, mode: DnssecMode = DnssecMode.REPORT_ONLY): DnsResponseInspection {
        if (queryBytes.size < 12 || responseBytes.size < 12) {
            throw DnsResponseValidationException("DNS message shorter than header")
        }
        val query = DnsPacketCodec.parseQuery(queryBytes)
            ?: throw DnsResponseValidationException("Original DNS question is invalid")
        val responseId = u16(responseBytes, 0)
        val queryId = u16(queryBytes, 0)
        if (responseId != queryId) fail("Transaction ID mismatch")
        val flags = u16(responseBytes, 2)
        if (flags and 0x8000 == 0) fail("Upstream packet is not a response")
        val queryOpcode = (u16(queryBytes, 2) ushr 11) and 0xF
        val responseOpcode = (flags ushr 11) and 0xF
        if (queryOpcode != responseOpcode) fail("DNS opcode mismatch")
        if (flags and 0x0040 != 0) fail("Reserved DNS Z bit is set")
        if (flags and 0x0200 != 0) fail("Truncated upstream response requires TCP transport")
        if (u16(responseBytes, 4) != 1) fail("Response question count does not match query")

        // Parse both questions through the same strict codec; domain case is insignificant.
        val responseQuestion = parseResponseQuestion(responseBytes)
        if (!responseQuestion.questionDomain.equals(query.questionDomain, ignoreCase = true) ||
            responseQuestion.qType != query.qType || responseQuestion.qClass != query.qClass
        ) {
            fail("Response question does not match original query")
        }

        val rcode = flags and 0xF
        if (rcode == 2 || rcode == 1 || rcode == 4) {
            throw DnsResponseValidationException("Upstream DNS failure RCODE=$rcode")
        }
        val answerCount = u16(responseBytes, 6)
        val recordTypes = DnsPacketCodec.inspectResponseRecordTypes(responseBytes)
            ?: throw DnsResponseValidationException("Malformed DNS resource records or trailing data")
        val hasRrsig = 46 in recordTypes
        val ad = flags and 0x0020 != 0
        val status = when {
            ad -> DnssecStatus.UPSTREAM_AUTHENTICATED
            hasRrsig -> DnssecStatus.SIGNATURES_PRESENT_UNVALIDATED
            else -> DnssecStatus.NOT_AUTHENTICATED
        }
        if (mode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS && rcode == 0 && answerCount > 0 && !ad) {
            throw DnsResponseValidationException("Strict DNSSEC policy rejected an answer without AD")
        }
        return DnsResponseInspection(
            responseCode = rcode,
            authenticatedData = ad,
            checkingDisabled = flags and 0x0010 != 0,
            truncated = false,
            answerCount = answerCount,
            dnssecStatus = status
        )
    }

    private fun parseResponseQuestion(response: ByteArray): DnsPacketCodec.ParsedDnsQuery {
        val queryCopy = response.copyOf()
        // The query parser expects QR=0; question fields and counts remain unchanged.
        val flags = u16(queryCopy, 2) and 0x7FFF
        queryCopy[2] = (flags ushr 8).toByte()
        queryCopy[3] = flags.toByte()
        return DnsPacketCodec.parseQuery(queryCopy)
            ?: throw DnsResponseValidationException("Malformed response question")
    }

    private fun u16(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun fail(message: String): Nothing = throw DnsResponseValidationException(message)
}
