package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsResolverConfig
import java.io.ByteArrayOutputStream
import java.net.IDN
import java.security.SecureRandom

/** Real DNS diagnostics: an actual query plus measured provider health, not an external leak test. */
data class DnsDiagnosticReport(
    val domain: String,
    val successful: Boolean,
    val transportAndProvider: String,
    val latencyMs: Int,
    val dnssecStatus: DnssecStatus?,
    val responseCode: Int?,
    val answerCount: Int?,
    val outcome: String,
    val ednsVersion: Int?,
    val extendedErrorCodes: List<Int>,
    val issues: List<DnsResolverIssue>,
    val providerHealth: List<DnsProviderHealth>
)

object DnsDiagnosticQueryFactory {
    private val random = SecureRandom()

    /** Builds an A query with EDNS0 and the DNSSEC OK bit so upstream AD/RRSIG evidence can be reported. */
    fun build(domainInput: String, transactionId: Int = random.nextInt(65536)): ByteArray {
        val input = domainInput.trim().removeSuffix(".")
        require(input.length in 1..253) { "Enter a valid DNS name" }
        val domain = input.split('.').joinToString(".") {
            IDN.toASCII(it, IDN.USE_STD3_ASCII_RULES)
        }
        require(domain.isNotBlank() && domain.length <= 253) { "Enter a valid DNS name" }
        val out = ByteArrayOutputStream()
        u16(out, transactionId)
        u16(out, 0x0100) // RD
        u16(out, 1)
        u16(out, 0)
        u16(out, 0)
        u16(out, 1) // EDNS0 OPT
        domain.split('.').forEach { label ->
            require(label.isNotEmpty() && label.length <= 63) { "Invalid DNS label" }
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        u16(out, DnsPacketCodec.TYPE_A)
        u16(out, DnsPacketCodec.CLASS_IN)
        out.write(0) // root owner for OPT
        u16(out, 41) // OPT
        u16(out, 1232) // requester UDP payload size
        out.write(0); out.write(0); out.write(0x80); out.write(0) // DO bit, extended RCODE/version 0
        u16(out, 0)
        return out.toByteArray()
    }

    private fun u16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}

suspend fun UpstreamDnsResolver.runDiagnostics(domain: String, config: DnsResolverConfig): DnsDiagnosticReport {
    val wire = DnsDiagnosticQueryFactory.build(domain)
    val query = DnsPacketCodec.parseQuery(wire) ?: error("Could not construct diagnostic query")
    val result = resolve(query, config, useCache = false)
    val reply = result.inspection
    return DnsDiagnosticReport(
        domain = query.questionDomain,
        successful = reply != null,
        transportAndProvider = result.protocolUsed,
        latencyMs = result.latencyMs,
        dnssecStatus = reply?.dnssecStatus,
        responseCode = reply?.responseCode,
        answerCount = reply?.answerCount,
        outcome = when {
            reply == null -> "No usable reply (local SERVFAIL)"
            reply.responseCode == 3 -> "NXDOMAIN · upstream reports the name does not exist"
            reply.hasRequestedAnswer -> "NOERROR · A record received"
            else -> "NOERROR · no A record returned"
        },
        ednsVersion = reply?.ednsVersion,
        extendedErrorCodes = reply?.extendedErrorCodes.orEmpty(),
        issues = result.issues,
        providerHealth = providerHealthSnapshots().filter { it.protocol == config.protocol }
    )
}

/** RFC 8914 and common registered codes. Never show untrusted free text from a reply. */
internal fun dnsExtendedErrorLabel(code: Int): String {
    val detail = when (code) {
        3 -> "Stale answer"
        6 -> "DNSSEC bogus"
        7 -> "Signature expired"
        8 -> "Signature not yet valid"
        9 -> "DNSKEY missing"
        10 -> "RRSIGs missing"
        13 -> "Cached error"
        14 -> "Not ready"
        15 -> "Blocked"
        16 -> "Censored"
        17 -> "Filtered"
        18 -> "Prohibited"
        19 -> "Stale NXDOMAIN answer"
        22 -> "No reachable authority"
        23 -> "Network error"
        24 -> "Invalid data"
        else -> null
    }
    return if (detail == null) "EDE $code" else "EDE $code: $detail"
}
