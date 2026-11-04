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
    val fromCache: Boolean,
    val dnssecStatus: DnssecStatus?,
    val responseCode: Int?,
    val answerCount: Int?,
    val providerHealth: List<DnsProviderHealth>
)

object DnsDiagnosticQueryFactory {
    private val random = SecureRandom()

    /** Builds an A query with EDNS0 and the DNSSEC OK bit so upstream AD/RRSIG evidence can be reported. */
    fun build(domainInput: String, transactionId: Int = random.nextInt(65536)): ByteArray {
        val domain = domainInput.trim().trimEnd('.').split('.').joinToString(".") {
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
    val result = resolve(query, config)
    val inspection = runCatching { DnsResponseValidator.validate(wire, result.responseBytes) }.getOrNull()
    return DnsDiagnosticReport(
        domain = query.questionDomain,
        successful = inspection?.responseCode == 0 || inspection?.responseCode == 3,
        transportAndProvider = result.protocolUsed,
        latencyMs = result.latencyMs,
        fromCache = result.fromCache,
        dnssecStatus = result.dnssecStatus ?: inspection?.dnssecStatus,
        responseCode = inspection?.responseCode,
        answerCount = inspection?.answerCount,
        providerHealth = providerHealthSnapshots()
    )
}
