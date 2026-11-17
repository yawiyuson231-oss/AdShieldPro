package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — DNS Security Engine
 *
 * Comprehensive DNS security layer:
 * - DNSSEC validation reporting (AD bit, RRSIG detection)
 * - DNS hijacking detection
 * - DNS leak detection
 * - Suspicious DNS response analysis
 * - Phishing/malware domain intelligence
 * - Secure DNS provider management
 * - Response validation with anomaly detection
 */
@Singleton
class DnsSecurityEngine @Inject constructor() {

    enum class ThreatType(val label: String, val severity: Int) {
        PHISHING("Phishing", 90),
        MALWARE("Malware Distribution", 95),
        SCAM("Scam/Fraud", 85),
        CRYPTOMINER("Cryptominer", 70),
        BOTNET_C2("Botnet C&C", 95),
        SPAM("Spam Infrastructure", 60),
        SUSPICIOUS("Suspicious", 40)
    }

    enum class DnsAnomaly(val label: String, val description: String) {
        UNEXPECTED_RCODE("Unexpected RCODE", "Response code doesn't match query expectations"),
        SUSPICIOUS_TTL("Suspicious TTL", "TTL value is anomalous (too short or too long)"),
        UNEXPECTED_RECORD_TYPE("Unexpected Record Type", "Response contains unexpected record types"),
        FAST_FLUX("Possible Fast-Flux", "Very short TTLs suggest fast-flux DNS"),
        DNS_TUNNELING("Possible DNS Tunneling", "Unusually long labels or TXT records"),
        HIJACK_INDICATOR("Hijack Indicator", "Response may be tampered — IP doesn't match expected"),
        LARGE_RESPONSE("Large Response", "Response is unusually large — possible amplification"),
        MISMATCHED_IDS("ID Mismatch", "Transaction ID doesn't match query")
    }

    data class SecurityAssessment(
        val domain: String,
        val isThreat: Boolean,
        val threatTypes: Set<ThreatType>,
        val riskScore: Int, // 0-100
        val anomalies: List<DnsAnomaly>,
        val dnssecStatus: DnssecStatus?,
        val recommendation: String,
        val shouldBlock: Boolean,
        val blockReason: String?
    )

    data class DnsLeakCheckResult(
        val hasLeak: Boolean,
        val leakedProviders: List<String>,
        val configuredProvider: String,
        val detectedResolvers: List<String>,
        val recommendation: String
    )

    data class HijackDetectionResult(
        val isHijacked: Boolean,
        val expectedIp: String?,
        val actualIp: String?,
        val confidence: Int,
        val details: String
    )

    companion object {
        // Known phishing/malware patterns (offline heuristics)
        val PHISHING_KEYWORDS = setOf(
            "secure-login", "verify-account", "update-payment", "confirm-identity",
            "account-suspended", "unusual-activity", "verify-now", "login-verify",
            "appleid-apple", "micorsoft", "paypa1", "amaz0n", "faceb00k",
            "goog1e", "netflix-verify", "banking-verify"
        )

        val MALWARE_TLDS = setOf("tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "date")
        val SUSPICIOUS_KEYWORDS = setOf(
            "free-gift", "claim-now", "you-won", "congratulations", "urgent-action",
            "click-here-now", "limited-offer", "act-now"
        )

        // Expected IPs for hijack detection (well-known domains)
        val KNOWN_GOOD_IPS = mapOf(
            "google.com" to setOf("142.250.", "172.217.", "216.58."),
            "cloudflare.com" to setOf("104.16.", "104.18."),
            "facebook.com" to setOf("31.13.", "157.240."),
            "apple.com" to setOf("17.")
        )

        const val SUSPICIOUS_TTL_SHORT = 10 // seconds
        const val SUSPICIOUS_TTL_LONG = 86400 // 24 hours
        const val FAST_FLUX_THRESHOLD = 30 // TTL under this in multiple records
    }

    fun assessDomainThreat(domain: String): SecurityAssessment {
        val normalized = domain.lowercase().trim().trimEnd('.')
        val threats = mutableSetOf<ThreatType>()
        var riskScore = 0
        val anomalies = mutableListOf<DnsAnomaly>()

        // Check phishing patterns
        for (keyword in PHISHING_KEYWORDS) {
            if (normalized.contains(keyword)) {
                threats.add(ThreatType.PHISHING)
                riskScore += 40
                break
            }
        }

        // Check malware TLD + suspicious structure
        val tld = normalized.substringAfterLast('.', "")
        if (tld in MALWARE_TLDS && normalized.length > 20 && normalized.count { it == '-' } >= 2) {
            threats.add(ThreatType.MALWARE)
            riskScore += 30
        }

        // Check scam patterns
        for (keyword in SUSPICIOUS_KEYWORDS) {
            if (normalized.contains(keyword)) {
                threats.add(ThreatType.SCAM)
                riskScore += 20
                break
            }
        }

        // Check hex-heavy (common in malware C&C)
        val labels = normalized.split('.')
        if (labels.any { label -> label.length >= 16 && label.all { it.isDigit() || it in 'a'..'f' } }) {
            threats.add(ThreatType.BOTNET_C2)
            riskScore += 25
        }

        // Check for IP-like structure (fast-flux / DGA)
        if (normalized.split('.').size >= 4 && normalized.count { it.isDigit() } > normalized.length * 0.5) {
            anomalies.add(DnsAnomaly.FAST_FLUX)
            riskScore += 15
        }

        riskScore = riskScore.coerceIn(0, 100)
        val isThreat = threats.isNotEmpty() && riskScore >= 40

        return SecurityAssessment(
            domain = normalized,
            isThreat = isThreat,
            threatTypes = threats,
            riskScore = riskScore,
            anomalies = anomalies,
            dnssecStatus = null, // set by caller from actual DNS response
            recommendation = when {
                isThreat -> "Block: ${threats.joinToString { it.label }} (risk $riskScore/100)"
                riskScore >= 20 -> "Monitor: suspicious indicators present"
                else -> "No threat indicators"
            },
            shouldBlock = isThreat,
            blockReason = if (isThreat) threats.joinToString { it.label } else null
        )
    }

    /**
     * Analyze DNS response for anomalies.
     */
    fun analyzeResponse(
        queryDomain: String,
        response: ByteArray,
        expectedProvider: String? = null
    ): List<DnsAnomaly> {
        val anomalies = mutableListOf<DnsAnomaly>()
        if (response.size < 12) return listOf(DnsAnomaly.MISMATCHED_IDS)

        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        val rcode = flags and 0x000F

        // Check RCODE anomalies
        if (rcode == 2) anomalies.add(DnsAnomaly.UNEXPECTED_RCODE) // SERVFAIL

        // Check for suspicious record types (large TXT = possible tunneling)
        val types = DnsPacketCodec.inspectResponseRecordTypes(response)
        if (types != null) {
            if (DnsPacketCodec.TYPE_TXT in types && response.size > 512) {
                anomalies.add(DnsAnomaly.DNS_TUNNELING)
            }
        } else if (response.size >= 12) {
            // Malformed but not empty — possible hijack
            anomalies.add(DnsAnomaly.HIJACK_INDICATOR)
        }

        // Check TTL anomalies
        val ttl = try { DnsPacketCodec.extractResponseTtlSeconds(response) } catch (_: Exception) { -1 }
        if (ttl in 1 until SUSPICIOUS_TTL_SHORT) {
            anomalies.add(DnsAnomaly.SUSPICIOUS_TTL)
        }

        // Check for large response (amplification)
        if (response.size > 2048) {
            anomalies.add(DnsAnomaly.LARGE_RESPONSE)
        }

        return anomalies
    }

    /**
     * Detect DNS hijacking by comparing resolved IP against known-good ranges.
     */
    fun detectHijacking(domain: String, resolvedIp: String): HijackDetectionResult {
        val normalized = domain.lowercase().trimEnd('.')
        val knownRanges = KNOWN_GOOD_IPS[normalized] ?: return HijackDetectionResult(
            isHijacked = false, expectedIp = null, actualIp = resolvedIp,
            confidence = 0, details = "No reference data for $normalized"
        )

        val isInKnownRange = knownRanges.any { prefix -> resolvedIp.startsWith(prefix) }
        return if (!isInKnownRange && knownRanges.isNotEmpty()) {
            HijackDetectionResult(
                isHijacked = true,
                expectedIp = knownRanges.first() + "x.x",
                actualIp = resolvedIp,
                confidence = 70,
                details = "IP $resolvedIp not in expected ranges for $normalized — possible hijack"
            )
        } else {
            HijackDetectionResult(
                isHijacked = false, expectedIp = null, actualIp = resolvedIp,
                confidence = 90, details = "IP matches expected ranges"
            )
        }
    }

    /**
     * Check for DNS leaks by analyzing which resolvers were actually used.
     * In a correct setup, only the configured provider should appear.
     */
    fun checkForLeaks(
        configuredProvider: String,
        observedResolvers: List<String>
    ): DnsLeakCheckResult {
        val leaked = observedResolvers.filter { resolver ->
            !resolver.contains(configuredProvider, ignoreCase = true) &&
                resolver != configuredProvider
        }
        return DnsLeakCheckResult(
            hasLeak = leaked.isNotEmpty(),
            leakedProviders = leaked,
            configuredProvider = configuredProvider,
            detectedResolvers = observedResolvers,
            recommendation = if (leaked.isNotEmpty()) {
                "DNS leak detected: queries went to ${leaked.joinToString()} instead of only $configuredProvider. Check VPN tunnel configuration."
            } else {
                "No leaks — all queries used configured provider"
            }
        )
    }

    /**
     * Validate DNSSEC status and return human-readable assessment.
     */
    fun assessDnssec(dnssecStatus: DnssecStatus?): String {
        return when (dnssecStatus) {
            DnssecStatus.UPSTREAM_AUTHENTICATED -> "Validated by upstream resolver (AD bit set)"
            DnssecStatus.SIGNATURES_PRESENT_UNVALIDATED -> "DNSSEC signatures present but not locally validated"
            DnssecStatus.NOT_AUTHENTICATED -> "No DNSSEC authentication"
            null -> "DNSSEC status unknown"
        }
    }
}
