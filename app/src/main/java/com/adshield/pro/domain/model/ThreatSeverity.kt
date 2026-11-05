package com.adshield.pro.domain.model

/**
 * Four-level threat severity used by the CyberShield command-center dashboard.
 *
 * Every level is derived from a real, logged DNS block and its matched rule category — never
 * invented. Allowed queries are not threats and map to `null`. The mapping is the single source
 * of truth shared by the VPN write path (persistent daily counters), the dashboard donut and the
 * Threats screen filters, so the numbers can never disagree with each other.
 */
enum class ThreatSeverity(val label: String, val rank: Int) {
    CRITICAL("Critical", 3),
    HIGH("High", 2),
    MEDIUM("Medium", 1),
    LOW("Low", 0);

    companion object {
        /**
         * Severity of one logged event. A blocked query with no category (legacy rows) is
         * conservatively MEDIUM: it was blocked by policy, but nothing verified it as malware.
         */
        fun of(isBlocked: Boolean, category: RuleCategory?): ThreatSeverity? {
            if (!isBlocked) return null
            return when (category) {
                RuleCategory.MALWARE -> CRITICAL
                RuleCategory.STRICT_TELEMETRY -> HIGH
                RuleCategory.ADS -> MEDIUM
                RuleCategory.CUSTOM -> MEDIUM
                RuleCategory.TRACKERS -> LOW
                null -> MEDIUM
            }
        }

        fun of(record: DnsActivityRecord): ThreatSeverity? = of(record.isBlocked, record.category)
    }
}

/** Aggregated severity counters. [total] is the number of classified blocked events. */
data class SeverityCounts(
    val critical: Long = 0L,
    val high: Long = 0L,
    val medium: Long = 0L,
    val low: Long = 0L
) {
    val total: Long get() = critical + high + medium + low

    fun countFor(severity: ThreatSeverity): Long = when (severity) {
        ThreatSeverity.CRITICAL -> critical
        ThreatSeverity.HIGH -> high
        ThreatSeverity.MEDIUM -> medium
        ThreatSeverity.LOW -> low
    }

    operator fun plus(other: SeverityCounts): SeverityCounts = SeverityCounts(
        critical = critical + other.critical,
        high = high + other.high,
        medium = medium + other.medium,
        low = low + other.low
    )

    companion object {
        fun from(records: List<DnsActivityRecord>): SeverityCounts {
            var critical = 0L
            var high = 0L
            var medium = 0L
            var low = 0L
            records.forEach { record ->
                when (ThreatSeverity.of(record)) {
                    ThreatSeverity.CRITICAL -> critical++
                    ThreatSeverity.HIGH -> high++
                    ThreatSeverity.MEDIUM -> medium++
                    ThreatSeverity.LOW -> low++
                    null -> Unit
                }
            }
            return SeverityCounts(critical, high, medium, low)
        }
    }
}
