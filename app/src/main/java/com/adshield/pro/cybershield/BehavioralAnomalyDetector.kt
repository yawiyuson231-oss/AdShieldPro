package com.adshield.pro.cybershield

import kotlin.math.ln
import kotlin.math.sqrt

/**
 * On-device behavioral anomaly detection over REAL recorded DNS events.
 *
 * Deterministic, explainable statistics — no cloud AI, no fabricated findings.
 * Every finding includes the evidence window and measured values that produced
 * it. Findings are FLAGGED for review; this detector never blocks anything.
 * Empty or sparse input produces no findings (honest empty state).
 */
object BehavioralAnomalyDetector {

    const val MIN_EVENTS = 8

    fun detect(
        events: List<DnsEventSnapshot>,
        nowEpochMs: Long,
        maxFindings: Int = 12
    ): List<AnomalyFinding> {
        if (events.size < MIN_EVENTS) return emptyList()
        val findings = ArrayList<AnomalyFinding>()
        val byDomain = events.groupBy { it.domain.lowercase() }

        // 1. Query burst: sudden high-frequency lookups for one exact domain.
        val fiveMinAgo = nowEpochMs - 5 * 60_000L
        for ((domain, group) in byDomain) {
            val recent = group.filter { it.timestampEpochMs >= fiveMinAgo }
            if (recent.size >= 30) {
                val span = (recent.maxOf { it.timestampEpochMs } - recent.minOf { it.timestampEpochMs })
                    .coerceAtLeast(1L)
                val ratePerMin = recent.size * 60_000.0 / span
                findings.add(
                    finding(
                        kind = "query_burst", domain = domain, severity = CsSeverity.MEDIUM,
                        title = "High-frequency DNS burst",
                        detail = "$domain was queried ${recent.size} times in the last 5 minutes " +
                            "(${String.format(java.util.Locale.US, "%.1f", ratePerMin)}/min). " +
                            "Bursts can indicate retry loops, aggressive telemetry or beaconing.",
                        evidence = listOf(
                            "window=5min", "count=${recent.size}",
                            "first=${recent.minOf { it.timestampEpochMs }}",
                            "last=${recent.maxOf { it.timestampEpochMs }}"
                        ),
                        group = recent
                    )
                )
            }
        }

        // 2. Unique-subdomain flood (possible DNS tunneling / enumeration).
        val byRegistrable = events.groupBy { ThreatEventMapper.registrableDomain(it.domain) }
        for ((base, group) in byRegistrable) {
            val unique = group.map { it.domain.lowercase() }.toSet()
            if (unique.size >= 15 && group.size >= 15) {
                findings.add(
                    finding(
                        kind = "subdomain_flood", domain = base, severity = CsSeverity.MEDIUM,
                        title = "Unique-subdomain flood",
                        detail = "${unique.size} distinct hostnames under $base were resolved in the " +
                            "observed window. Large unique-subdomain volume can indicate DNS tunneling " +
                            "or CDN sharding; review before acting.",
                        evidence = listOf("unique_subdomains=${unique.size}", "queries=${group.size}") +
                            unique.take(3).map { "sample=$it" },
                        group = group
                    )
                )
            }
        }

        // 3. Periodic beaconing: regular intervals to one domain.
        for ((domain, group) in byDomain) {
            val times = group.map { it.timestampEpochMs }.sorted()
            if (times.size < 6) continue
            val intervals = times.zipWithNext { a, b -> (b - a).toDouble() }.filter { it > 0 }
            if (intervals.size < 5) continue
            val mean = intervals.average()
            if (mean < 5_000.0) continue // faster than 5 s is covered by burst detection
            val variance = intervals.sumOf { (it - mean) * (it - mean) } / intervals.size
            val cv = sqrt(variance) / mean
            if (cv < 0.12) {
                findings.add(
                    finding(
                        kind = "beaconing", domain = domain, severity = CsSeverity.MEDIUM,
                        title = "Periodic beaconing pattern",
                        detail = "$domain was queried ${times.size} times at highly regular intervals " +
                            "(mean ${String.format(java.util.Locale.US, "%.1f", mean / 1000)} s, " +
                            "variation ${String.format(java.util.Locale.US, "%.0f", cv * 100)}%). " +
                            "Regular callbacks are typical of telemetry — and of malware check-ins.",
                        evidence = listOf(
                            "samples=${times.size}",
                            "mean_interval_ms=${mean.toLong()}",
                            "coefficient_of_variation=${String.format(java.util.Locale.US, "%.3f", cv)}"
                        ),
                        group = group
                    )
                )
            }
        }

        // 4. DGA-like hostnames: high-entropy, long, digit-heavy labels that were ALLOWED.
        val seenBases = HashSet<String>()
        for (event in events) {
            if (event.isBlocked) continue
            val domain = event.domain.lowercase()
            val label = domain.substringBefore('.')
            if (label.length < 12) continue
            val digits = label.count { it in '0'..'9' }
            val digitRatio = digits.toDouble() / label.length
            val entropy = shannonEntropy(label)
            if (entropy >= 3.7 && digitRatio >= 0.25 && label.any { it in 'a'..'z' }) {
                val base = ThreatEventMapper.registrableDomain(domain)
                if (!seenBases.add(base)) continue
                findings.add(
                    finding(
                        kind = "dga_pattern", domain = domain, severity = CsSeverity.HIGH,
                        title = "Algorithmically-generated hostname pattern",
                        detail = "$domain has a high-entropy, digit-heavy hostname " +
                            "(entropy ${String.format(java.util.Locale.US, "%.2f", entropy)} bits/char, " +
                            "${String.format(java.util.Locale.US, "%.0f", digitRatio * 100)}% digits). " +
                            "This resembles DGA output. Heuristic only — verify before blocking.",
                        evidence = listOf(
                            "label_length=${label.length}",
                            "entropy_bits_per_char=${String.format(java.util.Locale.US, "%.2f", entropy)}",
                            "digit_ratio=${String.format(java.util.Locale.US, "%.2f", digitRatio)}",
                            "decision=allowed (flagged for review, not blocked)"
                        ),
                        group = listOf(event)
                    )
                )
            }
        }

        return findings
            .sortedWith(compareByDescending<AnomalyFinding> { it.severity }.thenByDescending { it.lastSeenEpochMs })
            .take(maxFindings)
    }

    fun shannonEntropy(text: String): Double {
        if (text.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in text) counts[c] = (counts[c] ?: 0) + 1
        var result = 0.0
        for (count in counts.values) {
            val p = count.toDouble() / text.length
            result -= p * (ln(p) / ln(2.0))
        }
        return result
    }

    private fun finding(
        kind: String,
        domain: String,
        severity: CsSeverity,
        title: String,
        detail: String,
        evidence: List<String>,
        group: List<DnsEventSnapshot>
    ): AnomalyFinding = AnomalyFinding(
        id = "$kind:$domain",
        kind = kind,
        severity = severity,
        title = title,
        detail = detail,
        evidence = evidence,
        domain = domain,
        firstSeenEpochMs = group.minOf { it.timestampEpochMs },
        lastSeenEpochMs = group.maxOf { it.timestampEpochMs },
        eventCount = group.size
    )
}
