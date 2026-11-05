package com.adshield.pro.engine.detection

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.engine.aether.DomainRiskAnalyzer
import kotlin.math.sqrt

/**
 * CyberShield local detection pipeline.
 *
 * Four explainable, rule-based stages run over the device's own DNS log — the same real events
 * the VPN service records. There is no ML model and no cloud call; every finding names the
 * evidence that produced it, and a stage that has too little data says so instead of inventing
 * an analysis. The "progress" value is the fraction of stages that had enough data to complete,
 * which is a real measure of analysis coverage, never a simulated scan animation.
 *
 * Pure functions only, so the whole pipeline is unit-tested on the JVM.
 */
object LocalDetectionEngine {

    enum class Stage(val label: String) {
        BEHAVIOR("Behavior Analysis"),
        ANOMALY("Anomaly Detection"),
        CLASSIFICATION("Rule-based Classification"),
        CORRELATION("Threat Correlation")
    }

    enum class StageStatus { COMPLETE, INSUFFICIENT_DATA }

    data class StageResult(
        val stage: Stage,
        val status: StageStatus,
        val detail: String,
        val findingCount: Int
    )

    data class Finding(
        val id: String,
        val stage: Stage,
        val title: String,
        val detail: String,
        val severity: ThreatSeverity,
        val domain: String?,
        val evidence: List<String>
    )

    data class DetectionReport(
        val generatedAtEpochMs: Long,
        val analyzedEvents: Int,
        val windowStartEpochMs: Long?,
        val windowEndEpochMs: Long?,
        val stages: List<StageResult>,
        val findings: List<Finding>,
        /** Fraction of stages that completed with sufficient data (0..1). Real coverage, not animation. */
        val coverage: Float,
        val hasEnoughData: Boolean
    ) {
        val completedStages: Int get() = stages.count { it.status == StageStatus.COMPLETE }
    }

    // Minimum evidence thresholds. Below these a stage reports INSUFFICIENT_DATA.
    private const val MIN_EVENTS_BEHAVIOR = 5
    private const val MIN_EVENTS_ANOMALY = 12
    private const val MIN_EVENTS_CLASSIFICATION = 1
    private const val MIN_EVENTS_CORRELATION = 6

    private const val BEHAVIOR_REPEAT_THRESHOLD = 8
    private const val BURST_WINDOW_MS = 60_000L
    private const val BURST_THRESHOLD = 6
    private const val ANOMALY_BUCKET_MS = 5 * 60_000L
    private const val ANOMALY_Z_THRESHOLD = 3.0
    private const val ANOMALY_MIN_BUCKET_COUNT = 8
    private const val MAX_CLASSIFIED_DOMAINS = 120
    private const val MAX_FINDINGS_PER_STAGE = 12

    /** Runs all four stages over the real log window (newest-first or oldest-first both work). */
    fun run(logs: List<DnsActivityRecord>, nowEpochMs: Long = System.currentTimeMillis()): DetectionReport {
        val sorted = logs.sortedBy { it.timestampEpochMs }
        val behavior = analyzeBehavior(sorted)
        val anomaly = detectAnomalies(sorted)
        val classification = classify(sorted)
        val correlation = correlate(sorted)

        val stages = listOf(behavior, anomaly, classification, correlation).map { it.first }
        val findings = listOf(behavior, anomaly, classification, correlation).flatMap { it.second }
        val completed = stages.count { it.status == StageStatus.COMPLETE }
        return DetectionReport(
            generatedAtEpochMs = nowEpochMs,
            analyzedEvents = sorted.size,
            windowStartEpochMs = sorted.firstOrNull()?.timestampEpochMs,
            windowEndEpochMs = sorted.lastOrNull()?.timestampEpochMs,
            stages = stages,
            findings = findings.sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.title }),
            coverage = completed.toFloat() / Stage.entries.size,
            hasEnoughData = completed > 0
        )
    }

    // ------------------------------------------------------------------ Stage 1

    /**
     * Behavior analysis: repeated queries to one host and short-interval bursts. A burst is a
     * retry loop, a tracker, or beaconing — the finding says exactly what was measured and does
     * not claim which of those it is.
     */
    internal fun analyzeBehavior(logs: List<DnsActivityRecord>): Pair<StageResult, List<Finding>> {
        if (logs.size < MIN_EVENTS_BEHAVIOR) {
            return insufficient(Stage.BEHAVIOR, logs.size, MIN_EVENTS_BEHAVIOR)
        }
        val findings = ArrayList<Finding>()
        val byDomain = logs.groupBy { it.domain }

        byDomain.entries
            .filter { it.value.size >= BEHAVIOR_REPEAT_THRESHOLD }
            .sortedByDescending { it.value.size }
            .take(MAX_FINDINGS_PER_STAGE)
            .forEach { (domain, events) ->
                val blocked = events.count { it.isBlocked }
                val severity = if (events.any { it.category == RuleCategory.MALWARE && it.isBlocked }) {
                    ThreatSeverity.CRITICAL
                } else if (blocked > 0) ThreatSeverity.MEDIUM else ThreatSeverity.LOW
                findings += Finding(
                    id = "behavior-repeat-$domain",
                    stage = Stage.BEHAVIOR,
                    title = "Repeated queries to $domain",
                    detail = "$domain was queried ${events.size} times in the log window" +
                        if (blocked > 0) "; $blocked of those queries were blocked." else ".",
                    severity = severity,
                    domain = domain,
                    evidence = listOf(
                        "${events.size} DNS queries observed",
                        "$blocked blocked by the filter engine",
                        "First seen ${events.first().timestampEpochMs}, last ${events.last().timestampEpochMs}"
                    )
                )
            }

        // Burst detection: >= BURST_THRESHOLD queries to one domain inside any 60s window.
        byDomain.forEach { (domain, events) ->
            if (events.size < BURST_THRESHOLD) return@forEach
            var windowStart = 0
            for (windowEnd in events.indices) {
                while (events[windowEnd].timestampEpochMs - events[windowStart].timestampEpochMs > BURST_WINDOW_MS) {
                    windowStart++
                }
                val inWindow = windowEnd - windowStart + 1
                if (inWindow >= BURST_THRESHOLD) {
                    findings += Finding(
                        id = "behavior-burst-$domain",
                        stage = Stage.BEHAVIOR,
                        title = "Query burst: $domain",
                        detail = "$inWindow queries to $domain within 60 seconds — a retry loop, aggressive tracker or beaconing pattern.",
                        severity = if (events.any { it.isBlocked && it.category == RuleCategory.MALWARE }) ThreatSeverity.HIGH else ThreatSeverity.LOW,
                        domain = domain,
                        evidence = listOf(
                            "$inWindow queries in a 60s window",
                            "Window starts at ${events[windowStart].timestampEpochMs}"
                        )
                    )
                    return@forEach
                }
            }
        }

        val trimmed = findings.take(MAX_FINDINGS_PER_STAGE)
        return StageResult(
            stage = Stage.BEHAVIOR,
            status = StageStatus.COMPLETE,
            detail = "${byDomain.size} unique host(s) profiled across ${logs.size} events.",
            findingCount = trimmed.size
        ) to trimmed
    }

    // ------------------------------------------------------------------ Stage 2

    /**
     * Anomaly detection: 5-minute query-rate buckets compared against the window's own baseline
     * (z-score), plus an unusual unique-domain ratio. Both are plain statistics over real counts.
     */
    internal fun detectAnomalies(logs: List<DnsActivityRecord>): Pair<StageResult, List<Finding>> {
        if (logs.size < MIN_EVENTS_ANOMALY) {
            return insufficient(Stage.ANOMALY, logs.size, MIN_EVENTS_ANOMALY)
        }
        val findings = ArrayList<Finding>()
        val first = logs.first().timestampEpochMs
        val buckets = logs.groupBy { (it.timestampEpochMs - first) / ANOMALY_BUCKET_MS }
        val span = ((logs.last().timestampEpochMs - first) / ANOMALY_BUCKET_MS).toInt() + 1
        // Include empty buckets so a quiet baseline is not hidden.
        val counts = (0 until span).map { buckets[it.toLong()]?.size?.toDouble() ?: 0.0 }
        val mean = counts.average()
        val variance = counts.sumOf { (it - mean) * (it - mean) } / counts.size
        val stdDev = sqrt(variance)

        if (stdDev > 0.0) {
            counts.forEachIndexed { index, count ->
                val z = (count - mean) / stdDev
                if (z >= ANOMALY_Z_THRESHOLD && count >= ANOMALY_MIN_BUCKET_COUNT) {
                    val bucketEvents = buckets[index.toLong()].orEmpty()
                    val blocked = bucketEvents.count { it.isBlocked }
                    findings += Finding(
                        id = "anomaly-rate-$index",
                        stage = Stage.ANOMALY,
                        title = "DNS traffic spike",
                        detail = "${count.toInt()} queries in one 5-minute window vs a ${String.format(java.util.Locale.US, "%.1f", mean)} baseline (z=${String.format(java.util.Locale.US, "%.1f", z)}); $blocked were blocked.",
                        severity = if (blocked > count / 2) ThreatSeverity.HIGH else ThreatSeverity.MEDIUM,
                        domain = null,
                        evidence = listOf(
                            "Baseline mean ${String.format(java.util.Locale.US, "%.2f", mean)} queries/bucket",
                            "Standard deviation ${String.format(java.util.Locale.US, "%.2f", stdDev)}",
                            "Bucket start ${first + index * ANOMALY_BUCKET_MS}"
                        )
                    )
                }
            }
        }

        val uniqueRatio = logs.map { it.domain }.distinct().size.toDouble() / logs.size
        if (logs.size >= 30 && uniqueRatio > 0.85) {
            findings += Finding(
                id = "anomaly-unique-ratio",
                stage = Stage.ANOMALY,
                title = "Unusually high unique-domain ratio",
                detail = "${(uniqueRatio * 100).toInt()}% of queries target a distinct host. Heavy tracker rotation or generated domains can look like this; it is not proof of either.",
                severity = ThreatSeverity.LOW,
                domain = null,
                evidence = listOf(
                    "${logs.map { it.domain }.distinct().size} unique hosts in ${logs.size} queries"
                )
            )
        }

        val trimmed = findings.take(MAX_FINDINGS_PER_STAGE)
        return StageResult(
            stage = Stage.ANOMALY,
            status = StageStatus.COMPLETE,
            detail = "$span five-minute bucket(s) scored against the window baseline.",
            findingCount = trimmed.size
        ) to trimmed
    }

    // ------------------------------------------------------------------ Stage 3

    /**
     * Classification: blocked events are grouped into attack vectors by their matched rule
     * category, and unique blocked hosts are additionally screened with the same domain
     * heuristics the Aether decision core uses (punycode, brand lookalikes, risky TLDs…).
     * Heuristic hits are reported as suspected, never as verified malware.
     */
    internal fun classify(logs: List<DnsActivityRecord>): Pair<StageResult, List<Finding>> {
        val blocked = logs.filter { it.isBlocked }
        if (blocked.size < MIN_EVENTS_CLASSIFICATION) {
            return insufficient(Stage.CLASSIFICATION, blocked.size, MIN_EVENTS_CLASSIFICATION)
        }
        val findings = ArrayList<Finding>()
        blocked.map { it.domain }.distinct().take(MAX_CLASSIFIED_DOMAINS).forEach { domain ->
            val hits = DomainRiskAnalyzer.analyze(domain).filter { it.weight >= 18 }
            if (hits.isNotEmpty()) {
                val alreadyMalware = blocked.any { it.domain == domain && it.category == RuleCategory.MALWARE }
                findings += Finding(
                    id = "classify-$domain",
                    stage = Stage.CLASSIFICATION,
                    title = if (alreadyMalware) "Confirmed threat host: $domain" else "Suspicious host pattern: $domain",
                    detail = hits.joinToString("; ") { it.explanation },
                    severity = if (alreadyMalware) ThreatSeverity.CRITICAL else ThreatSeverity.HIGH,
                    domain = domain,
                    evidence = hits.map { "${it.code} (weight ${it.weight})" } +
                        if (alreadyMalware) listOf("Also matched a curated malware list") else listOf("Heuristic only — not list-verified")
                )
            }
        }
        val trimmed = findings.take(MAX_FINDINGS_PER_STAGE)
        return StageResult(
            stage = Stage.CLASSIFICATION,
            status = StageStatus.COMPLETE,
            detail = "${blocked.size} blocked event(s) classified; ${blocked.map { it.domain }.distinct().size} unique host(s) screened.",
            findingCount = trimmed.size
        ) to trimmed
    }

    // ------------------------------------------------------------------ Stage 4

    /**
     * Threat correlation: the same host blocked by two different lists, or persistently blocked
     * across separate time buckets, is stronger evidence than any single match. Correlated
     * incidents cite both sources.
     */
    internal fun correlate(logs: List<DnsActivityRecord>): Pair<StageResult, List<Finding>> {
        if (logs.size < MIN_EVENTS_CORRELATION) {
            return insufficient(Stage.CORRELATION, logs.size, MIN_EVENTS_CORRELATION)
        }
        val findings = ArrayList<Finding>()
        val blockedByDomain = logs.filter { it.isBlocked }.groupBy { it.domain }

        blockedByDomain.forEach { (domain, events) ->
            val sources = events.map { it.sourceList }.filter { it.isNotBlank() }.distinct()
            val buckets = events.map { it.timestampEpochMs / ANOMALY_BUCKET_MS }.distinct()
            val isMalware = events.any { it.category == RuleCategory.MALWARE }
            when {
                sources.size >= 2 -> findings += Finding(
                    id = "correlate-multi-$domain",
                    stage = Stage.CORRELATION,
                    title = "Multi-source confirmation: $domain",
                    detail = "$domain was blocked by ${sources.size} independent lists (${sources.take(3).joinToString()}).",
                    severity = if (isMalware) ThreatSeverity.CRITICAL else ThreatSeverity.MEDIUM,
                    domain = domain,
                    evidence = sources.map { "Blocked by $it" }
                )
                events.size >= 3 && buckets.size >= 2 -> findings += Finding(
                    id = "correlate-persist-$domain",
                    stage = Stage.CORRELATION,
                    title = "Persistent blocked activity: $domain",
                    detail = "$domain was blocked ${events.size} times across ${buckets.size} separate 5-minute windows — something on the device keeps requesting it.",
                    severity = if (isMalware) ThreatSeverity.CRITICAL else ThreatSeverity.MEDIUM,
                    domain = domain,
                    evidence = listOf(
                        "${events.size} blocks",
                        "${buckets.size} distinct time windows",
                        "Source: ${sources.firstOrNull() ?: "filter policy"}"
                    )
                )
            }
        }

        val trimmed = findings.sortedByDescending { it.severity.rank }.take(MAX_FINDINGS_PER_STAGE)
        return StageResult(
            stage = Stage.CORRELATION,
            status = StageStatus.COMPLETE,
            detail = "${blockedByDomain.size} blocked host(s) cross-checked across lists and time windows.",
            findingCount = trimmed.size
        ) to trimmed
    }

    private fun insufficient(stage: Stage, have: Int, need: Int): Pair<StageResult, List<Finding>> =
        StageResult(
            stage = stage,
            status = StageStatus.INSUFFICIENT_DATA,
            detail = "Needs at least $need logged events; $have available. Nothing was analyzed or invented.",
            findingCount = 0
        ) to emptyList()
}
