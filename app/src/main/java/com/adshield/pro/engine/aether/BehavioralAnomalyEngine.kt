package com.adshield.pro.engine.aether

import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln
import kotlin.math.roundToInt
import kotlin.math.sqrt

/**
 * AETHER On-Device Behavioral DNS Anomaly & Screen-Off Tracker Radar.
 *
 * Evaluates time-series and structural patterns across locally observed DNS queries with zero cloud
 * telemetry and zero fabricated baselines:
 * 1. **Periodic Beaconing Detection**: Measures inter-arrival intervals (`Δt`) per domain and
 *    computes the coefficient of variation (`CV = σ / μ`). Low-jitter periodic heartbeats
 *    (`>= 5` queries, `5s <= μ <= 3600s`, `CV <= 0.18`) surface as `PERIODIC_BEACONING`.
 * 2. **High-Entropy / DGA Subdomain Analysis**: Measures Shannon entropy (`bits/char`) and numeric
 *    density on subdomain labels to surface algorithmically generated or encoded hostnames.
 * 3. **DNS Tunneling / Payload Indicator**: Detects abnormally long encoded labels (`>= 48` chars
 *    or multi-label encoded prefixes `>= 85` chars) and elevated `TXT` query ratios.
 * 4. **Screen-Off Tracker Radar**: Tracks queries fired while `isScreenInteractive == false` so the
 *    user can audit which apps contact ad/tracker or external servers while the phone is locked.
 *
 * Honesty contract: Behavioral findings are surfaced as `SUSPECTED` / advisory anomalies with exact
 * measured evidence; heuristics never claim confirmed malware or silently break legitimate apps.
 */
@Singleton
class BehavioralAnomalyEngine @Inject constructor() {

    enum class AnomalyKind(val title: String) {
        PERIODIC_BEACONING("Periodic Background Beaconing"),
        HIGH_ENTROPY_DGA("High-Entropy / DGA-Like Hostname"),
        DNS_TUNNELING_PATTERN("DNS Tunneling / Encoded Subdomain Pattern"),
        SCREEN_OFF_TRACKING("Screen-Off Background Activity")
    }

    data class DomainAnomalyFinding(
        val domain: String,
        val anomalyScore: Int,
        val kinds: List<AnomalyKind>,
        val sampleCount: Int,
        val meanIntervalMs: Long?,
        val intervalJitterCv: Double?,
        val maxLabelEntropyBits: Double,
        val txtQueryRatio: Double,
        val screenOffQueries: Int,
        val topAppPackage: String?,
        val topAppName: String?,
        val evidence: List<String>
    )

    data class ScreenOffAppSummary(
        val appPackage: String,
        val appName: String,
        val totalScreenOffQueries: Int,
        val blockedScreenOffQueries: Int,
        val distinctDomains: Int,
        val topDomains: List<String>,
        val lastSeenEpochMs: Long
    )

    data class AnomalyRadarSnapshot(
        val observedDomainsCount: Int,
        val totalScreenOffQueries: Long,
        val blockedScreenOffQueries: Long,
        val findings: List<DomainAnomalyFinding>,
        val screenOffApps: List<ScreenOffAppSummary>
    )

    private class MutableDomainSeries(
        val domain: String
    ) {
        val timestampsMs = ArrayDeque<Long>(MAX_TIMESTAMPS_PER_DOMAIN)
        var totalQueries: Int = 0
        var txtQueries: Int = 0
        var screenOffQueries: Int = 0
        var blockedQueries: Int = 0
        var lastAppPackage: String? = null
        var lastAppName: String? = null
        var lastSeenMs: Long = 0L
    }

    private class MutableScreenOffApp(
        val appPackage: String,
        var appName: String
    ) {
        var totalQueries: Int = 0
        var blockedQueries: Int = 0
        var lastSeenEpochMs: Long = 0L
        val domainCounts = LinkedHashMap<String, Int>()
    }

    private val lock = Any()
    private val seriesByDomain = object : LinkedHashMap<String, MutableDomainSeries>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, MutableDomainSeries>?): Boolean =
            size > MAX_TRACKED_DOMAINS
    }
    private val screenOffByApp = object : LinkedHashMap<String, MutableScreenOffApp>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, MutableScreenOffApp>?): Boolean =
            size > MAX_TRACKED_APPS
    }
    private var totalScreenOffQueries: Long = 0L
    private var blockedScreenOffQueries: Long = 0L

    /** Records one real DNS observation from the local tunnel or log replay. */
    fun recordObservation(
        domain: String,
        queryType: String,
        timestampEpochMs: Long,
        isBlocked: Boolean,
        isScreenInteractive: Boolean = true,
        appPackageName: String? = null,
        appName: String? = null
    ) {
        val normalized = domain.trim().trimEnd('.').lowercase(Locale.US)
        if (normalized.isEmpty()) return
        val qTypeUpper = queryType.trim().uppercase(Locale.US)

        synchronized(lock) {
            val series = seriesByDomain.getOrPut(normalized) { MutableDomainSeries(normalized) }
            series.totalQueries += 1
            if (qTypeUpper == "TXT" || qTypeUpper == "NULL") {
                series.txtQueries += 1
            }
            if (isBlocked) {
                series.blockedQueries += 1
            }
            if (!isScreenInteractive) {
                series.screenOffQueries += 1
                totalScreenOffQueries += 1L
                if (isBlocked) blockedScreenOffQueries += 1L

                val pkg = appPackageName?.takeIf { it.isNotBlank() } ?: UNKNOWN_PACKAGE_KEY
                val label = appName?.takeIf { it.isNotBlank() }
                    ?: appPackageName?.takeIf { it.isNotBlank() }
                    ?: "Unattributed System / Native DNS"
                val appEntry = screenOffByApp.getOrPut(pkg) { MutableScreenOffApp(pkg, label) }
                appEntry.appName = label
                appEntry.totalQueries += 1
                if (isBlocked) appEntry.blockedQueries += 1
                if (timestampEpochMs > appEntry.lastSeenEpochMs) {
                    appEntry.lastSeenEpochMs = timestampEpochMs
                }
                if (appEntry.domainCounts.size < MAX_DOMAINS_PER_APP || normalized in appEntry.domainCounts) {
                    appEntry.domainCounts[normalized] = (appEntry.domainCounts[normalized] ?: 0) + 1
                }
            }

            if (appPackageName != null) {
                series.lastAppPackage = appPackageName
                series.lastAppName = appName ?: appPackageName
            }
            if (series.timestampsMs.isEmpty() || timestampEpochMs >= series.timestampsMs.last()) {
                if (series.timestampsMs.size >= MAX_TIMESTAMPS_PER_DOMAIN) {
                    series.timestampsMs.removeFirst()
                }
                series.timestampsMs.addLast(timestampEpochMs)
            } else {
                val sorted = (series.timestampsMs + timestampEpochMs).sorted().takeLast(MAX_TIMESTAMPS_PER_DOMAIN)
                series.timestampsMs.clear()
                series.timestampsMs.addAll(sorted)
            }
            series.lastSeenMs = maxOf(series.lastSeenMs, timestampEpochMs)
        }
    }

    /** Builds an immutable, ranked snapshot of behavioral anomalies and screen-off app activity. */
    fun buildSnapshot(minAnomalyScore: Int = 35, maxFindings: Int = 40): AnomalyRadarSnapshot {
        synchronized(lock) {
            val findings = ArrayList<DomainAnomalyFinding>()
            for (series in seriesByDomain.values) {
                val evaluated = evaluateSeries(series)
                if (evaluated != null && evaluated.anomalyScore >= minAnomalyScore) {
                    findings += evaluated
                }
            }
            findings.sortWith(
                compareByDescending<DomainAnomalyFinding> { it.anomalyScore }
                    .thenByDescending { it.sampleCount }
                    .thenBy { it.domain }
            )

            val apps = screenOffByApp.values.map { entry ->
                val topDomains = entry.domainCounts.entries
                    .sortedByDescending { it.value }
                    .take(5)
                    .map { it.key }
                ScreenOffAppSummary(
                    appPackage = entry.appPackage,
                    appName = entry.appName,
                    totalScreenOffQueries = entry.totalQueries,
                    blockedScreenOffQueries = entry.blockedQueries,
                    distinctDomains = entry.domainCounts.size,
                    topDomains = topDomains,
                    lastSeenEpochMs = entry.lastSeenEpochMs
                )
            }.sortedWith(
                compareByDescending<ScreenOffAppSummary> { it.blockedScreenOffQueries }
                    .thenByDescending { it.totalScreenOffQueries }
                    .thenBy { it.appName }
            )

            return AnomalyRadarSnapshot(
                observedDomainsCount = seriesByDomain.size,
                totalScreenOffQueries = totalScreenOffQueries,
                blockedScreenOffQueries = blockedScreenOffQueries,
                findings = findings.take(maxFindings),
                screenOffApps = apps.take(30)
            )
        }
    }

    fun clear() {
        synchronized(lock) {
            seriesByDomain.clear()
            screenOffByApp.clear()
            totalScreenOffQueries = 0L
            blockedScreenOffQueries = 0L
        }
    }

    private fun evaluateSeries(series: MutableDomainSeries): DomainAnomalyFinding? {
        val domain = series.domain
        if (domain in BENIGN_INFRASTRUCTURE_SUFFIXES ||
            BENIGN_INFRASTRUCTURE_SUFFIXES.any { domain.endsWith(".$it") }
        ) {
            return null
        }

        var score = 0
        val kinds = ArrayList<AnomalyKind>()
        val evidence = ArrayList<String>()

        // 1. Periodic Beaconing check across inter-arrival intervals
        var meanIntervalMs: Long? = null
        var jitterCv: Double? = null
        val stamps = series.timestampsMs.toList()
        if (stamps.size >= MIN_BEACON_SAMPLES) {
            val deltas = ArrayList<Long>(stamps.size - 1)
            for (i in 1 until stamps.size) {
                val dt = stamps[i] - stamps[i - 1]
                if (dt > 0L) deltas += dt
            }
            if (deltas.size >= MIN_BEACON_SAMPLES - 1) {
                val mean = deltas.average()
                if (mean in 5_000.0..3_600_000.0) {
                    val variance = deltas.sumOf { (it - mean) * (it - mean) } / deltas.size
                    val stdDev = sqrt(variance)
                    val cv = if (mean > 0.0) stdDev / mean else 1.0
                    meanIntervalMs = mean.toLong()
                    jitterCv = cv
                    if (cv <= MAX_BEACON_CV) {
                        val beaconPoints = if (cv <= 0.06) 45 else 35
                        score += beaconPoints
                        kinds += AnomalyKind.PERIODIC_BEACONING
                        val secs = (mean / 1000.0).roundToInt()
                        val cvPct = (cv * 100.0).roundToInt()
                        evidence += "Periodic cadence: ${deltas.size + 1} queries spaced ~${secs}s apart (jitter CV ${cvPct}%)"
                    }
                }
            }
        }

        // 2. Lexical entropy / DGA analysis on non-registrable subdomain labels
        val labels = domain.split('.').filter { it.isNotEmpty() }
        val inspectableLabels = if (labels.size >= 3) {
            labels.dropLast(2)
        } else if (labels.size == 2) {
            listOf(labels.first())
        } else {
            labels
        }

        var maxEntropy = 0.0
        var longestSubLabel = ""
        for (label in inspectableLabels) {
            val ent = shannonEntropyBits(label)
            if (ent > maxEntropy) maxEntropy = ent
            if (label.length > longestSubLabel.length) longestSubLabel = label
        }

        val digitCount = longestSubLabel.count { it.isDigit() }
        val digitRatio = if (longestSubLabel.isNotEmpty()) digitCount.toDouble() / longestSubLabel.length else 0.0
        if (longestSubLabel.length >= 14 && maxEntropy >= 3.75 && !longestSubLabel.startsWith("xn--")) {
            val dgaPoints = if (maxEntropy >= 4.15 || digitRatio >= 0.30) 42 else 32
            score += dgaPoints
            kinds += AnomalyKind.HIGH_ENTROPY_DGA
            evidence += String.format(
                Locale.US,
                "High-entropy label '%s' (%.2f bits/char, len=%d)",
                longestSubLabel.take(28),
                maxEntropy,
                longestSubLabel.length
            )
        }

        // 3. DNS Tunneling / TXT payload exfiltration pattern
        val subdomainPayloadChars = if (labels.size > 2) labels.dropLast(2).sumOf { it.length } else 0
        val txtRatio = if (series.totalQueries > 0) series.txtQueries.toDouble() / series.totalQueries else 0.0
        if (longestSubLabel.length >= 46 || subdomainPayloadChars >= 85 ||
            (series.totalQueries >= 4 && txtRatio >= 0.50 && subdomainPayloadChars >= 24)
        ) {
            score += 45
            kinds += AnomalyKind.DNS_TUNNELING_PATTERN
            evidence += "Encoded subdomain/TXT pattern (subdomain chars=$subdomainPayloadChars, TXT=${(txtRatio * 100).roundToInt()}%)"
        }

        // 4. Screen-Off background persistence
        if (series.screenOffQueries >= 4) {
            val screenOffRatio = series.screenOffQueries.toDouble() / series.totalQueries.coerceAtLeast(1)
            if (screenOffRatio >= 0.50 || series.screenOffQueries >= 10) {
                score += if (series.blockedQueries > 0) 28 else 18
                kinds += AnomalyKind.SCREEN_OFF_TRACKING
                evidence += "${series.screenOffQueries}/${series.totalQueries} queries occurred while screen was off"
            }
        }

        if (kinds.isEmpty()) return null

        return DomainAnomalyFinding(
            domain = domain,
            anomalyScore = score.coerceIn(0, 100),
            kinds = kinds,
            sampleCount = series.totalQueries,
            meanIntervalMs = meanIntervalMs,
            intervalJitterCv = jitterCv,
            maxLabelEntropyBits = maxEntropy,
            txtQueryRatio = txtRatio,
            screenOffQueries = series.screenOffQueries,
            topAppPackage = series.lastAppPackage,
            topAppName = series.lastAppName,
            evidence = evidence
        )
    }

    companion object {
        private const val MAX_TRACKED_DOMAINS = 512
        private const val MAX_TIMESTAMPS_PER_DOMAIN = 32
        private const val MAX_TRACKED_APPS = 128
        private const val MAX_DOMAINS_PER_APP = 32
        private const val MIN_BEACON_SAMPLES = 5
        private const val MAX_BEACON_CV = 0.18
        const val UNKNOWN_PACKAGE_KEY = "__system_or_unattributed__"

        private val BENIGN_INFRASTRUCTURE_SUFFIXES = setOf(
            "connectivitycheck.gstatic.com",
            "clients3.google.com",
            "captive.apple.com",
            "time.android.com",
            "pool.ntp.org"
        )

        /** Computes Shannon character entropy in bits per character (`0.0 .. log2(N)`). */
        fun shannonEntropyBits(text: String): Double {
            if (text.isEmpty()) return 0.0
            val counts = IntArray(128)
            var nonAscii = 0
            for (ch in text) {
                if (ch.code < 128) counts[ch.code]++ else nonAscii++
            }
            val len = text.length.toDouble()
            val invLn2 = 1.0 / ln(2.0)
            var entropy = 0.0
            for (c in counts) {
                if (c > 0) {
                    val p = c / len
                    entropy -= p * ln(p) * invLn2
                }
            }
            if (nonAscii > 0) {
                val p = nonAscii / len
                entropy -= p * ln(p) * invLn2
            }
            return entropy
        }
    }
}
