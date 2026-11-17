package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — Threat Intelligence Manager
 *
 * Manages threat intelligence feeds for malware, phishing, and scam domains.
 * Integrates with:
 * - Local bundled threat lists (HaGeZi TIF — 191k domains)
 * - Remote community feeds (URLHaus, StevenBlack, etc.)
 * - Heuristic threat detection
 * - Automatic updates with validation
 *
 * All sources are free, open-source, and legally accessible.
 */
@Singleton
class ThreatIntelligenceManager @Inject constructor() {

    enum class ThreatFeed(val label: String, val url: String, val format: String, val license: String) {
        HAGEZI_TIF(
            "HaGeZi Threat Intelligence Feeds",
            "asset://core_max_threats.txt",
            "hosts+adblock",
            "GPLv3"
        ),
        URLHAUS(
            "URLhaus Malware Domains",
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
            "adblock",
            "CC0"
        ),
        STEVENBLACK(
            "StevenBlack Unified Hosts",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "hosts",
            "MIT"
        ),
        PHISHTANK_LOCAL(
            "PhishTank Heuristics",
            "local://phishtank-heuristics",
            "heuristic",
            "CC0"
        ),
        OPENPHISH_LOCAL(
            "OpenPhish Heuristics",
            "local://openphish-heuristics",
            "heuristic",
            "CC0"
        )
    }

    enum class ThreatCategory(val label: String) {
        MALWARE("Malware Distribution"),
        PHISHING("Phishing"),
        SCAM("Scam/Fraud"),
        CRYPTOMINER("Cryptominer"),
        SPAM("Spam"),
        BOTNET("Botnet C&C"),
        RANSOMWARE("Ransomware")
    }

    data class ThreatEntry(
        val domain: String,
        val categories: Set<ThreatCategory>,
        val source: ThreatFeed,
        val confidence: Int, // 0-100
        val firstSeenMs: Long,
        val lastSeenMs: Long,
        val description: String?
    )

    data class ThreatLookupResult(
        val domain: String,
        val isThreat: Boolean,
        val entries: List<ThreatEntry>,
        val highestSeverity: ThreatCategory?,
        val combinedConfidence: Int,
        val recommendation: String
    )

    // In-memory threat index (populated from bundled + cached feeds)
    private val threatIndex = mutableMapOf<String, MutableList<ThreatEntry>>()
    private var lastUpdateMs: Long = 0L
    private var totalEntries: Int = 0

    @Synchronized
    fun loadEntries(entries: List<ThreatEntry>) {
        threatIndex.clear()
        for (entry in entries) {
            val key = entry.domain.lowercase().trimEnd('.')
            threatIndex.getOrPut(key) { mutableListOf() }.add(entry)
        }
        totalEntries = entries.size
        lastUpdateMs = System.currentTimeMillis()
    }

    @Synchronized
    fun addEntry(entry: ThreatEntry) {
        val key = entry.domain.lowercase().trimEnd('.')
        threatIndex.getOrPut(key) { mutableListOf() }.add(entry)
        totalEntries++
    }

    @Synchronized
    fun lookup(domain: String): ThreatLookupResult {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isEmpty()) {
            return ThreatLookupResult(domain, false, emptyList(), null, 0, "Invalid domain")
        }

        // Direct match
        val direct = threatIndex[normalized]
        if (direct != null && direct.isNotEmpty()) {
            return buildResult(normalized, direct)
        }

        // Subdomain walk: check if parent domain is flagged
        // e.g., evil.phishing.com where phishing.com is flagged as phishing
        val parts = normalized.split('.')
        for (i in 1 until parts.size) {
            val parent = parts.drop(i).joinToString(".")
            val parentEntries = threatIndex[parent]
            if (parentEntries != null && parentEntries.isNotEmpty()) {
                // Only inherit if the feed marks subdomain inclusion
                // For now, inherit malware/phishing at subdomain level
                val inheritable = parentEntries.filter {
                    it.categories.any { c -> c in setOf(ThreatCategory.MALWARE, ThreatCategory.PHISHING, ThreatCategory.BOTNET) }
                }
                if (inheritable.isNotEmpty()) {
                    return buildResult(normalized, inheritable)
                }
            }
        }

        return ThreatLookupResult(normalized, false, emptyList(), null, 0, "No threat intelligence match")
    }

    private fun buildResult(domain: String, entries: List<ThreatEntry>): ThreatLookupResult {
        val categories = entries.flatMap { it.categories }.toSet()
        val highestSeverity = categories.maxByOrNull { it.ordinal }
        val maxConfidence = entries.maxOf { it.confidence }
        return ThreatLookupResult(
            domain = domain,
            isThreat = true,
            entries = entries,
            highestSeverity = highestSeverity,
            combinedConfidence = maxConfidence,
            recommendation = when (highestSeverity) {
                ThreatCategory.MALWARE, ThreatCategory.RANSOMWARE, ThreatCategory.BOTNET ->
                    "BLOCK: Known ${highestSeverity?.label} infrastructure — high confidence"
                ThreatCategory.PHISHING ->
                    "BLOCK: Known phishing domain — warn user"
                ThreatCategory.SCAM ->
                    "BLOCK: Known scam domain"
                else -> "BLOCK: Threat intelligence match (${categories.joinToString { it.label }})"
            }
        )
    }

    @Synchronized
    fun getStats(): ThreatStats {
        val byCategory = mutableMapOf<ThreatCategory, Int>()
        val bySource = mutableMapOf<ThreatFeed, Int>()
        for (entries in threatIndex.values) {
            for (entry in entries) {
                for (cat in entry.categories) byCategory[cat] = (byCategory[cat] ?: 0) + 1
                bySource[entry.source] = (bySource[entry.source] ?: 0) + 1
            }
        }
        return ThreatStats(
            totalDomains = threatIndex.size,
            totalEntries = totalEntries,
            byCategory = byCategory,
            bySource = bySource,
            lastUpdateMs = lastUpdateMs
        )
    }

    data class ThreatStats(
        val totalDomains: Int,
        val totalEntries: Int,
        val byCategory: Map<ThreatCategory, Int>,
        val bySource: Map<ThreatFeed, Int>,
        val lastUpdateMs: Long
    )

    @Synchronized
    fun clear() {
        threatIndex.clear()
        totalEntries = 0
        lastUpdateMs = 0L
    }

    fun populateFromAssetLines(lines: List<String>, source: ThreatFeed = ThreatFeed.HAGEZI_TIF) {
        val entries = lines.mapNotNull { raw ->
            val d = parseHostsLine(raw, source, ThreatCategory.MALWARE) ?: return@mapNotNull null
            ThreatEntry(d, setOf(ThreatCategory.MALWARE), source, 85, System.currentTimeMillis(), System.currentTimeMillis(), null)
        }
        loadEntries(entries)
    }
    fun size(): Int = threatIndex.size

    companion object {
        /**
         * Parse a hosts-format threat feed line into domain entries.
         * Supports: "0.0.0.0 evil.com" and "||evil.com^"
         */
        fun parseHostsLine(line: String, source: ThreatFeed, category: ThreatCategory): String? {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("!")) return null
            return when {
                trimmed.startsWith("0.0.0.0 ") || trimmed.startsWith("127.0.0.1 ") -> {
                    val parts = trimmed.split(Regex("\\s+"))
                    if (parts.size >= 2) parts[1].lowercase().trim() else null
                }
                trimmed.startsWith("||") -> {
                    trimmed.removePrefix("||").substringBefore('^').substringBefore('$').lowercase().trim()
                }
                !trimmed.contains(' ') && !trimmed.contains('/') -> trimmed.lowercase()
                else -> null
            }?.takeIf { it.isNotEmpty() && it.contains('.') && !it.startsWith(".") }
        }
    }
}
