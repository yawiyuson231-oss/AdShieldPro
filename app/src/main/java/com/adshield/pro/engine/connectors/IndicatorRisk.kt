package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.IndicatorKind
import com.adshield.pro.domain.connectors.ThreatIndicator
import java.util.Locale

/**
 * Explainable, deterministic indicator matching.
 *
 * This is *not* an AI model and must never be presented as one. It combines cached public-feed
 * indicators with weights and produces a verdict plus the exact reasons behind it, so a user can
 * see why something was flagged and which source said so.
 *
 * Limits are stated in the output: a "confirmed match" means the value is present in a cached
 * public feed — not that the device is infected, nor that the site is certainly fraudulent.
 */
object IndicatorRisk {

    enum class Verdict {
        CONFIRMED_MATCH,
        SUSPICIOUS,
        SUPPRESSED,
        NO_MATCH;

        val label: String
            get() = when (this) {
                CONFIRMED_MATCH -> "KNOWN INDICATOR"
                SUSPICIOUS -> "SUSPICIOUS"
                SUPPRESSED -> "SUPPRESSED"
                NO_MATCH -> "NO MATCH"
            }
    }

    data class Assessment(
        val verdict: Verdict,
        val score: Int,
        val reasons: List<String>,
        val matches: List<ThreatIndicator>,
        val checkedKinds: List<IndicatorKind>
    )

    private fun weight(kind: IndicatorKind): Int = when (kind) {
        IndicatorKind.HASH_SHA256 -> 48
        IndicatorKind.URL -> 40
        IndicatorKind.IP -> 34
        IndicatorKind.DOMAIN -> 30
        IndicatorKind.MALWARE_FAMILY -> 34
        IndicatorKind.CVE -> 22
        IndicatorKind.ALERT -> 10
    }

    /**
     * @param candidates every cached indicator whose value matched the queried observation.
     * @param localRisk an optional 0-100 score from the app's own deterministic URL/file rules.
     */
    fun assess(candidates: List<ThreatIndicator>, localRisk: Int = 0): Assessment {
        if (candidates.isEmpty() && localRisk <= 0) {
            return Assessment(Verdict.NO_MATCH, 0, listOf("No cached indicator matches this value."), emptyList(), emptyList())
        }
        val suppressions = candidates.filter { it.confidence <= 0 }
        if (suppressions.isNotEmpty() && candidates.all { it.confidence <= 0 }) {
            return Assessment(
                Verdict.SUPPRESSED, 0,
                listOf("Suppressed by ${suppressions.first().attribution} (warninglist entry)."),
                candidates, candidates.map { it.kind }.distinct()
            )
        }
        val scoring = candidates.filter { it.confidence > 0 }
        val reasons = mutableListOf<String>()
        var best = 0
        val distinctSources = mutableSetOf<String>()
        scoring.forEach { indicator ->
            val points = (weight(indicator.kind) * indicator.confidence / 100).coerceIn(1, 60)
            if (points > best) best = points
            distinctSources += indicator.sourceId
            reasons += "${indicator.kind.name.lowercase(Locale.US)} matches ${indicator.attribution} " +
                "(confidence ${indicator.confidence}%): ${indicator.label}"
        }
        // Multiple independent sources agreeing is stronger evidence than one noisy feed.
        val corroboration = ((distinctSources.size - 1) * 6).coerceIn(0, 18)
        val localPart = (localRisk * 25 / 100).coerceIn(0, 25)
        val score = (best + corroboration + localPart).coerceIn(0, 100)
        if (corroboration > 0) reasons += "$corroboration point(s) from ${distinctSources.size} independent sources."
        if (localPart > 0) reasons += "Local deterministic rules contributed $localPart point(s)."
        val verdict = when {
            score >= 60 -> Verdict.CONFIRMED_MATCH
            score >= 25 -> Verdict.SUSPICIOUS
            else -> Verdict.SUSPICIOUS
        }
        reasons += "A match means the value appears in a cached public feed; it does not prove compromise."
        return Assessment(verdict, score, reasons, scoring, scoring.map { it.kind }.distinct())
    }

    /** Canonical form used for lookups so `HTTPS://Example.com/x` and `https://example.com/x` agree. */
    fun normalise(raw: String): String = raw.trim().lowercase(Locale.US).trimEnd('.')

    fun kindForValue(raw: String): IndicatorKind? {
        val value = normalise(raw)
        return when {
            value.startsWith("http://") || value.startsWith("https://") -> IndicatorKind.URL
            ConnectorParsers.isSha256(value) -> IndicatorKind.HASH_SHA256
            ConnectorParsers.isIpv4(value) -> IndicatorKind.IP
            ConnectorParsers.isCve(value) -> IndicatorKind.CVE
            ConnectorParsers.isDomain(value) -> IndicatorKind.DOMAIN
            else -> null
        }
    }
}
