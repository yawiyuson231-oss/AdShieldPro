package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleType
import kotlin.math.ln

/**
 * AdShield Pro — Deterministic Per-Domain Anomaly Scorer & Rule Suggestion Engine.
 *
 * Computes explainable lexical + statistical anomaly scores from real DNS observations:
 * - Shannon character entropy (bits/char) over the registrable/subdomain prefix (DGA indicator)
 * - Numeric ratio & consonant-run length
 * - Subdomain label depth & max label length
 * - Query burst rate in recent DNS log history
 *
 * Also derives actionable, reversible Custom Rule suggestions from observed activity logs.
 */
object DnsAnomalyScorer {

    data class DomainAnomalyAssessment(
        val domain: String,
        val anomalyScore: Int, // 0..100
        val shannonEntropyBits: Double,
        val digitRatio: Double,
        val labelDepth: Int,
        val observedQueryCount: Int,
        val reasons: List<String>
    ) {
        val isAnomalous: Boolean get() = anomalyScore >= 55
    }

    data class RuleSuggestion(
        val domain: String,
        val suggestedRuleType: RuleType,
        val confidenceScore: Int,
        val rationale: String
    )

    fun scoreDomain(
        rawDomain: String,
        recentLogs: List<DnsActivityRecord> = emptyList()
    ): DomainAnomalyAssessment {
        val clean = rawDomain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty() || !clean.contains('.')) {
            return DomainAnomalyAssessment(clean, 0, 0.0, 0.0, 0, 0, emptyList())
        }

        val labels = clean.split('.').filter { it.isNotEmpty() }
        val nonTld = labels.dropLast(1).joinToString("")
        val entropy = shannonEntropy(nonTld)
        val digits = nonTld.count { it.isDigit() }
        val digitRatio = if (nonTld.isNotEmpty()) digits.toDouble() / nonTld.length else 0.0
        val maxConsonantRun = longestConsonantRun(nonTld)
        val maxLabelLen = labels.maxOfOrNull { it.length } ?: 0
        val observed = recentLogs.count { it.domain.equals(clean, ignoreCase = true) }

        var score = 0
        val reasons = ArrayList<String>()

        if (nonTld.length >= 12 && entropy >= 3.85) {
            score += 35
            reasons.add("High character entropy (${"%.2f".format(java.util.Locale.US, entropy)} bits/char — typical of DGA/beacon hosts)")
        } else if (nonTld.length >= 10 && entropy >= 3.55) {
            score += 18
            reasons.add("Elevated lexical entropy (${"%.2f".format(java.util.Locale.US, entropy)} bits/char)")
        }

        if (nonTld.length >= 8 && digitRatio >= 0.35) {
            score += 22
            reasons.add("High numeric character density (${(digitRatio * 100).toInt()}%)")
        }

        if (maxConsonantRun >= 6) {
            score += 18
            reasons.add("Unpronounceable consonant cluster ($maxConsonantRun consecutive consonants)")
        }

        if (labels.size >= 5) {
            score += 12
            reasons.add("Deep subdomain hierarchy (${labels.size} labels)")
        }

        if (maxLabelLen >= 28) {
            score += 15
            reasons.add("Long encoded/tokenized label ($maxLabelLen chars — DNS tunneling/tracking indicator)")
        }

        if (observed >= 15) {
            score += 15
            reasons.add("High query repetition ($observed requests in recent log window)")
        }

        return DomainAnomalyAssessment(
            domain = clean,
            anomalyScore = score.coerceIn(0, 100),
            shannonEntropyBits = entropy,
            digitRatio = digitRatio,
            labelDepth = labels.size,
            observedQueryCount = observed,
            reasons = reasons
        )
    }

    /**
     * Generates explainable Block/Allow rule candidates from real [recentLogs] without black-box ML.
     */
    fun suggestRulesFromLogs(
        recentLogs: List<DnsActivityRecord>,
        existingCustomDomains: Set<String> = emptySet(),
        limit: Int = 6
    ): List<RuleSuggestion> {
        if (recentLogs.isEmpty()) return emptyList()
        val normalizedExisting = existingCustomDomains.mapTo(HashSet()) { it.lowercase() }
        val grouped = recentLogs.groupBy { it.domain.lowercase().trimEnd('.') }
        val suggestions = ArrayList<RuleSuggestion>()

        for ((domain, entries) in grouped) {
            if (domain.isBlank() || domain in normalizedExisting) continue
            val blockedCount = entries.count { it.isBlocked }
            val allowedCount = entries.size - blockedCount

            if (allowedCount >= 3) {
                val anomaly = scoreDomain(domain, recentLogs)
                val riskFindings = DomainRiskAnalyzer.analyze(domain)
                val riskScore = DomainRiskAnalyzer.riskScore(riskFindings)
                val combined = maxOf(anomaly.anomalyScore, riskScore)
                if (combined >= 50) {
                    val why = (riskFindings.map { it.explanation } + anomaly.reasons).firstOrNull() ?: "high lexical anomaly score"
                    suggestions.add(
                        RuleSuggestion(
                            domain = domain,
                            suggestedRuleType = RuleType.BLOCK,
                            confidenceScore = combined.coerceIn(50, 95),
                            rationale = "Allowed $allowedCount time(s) with $why."
                        )
                    )
                }
            } else if (blockedCount >= 8) {
                val riskFindings = DomainRiskAnalyzer.analyze(domain)
                if (DomainRiskAnalyzer.riskScore(riskFindings) == 0 && entries.none { it.category?.name == "MALWARE" }) {
                    suggestions.add(
                        RuleSuggestion(
                            domain = domain,
                            suggestedRuleType = RuleType.ALLOW,
                            confidenceScore = 55,
                            rationale = "Repeatedly blocked ($blockedCount times) by ${entries.first().sourceList.ifBlank { "filter list" }} — allowlist only if an app feature is broken."
                        )
                    )
                }
            }
        }

        return suggestions
            .sortedByDescending { it.confidenceScore }
            .take(limit)
    }

    fun shannonEntropy(text: String): Double {
        if (text.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (ch in text) {
            counts[ch] = (counts[ch] ?: 0) + 1
        }
        val n = text.length.toDouble()
        var sum = 0.0
        for (c in counts.values) {
            val p = c / n
            sum -= p * (ln(p) / ln(2.0))
        }
        return sum
    }

    private fun longestConsonantRun(text: String): Int {
        val vowels = setOf('a', 'e', 'i', 'o', 'u', 'y')
        var best = 0
        var cur = 0
        for (ch in text) {
            if (ch in 'a'..'z' && ch !in vowels) {
                cur++
                if (cur > best) best = cur
            } else {
                cur = 0
            }
        }
        return best
    }
}
