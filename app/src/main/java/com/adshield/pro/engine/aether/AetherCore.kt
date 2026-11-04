package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.RuleCategory

/**
 * Aether AI — the decision core.
 *
 * One place decides what to do with a DNS query, a URL or an app, from evidence that is always
 * traceable to a list, a user rule or a named heuristic. It is deliberately conservative:
 *
 *  - a curated list match (threat intel, ad/tracker lists) or a user rule yields VERIFIED;
 *    threat intel carries higher confidence than ad lists, and only verified items block;
 *  - heuristics alone can never block, they only produce SUSPECTED + ALLOW_AND_REVIEW;
 *  - a user allow rule outranks every heuristic (false-positive reduction);
 *  - unknown is a first-class answer, not a guess.
 *
 * Pure functions only, so the whole decision table is unit-tested on the JVM.
 */
object AetherCore {

    /** Autonomous response ceilings the user can pick in Settings. */
    enum class AutonomyLevel(val label: String, val description: String) {
        OFF("Manual", "Aether only observes and reports; nothing is blocked automatically."),
        VERIFIED_ONLY("Verified only", "Blocks only curated threat-list and user-rule matches."),
        VERIFIED_AND_SUSPECTED("Verified + suspected", "Also blocks domains that trip several heuristics (higher false-positive risk).")
    }

    private const val SUSPECTED_THRESHOLD = 45
    private const val MAX_EVIDENCE = 8

    /**
     * Evaluates one DNS query result from the filter engine (already computed on the hot path).
     *
     * @param heuristics extra domain findings (typically from [DomainRiskAnalyzer])
     */
    fun assessDnsQuery(
        domain: String,
        evaluation: FilterEvaluationResult,
        heuristics: List<DomainRiskAnalyzer.Finding> = emptyList(),
        autonomy: AutonomyLevel = AutonomyLevel.VERIFIED_ONLY,
        nowEpochMs: Long = System.currentTimeMillis()
    ): ThreatAssessment {
        val evidence = ArrayList<Evidence>()

        // 1. Filter engine evidence (the engine already applied user allow > user block > lists).
        // Source names come from FilterRuleEngine: "User Allowlist", "User Blocklist",
        // "User Custom Rule", "System Safety Allowlist", list names, or the bare "Allowed"
        // default when nothing matched. The bare default is NOT evidence of anything.
        if (evaluation.isBlocked) {
            val category = evaluation.matchedCategory ?: RuleCategory.ADS
            val source = evaluation.sourceName
            val isUserRule = source.contains("custom", ignoreCase = true) ||
                source.contains("user block", ignoreCase = true)
            val kind = when {
                isUserRule -> EvidenceKind.USER_BLOCK
                category == RuleCategory.MALWARE -> EvidenceKind.THREAT_LIST
                else -> EvidenceKind.AD_LIST
            }
            val confidence = when (kind) {
                EvidenceKind.USER_BLOCK -> 100
                EvidenceKind.THREAT_LIST -> 95
                else -> 85
            }
            evidence += Evidence(
                kind = kind,
                source = source.ifBlank { "Filter engine" },
                confidence = confidence,
                explanation = "Matched ${category.displayName.lowercase()} rule from ${source.ifBlank { "the active lists" }}"
            )
        } else {
            val source = evaluation.sourceName
            val isUserAllow = source.contains("user allow", ignoreCase = true) ||
                (source.contains("custom", ignoreCase = true) && source.contains("allow", ignoreCase = true))
            val isCuratedAllow = source.contains("allowlist", ignoreCase = true) ||
                source.contains("allow list", ignoreCase = true)
            when {
                isUserAllow -> evidence += Evidence(
                    kind = EvidenceKind.USER_ALLOW,
                    source = source,
                    confidence = 100,
                    explanation = "Explicitly allowed by $source"
                )
                isCuratedAllow -> evidence += Evidence(
                    kind = EvidenceKind.SAFE_ALLOWLIST,
                    source = source,
                    confidence = 100,
                    explanation = "Explicitly allowed by $source"
                )
                // "Allowed" / "Allowed (no rule match)": nothing matched, so there is no
                // evidence and confidence must stay 0 — unknown is a first-class answer.
            }
        }

        // 2. Heuristics (never enough on their own to verify a threat).
        val heuristicScore = DomainRiskAnalyzer.riskScore(heuristics)
        heuristics.forEach { finding ->
            evidence += Evidence(
                kind = EvidenceKind.HEURISTIC,
                source = finding.code,
                confidence = finding.weight.coerceIn(0, 60),
                explanation = finding.explanation
            )
        }

        return decide(
            target = domain,
            evidence = evidence,
            heuristicScore = heuristicScore,
            autonomy = autonomy,
            nowEpochMs = nowEpochMs
        )
    }

    /**
     * Evaluates a URL the user asked the scanner about (browser link check / paste-in scan).
     */
    fun assessUrl(
        rawUrl: String,
        hostBlockedByList: Boolean,
        hostBlockedCategory: RuleCategory? = null,
        listSource: String = "",
        autonomy: AutonomyLevel = AutonomyLevel.VERIFIED_ONLY,
        nowEpochMs: Long = System.currentTimeMillis()
    ): ThreatAssessment {
        val findings = DomainRiskAnalyzer.analyze(rawUrl)
        val evidence = ArrayList<Evidence>()
        if (hostBlockedByList) {
            val category = hostBlockedCategory ?: RuleCategory.MALWARE
            evidence += Evidence(
                kind = if (category == RuleCategory.MALWARE) EvidenceKind.THREAT_LIST else EvidenceKind.AD_LIST,
                source = listSource.ifBlank { "active threat lists" },
                confidence = if (category == RuleCategory.MALWARE) 95 else 80,
                explanation = "Host appears on the ${category.displayName.lowercase()} list"
            )
        }
        findings.forEach {
            evidence += Evidence(EvidenceKind.HEURISTIC, it.code, it.weight.coerceIn(0, 60), it.explanation)
        }
        return decide(
            target = DomainRiskAnalyzer.hostOf(rawUrl).ifEmpty { rawUrl },
            evidence = evidence,
            heuristicScore = DomainRiskAnalyzer.riskScore(findings),
            autonomy = autonomy,
            nowEpochMs = nowEpochMs
        )
    }

    /**
     * Evaluates an installed app from the audit signals already computed on-device.
     * App risk can make an app SUSPECTED, never VERIFIED — a permission stack is not malware.
     */
    fun assessApp(
        packageName: String,
        appName: String,
        highRiskSignals: Int,
        signalExplanations: List<String>,
        fromUnknownInstaller: Boolean,
        nowEpochMs: Long = System.currentTimeMillis()
    ): ThreatAssessment {
        val evidence = ArrayList<Evidence>()
        if (highRiskSignals > 0) {
            val confidence = (40 + highRiskSignals * 12).coerceAtMost(80)
            evidence += Evidence(
                kind = EvidenceKind.APP_RISK,
                source = "permission audit",
                confidence = confidence,
                explanation = "$highRiskSignals risky capability signal(s): " + signalExplanations.take(3).joinToString("; ")
            )
        }
        if (fromUnknownInstaller) {
            evidence += Evidence(
                EvidenceKind.APP_RISK,
                "installer",
                35,
                "Installed from an unknown source rather than an app store"
            )
        }
        val heuristicScore = ((highRiskSignals * 15) + if (fromUnknownInstaller) 20 else 0).coerceIn(0, 100)
        // Apps are never auto-blocked; the action is a review prompt.
        val base = decide(
            target = "$appName ($packageName)",
            evidence = evidence,
            heuristicScore = heuristicScore,
            autonomy = AutonomyLevel.OFF,
            nowEpochMs = nowEpochMs
        )
        return base.copy(
            action = AetherAction.ALLOW_AND_REVIEW,
            autonomyNote = "Apps are never blocked automatically — the audit only recommends a review."
        )
    }

    /**
     * The decision table. Kept tiny and explicit so it can be read and tested line by line.
     */
    private fun decide(
        target: String,
        evidence: List<Evidence>,
        heuristicScore: Int,
        autonomy: AutonomyLevel,
        nowEpochMs: Long
    ): ThreatAssessment {
        val trimmed = evidence.take(MAX_EVIDENCE)
        val hasUserAllow = trimmed.any { it.kind == EvidenceKind.USER_ALLOW }
        // Curated lists verify a block: threat intel, the user's own block rule, and the
        // ad/tracker lists (weaker confidence than threat intel, but still a list match).
        val verifiedItem = trimmed.firstOrNull {
            it.kind == EvidenceKind.THREAT_LIST || it.kind == EvidenceKind.USER_BLOCK ||
                it.kind == EvidenceKind.AD_LIST
        }
        val curatedAllow = trimmed.firstOrNull { it.kind == EvidenceKind.SAFE_ALLOWLIST }
        val riskScore = aggregateRisk(trimmed, heuristicScore)
        val confidence = aggregateConfidence(trimmed)

        // 1. A user allow rule always wins: that is the documented false-positive escape hatch.
        if (hasUserAllow) {
            return ThreatAssessment(
                target, ThreatVerdict.ALLOWED, AetherAction.ALLOW, riskScore.coerceAtMost(30), confidence,
                trimmed, "Allowed by your own rule — heuristics never override it.", nowEpochMs
            )
        }

        // 2. Verified: a curated list or the user's block rule says so.
        if (verifiedItem != null) {
            val blocked = when (autonomy) {
                AutonomyLevel.OFF -> AetherAction.ALLOW_AND_REVIEW
                else -> AetherAction.BLOCK
            }
            return ThreatAssessment(
                target, ThreatVerdict.VERIFIED, blocked, riskScore, confidence, trimmed,
                if (blocked == AetherAction.BLOCK) "Blocked automatically: verified by ${verifiedItem.source}."
                else "Automatic blocking is set to Manual, so this was reported instead of blocked.",
                nowEpochMs
            )
        }

        // 2b. A curated system allowlist is a verified answer too — an ALLOW. Heuristics do
        // not override curated exceptions, mirroring the engine's own priority ladder.
        if (curatedAllow != null) {
            return ThreatAssessment(
                target, ThreatVerdict.ALLOWED, AetherAction.ALLOW, riskScore.coerceAtMost(30), confidence,
                trimmed, "Allowed by ${curatedAllow.source} — heuristics do not override curated exceptions.",
                nowEpochMs
            )
        }

        // 3. Suspected: heuristics only. Blocks only if the user opted into that autonomy level.
        if (heuristicScore >= SUSPECTED_THRESHOLD) {
            val blocked = autonomy == AutonomyLevel.VERIFIED_AND_SUSPECTED && heuristicScore >= 60
            return ThreatAssessment(
                target, ThreatVerdict.SUSPECTED,
                if (blocked) AetherAction.BLOCK else AetherAction.ALLOW_AND_REVIEW,
                riskScore, confidence, trimmed,
                if (blocked) "Blocked by your \"verified + suspected\" setting (heuristic score $heuristicScore)."
                else "Looks suspicious, but heuristics are not proof — traffic is allowed and queued for review.",
                nowEpochMs
            )
        }

        // 4. Unknown with a little noise, or plainly allowed.
        val verdict = if (heuristicScore > 0) ThreatVerdict.UNKNOWN else ThreatVerdict.ALLOWED
        return ThreatAssessment(
            target, verdict, AetherAction.ALLOW, riskScore, confidence, trimmed,
            "No threat-list or rule match; heuristics did not reach the review threshold.",
            nowEpochMs
        )
    }

    /**
     * Risk aggregation: a verified list match dominates; heuristics contribute their own score but
     * cannot push an otherwise-clean target into "verified" territory.
     */
    fun aggregateRisk(evidence: List<Evidence>, heuristicScore: Int): Int {
        val listRisk = evidence
            .filter { it.kind == EvidenceKind.THREAT_LIST || it.kind == EvidenceKind.USER_BLOCK }
            .maxOfOrNull { it.confidence }
            ?: 0
        if (listRisk > 0) return (listRisk + heuristicScore / 4).coerceIn(0, 100)
        return heuristicScore.coerceIn(0, 100)
    }

    /** Confidence in the *assessment*, not the danger: more independent evidence = higher. */
    fun aggregateConfidence(evidence: List<Evidence>): Int {
        if (evidence.isEmpty()) return 0
        val strongest = evidence.maxOf { it.confidence }
        val corroboration = ((evidence.size - 1) * 5).coerceAtMost(20)
        return (strongest + corroboration).coerceIn(0, 100)
    }
}
