package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine

/**
 * Unmasks CNAME-cloaked trackers and ad/malware domains in upstream DNS Answer chains.
 *
 * Trackers frequently ask publishers to delegate a first-party subdomain (for example
 * `metrics.publisher.example`) via a DNS `CNAME` record pointing at a third-party collector
 * (`collector.adtech-tracker.example`). A question-only DNS filter lets the query pass because
 * the queried name looks first-party; inspecting the returned `CNAME` chain catches the real
 * destination while honouring user allowlists and [DnsMediaPlaybackGuard] streaming safety.
 */
object CnameCloakingInspector {

    data class CnameCloakDecision(
        val shouldBlock: Boolean,
        val cloakedTarget: String? = null,
        val matchedRule: String? = null,
        val matchedCategory: RuleCategory? = null,
        val sourceName: String = "Allowed",
        val cnameChain: List<String> = emptyList()
    )

    fun inspect(
        questionDomain: String,
        questionEvaluation: FilterEvaluationResult,
        dnsResponse: ByteArray,
        filterEngine: FilterRuleEngine,
        enabled: Boolean,
        bypassDomainFilters: Boolean
    ): CnameCloakDecision {
        if (!enabled || bypassDomainFilters) {
            return CnameCloakDecision(shouldBlock = false)
        }
        // Respect explicit user or system-safety allowlists on the queried first-party domain.
        if (isExplicitAllow(questionEvaluation)) {
            return CnameCloakDecision(shouldBlock = false)
        }

        val chain = DnsPacketCodec.extractCnameTargets(dnsResponse)
        if (chain.isEmpty()) {
            return CnameCloakDecision(shouldBlock = false)
        }

        val normalizedQuestion = questionDomain.trim().trimEnd('.').lowercase()
        for (target in chain) {
            if (target == normalizedQuestion) continue

            val targetEval = filterEngine.evaluate(target)
            if (isExplicitAllow(targetEval)) continue
            if (!targetEval.isBlocked) continue

            // Never break video/audio stream delivery when a site CNAMEs onto a protected playback
            // host (unless the user explicitly wrote a custom block rule for that target).
            val isExplicitUserBlock =
                targetEval.sourceName == "User Custom Rule" || targetEval.sourceName == "User Blocklist"
            if (!isExplicitUserBlock && DnsMediaPlaybackGuard.isProtectedPlaybackHost(target)) {
                continue
            }

            return CnameCloakDecision(
                shouldBlock = true,
                cloakedTarget = target,
                matchedRule = targetEval.matchedRule ?: target,
                matchedCategory = targetEval.matchedCategory,
                sourceName = "CNAME Uncloaking · ${targetEval.sourceName}",
                cnameChain = chain
            )
        }

        return CnameCloakDecision(shouldBlock = false, cnameChain = chain)
    }

    private fun isExplicitAllow(evaluation: FilterEvaluationResult): Boolean {
        if (evaluation.isBlocked) return false
        return evaluation.sourceName == "User Allowlist" ||
            evaluation.sourceName == "System Safety Allowlist" ||
            evaluation.sourceName == "User Custom Rule"
    }
}
