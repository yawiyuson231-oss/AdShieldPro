package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine

/**
 * DNS Alias Shield: checks destinations named by CNAME, HTTPS and SVCB answers against the
 * active filter rules. A publisher hostname can look safe while its answer names a tracker.
 * This is local to the DNS answer: no follow-up queries, including on upstream cache hits.
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
        questionEvaluation: FilterEvaluationResult? = null,
        dnsResponse: ByteArray,
        filterEngine: FilterRuleEngine,
        enabled: Boolean,
        bypassDomainFilters: Boolean
    ): CnameCloakDecision {
        if (!enabled || bypassDomainFilters) {
            return CnameCloakDecision(shouldBlock = false)
        }
        val aliases = DnsPacketCodec.extractAnswerAliases(dnsResponse, expectedQuestion = questionDomain)
        if (aliases.isEmpty()) return CnameCloakDecision(shouldBlock = false)
        // Use the current verdict when none was supplied, so an allowlist change made while
        // resolution was in flight can still take effect. Ordinary answers need no second check.
        if (isExplicitAllow(questionEvaluation ?: filterEngine.evaluate(questionDomain))) {
            return CnameCloakDecision(shouldBlock = false)
        }

        val cnameChain = aliases.filter { it.type == DnsPacketCodec.AnswerAliasType.CNAME }.map { it.target }
        for ((type, target) in aliases) {
            val targetEval = filterEngine.evaluate(target)
            if (!targetEval.isBlocked) continue

            // Preserve playback destinations unless the user explicitly blocked the target.
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
                sourceName = "${type.name} Uncloaking · ${targetEval.sourceName}",
                cnameChain = cnameChain
            )
        }

        return CnameCloakDecision(shouldBlock = false, cnameChain = cnameChain)
    }

    internal data class BlockedReply(val bytes: ByteArray, val label: String)

    internal fun blockedReply(query: DnsPacketCodec.ParsedDnsQuery, sinkholeZeroIp: Boolean): BlockedReply {
        if (query.qType == DnsPacketCodec.TYPE_HTTPS || query.qType == DnsPacketCodec.TYPE_SVCB) {
            // Drop the entire binding RRset, including any address hints. NXDOMAIN would also
            // tell a downstream cache the original name has no A/AAAA records.
            return BlockedReply(DnsPacketCodec.buildNoDataResponse(query), "Alias block · NODATA")
        }
        val label = when {
            !sinkholeZeroIp -> "Local NXDOMAIN"
            query.qClass == DnsPacketCodec.CLASS_IN && query.qType == DnsPacketCodec.TYPE_A -> "Sinkhole 0.0.0.0"
            query.qClass == DnsPacketCodec.CLASS_IN && query.qType == DnsPacketCodec.TYPE_AAAA -> "Sinkhole ::"
            else -> "NODATA"
        }
        return BlockedReply(DnsPacketCodec.buildBlockedResponse(query, sinkholeZeroIp), "Alias block · $label")
    }

    private fun isExplicitAllow(evaluation: FilterEvaluationResult): Boolean {
        if (evaluation.isBlocked) return false
        return evaluation.sourceName == "User Allowlist" ||
            evaluation.sourceName == "System Safety Allowlist" ||
            evaluation.sourceName == "User Custom Rule"
    }
}
