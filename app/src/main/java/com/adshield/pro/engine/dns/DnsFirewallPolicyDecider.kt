package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.NetworkTransportPolicy

data class DnsPolicyDecision(
    val isBlocked: Boolean,
    val bypassDomainFilters: Boolean,
    val sourceName: String,
    val matchedRule: String? = null,
    val matchedCategory: com.adshield.pro.domain.model.RuleCategory? = null
)

/** Pure, deterministic DNS-only policy enforcement. This does not inspect non-DNS connections. */
object DnsFirewallPolicyDecider {
    fun evaluate(
        evaluation: FilterEvaluationResult,
        appPackageName: String?,
        transport: NetworkTransportPolicy,
        policy: DnsFirewallPolicy
    ): DnsPolicyDecision {
        val explicitlyAllowed = evaluation.sourceName == "User Allowlist" ||
            evaluation.sourceName == "System Safety Allowlist" ||
            (evaluation.sourceName == "User Custom Rule" && !evaluation.isBlocked)

        if (policy.emergencyAllowlistOnly && !explicitlyAllowed) {
            return DnsPolicyDecision(
                isBlocked = true,
                bypassDomainFilters = false,
                sourceName = "Emergency Allowlist-Only DNS",
                matchedRule = evaluation.matchedRule,
                matchedCategory = evaluation.matchedCategory
            )
        }

        val appPolicy = appPackageName?.let { policy.appPolicies[it] } ?: AppDnsPolicy.DEFAULT
        if (appPolicy == AppDnsPolicy.BLOCK_ALL) {
            return DnsPolicyDecision(true, false, "Per-App DNS Block", appPackageName)
        }
        if (transport !in policy.protectedTransports) {
            return DnsPolicyDecision(false, true, "Network Policy Passthrough (${transport.label})")
        }
        if (appPolicy == AppDnsPolicy.ALLOW_ALL) {
            return DnsPolicyDecision(false, true, "Per-App DNS Filter Bypass", appPackageName)
        }
        return DnsPolicyDecision(
            isBlocked = evaluation.isBlocked,
            bypassDomainFilters = false,
            sourceName = evaluation.sourceName,
            matchedRule = evaluation.matchedRule,
            matchedCategory = evaluation.matchedCategory
        )
    }
}
