package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.AetherDnsPolicyReview.ExclusionEvidence
import com.adshield.pro.engine.dns.DnsFirewallPolicyDecider
import com.adshield.pro.engine.dns.DnsPolicyDecision

/** Explains Per-App Firewall's Filtered mode for one saved VPN exclusion. No writer or resolver. */
internal object AetherVpnExclusionPreview {
    // Imported settings may contain junk. Only show valid-looking IDs, without rewriting them.
    private val packageId = Regex("[a-zA-Z][a-zA-Z0-9_]*(?:\\.[a-zA-Z][a-zA-Z0-9_]*)*")

    enum class Example(val label: String, blockedByDomainRule: Boolean, source: String) {
        NO_MATCH("No matching domain rule", false, "Allowed"),
        DOMAIN_BLOCK("Matches a domain block rule", true, "Domain block rule"),
        EXPLICIT_ALLOW("Matches a user allowlist rule", false, "User Allowlist");

        // These are inputs to the real policy evaluator, not names inspected or sent by the Agent.
        val domainResult = FilterEvaluationResult(
            domain = "example.invalid", isBlocked = blockedByDomainRule, matchedRule = null,
            matchedCategory = null, matchType = null, sourceName = source, priority = 0
        )
    }

    data class Comparison(val example: Example, val saved: DnsPolicyDecision, val filtered: DnsPolicyDecision)
    data class TransportExamples(val transport: NetworkTransportPolicy, val comparisons: List<Comparison>)

    data class Report(
        val packageName: String,
        val savedAppPolicy: AppDnsPolicy,
        val exclusionEvidence: ExclusionEvidence,
        val tunnelGeneration: Long?,
        val filteringPaused: Boolean,
        val sampledAtMs: Long,
        val examples: List<TransportExamples>
    )

    fun targets(savedExclusions: Set<String>, ownPackage: String): List<String> =
        savedExclusions.filter { isUserTarget(it, ownPackage) }.sorted()

    /** Null means there is no longer an eligible saved exclusion for this exact selection. */
    fun compare(
        selectedPackage: String,
        ownPackage: String,
        savedExclusions: Set<String>,
        savedPolicy: DnsFirewallPolicy,
        runtime: VpnRuntimeState,
        sampledAtMs: Long
    ): Report? {
        if (selectedPackage !in savedExclusions || !isUserTarget(selectedPackage, ownPackage)) return null
        val receipt = runtime.activeTunnelReceipt
        // Filtered removes the saved exclusion and resets only this app's DNS override. The
        // examples below are conditional on the query actually reaching the DNS policy evaluator.
        val restored = savedPolicy.copy(appPolicies = savedPolicy.appPolicies - selectedPackage)
        return Report(
            packageName = selectedPackage,
            savedAppPolicy = savedPolicy.appPolicies[selectedPackage] ?: AppDnsPolicy.DEFAULT,
            exclusionEvidence = ExclusionEvidence.forPackage(selectedPackage, receipt),
            tunnelGeneration = receipt?.generation,
            filteringPaused = runtime.status == VpnStatus.PAUSED,
            sampledAtMs = sampledAtMs,
            examples = NetworkTransportPolicy.entries.map { transport ->
                TransportExamples(transport, Example.entries.map { example ->
                    Comparison(
                        example,
                        DnsFirewallPolicyDecider.evaluate(example.domainResult, selectedPackage, transport, savedPolicy),
                        DnsFirewallPolicyDecider.evaluate(example.domainResult, selectedPackage, transport, restored)
                    )
                })
            }
        )
    }

    private fun isUserTarget(packageName: String, ownPackage: String): Boolean =
        packageName != ownPackage && packageName.length <= 255 && packageId.matches(packageName)
}
