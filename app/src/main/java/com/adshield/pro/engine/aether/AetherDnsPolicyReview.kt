package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnTunnelReceipt
import com.adshield.pro.engine.dns.DnsProviderRegistry

/** Compares saved settings with a local setup receipt. Never probes or observes traffic. */
internal object AetherDnsPolicyReview {
    enum class Failover(val label: String) {
        OFF("Off"),
        NOT_AVAILABLE("Not used for standard DNS"),
        NO_BACKUPS("On, but no eligible backup is selected"),
        CONFIGURED("Selected encrypted backups configured")
    }

    enum class AppException(val label: String) {
        VPN_EXCLUDED("Saved VPN exclusion"),
        ACTIVE_ONLY("VPN exclusion no longer saved"),
        ALLOW_DNS("Saved Allow all DNS rule")
    }

    enum class ExclusionEvidence(val label: String) {
        ACCEPTED("Applied: accepted when the tunnel was set up"),
        REJECTED("Rejected during tunnel setup"),
        NOT_RECORDED("Not recorded in this tunnel setup"),
        UNKNOWN("Unknown: no current setup receipt");

        companion object {
            fun forPackage(packageName: String, receipt: VpnTunnelReceipt?): ExclusionEvidence = when {
                receipt == null -> UNKNOWN
                packageName in receipt.acceptedExclusions -> ACCEPTED
                packageName in receipt.rejectedExclusions -> REJECTED
                else -> NOT_RECORDED
            }
        }
    }

    data class TunnelComparison(
        val generation: Long,
        val establishedAtEpochMs: Long,
        val hasIpv6DnsRoute: Boolean,
        val filteringPaused: Boolean,
        val appliedSaved: Int,
        val rejectedSaved: Int,
        val unrecordedSaved: Int,
        val appliedButNoLongerSaved: Int
    )

    data class Summary(
        val primaryProvider: String,
        val protocol: DnsProtocol,
        val failover: Failover,
        val backups: List<String>,
        val allowlistOnly: Boolean,
        val aliasShieldOn: Boolean,
        val dnssecMode: DnssecMode,
        val vpnExcludedApps: Int,
        val allowDnsOverrides: Int,
        val excludedAppsWithBlockRules: Int,
        val networksWithoutDomainFiltering: List<NetworkTransportPolicy>,
        val subnetForwardingProviders: List<String>,
        val tunnel: TunnelComparison? = null
    )

    /** Package IDs stay in memory; the report exposes counts and only bounded matched details. */
    class Snapshot internal constructor(
        val summary: Summary,
        private val excluded: Set<String>,
        private val allowDns: Set<String>,
        private val receipt: VpnTunnelReceipt? = null
    ) {
        /** Take a single runtime snapshot when the report is assembled, not before the app scan. */
        fun compareWith(runtime: VpnRuntimeState): Snapshot {
            val current = runtime.activeTunnelReceipt
            val comparison = current?.let {
                val applied = excluded.count { it in current.acceptedExclusions }
                val rejected = excluded.count { it in current.rejectedExclusions }
                TunnelComparison(
                    generation = current.generation,
                    establishedAtEpochMs = current.establishedAtEpochMs,
                    hasIpv6DnsRoute = current.hasIpv6DnsRoute,
                    filteringPaused = runtime.status == VpnStatus.PAUSED,
                    appliedSaved = applied,
                    rejectedSaved = rejected,
                    unrecordedSaved = excluded.size - applied - rejected,
                    appliedButNoLongerSaved = current.acceptedExclusions.count { it !in excluded }
                )
            }
            return Snapshot(summary.copy(tunnel = comparison), excluded, allowDns, current)
        }

        fun exceptionFor(packageName: String): AppException? = when {
            packageName in excluded -> AppException.VPN_EXCLUDED
            receipt?.acceptedExclusions?.contains(packageName) == true -> AppException.ACTIVE_ONLY
            packageName in allowDns -> AppException.ALLOW_DNS
            else -> null
        }

        fun exclusionEvidenceFor(packageName: String): ExclusionEvidence? = when (exceptionFor(packageName)) {
            AppException.VPN_EXCLUDED, AppException.ACTIVE_ONLY -> ExclusionEvidence.forPackage(packageName, receipt)
            AppException.ALLOW_DNS, null -> null // DNS policy is evaluated per attributed request, not at setup.
        }
    }

    fun inspect(config: DnsResolverConfig, policy: DnsFirewallPolicy, excluded: Set<String>, aliasShieldOn: Boolean): Snapshot {
        val plan = DnsProviderRegistry.queryPlan(config)
        val backups = plan.drop(1)
        val exceptions = excluded.toSet()
        val allowDns = policy.appPolicies.filterValues { it == AppDnsPolicy.ALLOW_ALL }.keys.toSet()
        val subnetForwarding = plan.filter { endpoint ->
            DnsProviderPreset.entries.any { it.id == endpoint.providerId && it.forwardsClientSubnet }
        }.map { it.displayName }
        return Snapshot(
            Summary(
                primaryProvider = plan.first().displayName,
                protocol = config.protocol,
                failover = when {
                    !config.failoverEnabled -> Failover.OFF
                    config.protocol == DnsProtocol.UDP_TCP -> Failover.NOT_AVAILABLE
                    backups.isEmpty() -> Failover.NO_BACKUPS
                    else -> Failover.CONFIGURED
                },
                backups = backups.map { it.displayName },
                allowlistOnly = policy.emergencyAllowlistOnly,
                aliasShieldOn = aliasShieldOn,
                dnssecMode = config.dnssecMode,
                vpnExcludedApps = exceptions.size,
                allowDnsOverrides = allowDns.size,
                excludedAppsWithBlockRules = exceptions.count { policy.appPolicies[it] == AppDnsPolicy.BLOCK_ALL },
                networksWithoutDomainFiltering = NetworkTransportPolicy.entries.filterNot { it in policy.protectedTransports },
                subnetForwardingProviders = subnetForwarding
            ),
            excluded = exceptions,
            allowDns = allowDns
        )
    }
}
