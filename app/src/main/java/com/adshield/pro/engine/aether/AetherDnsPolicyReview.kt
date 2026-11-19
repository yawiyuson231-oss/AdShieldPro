package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.engine.dns.DnsProviderRegistry

/** Reviews saved settings, not traffic. No resolver, network, or write capability. */
internal object AetherDnsPolicyReview {
    enum class Failover(val label: String) {
        OFF("Off"),
        NOT_AVAILABLE("Not used for standard DNS"),
        NO_BACKUPS("On, but no eligible backup is selected"),
        CONFIGURED("Selected encrypted backups configured")
    }

    enum class AppException(val label: String) {
        VPN_EXCLUDED("Saved VPN exclusion"),
        ALLOW_DNS("Saved Allow all DNS rule")
    }

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
        val subnetForwardingProviders: List<String>
    )

    /** Package IDs are needed for one in-memory join. Only the summary escapes the coordinator. */
    class Snapshot internal constructor(
        val summary: Summary,
        private val excluded: Set<String>,
        private val allowDns: Set<String>
    ) {
        /** If both are saved, show the VPN exclusion: DNS rules require a request to reach the tunnel. */
        fun exceptionFor(packageName: String): AppException? = when (packageName) {
            in excluded -> AppException.VPN_EXCLUDED
            in allowDns -> AppException.ALLOW_DNS
            else -> null
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
