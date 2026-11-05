package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig

/** A concrete upstream provider. Secondary addresses remain inside the same trust boundary. */
data class DnsProviderEndpoint(
    val providerId: String,
    val displayName: String,
    val dohUrl: String,
    val dotHostname: String,
    val dotPort: Int,
    val ipv4Addresses: List<String>,
    val ipv6Addresses: List<String>
)

/**
 * Converts user configuration into an explicit, ordered provider plan.
 *
 * No response merging is performed. Failover is opt-in, uses only the providers the user selected,
 * and never changes an encrypted protocol to plaintext DNS.
 */
object DnsProviderRegistry {
    fun endpoint(preset: DnsProviderPreset, config: DnsResolverConfig): DnsProviderEndpoint {
        if (preset != DnsProviderPreset.CUSTOM) {
            return DnsProviderEndpoint(
                providerId = preset.id,
                displayName = preset.displayName,
                dohUrl = preset.dohUrl,
                dotHostname = preset.dotHostname,
                dotPort = preset.dotPort,
                ipv4Addresses = listOf(preset.primaryIpv4, preset.secondaryIpv4).distinct(),
                ipv6Addresses = listOf(preset.primaryIpv6, preset.secondaryIpv6).distinct()
            )
        }
        return DnsProviderEndpoint(
            providerId = preset.id,
            displayName = preset.displayName,
            dohUrl = config.customDohUrl.ifBlank { preset.dohUrl },
            dotHostname = config.customDotHost.ifBlank { preset.dotHostname },
            dotPort = preset.dotPort,
            ipv4Addresses = listOf(config.customPrimaryIpv4, config.customSecondaryIpv4)
                .filter { it.isNotBlank() }.distinct(),
            ipv6Addresses = listOf(config.customPrimaryIpv6, config.customSecondaryIpv6)
                .filter { it.isNotBlank() }.distinct()
        )
    }

    fun queryPlan(config: DnsResolverConfig): List<DnsProviderEndpoint> {
        val primary = endpoint(config.preset, config)
        if (!config.failoverEnabled || config.protocol == DnsProtocol.UDP_TCP) return listOf(primary)
        val selected = linkedMapOf(primary.providerId to primary)
        config.failoverProviderIds.forEach { id ->
            DnsProviderPreset.entries.firstOrNull { it.id == id && it != DnsProviderPreset.CUSTOM }
                ?.let { preset -> selected.putIfAbsent(preset.id, endpoint(preset, config)) }
        }
        return selected.values.toList()
    }

    fun orderedByHealth(
        plan: List<DnsProviderEndpoint>,
        health: DnsProviderHealthMonitor,
        protocol: DnsProtocol,
        fastestHealthy: Boolean
    ): List<DnsProviderEndpoint> {
        if (!fastestHealthy || plan.size < 2) return plan
        // Unknown latency stays in configured order; measured healthy providers sort by EWMA.
        return plan.withIndex().sortedWith(
            compareBy<IndexedValue<DnsProviderEndpoint>> {
                health.snapshot(it.value.providerId, protocol).ewmaLatencyMs ?: Long.MAX_VALUE
            }.thenBy { it.index }
        ).map { it.value }
    }
}
