package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsResolverConfig

/**
 * TitanShield Max — DNS Leak & Exposure Assessment (Module 1/6).
 *
 * Honest, on-device analysis of DNS exposure:
 * - With the local VPN active, ALL system DNS from every app is routed through the
 *   TitanShield tunnel (the VPN claims the DNS servers) — there is no plaintext
 *   port-53 leak around the tunnel for VPN-obeying apps.
 * - Apps that hardcode their own DoH/QUIC resolvers bypass any local DNS VPN — that
 *   vector is invisible at DNS level and is disclosed, not faked.
 * - Upstream leg: DoH/DoT = encrypted to the resolver; UDP/TCP = visible metadata
 *   to the local network/ISP between device and resolver.
 */
object DnsLeakDetector {

    data class LeakReport(
        val upstreamEncrypted: Boolean,
        val protocolLabel: String,
        val protectionSummary: String,
        val honestLimitations: List<String>
    )

    fun assess(config: DnsResolverConfig, vpnActive: Boolean): LeakReport {
        val encrypted = config.protocol == DnsProtocol.DOH || config.protocol == DnsProtocol.DOT
        val summary = when {
            !vpnActive -> "VPN is off — device DNS goes directly to your network's resolver and is visible to it."
            encrypted -> "All app DNS is captured by the TitanShield tunnel and forwarded encrypted (" +
                config.protocol.label + "). Your network/operator cannot read queried domain names."
            else -> "All app DNS is captured by the TitanShield tunnel, but the device→resolver leg uses " +
                config.protocol.label + " — query metadata is visible on the network path. Switch to DoH/DoT for full encryption."
        }
        val limitations = buildList {
            if (vpnActive) {
                add("Apps with hardcoded private DoH/QUIC resolvers bypass local DNS VPNs by design — they are not visible to any DNS filter.")
                if (!encrypted) add("Plaintext upstream DNS exposes queried names on the device→resolver path.")
            } else {
                add("Enable the VPN to route all app DNS through TitanShield's filter engine.")
            }
        }
        return LeakReport(
            upstreamEncrypted = encrypted && vpnActive,
            protocolLabel = config.protocol.label,
            protectionSummary = summary,
            honestLimitations = limitations
        )
    }
}
