package com.adshield.pro.engine.dns

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.service.AdShieldVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.util.Random
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — On-Device DNS Leak & Tunnel Bypass Auditor.
 *
 * Audits real network state without pinging an unaudited third-party tracking service:
 * 1. Inspects active `ConnectivityManager` networks + `LinkProperties` to verify whether the
 *    AdShield virtual DNS sinkhole (`10.215.173.2` / `fd00:ad5:1e1d::2`) owns DNS resolution.
 * 2. Detects Android system Private DNS (`LinkProperties.isPrivateDnsActive`) overrides that can
 *    bypass TUN port-53 routing unless configured consistently.
 * 3. Audits whether IPv6 DNS is covered when dual-stack networks are present, and whether the
 *    configured upstream encrypts DNS (`DoH` / `DoT`) vs plaintext `UDP_TCP`.
 * 4. Optionally executes a live wire-format probe through [UpstreamDnsResolver] to verify the
 *    encrypted upstream responds cleanly without plaintext fallback.
 */
@Singleton
class DnsLeakDetector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val upstreamDnsResolver: UpstreamDnsResolver
) {

    enum class AuditVerdict {
        PROTECTED,
        BYPASS_RISK,
        UNPROTECTED
    }

    data class LeakAuditInput(
        val vpnTunnelConnected: Boolean,
        val vpnDnsServers: List<String>,
        val physicalDnsServers: List<String>,
        val systemPrivateDnsActive: Boolean,
        val systemPrivateDnsHost: String?,
        val hasIpv6Connectivity: Boolean,
        val resolverConfig: DnsResolverConfig,
        val liveProbeSucceeded: Boolean?,
        val liveProbeProtocol: String?,
        val liveProbeLatencyMs: Int?
    )

    data class LeakAuditReport(
        val verdict: AuditVerdict,
        val encryptedUpstream: Boolean,
        val tunnelCapturesDns: Boolean,
        val observedDnsServers: List<String>,
        val findings: List<String>,
        val probeLatencyMs: Int?,
        val checkedAtEpochMs: Long
    )

    suspend fun runAudit(
        vpnConnected: Boolean,
        config: DnsResolverConfig,
        runLiveUpstreamProbe: Boolean = true
    ): LeakAuditReport = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val vpnDns = ArrayList<String>()
        val physicalDns = ArrayList<String>()
        var privateDnsActive = false
        var privateDnsHost: String? = null
        var hasIpv6 = false

        @Suppress("DEPRECATION")
        val networks = runCatching { cm?.allNetworks?.toList() }.getOrNull().orEmpty()
        for (network in networks) {
            val caps = runCatching { cm?.getNetworkCapabilities(network) }.getOrNull() ?: continue
            val props = runCatching { cm?.getLinkProperties(network) }.getOrNull() ?: continue
            val dnsIps = props.dnsServers.mapNotNull { it.hostAddress }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnDns.addAll(dnsIps)
            } else if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                physicalDns.addAll(dnsIps)
                if (props.linkAddresses.any { it.address.address.size == 16 && !it.address.isLinkLocalAddress }) {
                    hasIpv6 = true
                }
            }
            if (props.isPrivateDnsActive) {
                privateDnsActive = true
                if (!props.privateDnsServerName.isNullOrBlank()) {
                    privateDnsHost = props.privateDnsServerName
                }
            }
        }

        var probeOk: Boolean? = null
        var probeProto: String? = null
        var probeLatency: Int? = null
        if (runLiveUpstreamProbe) {
            val queryBytes = buildProbeWireQuery("example.com")
            val parsed = DnsPacketCodec.parseQuery(queryBytes)
            if (parsed != null) {
                val res = runCatching { upstreamDnsResolver.resolve(parsed, config) }.getOrNull()
                if (res != null) {
                    probeOk = !res.protocolUsed.startsWith("SERVFAIL") &&
                        UpstreamDnsResolver.shouldCacheDnsResponse(res.responseBytes)
                    probeProto = res.protocolUsed
                    probeLatency = res.latencyMs
                } else {
                    probeOk = false
                }
            }
        }

        evaluateAudit(
            LeakAuditInput(
                vpnTunnelConnected = vpnConnected,
                vpnDnsServers = vpnDns.distinct(),
                physicalDnsServers = physicalDns.distinct(),
                systemPrivateDnsActive = privateDnsActive,
                systemPrivateDnsHost = privateDnsHost,
                hasIpv6Connectivity = hasIpv6,
                resolverConfig = config,
                liveProbeSucceeded = probeOk,
                liveProbeProtocol = probeProto,
                liveProbeLatencyMs = probeLatency
            )
        )
    }

    companion object {
        fun evaluateAudit(input: LeakAuditInput): LeakAuditReport {
            val findings = ArrayList<String>()
            val encrypted = input.resolverConfig.protocol == DnsProtocol.DOH ||
                input.resolverConfig.protocol == DnsProtocol.DOT

            val capturesIpv4 = input.vpnDnsServers.contains(AdShieldVpnService.VIRTUAL_IPV4_DNS)
            val capturesIpv6 = input.vpnDnsServers.any {
                it.equals(AdShieldVpnService.VIRTUAL_IPV6_DNS, ignoreCase = true)
            }
            val tunnelCaptures = input.vpnTunnelConnected && (capturesIpv4 || input.vpnDnsServers.isEmpty())

            if (!input.vpnTunnelConnected) {
                findings.add("VPN tunnel is off: device DNS queries are sent directly to your ISP/network DNS (${input.physicalDnsServers.joinToString().ifBlank { "system default" }}).")
            }
            if (input.vpnTunnelConnected && input.vpnDnsServers.isNotEmpty() && !capturesIpv4) {
                findings.add("Active VPN interface does not list AdShield sinkhole ${AdShieldVpnService.VIRTUAL_IPV4_DNS} (another VPN may own the tunnel).")
            }
            if (input.systemPrivateDnsActive) {
                val hostDesc = input.systemPrivateDnsHost?.let { " ($it)" } ?: " (Opportunistic/Strict DoT)"
                findings.add("Android System Private DNS is active$hostDesc — system DoT on port 853 can bypass port-53 VPN DNS filtering unless set to Automatic/Off.")
            }
            if (input.vpnTunnelConnected && input.hasIpv6Connectivity && !input.resolverConfig.enableIpv6) {
                findings.add("Network has global IPv6 connectivity while AdShield IPv6 DNS routing is disabled — enable IPv6 Dual-Stack DNS Routing in Settings.")
            }
            if (!encrypted) {
                findings.add("Upstream DNS is set to unencrypted UDP/TCP port 53; ISP/network observers can inspect queried hostnames.")
            }
            if (input.liveProbeSucceeded == false) {
                findings.add("Configured upstream resolver failed live verification (${input.liveProbeProtocol ?: "no response"}). Encrypted DNS did not downgrade to plaintext.")
            } else if (input.liveProbeSucceeded == true && input.liveProbeProtocol != null) {
                findings.add("Verified upstream resolver response via ${input.liveProbeProtocol} (${input.liveProbeLatencyMs ?: 0} ms).")
            }

            val verdict = when {
                !input.vpnTunnelConnected -> AuditVerdict.UNPROTECTED
                input.systemPrivateDnsActive ||
                    !encrypted ||
                    (input.hasIpv6Connectivity && !input.resolverConfig.enableIpv6) ||
                    (input.vpnDnsServers.isNotEmpty() && !capturesIpv4) ||
                    input.liveProbeSucceeded == false -> AuditVerdict.BYPASS_RISK
                else -> AuditVerdict.PROTECTED
            }

            return LeakAuditReport(
                verdict = verdict,
                encryptedUpstream = encrypted,
                tunnelCapturesDns = tunnelCaptures && (capturesIpv6 || !input.hasIpv6Connectivity || input.resolverConfig.enableIpv6),
                observedDnsServers = (input.vpnDnsServers + input.physicalDnsServers).distinct(),
                findings = findings,
                probeLatencyMs = input.liveProbeLatencyMs,
                checkedAtEpochMs = System.currentTimeMillis()
            )
        }

        fun buildProbeWireQuery(domain: String): ByteArray {
            val txId = Random().nextInt(0xFFFF)
            val out = ByteArrayOutputStream(64)
            out.write((txId ushr 8) and 0xFF)
            out.write(txId and 0xFF)
            out.write(0x01) // RD=1
            out.write(0x00)
            out.write(0x00); out.write(0x01) // QDCOUNT=1
            out.write(0x00); out.write(0x00)
            out.write(0x00); out.write(0x00)
            out.write(0x00); out.write(0x00)
            for (label in domain.trim().trimEnd('.').split('.')) {
                val b = label.toByteArray(Charsets.US_ASCII)
                out.write(b.size)
                out.write(b)
            }
            out.write(0x00)
            out.write(0x00); out.write(0x01) // QTYPE A
            out.write(0x00); out.write(0x01) // QCLASS IN
            return out.toByteArray()
        }
    }
}
