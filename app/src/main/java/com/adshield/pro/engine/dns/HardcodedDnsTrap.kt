package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsResolverConfig
import java.net.InetAddress

/**
 * Anti-Bypass Hardcoded-DNS Trap.
 *
 * Many embedded SDKs, smart-TV/IoT companion apps, and aggressive analytics libraries ignore
 * Android's system DNS server (`10.215.173.2`) and send DNS queries directly to hardcoded public
 * resolvers such as `8.8.8.8`, `1.1.1.1`, or `9.9.9.9`.
 *
 * When enabled, [HardcodedDnsTrap] supplies `/32` (IPv4) and `/128` (IPv6) host routes for well-known
 * public DNS resolvers to `VpnService.Builder`:
 * - Port 53 UDP/TCP queries to any trapped resolver IP are intercepted, filtered locally through
 *   AdShield's rule engine + per-app firewall, resolved via the user's chosen encrypted upstream,
 *   and answered with a matching source IP (`IpPacketFraming` swaps `dstIp` -> `srcIp` transparently).
 * - Non-port-53 TCP packets (e.g. port 853 DoT bypass attempts) to trapped resolver literals receive
 *   an immediate stateless `RST+ACK` via [buildFastFailTcpReset] so client resolvers fall back to
 *   system DNS immediately instead of stalling on a connection timeout.
 */
object HardcodedDnsTrap {

    data class CidrRoute(
        val address: String,
        val prefixLength: Int
    )

    data class TrapRoutePlan(
        val ipv4Routes: List<CidrRoute>,
        val ipv6Routes: List<CidrRoute>,
        val excludedUpstreamLiterals: Set<String>
    )

    val KNOWN_PUBLIC_DNS_IPV4: List<String> = listOf(
        // Google Public DNS
        "8.8.8.8",
        "8.8.4.4",
        // Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        // Quad9
        "9.9.9.9",
        "149.112.112.112",
        "9.9.9.11",
        "149.112.112.11",
        // OpenDNS / Cisco Umbrella
        "208.67.222.222",
        "208.67.220.220",
        // AdGuard DNS
        "94.140.14.14",
        "94.140.15.15",
        "94.140.14.140",
        "94.140.14.141",
        // CleanBrowsing & Control D & NextDNS anycast
        "185.228.168.9",
        "185.228.169.9",
        "76.76.2.0",
        "76.76.10.0",
        "45.90.28.0",
        "45.90.30.0"
    )

    val KNOWN_PUBLIC_DNS_IPV6: List<String> = listOf(
        // Google Public DNS
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        // Cloudflare
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        // Quad9
        "2620:fe::fe",
        "2620:fe::9",
        "2620:fe::11",
        // OpenDNS
        "2620:119:35::35",
        "2620:119:53::53",
        // AdGuard DNS
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff",
        "2a10:50c0::1:ff",
        "2a10:50c0::2:ff"
    )

    private val normalizedTrappedBytes: Set<ByteKey> by lazy {
        (KNOWN_PUBLIC_DNS_IPV4 + KNOWN_PUBLIC_DNS_IPV6).mapNotNull { literal ->
            runCatching { ByteKey(InetAddress.getByName(literal).address) }.getOrNull()
        }.toSet()
    }

    private data class ByteKey(val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean = other is ByteKey && bytes.contentEquals(other.bytes)
        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /**
     * Builds the exact host routes to add to `VpnService.Builder`.
     *
     * Even though AdShield excludes its own package from the VPN and calls `VpnService.protect()`
     * on upstream sockets, when `UDP_TCP` mode is explicitly chosen we also omit the active
     * plaintext upstream literals from trap routes so misbehaving OEM network stacks can never
     * self-loop.
     */
    fun buildTrapRoutes(
        config: DnsResolverConfig,
        trapEnabled: Boolean
    ): TrapRoutePlan {
        if (!trapEnabled) {
            return TrapRoutePlan(emptyList(), emptyList(), emptySet())
        }

        val excluded = LinkedHashSet<String>()
        if (config.protocol == DnsProtocol.UDP_TCP) {
            excluded += config.activePrimaryIpv4.trim()
            excluded += config.activeSecondaryIpv4.trim()
            excluded += config.activePrimaryIpv6.trim().lowercase()
            excluded += config.activeSecondaryIpv6.trim().lowercase()
        }

        val v4 = KNOWN_PUBLIC_DNS_IPV4
            .filter { it !in excluded }
            .distinct()
            .map { CidrRoute(it, 32) }

        val v6 = if (config.enableIpv6) {
            KNOWN_PUBLIC_DNS_IPV6
                .filter { !sameIpLiteral(it, excluded) }
                .distinct()
                .map { CidrRoute(it, 128) }
        } else {
            emptyList()
        }

        return TrapRoutePlan(
            ipv4Routes = v4,
            ipv6Routes = v6,
            excludedUpstreamLiterals = excluded.filter { it.isNotBlank() }.toSet()
        )
    }

    fun isTrappedPublicResolverIp(addressBytes: ByteArray): Boolean =
        ByteKey(addressBytes) in normalizedTrappedBytes

    /**
     * Builds an immediate stateless TCP `RST+ACK` (or `RST`) for non-port-53 TCP packets hitting a
     * trapped DNS IP (for example port 853 DoT or port 443 probes), avoiding 30-second client hangs.
     * Never responds to an incoming `RST` packet (RFC 793 §3.4).
     */
    fun buildFastFailTcpReset(
        tcpPacket: IpPacketFraming.ParsedTransportPacket.TcpPacket
    ): ByteArray? {
        if (tcpPacket.destinationPort == 53) return null
        if ((tcpPacket.flags and IpPacketFraming.TCP_FLAG_RST) != 0) return null

        val hasAck = (tcpPacket.flags and IpPacketFraming.TCP_FLAG_ACK) != 0
        val synAdvance = if ((tcpPacket.flags and IpPacketFraming.TCP_FLAG_SYN) != 0) 1L else 0L
        val finAdvance = if ((tcpPacket.flags and IpPacketFraming.TCP_FLAG_FIN) != 0) 1L else 0L
        val segAdvance = (tcpPacket.payload.size.toLong() + synAdvance + finAdvance).coerceAtLeast(1L)

        return if (hasAck) {
            IpPacketFraming.buildTcpResponsePacket(
                request = tcpPacket,
                seqNum = tcpPacket.acknowledgmentNumber and 0xFFFFFFFFL,
                ackNum = 0L,
                flags = IpPacketFraming.TCP_FLAG_RST,
                tcpPayload = ByteArray(0)
            )
        } else {
            IpPacketFraming.buildTcpResponsePacket(
                request = tcpPacket,
                seqNum = 0L,
                ackNum = (tcpPacket.sequenceNumber + segAdvance) and 0xFFFFFFFFL,
                flags = IpPacketFraming.TCP_FLAG_RST or IpPacketFraming.TCP_FLAG_ACK,
                tcpPayload = ByteArray(0)
            )
        }
    }

    private fun sameIpLiteral(candidate: String, excluded: Set<String>): Boolean {
        if (candidate.lowercase() in excluded) return true
        val candBytes = runCatching { InetAddress.getByName(candidate).address }.getOrNull() ?: return false
        return excluded.any { ex ->
            ex.isNotBlank() && runCatching { InetAddress.getByName(ex).address }
                .getOrNull()
                ?.contentEquals(candBytes) == true
        }
    }
}
