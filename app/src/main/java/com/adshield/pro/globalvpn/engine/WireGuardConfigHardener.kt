package com.adshield.pro.globalvpn.engine

import com.adshield.pro.globalvpn.model.SplitTunnelMode

/**
 * Pure, side-effect-free hardening of wg-quick configuration text. Kept free of Android types so it
 * is unit-testable on the JVM. It never invents keys or endpoints; it only adjusts routing, DNS and
 * per-app lists on a configuration the user already imported.
 */
object WireGuardConfigHardener {

    data class Sections(
        val interfaceLines: List<String>,
        val peers: List<List<String>>
    )

    fun splitSections(text: String): Sections {
        val interfaceLines = mutableListOf<String>()
        val peers = mutableListOf<MutableList<String>>()
        var current: MutableList<String>? = null
        var inInterface = false
        for (raw in text.lines()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            when {
                line.equals("[Interface]", ignoreCase = true) -> {
                    inInterface = true
                    current = null
                }
                line.equals("[Peer]", ignoreCase = true) -> {
                    inInterface = false
                    current = mutableListOf<String>().also { peers.add(it) }
                }
                inInterface -> interfaceLines.add(line)
                current != null -> current?.add(line)
            }
        }
        return Sections(interfaceLines, peers)
    }

    fun endpointOf(text: String): Pair<String, Int>? {
        val sections = splitSections(text)
        val endpoint = sections.peers.firstNotNullOfOrNull { peer ->
            peer.firstOrNull { it.startsWith("Endpoint", ignoreCase = true) }
                ?.substringAfter('=')?.trim()
        } ?: return null
        val host = endpoint.substringBeforeLast(':').trim().removePrefix("[").removeSuffix("]")
        val port = endpoint.substringAfterLast(':').trim().toIntOrNull() ?: return null
        if (host.isBlank()) return null
        return host to port
    }

    fun hasIpv6Address(text: String): Boolean =
        splitSections(text).interfaceLines.any {
            it.startsWith("Address", ignoreCase = true) && it.substringAfter('=').contains(':')
        }

    private fun withoutKeys(lines: List<String>, vararg keys: String): List<String> =
        lines.filter { line ->
            val key = line.substringBefore('=').trim().lowercase()
            keys.none { it.lowercase() == key }
        }

    /**
     * Returns a hardened wg-quick string. When [leakProtection] is on, the first peer is forced to
     * full-tunnel (0.0.0.0/0 and, when the interface has an IPv6 address or IPv6 should be blocked,
     * ::/0) and DNS is pinned so resolver queries cannot bypass the tunnel.
     */
    fun harden(
        original: String,
        leakProtection: Boolean,
        blockIpv6WhenUnsupported: Boolean,
        dnsServers: List<String>,
        splitMode: SplitTunnelMode,
        splitPackages: Set<String>
    ): String {
        val sections = splitSections(original)
        require(sections.peers.isNotEmpty()) { "Configuration has no [Peer] section" }

        var interfaceLines = sections.interfaceLines
        val hasV6 = hasIpv6Address(original)

        if (leakProtection) {
            val dns = if (dnsServers.isNotEmpty()) dnsServers else listOf("1.1.1.1", "1.0.0.1")
            interfaceLines = withoutKeys(interfaceLines, "DNS")
            interfaceLines = interfaceLines + "DNS = ${dns.joinToString(", ")}"
        }

        interfaceLines = withoutKeys(interfaceLines, "ExcludedApplications", "IncludedApplications")
        if (splitPackages.isNotEmpty()) {
            when (splitMode) {
                SplitTunnelMode.EXCLUDE_SELECTED ->
                    interfaceLines = interfaceLines + "ExcludedApplications = ${splitPackages.joinToString(", ")}"
                SplitTunnelMode.INCLUDE_SELECTED ->
                    interfaceLines = interfaceLines + "IncludedApplications = ${splitPackages.joinToString(", ")}"
                SplitTunnelMode.OFF -> Unit
            }
        }

        val hardenedPeers = sections.peers.mapIndexed { index, peer ->
            if (index == 0 && leakProtection) {
                val allowed = if (hasV6 || blockIpv6WhenUnsupported) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
                withoutKeys(peer, "AllowedIPs") + "AllowedIPs = $allowed"
            } else {
                peer
            }
        }

        return buildString {
            append("[Interface]\n")
            interfaceLines.forEach { append(it).append('\n') }
            hardenedPeers.forEach { peer ->
                append("\n[Peer]\n")
                peer.forEach { append(it).append('\n') }
            }
        }
    }
}
