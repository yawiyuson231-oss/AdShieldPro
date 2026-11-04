package com.adshield.pro.engine.network

import java.net.InetAddress

/** Conservative IP classification; no unconfigured cloud reputation claim. */
object IpReputationAnalyzer {
    enum class Reputation { LOCAL_OR_PRIVATE, RESERVED, UNVERIFIED_PUBLIC, INVALID }

    data class Assessment(
        val ip: String,
        val reputation: Reputation,
        val explanation: String
    )

    fun assessLiteral(value: String): Assessment {
        val ip = value.trim()
        // Prevent InetAddress from performing a DNS lookup on non-literal input.
        val literalShape = Regex("^[0-9A-Fa-f:.]+$")
        if (!literalShape.matches(ip) || (!ip.contains('.') && !ip.contains(':'))) {
            return Assessment(ip.take(80), Reputation.INVALID, "Not an IP literal; no reputation lookup performed.")
        }
        val address = runCatching { InetAddress.getByName(ip) }.getOrNull()
            ?: return Assessment(ip.take(80), Reputation.INVALID, "Invalid IP literal.")
        return when {
            address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
                address.isSiteLocalAddress -> Assessment(
                ip,
                Reputation.LOCAL_OR_PRIVATE,
                "Local/private address. For a public domain this can be a DNS-rebinding signal; it is not labeled malware on IP evidence alone."
            )
            address.isMulticastAddress -> Assessment(
                ip,
                Reputation.RESERVED,
                "Multicast/reserved address; not a normal public web destination."
            )
            else -> Assessment(
                ip,
                Reputation.UNVERIFIED_PUBLIC,
                "Public IP with no configured third-party IP-reputation verdict. Unknown is not classified as safe or malicious."
            )
        }
    }
}
