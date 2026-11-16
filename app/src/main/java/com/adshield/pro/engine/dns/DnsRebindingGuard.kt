package com.adshield.pro.engine.dns

/**
 * DNS rebinding: a public name that resolves into a private address.
 *
 * The attack needs no exploit in the device. A page loads `attacker.example`, keeps the answer
 * fresh, and then re-resolves it after the browser has decided the origin is "public": the second
 * answer is `192.168.1.1`, and the page is now talking to the router's admin interface or an
 * intranet service with no origin check of its own.
 *
 * A resolver sees exactly the thing that makes this possible — a public name returning a private,
 * loopback, link-local, CGNAT or unique-local address — so it can refuse the answer. It is not
 * enforced by default in the balanced modes, because split-horizon corporate DNS legitimately
 * answers internal names with RFC 1918 addresses; Strict and Custom, which already warn about
 * compatibility, refuse those answers unless the name itself is a local one.
 */
object DnsRebindingGuard {

    data class Finding(
        val address: String,
        val family: String,
        val range: String
    )

    /** Names that legitimately resolve into private space: intranet, mDNS, reverse lookups. */
    private val LOCAL_SUFFIXES = listOf(
        ".local", ".localdomain", ".lan", ".home", ".home.arpa", ".internal", ".intranet",
        ".corp", ".private", ".arpa", ".test", ".invalid", ".localhost"
    )

    /** True when the *query* is for a name that may legitimately answer with a private address. */
    fun isLocalName(domain: String): Boolean {
        val name = domain.trim().trimEnd('.').lowercase()
        if (name.isEmpty()) return true
        if (!name.contains('.')) return true // single-label: a LAN hostname by definition
        return LOCAL_SUFFIXES.any { name == it.removePrefix(".") || name.endsWith(it) }
    }

    /**
     * The first private address in [responseBytes], or null when the answer is public, empty, or
     * cannot be walked (in which case the guard stays out of the way rather than guessing).
     */
    fun firstPrivateAnswer(responseBytes: ByteArray): Finding? {
        val answers = DnsPacketCodec.extractAddressAnswers(responseBytes) ?: return null
        for (answer in answers) {
            val finding = classify(answer) ?: continue
            return finding
        }
        return null
    }

    private fun classify(answer: DnsPacketCodec.AddressAnswer): Finding? {
        val bytes = answer.addressBytes
        if (answer.type == DnsPacketCodec.TYPE_A && bytes.size == 4) {
            val a = bytes[0].toInt() and 0xFF
            val b = bytes[1].toInt() and 0xFF
            val text = "${a}.${b}.${bytes[2].toInt() and 0xFF}.${bytes[3].toInt() and 0xFF}"
            val range = when {
                a == 0 -> "this-network"
                a == 10 -> "private (RFC 1918)"
                a == 127 -> "loopback"
                a == 169 && b == 254 -> "link-local"
                a == 172 && b in 16..31 -> "private (RFC 1918)"
                a == 192 && b == 168 -> "private (RFC 1918)"
                a == 100 && b in 64..127 -> "carrier-grade NAT"
                a == 192 && b == 0 && (bytes[2].toInt() and 0xFF) == 0 -> "IETF protocol assignment"
                a >= 224 -> "multicast or reserved"
                else -> null
            }
            return range?.let { Finding(text, "IPv4", it) }
        }
        if (answer.type == DnsPacketCodec.TYPE_AAAA && bytes.size == 16) {
            val first = bytes[0].toInt() and 0xFF
            val second = bytes[1].toInt() and 0xFF
            val allZeroExceptLast = bytes.take(15).all { it.toInt() == 0 } && bytes[15].toInt() == 1
            val text = formatIpv6(bytes)
            val range = when {
                allZeroExceptLast -> "loopback"
                bytes.all { it.toInt() == 0 } -> "unspecified"
                first == 0xFE && (second and 0xC0) == 0x80 -> "link-local"
                (first and 0xFE) == 0xFC -> "unique local (RFC 4193)"
                first == 0xFF -> "multicast"
                else -> null
            }
            return range?.let { Finding(text, "IPv6", it) }
        }
        return null
    }

    private fun formatIpv6(bytes: ByteArray): String =
        (0 until 16 step 2).joinToString(":") { index ->
            (((bytes[index].toInt() and 0xFF) shl 8) or (bytes[index + 1].toInt() and 0xFF))
                .toString(16)
        }
}
