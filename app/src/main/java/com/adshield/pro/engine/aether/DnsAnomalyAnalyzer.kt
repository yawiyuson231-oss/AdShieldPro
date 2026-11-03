package com.adshield.pro.engine.aether

/**
 * OmniShield X — DNS anomaly analysis (Parts 4/5/6).
 *
 * Deterministic, explainable detectors over DNS metadata:
 * - Label entropy (DGA-style domain detection) → OBSERVE only.
 * - Subdomain/label-structure tunneling patterns → OBSERVE only.
 * - DNS rebinding guard: public domains answering with private/loopback IPs
 *   are sinkholed by the VPN service (deterministic, always-on protection).
 */
object DnsAnomalyAnalyzer {

    // --- Shannon entropy over label characters ---

    fun labelEntropy(label: String): Double {
        if (label.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (c in label) freq.merge(c, 1, Int::plus)
        var entropy = 0.0
        val n = label.size.toDouble()
        for (count in freq.values) {
            val p = count / n
            entropy -= p * (Math.log(p) / Math.log(2.0))
        }
        return entropy
    }

    /** DGA-like structure: high-entropy long alphabetic labels (e.g. "xkqjvbmzpqowierutasl"). */
    fun looksDgaGenerated(domain: String): Boolean {
        val labels = domain.lowercase().split('.')
        for (label in labels) {
            if (label.length >= 14 &&
                labelEntropy(label) >= 3.4 &&
                label.all { it in 'a'..'z' } &&
                label.none { it in "aeiou" } == false && // vowels allowed; entropy does the work
                countDigits(label) == 0
            ) return true
        }
        return false
    }

    private fun countDigits(s: String): Int = s.count { it in '0'..'9' }

    /**
     * DNS-tunneling structure: excessive label depth, oversized labels, or long
     * base32/hex-looking payloads. These are OBSERVE findings — many CDNs use
     * long labels, so uncertainty is disclosed, never punished with a block.
     */
    fun looksTunnelingPattern(domain: String): Boolean {
        val labels = domain.lowercase().split('.')
        if (labels.size >= 7) return true
        return labels.any { it.length >= 50 } ||
            (labels.getOrNull(0)?.let { it.length >= 30 && countDigits(it) >= 6 } == true)
    }

    // --- DNS Rebinding Guard (deterministic, enforced in the VPN answer path) ---

    private val PRIVATE_IP_PREFIXES = listOf(
        "127.", "10.", "192.168.", "169.254.", "0.0.0.0"
    )

    private fun isPrivateIpv4(ip: String): Boolean {
        if (PRIVATE_IP_PREFIXES.any { ip.startsWith(it) }) return true
        if (ip.startsWith("172.")) {
            val second = ip.split('.').getOrNull(1)?.toIntOrNull() ?: return false
            if (second in 16..31) return true
        }
        return false
    }

    private fun isPrivateIpv6(ip: String): Boolean {
        val v = ip.lowercase().replace(Regex("%.*$"), "")
        return v == "::1" || v == "::" ||
            v.startsWith("fc") || v.startsWith("fd") || // ULA fc00::/7
            v.startsWith("fe80") // link-local
    }

    /** Internal-use domains legitimately answer with private addresses. */
    private val LEGITIMATE_PRIVATE_ANSWERS = setOf(
        "localhost", "local", "home.arpa", "lan", "internal", "intranet"
    )

    fun isInternalNamespace(domain: String): Boolean {
        val d = domain.lowercase().trimEnd('.')
        return d == "localhost" || LEGITIMATE_PRIVATE_ANSWERS.any { d == it || d.endsWith(".$it") }
    }

    /**
     * True when a public-domain query was answered with a private/loopback address —
     * the classic DNS rebinding attack shape (router/intranet access from the web).
     */
    fun isRebindingAttempt(domain: String, answerIps: List<String>): Boolean {
        if (answerIps.isEmpty() || isInternalNamespace(domain)) return false
        return answerIps.any { isPrivateIpv4(it) || isPrivateIpv6(it) }
    }

    /**
     * Minimal, allocation-light A/AAAA answer extractor over raw DNS wire bytes.
     * Handles name compression pointers per RFC 1035. Returns dotted-quad IPv4 and
     * colon-hex IPv6 strings; empty list when nothing can be parsed.
     */
    fun extractAnswerIps(response: ByteArray): List<String> {
        val ips = ArrayList<String>(2)
        return runCatching {
            if (response.size < 12) return emptyList()
            fun u16(off: Int): Int = ((response[off].toInt() and 0xFF) shl 8) or (response[off + 1].toInt() and 0xFF)

            val qd = u16(4)
            val an = u16(6)
            var off = 12

            fun skipName(pos: Int): Int {
                var p = pos
                while (p < response.size) {
                    val len = response[p].toInt() and 0xFF
                    when {
                        len == 0 -> return p + 1
                        len and 0xC0 == 0xC0 -> return p + 2 // compression pointer
                        else -> p += 1 + len
                    }
                }
                return response.size
            }

            repeat(qd) {
                if (off >= response.size) return emptyList()
                off = skipName(off) + 4 // type + class
            }

            repeat(an) {
                if (off >= response.size) return ips
                off = skipName(off)
                if (off + 10 > response.size) return ips
                val type = u16(off)
                val rdLength = u16(off + 8)
                val rdStart = off + 10
                if (rdStart + rdLength > response.size) return ips
                when {
                    type == 1 && rdLength == 4 ->
                        ips.add("${response[rdStart].toInt() and 0xFF}.${response[rdStart + 1].toInt() and 0xFF}.${response[rdStart + 2].toInt() and 0xFF}.${response[rdStart + 3].toInt() and 0xFF}")
                    type == 28 && rdLength == 16 -> {
                        val sb = StringBuilder()
                        for (i in 0 until 16) {
                            if (i > 0 && i % 2 == 0) sb.append(':')
                            sb.append("%02x".format(response[rdStart + i].toInt() and 0xFF))
                        }
                        ips.add(sb.toString())
                    }
                }
                off = rdStart + rdLength
            }
            ips
        }.getOrDefault(emptyList())
    }
}
