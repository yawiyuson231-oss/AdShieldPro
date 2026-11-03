package com.adshield.pro.engine.firewall

/**
 * OmniShield X — TLS SNI Inspector (Part 2 Layer 2 groundwork).
 *
 * Extracts the Server Name Indication hostname from a TLS ClientHello record.
 * SNI is plaintext by design (RFC 6066), so even apps that bypass the local
 * DNS filter with their own encrypted resolvers still announce which domain
 * they connect to — making CONNECTION-LEVEL ad/tracker blocking possible.
 *
 * This parser is pure and unit-tested; the VPN integration routes matched
 * connections to the block policy in a future tunnel revision (shipped only
 * after on-device testing — never enabled silently).
 */
object TlsSniInspector {

    /**
     * Returns the SNI hostname from the first ClientHello found in [payload]
     * (the first client-side bytes of a TCP flow), or null.
     */
    fun extractSni(payload: ByteArray): String? = runCatching {
        if (payload.size < 43) return null
        var off = 0

        // Allow the payload to start directly with the handshake, or skip a TLS record header
        if (payload[off] == 0x16.toByte()) {
            off += 5 // content type + version(2) + length(2)
        }
        if (off >= payload.size || payload[off] != 0x01.toByte()) return null // not ClientHello
        off += 1 // handshake type
        if (off + 3 > payload.size) return null
        off += 3 // handshake length
        off += 2 // client version
        if (off + 32 > payload.size) return null
        off += 32 // random
        val sessionIdLen = payload[off].toInt() and 0xFF; off += 1
        off += sessionIdLen
        if (off + 2 > payload.size) return null
        val cipherSuitesLen = ((payload[off].toInt() and 0xFF) shl 8) or (payload[off + 1].toInt() and 0xFF)
        off += 2 + cipherSuitesLen
        if (off >= payload.size) return null
        val compressionLen = payload[off].toInt() and 0xFF; off += 1
        off += compressionLen
        if (off + 2 > payload.size) return null
        val extensionsLen = ((payload[off].toInt() and 0xFF) shl 8) or (payload[off + 1].toInt() and 0xFF)
        off += 2
        val extensionsEnd = off + extensionsLen
        if (extensionsEnd > payload.size) extensionsEnd = payload.size

        while (off + 4 <= extensionsEnd) {
            val extType = ((payload[off].toInt() and 0xFF) shl 8) or (payload[off + 1].toInt() and 0xFF)
            val extLen = ((payload[off + 2].toInt() and 0xFF) shl 8) or (payload[off + 3].toInt() and 0xFF)
            val extData = off + 4
            if (extType == 0x0000) { // server_name
                if (extData + 5 > payload.size) return null
                // server_name_list length(2) + entry type(1)=0 + name length(2)
                val nameLen = ((payload[extData + 3].toInt() and 0xFF) shl 8) or (payload[extData + 4].toInt() and 0xFF)
                val nameStart = extData + 5
                if (nameStart + nameLen > payload.size) return null
                return String(payload, nameStart, nameLen, Charsets.US_ASCII)
            }
            off = extData + extLen
        }
        null
    }.getOrNull()
}

/**
 * Connection-level firewall decision bound to the filter engine at production
 * wiring time; pure predicate injection keeps it unit-testable.
 */
class SniFirewall(private val shouldBlockDomain: (String) -> Boolean) {

    data class Decision(val blocked: Boolean, val sni: String?, val reason: String)

    fun inspect(payload: ByteArray): Decision {
        val sni = TlsSniInspector.extractSni(payload) ?: return Decision(false, null, "no SNI")
        return if (shouldBlockDomain(sni)) Decision(true, sni, "SNI matches block policy")
        else Decision(false, sni, "allowed")
    }
}
