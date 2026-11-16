package com.adshield.pro.engine.filter

import java.net.IDN

/**
 * One place that decides what "the same hostname" means.
 *
 * A DNS query, a filter list line and a catalogue entry can each name the same host three ways:
 * mixed case, with a trailing dot, or as Unicode (a U-label such as `münchen.example`) instead of
 * its punycode form (an A-label such as `xn--mnchen-3ya.example`). Both forms are legal and both
 * reach the wire, so a comparison that only lowercases silently misses half of them — which is a
 * real bypass, not a cosmetic bug.
 *
 * Conversion is per label, so wildcard labels (`*`) and any label that is already ASCII survive
 * untouched, and input that the IDN codec refuses is returned unchanged rather than thrown away.
 */
object HostNameNormalizer {

    /** Unicode labels become punycode; ASCII labels are returned exactly as they arrived. */
    fun toAscii(host: String): String {
        if (host.isEmpty()) return host
        if (host.all { it.code < 0x80 }) return host
        return host.split('.').joinToString(".") { label -> toAsciiLabel(label) }
    }

    private fun toAsciiLabel(label: String): String {
        if (label.isEmpty() || label.all { it.code < 0x80 }) return label
        return runCatching { IDN.toASCII(label, IDN.ALLOW_UNASSIGNED) }.getOrDefault(label)
    }
}
