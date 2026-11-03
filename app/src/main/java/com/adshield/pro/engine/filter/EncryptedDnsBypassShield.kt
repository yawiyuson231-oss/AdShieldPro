package com.adshield.pro.engine.filter

import com.adshield.pro.domain.model.DnsResolverConfig

/**
 * OmniShield X — Encrypted-DNS Bypass Shield.
 *
 * Apps and browsers can hardcode their own DNS-over-HTTPS (Chrome "Secure DNS",
 * Firefox DoH, various SDKs). Their DoH client must first RESOLVE the provider
 * hostname via the system resolver — this shield sinks those bootstrap hostnames
 * so the app's private DoH fails to start and it falls back to normal system DNS,
 * which the local firewall filters. This is the standard, honest anti-bypass
 * technique: browsing continues working; only the bypass is cut.
 *
 * The user's OWN selected DoH provider is never sunk (checked at merge time).
 */
object EncryptedDnsBypassShield {

    /** DoH/DoT provider bootstrap hostnames (public resolvers, browser defaults). */
    val BOOTSTRAP_HOSTS: Set<String> = setOf(
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
        "dns.adguard.com",
        "dns.adguard-dns.com",
        "doh.opendns.com",
        "doh.cleanbrowsing.org",
        "use-application-dns.net"
    )

    const val SOURCE_NAME = "Encrypted-DNS Bypass Shield"

    /** Extracts the hostname from a DoH URL ("https://dns.google/dns-query" → "dns.google"). */
    fun hostnameFromUrl(url: String): String? {
        val s = url.trim().lowercase()
        if (!s.startsWith("http")) return null
        return s.removePrefix("https://").removePrefix("http://")
            .substringBefore('/')
            .substringBefore(':')
            .takeIf { it.contains('.') }
    }

    /** The user's own configured DoH provider host — must never be sunk. */
    fun ownProviderHostname(config: DnsResolverConfig): String? =
        hostnameFromUrl(config.activeDohUrl)
}
