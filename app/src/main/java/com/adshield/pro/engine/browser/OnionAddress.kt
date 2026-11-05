package com.adshield.pro.engine.browser

/**
 * Tor / .onion handling for the private browser tab.
 *
 * Android cannot ship the Tor daemon inside an APK in a way that stays current and legal to
 * redistribute safely, so the app uses the standard, user-controlled approach: route the
 * WebView through a local SOCKS5 proxy that the user already runs (Orbot is free and open
 * source). When no proxy is configured the browser says so plainly instead of pretending to
 * be anonymous.
 */
object OnionAddress {

    const val DEFAULT_SOCKS_HOST = "127.0.0.1"
    const val DEFAULT_SOCKS_PORT = 9050
    const val ORBOT_HTTP_PORT = 8118

    /** A v3 onion service is exactly 56 base32 characters followed by `.onion`. */
    private val V3 = Regex("^[a-z2-7]{56}\\.onion$")
    /** v2 onion services are deprecated by the Tor Project but still recognised. */
    private val V2 = Regex("^[a-z2-7]{16}\\.onion$")

    fun hostOf(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ""
        return runCatching {
            val withScheme = if (trimmed.contains("://")) trimmed else "http://$trimmed"
            java.net.URI(withScheme).host?.lowercase()?.trimEnd('.') ?: ""
        }.getOrElse { trimmed.lowercase() }
    }

    fun isOnion(raw: String): Boolean = hostOf(raw).endsWith(".onion")

    fun isOnionHost(host: String): Boolean {
        val normalized = host.lowercase().trimEnd('.')
        return V3.matches(normalized) || V2.matches(normalized)
    }

    fun isVersion3(host: String): Boolean = V3.matches(host.lowercase().trimEnd('.'))

    /** Normalises user input into a loadable URL, defaulting to http for onion services. */
    fun toLoadableUrl(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        // Reject non-web schemes outright (javascript:, file:, intent:, content: ...).
        val explicitScheme = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*):").find(trimmed)?.groupValues?.getOrNull(1)?.lowercase()
        if (explicitScheme != null && explicitScheme !in setOf("http", "https")) return null
        val candidate = when {
            trimmed.contains("://") -> trimmed
            isOnion(trimmed) -> "http://$trimmed"
            trimmed.contains('.') -> "https://$trimmed"
            else -> "https://duckduckgo.com/?q=${java.net.URLEncoder.encode(trimmed, "UTF-8")}"
        }
        val uri = runCatching { java.net.URI(candidate) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme !in setOf("http", "https")) return null
        return candidate
    }

    /**
     * Verdict for the UI banner: whether the page can be reached with the current settings.
     */
    fun reachability(rawUrl: String, torEnabled: Boolean, proxyConfigured: Boolean): Reachability = when {
        !isOnion(rawUrl) -> Reachability.CLEARNET
        !proxyConfigured -> Reachability.ONION_WITHOUT_PROXY
        !torEnabled -> Reachability.ONION_PROXY_DISABLED
        else -> Reachability.ONION_VIA_PROXY
    }

    enum class Reachability {
        CLEARNET,
        ONION_VIA_PROXY,
        ONION_WITHOUT_PROXY,
        ONION_PROXY_DISABLED
    }
}
