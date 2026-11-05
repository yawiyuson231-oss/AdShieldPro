package com.adshield.pro.engine.browser

import kotlinx.serialization.Serializable

/**
 * AdShield Pro — private search providers.
 *
 * Both providers are reached over HTTPS inside the app's own WebView, which already sends
 * `DNT: 1` / `Sec-GPC: 1`, blocks third-party cookies (user setting) and strips cross-site
 * tracking parameters via [BrowserContentBlocker.sanitizeTrackingParameters].
 *
 * Honesty note: choosing Google still sends the query to Google, and Google may log it.
 * The provider label says so rather than implying the app makes Google anonymous.
 */
@Serializable
enum class SearchProvider(
    val label: String,
    val homeUrl: String,
    val privacyNote: String
) {
    DUCKDUCKGO(
        label = "DuckDuckGo",
        homeUrl = "https://duckduckgo.com/",
        privacyNote = "Default. Does not build a search history profile tied to you."
    ),
    DUCKDUCKGO_ONION(
        label = "DuckDuckGo (Onion)",
        homeUrl = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
        privacyNote = "DuckDuckGo's Tor onion service — reachable only with an onion-routing setup " +
            "(e.g. Orbot) active; the app does not bundle a Tor client."
    ),
    BRAVE(
        label = "Brave Search",
        homeUrl = "https://search.brave.com/",
        privacyNote = "Independent index; does not profile you like Google. Brave still receives the query."
    ),
    GOOGLE(
        label = "Google",
        homeUrl = "https://www.google.com/",
        privacyNote = "Google receives and may log your query. Tracking-parameter stripping and " +
            "cookie blocking still apply, but the query itself is not anonymous."
    );

    /** Builds the provider's query URL with the term percent-encoded exactly once. */
    fun searchUrl(query: String): String {
        val encoded = percentEncodeQueryComponent(query.trim())
        return when (this) {
            DUCKDUCKGO -> "https://duckduckgo.com/?q=$encoded"
            DUCKDUCKGO_ONION -> "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=$encoded"
            BRAVE -> "https://search.brave.com/search?q=$encoded"
            GOOGLE -> "https://www.google.com/search?q=$encoded"
        }
    }

    companion object {
        /** Unknown / legacy / corrupt preference values fall back to the privacy default. */
        fun fromName(raw: String?): SearchProvider =
            entries.firstOrNull { it.name.equals(raw?.trim(), ignoreCase = true) } ?: DUCKDUCKGO
    }
}

/**
 * Pure address-bar resolution. Deliberately free of `android.net.Uri` so the rules that decide
 * "is this a search or an address" are unit-testable on the JVM.
 */
object PrivateSearch {

    /**
     * True when the input should be treated as an address rather than a search term.
     * An explicit scheme always wins; otherwise a dot with no whitespace is treated as a host.
     */
    fun looksLikeAddress(raw: String): Boolean {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return false
        if (hasExplicitScheme(trimmed)) return true
        return trimmed.contains('.') && trimmed.none { it.isWhitespace() }
    }

    fun hasExplicitScheme(raw: String): Boolean =
        raw.startsWith("https://", ignoreCase = true) || raw.startsWith("http://", ignoreCase = true)

    fun isSecure(url: String): Boolean = url.startsWith("https://", ignoreCase = true)

    /**
     * Resolves address-bar input to a URL.
     *
     * - empty input goes to the selected provider's home page
     * - an explicit `http://` is preserved (silently rewriting it would break local routers and
     *   other HTTP-only hosts); the address bar shows the insecure indicator instead
     * - a bare host is upgraded to HTTPS
     * - anything else becomes a provider search
     */
    fun resolveInput(raw: String, provider: SearchProvider): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return provider.homeUrl
        if (hasExplicitScheme(trimmed)) return trimmed
        if (looksLikeAddress(trimmed)) return "https://$trimmed"
        return provider.searchUrl(trimmed)
    }
}

private const val HEX_DIGITS = "0123456789ABCDEF"

/**
 * RFC 3986 percent-encoding of a query component. Spaces become `%20` (valid for both providers
 * and unambiguous), UTF-8 multibyte characters are encoded per byte, and reserved characters such
 * as `&`, `=` and `+` are escaped so a search term can never inject extra query parameters.
 */
internal fun percentEncodeQueryComponent(value: String): String {
    val bytes = value.toByteArray(Charsets.UTF_8)
    val out = StringBuilder(bytes.size)
    for (byte in bytes) {
        val code = byte.toInt() and 0xFF
        val char = code.toChar()
        val unreserved = char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' ||
            char == '-' || char == '_' || char == '.' || char == '~'
        if (unreserved) {
            out.append(char)
        } else {
            out.append('%').append(HEX_DIGITS[code shr 4]).append(HEX_DIGITS[code and 0x0F])
        }
    }
    return out.toString()
}
