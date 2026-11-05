package com.adshield.pro.engine.browser

import com.adshield.pro.domain.model.SearchProvider
import java.net.URLEncoder

/**
 * Pure address-bar resolution. Deliberately free of `android.net.Uri` so the rules that decide
 * "is this a search or an address" are unit-testable on the JVM.
 *
 * Two resolution styles coexist on purpose and are documented separately:
 *  - [navigationTarget] is what the browser address bar uses: it upgrades cleartext `http://` to
 *    HTTPS because the app rejects cleartext traffic.
 *  - [resolveInput] is the lower-level rule set: it preserves an explicit `http://` so HTTP-only
 *    hosts (a local router, for example) are never silently rewritten, and the address bar can
 *    show its own insecure indicator instead.
 */
object PrivateSearch {

    /**
     * URLs are restricted to HTTP(S); HTTP is upgraded because the app rejects cleartext traffic.
     * Everything else is treated as a search query, never as a WebView script/custom scheme.
     */
    fun navigationTarget(rawInput: String, provider: SearchProvider): String {
        val input = rawInput.trim()
        require(input.isNotEmpty()) { "Enter a search or HTTPS address" }
        if (input.startsWith("https://", ignoreCase = true)) return input
        if (input.startsWith("http://", ignoreCase = true)) return "https://" + input.substring(7)
        if (looksLikeHost(input)) return "https://$input"
        val encoded = URLEncoder.encode(input, Charsets.UTF_8.name()).replace("+", "%20")
        return provider.searchBaseUrl + encoded
    }

    fun isSearchQuery(rawInput: String): Boolean {
        val input = rawInput.trim()
        return input.isNotEmpty() && !input.startsWith("https://", true) &&
            !input.startsWith("http://", true) && !looksLikeHost(input)
    }

    private fun looksLikeHost(input: String): Boolean {
        if (input.length > 2048 || input.any { it.isWhitespace() || it.isISOControl() }) return false
        if (!input.contains('.') || input.contains('/') && !input.matches(HOST_WITH_OPTIONAL_PATH)) return false
        return input.matches(HOST_WITH_OPTIONAL_PATH)
    }

    private val HOST_WITH_OPTIONAL_PATH = Regex(
        "^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+" +
            "[A-Za-z]{2,63}(?::\\d{1,5})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*)?$"
    )

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
