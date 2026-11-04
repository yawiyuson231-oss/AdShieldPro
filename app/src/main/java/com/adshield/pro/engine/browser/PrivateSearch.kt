package com.adshield.pro.engine.browser

import com.adshield.pro.domain.model.SearchProvider
import java.net.URLEncoder

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
}
