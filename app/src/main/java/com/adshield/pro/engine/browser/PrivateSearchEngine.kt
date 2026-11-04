package com.adshield.pro.engine.browser

import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * AdShield Pro — Private Search Engine & Privacy Navigation Resolver.
 *
 * Supports DuckDuckGo and Google Search with:
 * - Encrypted HTTPS search endpoints only
 * - Non-personalized search parameters (`pws=0` on Google, `ia=web` on DuckDuckGo)
 * - Unwrapping of search-result redirect trackers (`/l/?uddg=...`, `/url?q=...`)
 * - Stripping of search/ad click-tracking query parameters (`utm_*`, `gclid`, `fbclid`, `ved`, `ei`, `gs_lcp`, `sclient`)
 * - Automatic `http://` -> `https://` upgrade for non-loopback hosts when enabled
 * - Rejection of dangerous script/file pseudo-schemes (`javascript:`, `vbscript:`, `file:`)
 */
@Serializable
enum class SearchProvider(
    val id: String,
    val displayName: String,
    val shortBadge: String,
    val homeUrl: String,
    val privacySummary: String
) {
    DUCKDUCKGO(
        id = "duckduckgo",
        displayName = "DuckDuckGo",
        shortBadge = "DDG",
        homeUrl = "https://duckduckgo.com/",
        privacySummary = "Private HTTPS search with no search-history profiling and redirect tracker unwrapping."
    ),
    GOOGLE(
        id = "google",
        displayName = "Google Search",
        shortBadge = "Google",
        homeUrl = "https://www.google.com/?pws=0",
        privacySummary = "Encrypted HTTPS Google Search with personalization off (pws=0) and click-tracker stripping."
    )
}

object PrivateSearchEngine {

    private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?(/.*)?$""")
    private val DOMAIN_LIKE = Regex("""^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}(:\d{1,5})?(/.*)?$""")

    private val BLOCKED_SCHEMES = setOf(
        "javascript",
        "vbscript",
        "file",
        "content",
        "intent"
    )

    private val TRACKING_PARAMS = setOf(
        "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "ttclid", "twclid", "yclid",
        "mc_cid", "mc_eid", "_ga", "_gl", "igshid", "vero_id", "rb_clickid",
        "ved", "ei", "gs_lcp", "sclient", "sca_esv", "sei", "bih", "biw", "oq", "aqs", "sourceid"
    )

    /** Standard privacy headers attached to search and top-level browser requests. */
    fun privacyRequestHeaders(): Map<String, String> = mapOf(
        "DNT" to "1",
        "Sec-GPC" to "1"
    )

    /**
     * Builds an encrypted HTTPS search URL for [query] using [provider].
     */
    fun buildSearchUrl(
        query: String,
        provider: SearchProvider,
        safeSearchStrict: Boolean = false
    ): String {
        val cleaned = query.trim()
        if (cleaned.isEmpty()) return provider.homeUrl

        val encoded = URLEncoder.encode(cleaned, StandardCharsets.UTF_8.name())
            .replace("+", "%20")

        return when (provider) {
            SearchProvider.DUCKDUCKGO -> buildString {
                append("https://duckduckgo.com/?q=")
                append(encoded)
                append("&ia=web")
                if (safeSearchStrict) append("&kp=1")
            }
            SearchProvider.GOOGLE -> buildString {
                append("https://www.google.com/search?q=")
                append(encoded)
                append("&pws=0")
                if (safeSearchStrict) append("&safe=active")
            }
        }
    }

    /**
     * Resolves user address-bar input into either a sanitized HTTPS/HTTP navigation URL
     * or a private search URL on the user's selected [provider].
     */
    fun resolveNavigationInput(
        rawInput: String,
        provider: SearchProvider,
        upgradeHttpToHttps: Boolean = true,
        safeSearchStrict: Boolean = false
    ): String {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) return provider.homeUrl

        // Block dangerous pseudo-schemes by treating them as plain text search queries
        val schemeCandidate = trimmed.substringBefore(':', "").lowercase()
        if (schemeCandidate in BLOCKED_SCHEMES) {
            return buildSearchUrl(trimmed, provider, safeSearchStrict)
        }
        if (schemeCandidate == "data") {
            return provider.homeUrl
        }

        if (trimmed.startsWith("https://", ignoreCase = true) ||
            trimmed.startsWith("http://", ignoreCase = true)
        ) {
            val upgraded = if (upgradeHttpToHttps) upgradeToHttpsIfApplicable(trimmed) else trimmed
            return sanitizeAndUnwrapUrl(upgraded, upgradeHttpToHttps)
        }

        val isLocalhost = trimmed.equals("localhost", ignoreCase = true) ||
            trimmed.startsWith("localhost:", ignoreCase = true) ||
            trimmed.startsWith("localhost/", ignoreCase = true)

        if (!trimmed.contains(' ') && (isLocalhost || IPV4_LITERAL.matches(trimmed) || DOMAIN_LIKE.matches(trimmed))) {
            val hostPart = trimmed.substringBefore('/').substringBefore(':').lowercase()
            val scheme = if (!upgradeHttpToHttps || isLoopbackHost(hostPart)) "http://" else "https://"
            return sanitizeAndUnwrapUrl("$scheme$trimmed", upgradeHttpToHttps)
        }

        return buildSearchUrl(trimmed, provider, safeSearchStrict)
    }

    /**
     * Unwraps Google / DuckDuckGo outbound redirect URLs (`https://www.google.com/url?q=...` and
     * `https://duckduckgo.com/l/?uddg=...`) and strips known tracking parameters.
     */
    fun sanitizeAndUnwrapUrl(
        rawUrl: String,
        upgradeHttpToHttps: Boolean = false
    ): String {
        val working = if (upgradeHttpToHttps) upgradeToHttpsIfApplicable(rawUrl) else rawUrl
        val uri = runCatching { URI(working) }.getOrNull() ?: return working
        val host = uri.host?.lowercase()?.removePrefix("www.") ?: return working
        val path = uri.rawPath ?: ""
        val rawQuery = uri.rawQuery

        // 1. Unwrap search-engine outbound redirectors when target is an external HTTP(S) URL
        if (!rawQuery.isNullOrBlank()) {
            val redirectTarget = when {
                (host == "google.com" || host.startsWith("google.")) && path == "/url" ->
                    extractQueryParam(rawQuery, "q") ?: extractQueryParam(rawQuery, "url")
                host == "duckduckgo.com" && (path == "/l/" || path == "/l") ->
                    extractQueryParam(rawQuery, "uddg")
                else -> null
            }
            if (!redirectTarget.isNullOrBlank() &&
                (redirectTarget.startsWith("https://", ignoreCase = true) ||
                    redirectTarget.startsWith("http://", ignoreCase = true))
            ) {
                val upgradedTarget = if (upgradeHttpToHttps) upgradeToHttpsIfApplicable(redirectTarget) else redirectTarget
                return stripTrackingQueryParameters(upgradedTarget)
            }
        }

        return stripTrackingQueryParameters(working)
    }

    /**
     * Upgrades `http://` URLs to `https://` except for loopback/RFC1918 local development hosts.
     */
    fun upgradeToHttpsIfApplicable(url: String): String {
        if (!url.startsWith("http://", ignoreCase = true)) return url
        val uri = runCatching { URI(url) }.getOrNull() ?: return url
        val host = uri.host?.lowercase() ?: return url
        if (isLoopbackHost(host)) return url
        return "https://" + url.substring("http://".length)
    }

    fun stripTrackingQueryParameters(url: String): String {
        val qIdx = url.indexOf('?')
        if (qIdx < 0) return url
        val hashIdx = url.indexOf('#', qIdx)
        val base = url.substring(0, qIdx)
        val queryPart = if (hashIdx >= 0) url.substring(qIdx + 1, hashIdx) else url.substring(qIdx + 1)
        val fragmentPart = if (hashIdx >= 0) url.substring(hashIdx) else ""

        if (queryPart.isEmpty()) return url

        val kept = ArrayList<String>()
        for (pair in queryPart.split('&')) {
            if (pair.isEmpty()) continue
            val rawName = pair.substringBefore('=')
            val decodedName = runCatching {
                URLDecoder.decode(rawName, StandardCharsets.UTF_8.name())
            }.getOrDefault(rawName).lowercase()

            val isTracker = decodedName.startsWith("utm_") || decodedName in TRACKING_PARAMS
            if (!isTracker) {
                kept.add(pair)
            }
        }

        return buildString {
            append(base)
            if (kept.isNotEmpty()) {
                append('?')
                append(kept.joinToString("&"))
            }
            append(fragmentPart)
        }
    }

    private fun extractQueryParam(rawQuery: String, targetKey: String): String? {
        for (pair in rawQuery.split('&')) {
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            val key = pair.substring(0, eq)
            if (key.equals(targetKey, ignoreCase = true)) {
                val value = pair.substring(eq + 1)
                return runCatching {
                    URLDecoder.decode(value, StandardCharsets.UTF_8.name())
                }.getOrNull()
            }
        }
        return null
    }

    private fun isLoopbackHost(host: String): Boolean {
        return host == "localhost" ||
            host == "127.0.0.1" ||
            host == "[::1]" ||
            host == "::1" ||
            host.endsWith(".localhost")
    }
}
