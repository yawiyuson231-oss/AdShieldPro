package com.adshield.pro.engine.browser

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Pure-Kotlin, zero-network URL & shared-text sanitizer for AdShield Pro's Android Share-Sheet
 * Link Cleaner, Security Center URL tools, and built-in Privacy Browser.
 *
 * Responsibilities:
 * 1. Extracts `http://` and `https://` URLs from free-form shared text while preserving balanced
 *    parentheses (for example `https://en.wikipedia.org/wiki/DNS_(protocol)`) and trimming
 *    trailing prose punctuation.
 * 2. Peels known first-party outbound redirect wrappers (`l.facebook.com/l.php?u=`,
 *    `l.instagram.com/?u=`, `google.com/url?q=`, `youtube.com/redirect?q=`,
 *    `duckduckgo.com/l/?uddg=`, `out.reddit.com/?url=`, Outlook SafeLinks) only when the target
 *    is itself a well-formed `http`/`https` URL with a non-empty host.
 * 3. Strips global, prefix-based, and host-scoped tracking query parameters (`utm_*`, `fbclid`,
 *    `gclid`, `igshid`, `si`, `ttclid`, `msclkid`, `mc_eid`, `mkt_tok`, Amazon affiliate tags,
 *    etc.) without removing functional parameters such as YouTube video IDs/timestamps (`v`, `t`,
 *    `list`), search queries (`q`), product variants (`th`, `psc`), or pagination (`page`).
 */
object LinkSanitizer {

    data class SanitizedLinkResult(
        val originalUrl: String,
        val cleanedUrl: String,
        val removedParams: List<String>,
        val unwrappedFromHosts: List<String>,
        val charsSaved: Int
    ) {
        val wasModified: Boolean
            get() = cleanedUrl != originalUrl
    }

    data class SharedTextSanitizeResult(
        val originalText: String,
        val cleanedText: String,
        val links: List<SanitizedLinkResult>
    ) {
        val primaryLink: SanitizedLinkResult?
            get() = links.firstOrNull()

        val totalRemovedParams: Int
            get() = links.sumOf { it.removedParams.size }

        val totalUnwrappedRedirects: Int
            get() = links.sumOf { it.unwrappedFromHosts.size }
    }

    private val URL_CANDIDATE_REGEX = Regex("""https?://[^\s<>"'`]+""", RegexOption.IGNORE_CASE)
    private const val MAX_UNWRAP_HOPS = 3

    /**
     * Extracts all HTTP(S) URLs from arbitrary text (such as an Android Share Sheet payload).
     */
    fun extractUrls(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return findUrlRanges(text).map { range -> text.substring(range.first, range.last + 1) }
    }

    /**
     * Cleans every HTTP(S) URL inside [sharedText] and returns both the rewritten text and
     * detailed per-link results. If [sharedText] is a bare domain/URL without a scheme (e.g.
     * `example.com/item?utm_source=ads`), upgrades it to `https://` for sanitization.
     */
    fun sanitizeSharedText(sharedText: String, unwrapRedirects: Boolean = true): SharedTextSanitizeResult {
        val trimmed = sharedText.trim()
        if (trimmed.isEmpty()) {
            return SharedTextSanitizeResult(sharedText, sharedText, emptyList())
        }

        val ranges = findUrlRanges(trimmed)
        if (ranges.isEmpty()) {
            // Handle single bare URL pasted without scheme (e.g. "youtube.com/watch?v=abc&si=xyz")
            if (!trimmed.contains(' ') && !trimmed.contains('\n') && trimmed.contains('.') &&
                !trimmed.contains("://")
            ) {
                val candidate = "https://$trimmed"
                val parsed = runCatching { URI(candidate) }.getOrNull()
                val candidateHost = parsed?.host
                if (!candidateHost.isNullOrBlank() && candidateHost.contains('.')) {
                    val single = sanitize(candidate, unwrapRedirects = unwrapRedirects)
                    return SharedTextSanitizeResult(
                        originalText = trimmed,
                        cleanedText = single.cleanedUrl,
                        links = listOf(single)
                    )
                }
            }
            return SharedTextSanitizeResult(trimmed, trimmed, emptyList())
        }

        val out = StringBuilder(trimmed.length)
        val results = ArrayList<SanitizedLinkResult>(ranges.size)
        var cursor = 0
        for (range in ranges) {
            if (range.first > cursor) {
                out.append(trimmed, cursor, range.first)
            }
            val rawUrl = trimmed.substring(range.first, range.last + 1)
            val cleaned = sanitize(rawUrl, unwrapRedirects = unwrapRedirects)
            results.add(cleaned)
            out.append(cleaned.cleanedUrl)
            cursor = range.last + 1
        }
        if (cursor < trimmed.length) {
            out.append(trimmed, cursor, trimmed.length)
        }
        return SharedTextSanitizeResult(
            originalText = trimmed,
            cleanedText = out.toString(),
            links = results
        )
    }

    /**
     * Sanitizes a single HTTP(S) URL. Non-HTTP(S) or unparseable strings are returned unchanged.
     */
    fun sanitize(rawUrl: String, unwrapRedirects: Boolean = true): SanitizedLinkResult {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            return SanitizedLinkResult(rawUrl, rawUrl, emptyList(), emptyList(), 0)
        }

        var working = trimmed
        val unwrappedHosts = ArrayList<String>()

        if (unwrapRedirects) {
            repeat(MAX_UNWRAP_HOPS) {
                val unwrapped = tryUnwrapRedirect(working) ?: return@repeat
                unwrappedHosts.add(unwrapped.first)
                working = unwrapped.second
            }
        }

        val uri = runCatching { URI(working) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val rawHost = uri?.host
        if (uri == null || uri.isOpaque || (scheme != "http" && scheme != "https") || rawHost.isNullOrBlank()) {
            return SanitizedLinkResult(rawUrl, rawUrl, emptyList(), emptyList(), 0)
        }

        val host = rawHost.lowercase().trimEnd('.')
        val path = (uri.rawPath ?: "").lowercase()
        val rawQuery = uri.rawQuery
        val removed = ArrayList<String>()

        val finalUrl = if (rawQuery.isNullOrEmpty()) {
            working
        } else {
            val pairs = rawQuery.split('&').filter { it.isNotEmpty() }
            val keptPairs = ArrayList<String>(pairs.size)
            for (pair in pairs) {
                val rawName = pair.substringBefore('=')
                val decodedName = decodePercentSafe(rawName).lowercase()
                if (isTrackingParam(decodedName, host, path)) {
                    removed.add(decodedName)
                } else {
                    keptPairs.add(pair)
                }
            }
            if (removed.isEmpty()) {
                working
            } else {
                val base = working.substringBefore('?').substringBefore('#')
                val fragment = cleanFragment(uri.rawFragment)
                if (keptPairs.isEmpty()) {
                    "$base$fragment"
                } else {
                    "$base?${keptPairs.joinToString("&")}$fragment"
                }
            }
        }

        // Even when no query params were stripped, clean pure utm_* tracking fragments if present.
        val fragmentCleaned = if (removed.isEmpty() && !uri.rawFragment.isNullOrEmpty()) {
            val baseAndQuery = working.substringBefore('#')
            val cleanedFrag = cleanFragment(uri.rawFragment, removed)
            "$baseAndQuery$cleanedFrag"
        } else {
            finalUrl
        }

        val saved = (trimmed.length - fragmentCleaned.length).coerceAtLeast(0)
        return SanitizedLinkResult(
            originalUrl = trimmed,
            cleanedUrl = fragmentCleaned,
            removedParams = removed,
            unwrappedFromHosts = unwrappedHosts,
            charsSaved = saved
        )
    }

    private fun tryUnwrapRedirect(url: String): Pair<String, String>? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        if ((scheme != "http" && scheme != "https") || uri.isOpaque) return null
        val host = uri.host?.lowercase()?.trimEnd('.') ?: return null
        val path = (uri.rawPath ?: "").lowercase()
        val query = uri.rawQuery ?: return null

        val targetKeys: List<String> = when {
            (host == "l.facebook.com" || host == "lm.facebook.com" || host == "m.facebook.com") &&
                path == "/l.php" -> listOf("u")
            host == "l.instagram.com" && (path.isEmpty() || path == "/") -> listOf("u")
            (host == "google.com" || host == "www.google.com" || host.startsWith("www.google.")) &&
                path == "/url" -> listOf("url", "q")
            (host == "youtube.com" || host == "www.youtube.com" || host == "m.youtube.com") &&
                path == "/redirect" -> listOf("q")
            (host == "duckduckgo.com" || host == "html.duckduckgo.com" || host == "lite.duckduckgo.com") &&
                (path == "/l/" || path == "/l") -> listOf("uddg")
            host == "out.reddit.com" -> listOf("url")
            host.endsWith(".safelinks.protection.outlook.com") -> listOf("url")
            host == "link.zhihu.com" -> listOf("target")
            else -> return null
        }

        val params = query.split('&').mapNotNull { part ->
            val eq = part.indexOf('=')
            if (eq <= 0) null else part.substring(0, eq).lowercase() to part.substring(eq + 1)
        }.toMap()

        for (key in targetKeys) {
            val encodedTarget = params[key] ?: continue
            val decoded = decodePercentSafe(encodedTarget).trim()
            val targetUri = runCatching { URI(decoded) }.getOrNull() ?: continue
            val targetScheme = targetUri.scheme?.lowercase() ?: continue
            if ((targetScheme == "http" || targetScheme == "https") &&
                !targetUri.isOpaque &&
                !targetUri.host.isNullOrBlank() &&
                !decoded.any { it.code < 0x20 || it.code == 0x7F }
            ) {
                return host to decoded
            }
        }
        return null
    }

    private fun cleanFragment(rawFragment: String?, removedSink: MutableList<String>? = null): String {
        if (rawFragment.isNullOrEmpty()) return ""
        // Only touch fragments structured like query strings containing utm_/fbclid/gclid pairs;
        // leave heading anchors (#section-2) and SPA routes (#!/dashboard) untouched.
        if (rawFragment.startsWith("!") || rawFragment.startsWith("/") || !rawFragment.contains('=')) {
            return "#$rawFragment"
        }
        val parts = rawFragment.split('&').filter { it.isNotEmpty() }
        val kept = ArrayList<String>(parts.size)
        var strippedAny = false
        for (part in parts) {
            val key = decodePercentSafe(part.substringBefore('=')).lowercase()
            if (key.startsWith("utm_") || key in GLOBAL_TRACKING_PARAMS) {
                strippedAny = true
                removedSink?.add("#$key")
            } else {
                kept.add(part)
            }
        }
        if (!strippedAny) return "#$rawFragment"
        return if (kept.isEmpty()) "" else "#${kept.joinToString("&")}"
    }

    private fun isTrackingParam(name: String, host: String, path: String): Boolean {
        if (name.isEmpty()) return false
        if (name in GLOBAL_TRACKING_PARAMS) return true
        if (TRACKING_PREFIXES.any { name.startsWith(it) }) return true

        // YouTube & YouTube Music — strip share token (`si`), promo param (`pp`), `feature`;
        // preserve `v`, `t`, `start`, `end`, `list`, `index`, `search_query`, `clip`, `clipt`.
        if (host == "youtu.be" || isDomainOrSub(host, "youtube.com")) {
            return name in YOUTUBE_TRACKING_PARAMS
        }

        // X / Twitter — strip share tokens `s`, `t`, `cxt` on status/profile URLs; keep search `q`, `f`.
        if (isDomainOrSub(host, "x.com") || isDomainOrSub(host, "twitter.com")) {
            if (!path.startsWith("/search")) {
                return name in TWITTER_TRACKING_PARAMS
            }
            return false
        }

        // Instagram / Threads / Facebook
        if (isDomainOrSub(host, "instagram.com") || isDomainOrSub(host, "threads.net") ||
            isDomainOrSub(host, "facebook.com") || isDomainOrSub(host, "fb.watch")
        ) {
            return name in META_TRACKING_PARAMS
        }

        // TikTok
        if (isDomainOrSub(host, "tiktok.com")) {
            return name in TIKTOK_TRACKING_PARAMS
        }

        // Spotify
        if (isDomainOrSub(host, "spotify.com")) {
            return name in SPOTIFY_TRACKING_PARAMS
        }

        // Reddit — keep `context`, `sort`, `q`, `t`
        if (isDomainOrSub(host, "reddit.com") || host == "redd.it") {
            return name in REDDIT_TRACKING_PARAMS
        }

        // LinkedIn
        if (isDomainOrSub(host, "linkedin.com")) {
            return name in LINKEDIN_TRACKING_PARAMS
        }

        // Amazon storefronts — strip affiliate/campaign metadata while preserving variant selectors (`th`, `psc`) and search (`k`, `i`, `rh`, `page`).
        if (isAmazonHost(host)) {
            return name in AMAZON_TRACKING_PARAMS
        }

        // Google Search share links — preserve `q`, `tbm`, `udm`, `hl`, `gl`, `start`, `tbs`.
        if (host == "google.com" || host == "www.google.com" || host.startsWith("www.google.")) {
            if (path == "/search") {
                return name in GOOGLE_SEARCH_TRACKING_PARAMS
            }
        }

        return false
    }

    private fun isDomainOrSub(host: String, domain: String): Boolean =
        host == domain || host.endsWith(".$domain")

    private fun isAmazonHost(host: String): Boolean =
        AMAZON_HOST_REGEX.matches(host)

    private fun findUrlRanges(text: String): List<IntRange> {
        val out = ArrayList<IntRange>()
        for (match in URL_CANDIDATE_REGEX.findAll(text)) {
            val start = match.range.first
            var end = match.range.last
            // Count delimiters once in O(n) over the candidate and update close counts in O(1).
            var openParens = 0
            var closeParens = 0
            var openBrackets = 0
            var closeBrackets = 0
            for (idx in start..end) {
                when (text[idx]) {
                    '(' -> openParens++
                    ')' -> closeParens++
                    '[' -> openBrackets++
                    ']' -> closeBrackets++
                }
            }
            while (end > start) {
                val ch = text[end]
                if (ch in TRAILING_PUNCTUATION) {
                    end--
                } else if (ch == ')') {
                    // Preserve closing ')' only when balanced by an opening '(' inside the URL.
                    if (closeParens > openParens) {
                        closeParens--
                        end--
                    } else {
                        break
                    }
                } else if (ch == ']') {
                    if (closeBrackets > openBrackets) {
                        closeBrackets--
                        end--
                    } else {
                        break
                    }
                } else {
                    break
                }
            }
            val candidate = text.substring(start, end + 1)
            val parsed = runCatching { URI(candidate) }.getOrNull()
            if (parsed != null && !parsed.host.isNullOrBlank()) {
                out.add(start..end)
            }
        }
        return out
    }

    private fun decodePercentSafe(value: String): String {
        if (!value.contains('%')) return value
        // Preserve literal '+' characters (URLDecoder turns '+' into space, breaking URLs with '+').
        return runCatching {
            URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())
        }.getOrDefault(value)
    }

    private val TRAILING_PUNCTUATION = charArrayOf('.', ',', ';', ':', '!', '?', '}', '>')
    private val AMAZON_HOST_REGEX = Regex("""^(?:www\.|m\.|smile\.)?amazon\.(?:com|co\.uk|de|fr|it|es|ca|co\.jp|in|com\.au|com\.br|com\.mx|nl|se|pl|sg)$""")

    private val TRACKING_PREFIXES = listOf(
        "utm_",
        "hsa_",
        "mtm_",
        "matomo_",
        "gad_",
        "pd_rd_",
        "pf_rd_",
        "ga_"
    )

    private val GLOBAL_TRACKING_PARAMS = setOf(
        "fbclid",
        "gclid",
        "gclsrc",
        "dclid",
        "wbraid",
        "gbraid",
        "msclkid",
        "ttclid",
        "twclid",
        "li_fat_id",
        "yclid",
        "ymclid",
        "ysclid",
        "mc_cid",
        "mc_eid",
        "mkt_tok",
        "_ga",
        "_gl",
        "_gac",
        "_hsenc",
        "_hsmi",
        "_openstat",
        "igshid",
        "igsh",
        "mibextid",
        "vero_id",
        "vero_conv",
        "oly_enc_id",
        "oly_anon_id",
        "rb_clickid",
        "wickedid",
        "srsltid",
        "s_kwcid",
        "ef_id",
        "zanpid",
        "irclickid",
        "aff_trace_key",
        "pk_campaign",
        "pk_kwd",
        "pk_source",
        "pk_medium",
        "pk_content",
        "pk_cid",
        "fb_action_ids",
        "fb_action_types",
        "fb_source",
        "fb_ref",
        "action_object_map",
        "action_type_map",
        "action_ref_map",
        "ref_src",
        "ref_url",
        "spm",
        "scm"
    )

    private val YOUTUBE_TRACKING_PARAMS = setOf("si", "pp", "feature", "kw")
    private val TWITTER_TRACKING_PARAMS = setOf("s", "t", "cxt")
    private val META_TRACKING_PARAMS = setOf("rdid", "share_url", "xmt", "eav", "__cft__[0]", "__tn__")
    private val TIKTOK_TRACKING_PARAMS = setOf(
        "_r", "_t", "checksum", "is_from_webapp", "sender_device", "sender_web_id",
        "share_app_id", "share_item_id", "share_link_id", "u_code", "sec_user_id"
    )
    private val SPOTIFY_TRACKING_PARAMS = setOf("si", "nd", "pt", "dl_branch")
    private val REDDIT_TRACKING_PARAMS = setOf("share_id", "rdt", "correlation_id")
    private val LINKEDIN_TRACKING_PARAMS = setOf("trk", "trkinfo", "lipi", "licu", "rcm")
    private val AMAZON_TRACKING_PARAMS = setOf(
        "tag", "linkcode", "linkid", "ascsubtag", "qid", "sr", "crid",
        "sprefix", "dib", "dib_tag", "camp", "creative", "creativeasin", "ref_"
    )
    private val GOOGLE_SEARCH_TRACKING_PARAMS = setOf(
        "ved", "ei", "sei", "uact", "oq", "gs_lcrp", "gs_lp", "sclient", "sourceid", "sca_esv"
    )
}
