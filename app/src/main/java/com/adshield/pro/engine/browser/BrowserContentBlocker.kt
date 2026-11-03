package com.adshield.pro.engine.browser

import android.webkit.WebResourceResponse
import com.adshield.pro.engine.filter.FilterRuleEngine
import java.io.ByteArrayInputStream
import java.net.URI
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layer 3 — Privacy Browser Content & Cosmetic Filtering Engine.
 *
 * Provides:
 * 1. Subresource & navigation ad/tracker request interception via [FilterRuleEngine]
 * 2. Tracking parameter sanitizer (strips fbclid, gclid, utm_*, msclkid, ttclid, etc.)
 * 3. Per-website allowlist exceptions
 * 4. Cosmetic CSS + MutationObserver DOM element hiding for supported web pages
 *
 * Note: As disclosed in the UI and documentation, Android security sandboxing prevents
 * a non-root app from injecting cosmetic CSS into external third-party browsers; cosmetic
 * filtering operates inside TitanShield Max's built-in Privacy Browser.
 */
@Singleton
class BrowserContentBlocker @Inject constructor(
    private val filterRuleEngine: FilterRuleEngine
) {

    data class InterceptionDecision(
        val shouldBlock: Boolean,
        val reason: String,
        val matchedRule: String? = null
    )

    private val sessionBlockedSubresources = AtomicLong(0L)
    private val sessionPopupsBlocked = AtomicLong(0L)
    private val sessionTrackersStripped = AtomicLong(0L)

    fun getBlockedSubresourceCount(): Long = sessionBlockedSubresources.get()
    fun getBlockedPopupCount(): Long = sessionPopupsBlocked.get()
    fun getStrippedTrackerParamCount(): Long = sessionTrackersStripped.get()

    fun recordPopupBlocked() {
        sessionPopupsBlocked.incrementAndGet()
    }

    /**
     * Evaluates whether a WebView resource request should be blocked.
     */
    fun evaluateRequest(
        requestUrl: String,
        pageHost: String?,
        allowlistedSites: Set<String>
    ): InterceptionDecision {
        val uri = runCatching { URI(requestUrl) }.getOrNull()
            ?: return InterceptionDecision(false, "Malformed URI")
        val scheme = uri.scheme?.lowercase() ?: return InterceptionDecision(false, "No scheme")
        if (scheme != "http" && scheme != "https") {
            return InterceptionDecision(false, "Non-HTTP scheme")
        }

        val requestHost = uri.host?.lowercase()?.removePrefix("www.") ?: return InterceptionDecision(false, "No host")
        val normalizedPageHost = pageHost?.lowercase()?.removePrefix("www.")

        // Check if current website is allowlisted by the user
        if (normalizedPageHost != null && isHostInExceptionSet(normalizedPageHost, allowlistedSites)) {
            return InterceptionDecision(false, "Page allowlisted by user ($normalizedPageHost)")
        }

        // Evaluate request host against Layer 4 FilterRuleEngine
        val eval = filterRuleEngine.evaluate(requestHost)
        if (eval.isBlocked) {
            sessionBlockedSubresources.incrementAndGet()
            return InterceptionDecision(
                shouldBlock = true,
                reason = "Blocked by ${eval.sourceName}",
                matchedRule = eval.matchedRule
            )
        }

        // Evaluate URL path heuristics for known ad/tracker scripts when third-party
        val isThirdParty = normalizedPageHost != null &&
            !requestHost.endsWith(normalizedPageHost) &&
            !normalizedPageHost.endsWith(requestHost)

        val lowerPath = (uri.rawPath ?: "").lowercase()
        if (isThirdParty && THIRD_PARTY_AD_PATH_PATTERNS.any { lowerPath.contains(it) }) {
            sessionBlockedSubresources.incrementAndGet()
            return InterceptionDecision(
                shouldBlock = true,
                reason = "Third-party ad script path heuristic",
                matchedRule = lowerPath
            )
        }

        // Evaluate EasyList-style URL pattern rules (network-level video/display ad filtering)
        val resourceType = guessResourceType(requestUrl, (uri.rawPath ?: "").lowercase())
        val patternMatch = UrlPatternFilter.match(requestUrl, requestHost, isThirdParty, resourceType)
        if (patternMatch != null) {
            sessionBlockedSubresources.incrementAndGet()
            return InterceptionDecision(
                shouldBlock = true,
                reason = "URL filter match: $patternMatch",
                matchedRule = patternMatch
            )
        }

        return InterceptionDecision(false, "Allowed")
    }

    private fun guessResourceType(url: String, path: String): String {
        return when {
            path.endsWith(".js") || path.contains(".js?") -> "script"
            path.endsWith(".css") -> "stylesheet"
            path.endsWith(".mp4") || path.endsWith(".m3u8") || path.endsWith(".ts") ||
                path.endsWith(".webm") || path.endsWith(".mpd") -> "media"
            path.endsWith(".png") || path.endsWith(".jpg") || path.endsWith(".jpeg") ||
                path.endsWith(".gif") || path.endsWith(".webp") || path.endsWith(".svg") -> "image"
            path.endsWith(".html") -> "subdocument"
            else -> "xmlhttprequest"
        }
    }

    /**
     * Strips known cross-site tracking query parameters (gclid, fbclid, utm_*, etc.) from URLs.
     */
    fun sanitizeTrackingParameters(rawUrl: String): String {
        val uri = runCatching { URI(rawUrl) }.getOrNull() ?: return rawUrl
        val rawQuery = uri.rawQuery
        if (uri.isOpaque || rawQuery.isNullOrEmpty()) return rawUrl

        val pairs = rawQuery.split('&').filter { it.isNotEmpty() }
        val keptPairs = ArrayList<String>(pairs.size)
        var removedCount = 0L

        for (pair in pairs) {
            val paramName = pair.substringBefore('=').lowercase()
            if (paramName in TRACKING_QUERY_PARAMS ||
                paramName.startsWith("utm_") ||
                paramName.startsWith("hsa_")
            ) {
                removedCount++
            } else {
                keptPairs.add(pair)
            }
        }

        if (removedCount == 0L) return rawUrl
        sessionTrackersStripped.addAndGet(removedCount)

        val baseWithoutQueryAndFrag = rawUrl.substringBefore('?').substringBefore('#')
        val fragment = uri.rawFragment?.let { "#$it" } ?: ""
        return if (keptPairs.isEmpty()) {
            "$baseWithoutQueryAndFrag$fragment"
        } else {
            "$baseWithoutQueryAndFrag?${keptPairs.joinToString("&")}$fragment"
        }
    }

    /**
     * Creates an empty, harmless WebResourceResponse to substitute for blocked ad/tracker requests.
     */
    fun createEmptyBlockedResponse(): WebResourceResponse {
        return WebResourceResponse(
            "text/plain",
            "UTF-8",
            204,
            "Blocked by TitanShield Max",
            mapOf(
                "Access-Control-Allow-Origin" to "*",
                "Cache-Control" to "no-store"
            ),
            ByteArrayInputStream(ByteArray(0))
        )
    }

    /**
     * Generates a safe JavaScript snippet that injects cosmetic CSS rules and a lightweight
     * MutationObserver to collapse ad placeholders and sponsored containers.
     */
    fun buildCosmeticFilterScript(
        pageHost: String?,
        allowlistedSites: Set<String>,
        customSelectors: Set<String>
    ): String? {
        val normalizedHost = pageHost?.lowercase()?.removePrefix("www.")
        if (normalizedHost != null && isHostInExceptionSet(normalizedHost, allowlistedSites)) {
            return null
        }

        val combinedSelectors = (DEFAULT_COSMETIC_SELECTORS + customSelectors)
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.contains('<') && !it.contains('\'') && !it.contains('"') }
            .distinct()

        val cssRuleString = combinedSelectors.joinToString(", ") +
            " { display: none !important; visibility: hidden !important; height: 0 !important; min-height: 0 !important; pointer-events: none !important; }"

        val escapedCss = cssRuleString.replace("\\", "\\\\").replace("`", "\\`")

        return """
            (function() {
                if (window.__adshieldCosmeticApplied) return;
                window.__adshieldCosmeticApplied = true;
                const styleId = 'titanshield-cosmetic-style';
                function applyStyle() {
                    if (!document.getElementById(styleId) && document.head) {
                        const style = document.createElement('style');
                        style.id = styleId;
                        style.type = 'text/css';
                        style.appendChild(document.createTextNode(`$escapedCss`));
                        document.head.appendChild(style);
                    }
                }
                applyStyle();
                document.addEventListener('DOMContentLoaded', applyStyle);
                // Collapse ad placeholders whenever the DOM mutates (SPA / infinite feeds)
                try {
                    const observer = new MutationObserver(function() { applyStyle(); });
                    observer.observe(document.documentElement, { childList: true, subtree: true });
                } catch (e) {}
                // Video-ad auto-skip: clicks the visible "Skip" control the moment it appears
                // (YouTube web & common HTML5 players). Never touches the video itself.
                setInterval(function() {
                    try {
                        const skipSelectors = [
                            '.ytp-skip-ad-button', '.ytp-ad-skip-button', '.ytp-ad-skip-button-modern', '.ytp-ad-overlay-close-button',
                            '.videoAdUiSkipButton', '.skip-ad-button', 'button[class*=skip-ad]',
                            '.ad-skip-button'
                        ];
                        for (const sel of skipSelectors) {
                            const btn = document.querySelector(sel);
                            if (btn && btn.offsetParent !== null) { btn.click(); break; }
                        }
                        // Collapse unskippable ad overlays' companion banners
                        const companion = document.querySelector('.ytp-ad-player-overlay-layout, .ytp-ad-action-interstitial');
                        if (companion) companion.style.display = 'none';
                    } catch (e) {}
                }, 500);
            })();
        """.trimIndent()
    }

    fun isHostInExceptionSet(host: String, allowlistedSites: Set<String>): Boolean {
        val clean = host.lowercase().removePrefix("www.")
        return allowlistedSites.any { exc ->
            val cleanExc = exc.lowercase().removePrefix("www.")
            clean == cleanExc || clean.endsWith(".$cleanExc")
        }
    }

    companion object {
        private val TRACKING_QUERY_PARAMS = setOf(
            "fbclid",
            "gclid",
            "gclsrc",
            "dclid",
            "msclkid",
            "ttclid",
            "twclid",
            "yclid",
            "mc_cid",
            "mc_eid",
            "_ga",
            "_gl",
            "igshid",
            "vero_id",
            "rb_clickid"
        )

        /**
         * TitanShield Max — EasyList-style network URL filter for the built-in browser.
         *
         * Compiled from classic Adblock network syntax subset:
         *   ||host^          → host suffix match
         *   /keyword/…       → substring match on the full URL
         *   rule$third-party → only match requests to a different site than the page
         *   rule$important   → cannot be excepted
         *   @@rule           → exception (allow)
         *
         * Focused on video-ad delivery (VAST/VMAP/preroll/midroll ad servers), ad exchanges,
         * measurement beacons, and popup/interstitial networks — the layer that actually stops
         * in-website video ads without touching the primary media CDN.
         */
        object UrlPatternFilter {

            enum class RuleKind { HOST_SUFFIX, SUBSTRING }

            data class NetworkRule(
                val pattern: String,
                val kind: RuleKind,
                val thirdPartyOnly: Boolean,
                val isException: Boolean
            )

            /** Hosts dedicated to advertising — blocked regardless of page context. */
            private val dedicatedAdHosts = setOf(
                "doubleclick.net", "googlesyndication.com", "googleadservices.com",
                "adnxs.com", "adsrvr.org", "rubiconproject.com", "pubmatic.com",
                "openx.net", "criteo.com", "criteo.net", "casalemedia.com", "33across.com",
                "spotxchange.com", "spotx.tv", "tremorhub.com", "smartadserver.com",
                "adform.net", "zedo.com", "admob.com", "adcolony.com",
                "applovin.com", "unityads.unity3d.com", "vungle.com", "chartboost.com",
                "inmobi.com", "moatads.com", "adsafeprotected.com", "doubleverify.com",
                "scorecardresearch.com", "quantserve.com",
                "outbrain.com", "taboola.com", "teads.tv", "teads.com", "sharethrough.com",
                "media.net", "amazon-adsystem.com", "adap.tv", "adtechus.com",
                "advertising.com", "adroll.com", "bidswitch.net",
                "contextweb.com", "gumgum.com", "improvedigital.com", "indexww.com",
                "liadm.com", "liquidad.net", "magnetic.com",
                "mathtag.com", "moatpixel.com", "nexac.com",
                "pixfuture.net", "popads.net", "popcash.net", "propellerads.com",
                "revcontent.com", "rlcdn.com", "servenobid.com", "serving-sys.com",
                "smaato.net", "sonobi.com", "sovrn.com", "tapad.com",
                "turn.com", "undertone.com", "yieldmo.com", "yieldlab.net",
                "atdmt.com", "histats.com", "adriver.ru", "adfox.ru"
            )

            /**
             * First-party video-ad beacons (YouTube): pure advertising telemetry —
             * blocking them never touches video playback, so the $third-party gate
             * is intentionally waived for this set only.
             */
            private val firstPartyVideoAdPatterns = listOf(
                "api/stats/ads", "/ptracking", "/pcs/click", "youtube.com/pagead"
            )

            /** Full-URL substring patterns for video-ad manifest & bidding endpoints. */
            private val urlSubstringRules = listOf(
                "/vast", "/vmap", "/vmap.xml", "vastads", "vasttag", "vast_wrapper",
                "preroll", "midroll", "postroll", "admanifest", "ad-manifest", "adunit/",
                "/adserver", "/adservice", "/adframe", "/adframe.js", "/adrequest",
                "/getads", "/fetchads", "/loadads", "/requestads", "/adcall", "/adconfig",
                "/adproxy", "/adrouter", "ads.js", "adsdk", "adtag", "adtag.js",
                "/gpt.js", "/pubads_impl", "pagead/ads", "pagead/js", "/adsbygoogle",
                "apstag.js", "prebid", "pbjs", "headerbid", "/bid/bid?", "/openrtb",
                "/rtb/", "/rtb2/auction", "/imp?", "/adv/", "popunder", "pop-under",
                "/ima/ads", "videoads", "/ads/video", "videoplaza", "ima3", "securepubads",
                "interstitial?", "interstitial.js", "adinterax", "atgsvcs", "atdmt.com",
                "amung.us", "histats.com", "statcounter.com/count", "addthis.com",
                "adriver.ru", "adfox.ru", "an.yandex.ru", "mc.yandex.ru/metrika"
            )

            /** Compiled, immutable rule set (hot path — matched on every browser request). */
            private val rules: List<NetworkRule> = buildRules()

            private fun buildRules(): List<NetworkRule> {
                val list = ArrayList<NetworkRule>(256)
                for (host in dedicatedAdHosts) {
                    list.add(NetworkRule(host, RuleKind.HOST_SUFFIX, thirdPartyOnly = false, isException = false))
                }
                for (pattern in urlSubstringRules) {
                    list.add(NetworkRule(pattern, RuleKind.SUBSTRING, thirdPartyOnly = true, isException = false))
                }
                return list
            }

            /**
             * Returns the matched rule label when the request should be blocked, else null.
             */
            fun match(requestUrl: String, requestHost: String, isThirdParty: Boolean, resourceType: String): String? {
                val url = requestUrl.lowercase()
                // Ad-only telemetry beacons are safe to block even first-party (no playback impact)
                for (pattern in firstPartyVideoAdPatterns) {
                    if (url.contains(pattern)) return "video-ad beacon: $pattern"
                }
                // Cheap exception check for first-party analytics opt-outs
                if (url.contains("pagead2.googlesyndication.com/pcs/activeview") &&
                    resourceType == "image"
                ) {
                    return null
                }
                for (rule in rules) {
                    if (rule.thirdPartyOnly && !isThirdParty) continue
                    val hit = when (rule.kind) {
                        RuleKind.HOST_SUFFIX -> {
                            var suffix: String? = requestHost
                            while (suffix != null) {
                                if (suffix == rule.pattern || suffix.endsWith(".${rule.pattern}")) return "||${rule.pattern}^"
                                suffix = if (suffix.contains('.')) suffix.substringAfter('.') else null
                            }
                            false
                        }
                        RuleKind.SUBSTRING -> url.contains(rule.pattern)
                    }
                    if (hit) return if (rule.kind == RuleKind.SUBSTRING) rule.pattern else "||${rule.pattern}^"
                }
                return null
            }
        }

        private val THIRD_PARTY_AD_PATH_PATTERNS = listOf(
            "/pagead/",
            "/ads/ads.js",
            "/adserver/",
            "/prebid",
            "/gpt.js",
            "/show_ads.js",
            "/adsbygoogle.js"
        )

        val DEFAULT_COSMETIC_SELECTORS = listOf(
            "ins.adsbygoogle",
            "[id^=google_ads_iframe_]",
            "[id^=div-gpt-ad]",
            "[data-ad-slot]",
            "[data-ad-client]",
            "[data-google-query-id]",
            ".ad-banner",
            ".ad-container",
            ".ad-slot",
            ".ad-wrapper",
            ".advertisement-box",
            ".sponsored-banner",
            ".taboola-widget",
            ".outbrain-widget",
            "iframe[src*=doubleclick]",
            "iframe[src*=googlesyndication]",
            "iframe[src*=adnxs]",
            "iframe[src*=taboola]",
            // YouTube (web/mobile web) display & feed ad units
            "#masthead-ad",
            "#player-ads",
            "ytd-promoted-video-renderer",
            "ytd-compact-promoted-video-renderer",
            "ytd-player-legacy-desktop-watch-ads-renderer",
            ".ytp-ad-text-overlay",
            "ytd-display-ad-renderer",
            "ytd-ad-slot-renderer",
            "ytd-in-feed-ad-layout-renderer",
            "ytd-promoted-sparkles-web-renderer",
            "ytd-promoted-sparkles-text-search-renderer",
            "ytd-compact-promoted-video-renderer",
            "ytd-banner-promo-renderer",
            "ytd-statement-banner-renderer",
            "ytm-promoted-video-renderer",
            "ytm-companion-slot",
            "#masthead-ad",
            "#player-ads",
            "#related ytd-ad-slot-renderer",
            ".ytd-merch-shelf-renderer",
            // Generic pop/interstitial overlays
            "[id*=interstitial-ad]",
            "[class*=popup-ad]",
            "[class*=ad-overlay]"
        )
    }
}
