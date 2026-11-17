package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — Video Ad Intelligence Engine
 *
 * Advanced video advertising domain classification and endpoint identification.
 *
 * Handles:
 * - In-stream ad domain detection (pre-roll, mid-roll, post-roll)
 * - Video ad-serving infrastructure identification
 * - Platform-specific ad behavior (YouTube, TikTok, Twitch, etc.)
 * - Third-party video tracker detection
 * - Streaming compatibility protection (never break playback)
 * - Sponsored content infrastructure
 *
 * CRITICAL HONESTY: DNS cannot distinguish ads from content when both use the
 * same domain. This engine only blocks third-party ad infrastructure, never
 * the media delivery domain itself.
 */
@Singleton
class VideoAdIntelligence @Inject constructor() {

    enum class VideoPlatform(val label: String) {
        YOUTUBE("YouTube"),
        TIKTOK("TikTok"),
        FACEBOOK("Facebook/Meta"),
        INSTAGRAM("Instagram"),
        TWITCH("Twitch"),
        NETFLIX("Netflix"),
        DISNEY_PLUS("Disney+"),
        HULU("Hulu"),
        HBO_MAX("HBO Max"),
        PRIME_VIDEO("Prime Video"),
        VIMEO("Vimeo"),
        DAILYMOTION("Dailymotion"),
        SPOTIFY("Spotify"),
        GENERIC("Generic Streaming")
    }

    enum class AdType(val label: String) {
        PRE_ROLL("Pre-roll"),
        MID_ROLL("Mid-roll"),
        POST_ROLL("Post-roll"),
        BANNER_OVERLAY("Banner/Overlay"),
        SPONSORED_CONTENT("Sponsored Content"),
        TRACKER("Video Tracker"),
        AD_SERVING("Ad Serving Infrastructure"),
        ANALYTICS("Video Analytics")
    }

    data class VideoAdEndpoint(
        val domain: String,
        val platform: VideoPlatform?,
        val adTypes: Set<AdType>,
        val confidence: Int, // 0-100
        val blockable: Boolean,
        val reason: String,
        val category: String
    )

    data class VideoIntelligenceResult(
        val domain: String,
        val isVideoAdInfrastructure: Boolean,
        val endpoints: List<VideoAdEndpoint>,
        val shouldBlock: Boolean,
        val blockReason: String?,
        val platformHints: Set<VideoPlatform>,
        val compatibilityRisk: CompatibilityRisk
    )

    enum class CompatibilityRisk(val label: String) {
        NONE("No playback risk"),
        LOW("Low — ad infrastructure only"),
        MEDIUM("Medium — shared infrastructure"),
        HIGH("High — would break playback"),
        CRITICAL("Critical — media delivery domain")
    }

    companion object {
        // ---- Third-party video ad serving infrastructure (always safe to block) ----

        /** Google IMA / DoubleClick video ad serving */
        val GOOGLE_VIDEO_ADS = setOf(
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "googleads.g.doubleclick.net",
            "pubads.g.doubleclick.net",
            "securepubads.g.doubleclick.net",
            "static.doubleclick.net",
            "stats.g.doubleclick.net",
            "ad.doubleclick.net",
            "tpc.googlesyndication.com",
            "pagead2.googlesyndication.com",
            "imasdk.googleapis.com",
            "adservice.google.com",
            "s0.2mdn.net",
            "s1.2mdn.net",
            "2mdn.net",
            "google-analytics.com",
            "googletagmanager.com",
            "googletagservices.com"
        )

        /** YouTube-specific ad infrastructure (third-party only) */
        val YOUTUBE_AD_INFRA = setOf(
            "youtube-nocookie.com", // only when used for tracking
            "yt3.ggpht.com", // thumbnails — NOT ad serving alone
            "ad.youtube.com",
            "ads.youtube.com"
        )

        /** TikTok ad/tracking */
        val TIKTOK_AD_INFRA = setOf(
            "analytics.tiktok.com",
            "ads.tiktok.com",
            "ads-api.tiktok.com",
            "business-api.tiktok.com",
            "log.byteoversea.com",
            "log.tiktokv.com",
            "mcs.tiktokv.com",
            "mon.musical.ly",
            "impression.tiktok.com",
            "ads-creative.facebook.net"
        )

        /** Facebook/Instagram ad infrastructure */
        val META_AD_INFRA = setOf(
            "an.facebook.com",
            "ads-*.facebook.com",
            "graph.facebook.com", // careful — also login
            "connect.facebook.net",
            "instagram.com/api/graphql", // not DNS-level
            "ads.instagram.com"
        )

        /** Twitch ad infrastructure */
        val TWITCH_AD_INFRA = setOf(
            "ads.twitch.tv",
            "usher.ttvnw.net", // actually playback — do NOT block
            "spade.twitch.tv",
            "countess.twitch.tv",
            "gql.twitch.tv" // API — not ad
        )

        /** Programmatic video ad exchanges */
        val PROGRAMMATIC_VIDEO_ADS = setOf(
            "pubmatic.com",
            "rubiconproject.com",
            "openx.net",
            "criteo.com",
            "criteo.net",
            "taboola.com",
            "outbrain.com",
            "adsrvr.org",
            "adnxs.com",
            "quantserve.com",
            "scorecardresearch.com",
            "moatads.com",
            "doubleverify.com",
            "adsafeprotected.com",
            "betrad.com",
            "openxadexchange.com",
            "spotxchange.com",
            "spotx.tv",
            "freewheel.tv",
            "freewheel.com",
            "springserve.com",
            "aniview.com",
            "teads.tv",
            "unruly.co",
            "connexity.com",
            "sharethrough.com",
            "yieldmo.com",
            "undertone.com"
        )

        /** Mobile video ad SDKs */
        val MOBILE_VIDEO_AD_SDKS = setOf(
            "unityads.unity3d.com",
            "applovin.com",
            "vungle.com",
            "ironsrc.com",
            "chartboost.com",
            "inmobi.com",
            "mopub.com",
            "adcolony.com",
            "tapjoy.com",
            "fyber.com",
            "supersonicads.com",
            "admob.com",
            "googleads.g.doubleclick.net",
            "amazon-adsystem.com"
        )

        /** K-drama / Asian streaming ad infrastructure */
        val KDRAMA_AD_INFRA = setOf(
            "ads.viki.com",
            "analytics.viki.com",
            "ad.kakao.com",
            "ads.kakao.com",
            "ad.doubleclick.net",
            "dramacool.*",
            "asianwiki.ads.*",
            // 2026 refresh
            "players.brightcove.net",
            "brightcove.net",
            "brid.tv",
            "pbis.brid.tv"
        )

        /** Video analytics & measurement (Nielsen, Comscore, etc.) */
        val VIDEO_ANALYTICS = setOf(
            "nielsen.com",
            "imrworldwide.com",
            "scorecardresearch.com",
            "comscore.com",
            "hotjar.com",
            "conviva.com",
            "youbora.com",
            "mux.com",
            "datadog.com",
            "newrelic.com"
        )

        // ---- Media delivery domains (NEVER block) ----
        val PROTECTED_MEDIA_DOMAINS = setOf(
            "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com",
            "nflxvideo.net", "nflximg.net", "netflix.com",
            "primevideo.com", "aiv-cdn.net", "aiv-delivery.net",
            "dssott.com", "bamgrid.com", "disneyplus.com",
            "hulu.com", "hbomax.com", "max.com",
            "ttvnw.net", "jtvnw.net", "twitch.tv",
            "fbcdn.net", "cdninstagram.com",
            "tiktokcdn.com", "tiktokv.com", "muscdn.com", "byteoversea.com",
            "vimeocdn.com", "dmcdn.net",
            "scdn.co", "spotify.com"
        )

        fun isProtectedMediaDomain(domain: String): Boolean {
            val lower = domain.lowercase().trimEnd('.')
            return PROTECTED_MEDIA_DOMAINS.any { protected ->
                lower == protected || lower.endsWith(".$protected")
            }
        }

        fun isKnownVideoAdDomain(domain: String): Boolean {
            val lower = domain.lowercase().trimEnd('.')
            val allAdDomains = GOOGLE_VIDEO_ADS + TIKTOK_AD_INFRA + META_AD_INFRA +
                PROGRAMMATIC_VIDEO_ADS + MOBILE_VIDEO_AD_SDKS + VIDEO_ANALYTICS
            return allAdDomains.any { ad ->
                when {
                    ad.contains("*") -> {
                        val pattern = ad.replace(".", "\\.").replace("*", ".*")
                        Regex(pattern).matches(lower)
                    }
                    else -> lower == ad || lower.endsWith(".$ad")
                }
            }
        }
    }

    fun analyze(domain: String): VideoIntelligenceResult {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isEmpty()) {
            return VideoIntelligenceResult(
                domain = domain, isVideoAdInfrastructure = false,
                endpoints = emptyList(), shouldBlock = false,
                blockReason = null, platformHints = emptySet(),
                compatibilityRisk = CompatibilityRisk.NONE
            )
        }

        // Protected media domain — never block
        if (isProtectedMediaDomain(normalized)) {
            // Check if it's an ad sublabel on a media domain (e.g., ads.twitch.tv)
            val isAdSublabel = normalized.split('.').any { label ->
                label in setOf("ads", "ad", "advert", "adsystem", "adservice")
            }
            if (isAdSublabel) {
                val endpoint = VideoAdEndpoint(
                    domain = normalized,
                    platform = detectPlatform(normalized),
                    adTypes = setOf(AdType.AD_SERVING),
                    confidence = 85,
                    blockable = true,
                    reason = "Ad sublabel on media domain — blockable",
                    category = "Video Ad Serving"
                )
                return VideoIntelligenceResult(
                    domain = normalized, isVideoAdInfrastructure = true,
                    endpoints = listOf(endpoint), shouldBlock = true,
                    blockReason = "Ad-serving sublabel on media infrastructure",
                    platformHints = setOfNotNull(detectPlatform(normalized)),
                    compatibilityRisk = CompatibilityRisk.LOW
                )
            }
            return VideoIntelligenceResult(
                domain = normalized, isVideoAdInfrastructure = false,
                endpoints = emptyList(), shouldBlock = false,
                blockReason = null, platformHints = setOfNotNull(detectPlatform(normalized)),
                compatibilityRisk = CompatibilityRisk.CRITICAL
            )
        }

        val endpoints = mutableListOf<VideoAdEndpoint>()

        // Check each category
        checkCategory(normalized, GOOGLE_VIDEO_ADS, VideoPlatform.YOUTUBE, AdType.AD_SERVING, "Google Video Ads", endpoints)
        checkCategory(normalized, TIKTOK_AD_INFRA, VideoPlatform.TIKTOK, AdType.TRACKER, "TikTok Ad Infrastructure", endpoints)
        checkCategory(normalized, PROGRAMMATIC_VIDEO_ADS, null, AdType.AD_SERVING, "Programmatic Video Exchange", endpoints)
        checkCategory(normalized, MOBILE_VIDEO_AD_SDKS, null, AdType.PRE_ROLL, "Mobile Video Ad SDK", endpoints)
        checkCategory(normalized, VIDEO_ANALYTICS, null, AdType.ANALYTICS, "Video Analytics", endpoints)
        checkCategory(normalized, KDRAMA_AD_INFRA, null, AdType.AD_SERVING, "K-Drama Streaming Ads", endpoints)

        // Heuristic: video ad keyword detection for unknown domains
        if (endpoints.isEmpty()) {
            val heuristic = heuristicVideoAdCheck(normalized)
            if (heuristic != null) endpoints.add(heuristic)
        }

        val isVideoAd = endpoints.isNotEmpty()
        val shouldBlock = endpoints.any { it.blockable }
        val risk = when {
            !isVideoAd -> CompatibilityRisk.NONE
            endpoints.all { it.blockable } -> CompatibilityRisk.LOW
            else -> CompatibilityRisk.MEDIUM
        }

        return VideoIntelligenceResult(
            domain = normalized,
            isVideoAdInfrastructure = isVideoAd,
            endpoints = endpoints,
            shouldBlock = shouldBlock,
            blockReason = endpoints.firstOrNull { it.blockable }?.reason,
            platformHints = endpoints.mapNotNull { it.platform }.toSet(),
            compatibilityRisk = risk
        )
    }

    private fun checkCategory(
        domain: String,
        knownSet: Set<String>,
        platform: VideoPlatform?,
        adType: AdType,
        categoryLabel: String,
        out: MutableList<VideoAdEndpoint>
    ) {
        for (known in knownSet) {
            val matches = when {
                known.contains("*") -> {
                    val regex = known.replace(".", "\\.").replace("*", ".*")
                    Regex(regex).matches(domain)
                }
                else -> domain == known || domain.endsWith(".$known")
            }
            if (matches) {
                // Twitch special cases — some domains are playback, not ads
                if (domain == "usher.ttvnw.net" || domain == "gql.twitch.tv") return
                out.add(
                    VideoAdEndpoint(
                        domain = domain,
                        platform = platform ?: detectPlatform(domain),
                        adTypes = setOf(adType),
                        confidence = 90,
                        blockable = true,
                        reason = "Known $categoryLabel: $known",
                        category = categoryLabel
                    )
                )
                return
            }
        }
    }

    private fun heuristicVideoAdCheck(domain: String): VideoAdEndpoint? {
        val labels = domain.split('.')
        val videoAdKeywords = setOf(
            "vast", "vmap", "adbreak", "midroll", "preroll", "postroll",
            "adpod", "adunit", "videoads", "videoad", "ima3", "ima-sdk"
        )
        for (label in labels) {
            if (label.lowercase() in videoAdKeywords) {
                return VideoAdEndpoint(
                    domain = domain,
                    platform = null,
                    adTypes = setOf(AdType.AD_SERVING),
                    confidence = 55,
                    blockable = false, // heuristic only — don't auto-block
                    reason = "Heuristic: label '$label' suggests video ad serving (not verified — review needed)",
                    category = "Heuristic Video Ad"
                )
            }
        }
        return null
    }

    private fun detectPlatform(domain: String): VideoPlatform? {
        return when {
            domain.contains("googlevideo") || domain.contains("youtube") || domain.contains("ggpht") -> VideoPlatform.YOUTUBE
            domain.contains("tiktok") || domain.contains("byteoversea") || domain.contains("musical") -> VideoPlatform.TIKTOK
            domain.contains("fbcdn") || domain.contains("facebook") -> VideoPlatform.FACEBOOK
            domain.contains("instagram") || domain.contains("cdninstagram") -> VideoPlatform.INSTAGRAM
            domain.contains("ttvnw") || domain.contains("twitch") -> VideoPlatform.TWITCH
            domain.contains("nflx") || domain.contains("netflix") -> VideoPlatform.NETFLIX
            domain.contains("dssott") || domain.contains("bamgrid") || domain.contains("disneyplus") -> VideoPlatform.DISNEY_PLUS
            domain.contains("primevideo") || domain.contains("aiv-") -> VideoPlatform.PRIME_VIDEO
            domain.contains("hulu") -> VideoPlatform.HULU
            domain.contains("vimeo") -> VideoPlatform.VIMEO
            domain.contains("dailymotion") || domain.contains("dmcdn") -> VideoPlatform.DAILYMOTION
            domain.contains("spotify") || domain.contains("scdn") -> VideoPlatform.SPOTIFY
            else -> null
        }
    }

    /**
     * Batch analysis for multiple domains (e.g., all domains seen in a browsing session).
     */
    fun analyzeBatch(domains: List<String>): Map<String, VideoIntelligenceResult> {
        return domains.associateWith { analyze(it) }
    }

    /**
     * Get platform-specific ad domains that are safe to block.
     */
    fun platformForDomain(domain: String): VideoPlatform? = detectPlatform(domain.lowercase())
    fun getPlatformAdDomains(platform: VideoPlatform): Set<String> {
        return when (platform) {
            VideoPlatform.YOUTUBE -> GOOGLE_VIDEO_ADS.filter { it.contains("doubleclick") || it.contains("2mdn") || it.contains("imasdk") }.toSet()
            VideoPlatform.TIKTOK -> TIKTOK_AD_INFRA
            VideoPlatform.FACEBOOK, VideoPlatform.INSTAGRAM -> META_AD_INFRA.filter { !it.contains("graph.") }.toSet()
            VideoPlatform.TWITCH -> setOf("ads.twitch.tv", "spade.twitch.tv", "countess.twitch.tv")
            else -> emptySet()
        }
    }
}
