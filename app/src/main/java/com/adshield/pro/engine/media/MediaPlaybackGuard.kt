package com.adshield.pro.engine.media

/**
 * AdShield Pro — media playback guarantee.
 *
 * THE CONTRACT THIS FILE ENFORCES
 * -------------------------------
 * **Playback hosts are never blocked, by any list, in any protection mode.** Video must not break.
 * That is a promise with a measurable consequence, so it is implemented as an allowlist that sits
 * *above* filter lists in the evaluation order, not as good intentions about what the bundled lists
 * happen to contain.
 *
 * This is a **pure APK** product: blocking happens in the native VPN/DNS engine
 * ([com.adshield.pro.service.AdShieldVpnService] -> [com.adshield.pro.engine.filter.FilterRuleEngine]),
 * so it applies to every app on the device — Chrome, the YouTube app, TikTok, a podcast player —
 * with no WebView and no browser extension anywhere in the path. DNS sees hostnames only, never
 * "the page you are on", so the guarantee is a hostname allowlist: [PROTECTED_DELIVERY_HOSTS],
 * exempted at priority 79, above every filter list (50).
 *
 * WHY THE TRADE-OFF IS STATED, NOT HIDDEN
 * ---------------------------------------
 * Exempting a host means *nothing* on that host is blocked, including analytics that share it
 * (`tiktokv.com` carries both API and telemetry). The choice is deliberate and matches the product
 * requirement: a user would rather keep the video and lose a tracker than the reverse. Generic
 * ad-carrying CDNs (`cloudfront.net`, `fastly.net`, `akamaihd.net`) are deliberately **not**
 * exempted — they serve ads too, so exempting them would gut ad blocking for a promise they do not
 * need. Our own video-ad rules never name a playback host; a test enforces that, and a second test
 * feeds the engine a hostile list that tries to block every protected host and proves it cannot.
 *
 * WHAT THIS CANNOT DO
 * -------------------
 * It cannot remove ads stitched into the same stream as the video (YouTube, TikTok, Facebook SSAI).
 * Those are not separate requests, so DNS has nothing to resolve and nothing to block. That limit is
 * stated in the UI and in docs/MEDIA_PLAYBACK.md rather than papered over.
 */
object MediaPlaybackGuard {

    /** The user-facing sentence shown wherever video blocking is described. */
    const val HONEST_CAPABILITY_STATEMENT: String =
        "Blocks third-party video-ad servers on every app. Stitched-in ads on YouTube, " +
            "TikTok and Facebook cannot be removed by DNS, and playback hosts are never blocked."

    /**
     * Delivery/platform hosts that must never be blocked at the DNS layer.
     *
     * Every entry is a host whose primary role is media delivery or the platform that plays it.
     * A hosted tracker on the same family comes along with the exemption — documented above.
     */
    val PROTECTED_DELIVERY_HOSTS: Set<String> = setOf(
        // YouTube / Google video
        "youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "googlevideo.com",
        "ytimg.com",
        "yt3.ggpht.com",
        // Netflix
        "netflix.com",
        "nflxvideo.net",
        "nflximg.net",
        "nflxso.net",
        // TikTok / ByteDance
        "tiktok.com",
        "tiktokv.com",
        "tiktokcdn.com",
        "tiktokcdn-us.com",
        "byteoversea.com",
        "ibytedtos.com",
        "muscdn.com",
        // Meta
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "cdninstagram.com",
        // Twitch
        "twitch.tv",
        "ttvnw.net",
        "jtvnw.net",
        // Prime Video / Disney+ / Hotstar
        "primevideo.com",
        "aiv-cdn.net",
        "aiv-delivery.net",
        "disneyplus.com",
        "dssott.com",
        "hotstar.com",
        // Open web video platforms and players
        "dailymotion.com",
        "dmcdn.net",
        "vimeo.com",
        "vimeocdn.com",
        "jwplayer.com",
        "jwplatform.com",
        "jwpcdn.com",
        "brightcove.net",
        "bcovlive.com",
        "kaltura.com",
        "streamable.com",
        "rumble.com",
        "odysee.com",
        "bilibili.com",
        "soundcloud.com",
        "spotify.com",
        "scdn.co"
    )

    /** True when [host] is (or is a subdomain of) a protected delivery host. */
    fun isProtectedDeliveryHost(host: String?): Boolean = matchesSuffixSet(host, PROTECTED_DELIVERY_HOSTS)

    /**
     * Should this hostname be exempted from every block list?
     * Returns a human-readable reason for the query log, or null when it is a normal host.
     */
    fun exemptionReason(host: String?): String? {
        if (host == null) return null
        return if (isProtectedDeliveryHost(host)) {
            "Media Playback Guard — video delivery host, never blocked"
        } else {
            null
        }
    }

    /**
     * Every protected host that [rules] would block, if any.
     *
     * Used two ways: a JVM test proves the shipped rule sets return an empty list, and the app can
     * warn when a user-synced third-party feed would cost someone their video.
     */
    fun blockedPlaybackHosts(rules: Set<String>): List<String> {
        if (rules.isEmpty()) return emptyList()
        return PROTECTED_DELIVERY_HOSTS.filter { host -> blocksHost(rules, host) }.sorted()
    }

    private fun blocksHost(rules: Set<String>, host: String): Boolean {
        var current = host
        while (true) {
            if (current in rules) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
        }
    }

    private fun matchesSuffixSet(host: String?, set: Set<String>): Boolean {
        if (host.isNullOrBlank()) return false
        var current = host.trim().lowercase().trimEnd('.')
        while (true) {
            if (current in set) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
        }
    }
}
