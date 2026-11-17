package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Detects when video apps bypass DNS filtering via hardcoded DoH/QUIC.
 * Purely observational — never claims to intercept TLS.
 */
@Singleton
class VideoBypassDetector @Inject constructor() {

    data class BypassSignal(
        val packageName: String,
        val appLabel: String,
        val dnsQueryCount: Long,
        val expectedMinQueries: Long,
        val isPossiblyBypassing: Boolean,
        val message: String
    )

    private val KNOWN_HARDENED_VIDEO_APPS = mapOf(
        "com.google.android.youtube" to 15L,
        "com.zhiliaoapp.musically" to 10L, // TikTok
        "com.instagram.android" to 12L,
        "com.facebook.katana" to 12L,
        "tv.twitch.android.app" to 8L
    )

    fun detect(
        appDnsCounts: Map<String, Long>, // packageName -> dns query count in session
        appLabels: Map<String, String>,
        vpnConnected: Boolean
    ): List<BypassSignal> {
        if (!vpnConnected) return emptyList()
        return KNOWN_HARDENED_VIDEO_APPS.mapNotNull { (pkg, minExpected) ->
            val count = appDnsCounts[pkg] ?: 0L
            // If app was seen in topApps but has suspiciously low DNS footprint while video played
            // We use heuristic: if other apps have traffic but this video app has 0 queries after 2+ min session, likely bypass
            val possiblyBypassing = count == 0L && appDnsCounts.values.sum() > 50
            if (possiblyBypassing) {
                BypassSignal(
                    packageName = pkg,
                    appLabel = appLabels[pkg] ?: pkg,
                    dnsQueryCount = count,
                    expectedMinQueries = minExpected,
                    isPossiblyBypassing = true,
                    message = "${appLabels[pkg] ?: pkg} may be using private DNS — use Privacy Browser for best pre-roll coverage."
                )
            } else null
        }
    }
}
