package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.RuleCategory

/**
 * OmniShield X — Live Monitor feed mapping (Part 12).
 *
 * Pure classification of REAL recorded DNS events into visualization lanes and
 * category tags. No simulation: the Live screen animates only what the VPN
 * actually observed and recorded in the database.
 */
object LiveFeedMapper {

    enum class Lane(val label: String) {
        VIDEO("Video"),
        GAME("Game"),
        SOCIAL("Social"),
        SYSTEM("System"),
        WEB("Web")
    }

    data class FeedTag(val label: String, val colorHex: Long)

    val TAG_AD = FeedTag("Ad", 0xFFFF5470)
    val TAG_TRACKER = FeedTag("Tracker", 0xFFFFB020)
    val TAG_MALICIOUS = FeedTag("Malicious", 0xFFFF3355)
    val TAG_ANALYTICS = FeedTag("Analytics", 0xFFB478FF)
    val TAG_CUSTOM = FeedTag("Custom", 0xFF22D3EE)
    val TAG_NOT_LISTED = FeedTag("Not listed", 0xFF34D399)

    private val VIDEO_HOSTS = listOf(
        "googlevideo", "ytimg", "youtube", "tiktok", "muscdn", "musical.ly",
        "netflix", "nflx", "twitch", "fbcdn", "instagram", "cdninstagram",
        "hulu", "primevideo", "dailymotion", "dmcdn", "vimeo", "disney"
    )

    private val GAME_HOSTS = listOf(
        "aena.ms", "moonton", "mobilelegends", "roblox", "riotgames",
        "supercell", "clashofclans", "clashroyale", "garena", "garenanow",
        "mihoyo", "hoyoverse", "yuanshen", "epicgames", "activision",
        "callofduty", "wildrift", "steampowered", "steamcontent", "minecraft", "mojang"
    )

    private val SOCIAL_HOSTS = listOf(
        "facebook", "whatsapp", "telegram", "twitter", "twimg",
        "reddit", "discord", "snapchat", "linkedin", "pinterest", "tiktokv"
    )

    private val SYSTEM_HOSTS = listOf(
        "gstatic", "googleapis", "android.clients", "connectivitycheck",
        "apple.com", "icloud", "samsung", "mi.com", "huawei", "oppomobile",
        "windowsupdate", "play.googleapis"
    )

    fun laneFor(domain: String): Lane {
        val d = domain.lowercase()
        return when {
            VIDEO_HOSTS.any { d.contains(it) } -> Lane.VIDEO
            GAME_HOSTS.any { d.contains(it) } -> Lane.GAME
            SOCIAL_HOSTS.any { d.contains(it) } -> Lane.SOCIAL
            SYSTEM_HOSTS.any { d.contains(it) } -> Lane.SYSTEM
            else -> Lane.WEB
        }
    }

    fun tagFor(category: RuleCategory?): FeedTag = when (category) {
        RuleCategory.ADS -> TAG_AD
        RuleCategory.TRACKERS -> TAG_TRACKER
        RuleCategory.MALWARE -> TAG_MALICIOUS
        RuleCategory.STRICT_TELEMETRY -> TAG_ANALYTICS
        RuleCategory.CUSTOM -> TAG_CUSTOM
        null -> TAG_NOT_LISTED
    }
}
