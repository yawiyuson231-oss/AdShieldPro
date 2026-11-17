package com.adshield.pro.engine.aether

import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks recent video host queries to enable time-boxed heuristic throttle.
 * Blocks ad infra only within 3s of video init, preventing mid-stream kills.
 */
object VideoSessionTracker {

    private data class VideoInit(val host: String, val timestampMs: Long)

    private val recentVideoInits = ConcurrentHashMap<String, Long>() // registrant -> timestamp

    private val VIDEO_INIT_HOSTS = setOf(
        "youtube.com", "youtu.be", "googlevideo.com",
        "facebook.com", "fbcdn.net", "instagram.com",
        "tiktok.com", "byteoversea.com", "twitch.tv", "ttvnw.net"
    )

    fun onDnsQuery(domain: String, nowMs: Long = System.currentTimeMillis()) {
        val lower = domain.lowercase()
        if (VIDEO_INIT_HOSTS.any { lower.endsWith(it) }) {
            recentVideoInits[lower] = nowMs
        }
        // Cleanup old entries > 10s
        recentVideoInits.entries.removeIf { nowMs - it.value > 10_000 }
    }

    fun shouldBlockAdInfra(adDomain: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        // Only block if within 3s of a video init host query
        val recentInit = recentVideoInits.values.maxOrNull() ?: return true // No init seen = allow conservative block (startup)
        return nowMs - recentInit <= 3_000
    }

    fun clear() = recentVideoInits.clear()
}
