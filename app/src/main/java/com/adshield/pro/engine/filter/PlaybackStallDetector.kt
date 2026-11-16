package com.adshield.pro.engine.filter

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Recognises the shape of a stalled playback: one app asking for the same blocked zone again and
 * again within a few seconds.
 *
 * This is a *symptom*, not a diagnosis. Players also retry adverts that loaded fine, so the signal is
 * only ever shown next to the block — it never unblocks anything by itself. Its purpose is to put the
 * fifteen-minute lease in front of the user at the moment the app is visibly stuck, instead of
 * leaving them to guess which of a dozen rows is the culprit.
 *
 * Bounded on purpose: at most [MAX_TRACKED] app/zone pairs are remembered, the oldest observation is
 * dropped first, and an entry that has not been repeated inside [WINDOW_MS] is forgotten.
 */
@Singleton
class PlaybackStallDetector @Inject constructor() {

    /**
     * A repeated block: the app involved, the zone it kept asking for, and how many times it asked
     * inside the window.
     */
    data class Signal(val appPackage: String?, val domain: String, val attempts: Int)

    private data class Observation(val appPackage: String?, val domain: String, var attempts: Int, var lastSeenMs: Long)

    /** Overridable in tests so the window can be exercised without sleeping. */
    @Volatile
    internal var clock: () -> Long = { System.currentTimeMillis() }

    private val observations = LinkedHashMap<String, Observation>()
    private val lock = Any()

    /**
     * Records one block of [domain] for [appPackage] and returns a [Signal] once the threshold is
     * reached, or null while the pattern is still ordinary traffic.
     */
    fun record(appPackage: String?, domain: String, nowMs: Long = clock()): Signal? {
        val name = domain.trim().trimEnd('.').lowercase()
        if (name.isEmpty()) return null
        val key = "${appPackage ?: "unknown"}|$name"
        synchronized(lock) {
            purgeExpiredLocked(nowMs)
            val existing = observations[key]
            val observation = if (existing == null) {
                if (observations.size >= MAX_TRACKED) {
                    observations.entries.minByOrNull { it.value.lastSeenMs }?.let { observations.remove(it.key) }
                }
                Observation(appPackage, name, attempts = 0, lastSeenMs = nowMs).also { observations[key] = it }
            } else {
                existing
            }
            observation.attempts += 1
            observation.lastSeenMs = nowMs
            return if (observation.attempts >= THRESHOLD) {
                Signal(appPackage, name, observation.attempts)
            } else {
                null
            }
        }
    }

    fun forget(appPackage: String?, domain: String) {
        val name = domain.trim().trimEnd('.').lowercase()
        synchronized(lock) { observations.remove("${appPackage ?: "unknown"}|$name") }
    }

    fun clear() {
        synchronized(lock) { observations.clear() }
    }

    internal fun trackedCount(): Int = synchronized(lock) { observations.size }

    private fun purgeExpiredLocked(nowMs: Long) {
        observations.entries.removeAll { nowMs - it.value.lastSeenMs > WINDOW_MS }
    }

    companion object {
        /** Three asks inside twenty seconds is the pattern; two is ordinary ad refresh traffic. */
        const val THRESHOLD = 3
        const val WINDOW_MS = 20_000L
        const val MAX_TRACKED = 256
    }
}
