package com.adshield.pro.engine.dns

/**
 * RFC 2308 §7.1 failure caching, bounded and short.
 *
 * When every upstream provider has just failed for a name, a page will typically fire the same
 * lookup a dozen times in a row while its spinner turns. Re-walking the whole provider plan for
 * each of those is the difference between a slow resolver and a dead one, so the failure itself is
 * remembered for a few seconds.
 *
 * Deliberate limits:
 * - Seconds, not minutes: the cache must never slow recovery once the network is back.
 * - Only the exact question (name, type, class, protocol, resolver) is remembered.
 * - A stale answer is always preferred over a remembered failure; this class does not decide that,
 *   [UpstreamDnsResolver] does.
 */
class DnsFailureCache(
    private val ttlMs: Long = DEFAULT_TTL_MS,
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    private val failures = HashMap<String, Long>()
    private val lock = Any()

    fun recordFailure(key: String, nowMs: Long = clock()) {
        synchronized(lock) {
            purgeExpiredLocked(nowMs)
            if (!failures.containsKey(key) && failures.size >= maxEntries) {
                failures.entries.minByOrNull { it.value }?.let { failures.remove(it.key) }
            }
            failures[key] = nowMs + ttlMs
        }
    }

    /** Milliseconds left on a remembered failure, or 0 when there is none. */
    fun remainingMs(key: String, nowMs: Long = clock()): Long {
        synchronized(lock) {
            val until = failures[key] ?: return 0L
            val remaining = until - nowMs
            if (remaining <= 0L) {
                failures.remove(key)
                return 0L
            }
            return remaining
        }
    }

    fun isFailing(key: String, nowMs: Long = clock()): Boolean = remainingMs(key, nowMs) > 0L

    fun clear(key: String) {
        synchronized(lock) { failures.remove(key) }
    }

    fun clearAll() {
        synchronized(lock) { failures.clear() }
    }

    internal fun size(): Int = synchronized(lock) { failures.size }

    private fun purgeExpiredLocked(nowMs: Long) {
        failures.entries.removeAll { it.value <= nowMs }
    }

    companion object {
        /** Long enough to absorb one page's burst, short enough to be invisible once the network returns. */
        const val DEFAULT_TTL_MS = 15_000L
        const val DEFAULT_MAX_ENTRIES = 512
    }
}
