package com.adshield.pro.engine.dns

/**
 * OmniShield X — Resolver Health Monitor (Parts 4/8/11).
 *
 * Records REAL per-resolver success/latency measurements taken from live DNS
 * traffic and the connectivity watchdog, then ranks resolvers. Bounded
 * autonomous optimization: it can recommend (and the service may apply)
 * failover between KNOWN PUBLIC PRESETS only — a user's CUSTOM resolver is
 * never silently replaced, only reported.
 */
class ResolverHealthMonitor @javax.inject.Inject constructor() {

    data class ResolverStats(
        val key: String,
        var probes: Long = 0L,
        var failures: Long = 0L,
        var totalLatencyMs: Long = 0L,
        var lastFailureEpochMs: Long = 0L
    ) {
        val successRate: Double get() = if (probes == 0L) 1.0 else (probes - failures).toDouble() / probes
        val avgLatencyMs: Int get() = if (probes == 0L) 0 else (totalLatencyMs / probes).toInt()
    }

    private val stats = LinkedHashMap<String, ResolverStats>()

    @Synchronized
    fun record(resolverKey: String, latencyMs: Int, succeeded: Boolean) {
        val s = stats.getOrPut(resolverKey) { ResolverStats(resolverKey) }
        s.probes++
        if (succeeded) {
            s.totalLatencyMs += latencyMs.coerceAtLeast(0)
        } else {
            s.failures++
            s.lastFailureEpochMs = System.currentTimeMillis()
        }
        if (stats.size > 24) { // bound memory: at most 24 tracked resolvers
            stats.remove(stats.keys.first())
        }
    }

    fun statsFor(resolverKey: String): ResolverStats? = synchronized(stats) { stats[resolverKey] }

    /**
     * Ranks measured resolvers: success first, then latency. Returns null when
     * there is no measured alternative to the current resolver.
     */
    @Synchronized
    fun bestMeasuredResolver(excludeKey: String): ResolverStats? =
        stats.values
            .filter { it.key != excludeKey && it.probes >= 3L && it.successRate >= 0.9 }
            .minByOrNull { it.successRate * -1_000.0 + it.avgLatencyMs }

    @Synchronized
    fun summaryLine(currentKey: String): String {
        val cur = stats[currentKey]
        return when {
            cur == null -> "No resolver measurements yet"
            cur.failures == 0L -> "$currentKey: 100% success, ${cur.avgLatencyMs}ms avg (${cur.probes} probes)"
            else -> "$currentKey: ${(cur.successRate * 100).toInt()}% success, ${cur.avgLatencyMs}ms avg, ${cur.failures} failures"
        }
    }
}
