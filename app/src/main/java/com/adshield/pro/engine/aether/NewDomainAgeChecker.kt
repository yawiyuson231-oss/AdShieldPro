package com.adshield.pro.engine.aether

/**
 * OmniShield X — New-Domain Age Checker (platform spec: "Flag new domains (registered in
 * the last 30 days)").
 *
 * Honest limitations, stated up front:
 * - Domain registration dates are not available offline. This checker queries the
 *   registry's RDAP service (rdap.org bootstrap → registry RDAP) over HTTPS, is OPT-IN
 *   (default OFF), cached per domain for 6 hours, hard-capped at 2s per lookup, and only
 *   consulted in Strict mode when the user enables it.
 * - Some registries/second-level registries do not expose registration dates via RDAP;
 *   in that case the result is null (unknown) and NO heuristic action is taken.
 */
object NewDomainAgeChecker {

    data class Lookup(val ageDays: Int?, val source: String)

    private val cache = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, Lookup>>()
    private const val CACHE_TTL_MS = 6 * 60 * 60 * 1000L

    /**
     * Pure parser: extract the earliest "registration" event date from RDAP JSON.
     * Canned and real RDAP both look like: {"events":[{"eventAction":"registration","eventDate":"2026-09-01T00:00:00Z"}]}
     */
    fun parseAgeDaysFromRdap(json: String, nowEpochMs: Long): Int? {
        val date = Regex("\"eventAction\"\\s*:\\s*\"registration\"\\s*,\\s*\"eventDate\"\\s*:\\s*\"([^\"]+)\"")
            .find(json)?.groupValues?.get(1)
            ?: Regex("\"eventDate\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"eventAction\"\\s*:\\s*\"registration\"")
                .find(json)?.groupValues?.get(1)
            ?: return null
        val epoch = parseIso8601Utc(date) ?: return null
        val days = ((nowEpochMs - epoch) / 86_400_000L).toInt()
        return if (days < 0) 0 else days
    }

    /** Minimal ISO-8601 UTC parser ("2026-09-01T12:34:56Z"), avoids java.time on old desugaring. */
    fun parseIso8601Utc(iso: String): Long? {
        val m = Regex("(\\d{4})-(\\d{2})-(\\d{2})[Tt ](\\d{2}):(\\d{2}):(\\d{2})").find(iso) ?: return null
        val (y, mo, d, h, mi, s) = m.destructured
        val cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
        cal.clear()
        cal.set(y.toInt(), mo.toInt() - 1, d.toInt(), h.toInt(), mi.toInt(), s.toInt())
        return cal.timeInMillis
    }

    /**
     * Runtime lookup with cache. [fetchRdap] performs the network call (injected for
     * testability); returns null when unknown/disabled/failed — never throws.
     */
    suspend fun ageDays(
        domain: String,
        fetchRdap: suspend (String) -> String?
    ): Int? {
        val now = System.currentTimeMillis()
        val key = domain.lowercase().trimEnd('.')
        if (!key.contains('.')) return null
        cache[key]?.let { (ts, lookup) ->
            if (now - ts < CACHE_TTL_MS) return lookup.ageDays
            cache.remove(key)
        }
        val body = runCatching { fetchRdap(key) }.getOrNull() ?: return null
        val age = parseAgeDaysFromRdap(body, now)
        cache[key] = now to Lookup(age, "RDAP")
        return age
    }

    fun clearCache() = cache.clear()
}
