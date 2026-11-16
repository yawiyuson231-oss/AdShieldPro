package com.adshield.pro.engine.filter

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Short-lived, in-memory "let this through for a few minutes" grants.
 *
 * This is the escape hatch for the case every DNS blocker eventually meets: a streaming app stalls
 * on an advert step and the user cannot tell which blocked zone caused it. Instead of disabling
 * protection (which unblocks everything), the user grants one domain a bounded lease.
 *
 * Deliberate limits:
 * - Grants live in memory only, so a restart of the process drops them. Nothing silently persists.
 * - A grant needs at least two labels: allowing a whole public suffix such as `com` is refused.
 * - A grant is capped in duration and in count, and the soonest-expiring grant is evicted first.
 * - A grant covers the granted name and its subdomains, nothing else.
 */
@Singleton
class TemporaryAllowlist @Inject constructor() {

    data class Grant(val domain: String, val expiresAtEpochMs: Long)

    /** Overridable in tests so expiry can be exercised without sleeping. */
    @Volatile
    internal var clock: () -> Long = { System.currentTimeMillis() }

    private val grants = LinkedHashMap<String, Grant>()
    private val lock = Any()

    fun grant(
        domain: String,
        durationMs: Long = DEFAULT_DURATION_MS
    ): Grant? {
        val normalized = normalize(domain) ?: return null
        if (!isGrantable(normalized)) return null
        val effectiveDuration = durationMs.coerceIn(MIN_DURATION_MS, MAX_DURATION_MS)
        val now = clock()
        synchronized(lock) {
            purgeExpiredLocked(now)
            if (!grants.containsKey(normalized) && grants.size >= MAX_GRANTS) {
                grants.entries
                    .minByOrNull { it.value.expiresAtEpochMs }
                    ?.let { grants.remove(it.key) }
            }
            val grant = Grant(normalized, now + effectiveDuration)
            grants[normalized] = grant
            return grant
        }
    }

    /** The active grant covering [domain], or null. Exact match or a parent-name match. */
    fun match(domain: String): Grant? {
        val normalized = normalize(domain) ?: return null
        val now = clock()
        synchronized(lock) {
            purgeExpiredLocked(now)
            var candidate = normalized
            while (true) {
                grants[candidate]?.let { return it }
                val dot = candidate.indexOf('.')
                if (dot < 0) return null
                candidate = candidate.substring(dot + 1)
            }
        }
    }

    fun isAllowed(domain: String): Boolean = match(domain) != null

    fun activeGrants(): List<Grant> {
        val now = clock()
        synchronized(lock) {
            purgeExpiredLocked(now)
            return grants.values.sortedBy { it.expiresAtEpochMs }
        }
    }

    fun revoke(domain: String): Boolean {
        val normalized = normalize(domain) ?: return false
        synchronized(lock) { return grants.remove(normalized) != null }
    }

    fun clear() {
        synchronized(lock) { grants.clear() }
    }

    private fun purgeExpiredLocked(now: Long) {
        grants.entries.removeAll { it.value.expiresAtEpochMs <= now }
    }

    private fun normalize(domain: String): String? {
        val trimmed = domain.trim().trimEnd('.').lowercase()
        if (trimmed.isEmpty() || trimmed.length > MAX_DOMAIN_LENGTH) return null
        if (!DOMAIN_PATTERN.matches(trimmed)) return null
        return trimmed
    }

    /** At least two labels: a bare public suffix would allow far more than the user was told. */
    private fun isGrantable(normalized: String): Boolean = normalized.count { it == '.' } >= 1

    companion object {
        const val DEFAULT_DURATION_MS = 15L * 60L * 1000L
        const val MIN_DURATION_MS = 60L * 1000L
        const val MAX_DURATION_MS = 60L * 60L * 1000L
        const val MAX_GRANTS = 32
        private const val MAX_DOMAIN_LENGTH = 253

        private val DOMAIN_PATTERN = Regex(
            "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
        )
    }
}
