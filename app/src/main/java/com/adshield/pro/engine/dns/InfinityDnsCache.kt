package com.adshield.pro.engine.dns

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * INFINITY DNS — Advanced TTL-Aware LRU Cache
 *
 * Upgrades the simple LinkedHashMap cache in UpstreamDnsResolver with:
 * - True LRU eviction with O(1) ops
 * - Per-entry TTL from DNS response (TTL-aware expiration)
 * - Negative caching for NXDOMAIN (short TTL)
 * - Stale-while-revalidate support
 * - Cache metrics & analytics
 * - Memory-bounded (configurable max entries & max memory bytes)
 * - Thread-safe with read-write lock for high concurrent read throughput
 *
 * Benchmark target: <1µs cache hit, <5µs miss path
 */
class InfinityDnsCache(
    private val maxEntries: Int = 2048,
    private val maxMemoryBytes: Long = 4L * 1024 * 1024, // 4 MB
    private val negativeTtlSeconds: Int = 30,
    private val staleTtlMs: Long = 5000L // serve stale for 5s while revalidating
) {
    companion object {
        fun maxProfile() = InfinityDnsCache(
            maxEntries = 4096,
            maxMemoryBytes = 8L * 1024 * 1024,
            negativeTtlSeconds = 15,
            staleTtlMs = 8000L
        )
        fun standard() = InfinityDnsCache()
    }

    data class CacheEntry(
        val key: String,
        val response: ByteArray,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        val ttlSeconds: Int,
        val isNegative: Boolean,
        val protocol: String,
        val sizeBytes: Int
    ) {
        fun isExpired(nowMs: Long): Boolean = nowMs >= expiresAtMs
        fun isStale(nowMs: Long): Boolean = nowMs >= expiresAtMs && nowMs < expiresAtMs + 5000L
        fun remainingTtlMs(nowMs: Long): Long = (expiresAtMs - nowMs).coerceAtLeast(0)
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CacheEntry) return false
            return key == other.key && createdAtMs == other.createdAtMs
        }
        override fun hashCode(): Int = key.hashCode() * 31 + createdAtMs.hashCode()
    }

    data class CacheStats(
        val hits: Long,
        val misses: Long,
        val expirations: Long,
        val evictions: Long,
        val negativeHits: Long,
        val staleServed: Long,
        val currentEntries: Int,
        val currentMemoryBytes: Long,
        val hitRate: Double
    ) {
        val totalRequests: Long get() = hits + misses
    }

    data class CacheResult(
        val response: ByteArray,
        val isStale: Boolean,
        val remainingTtlMs: Long
    )

    // Doubly-linked LRU using LinkedHashMap in access-order mode
    private val map = object : LinkedHashMap<String, CacheEntry>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?): Boolean {
            if (size > maxEntries) {
                evictions++
                eldest?.let { currentMemoryBytes -= it.value.sizeBytes }
                return true
            }
            if (currentMemoryBytes > maxMemoryBytes) {
                eldest?.let { currentMemoryBytes -= it.value.sizeBytes }
                evictions++
                return true
            }
            return false
        }
    }

    private val lock = ReentrantReadWriteLock()
    private var currentMemoryBytes: Long = 0L

    @Volatile private var hits: Long = 0L
    @Volatile private var misses: Long = 0L
    @Volatile private var expirations: Long = 0L
    @Volatile private var evictions: Long = 0L
    @Volatile private var negativeHits: Long = 0L
    @Volatile private var staleServed: Long = 0L

    /**
     * Try to get a cached response. Returns null on miss or hard expiration.
     * If stale-while-revalidate window applies, returns stale entry with flag.
     */
    fun get(key: String, nowMs: Long = System.currentTimeMillis()): CacheResult? {
        // Fast path: read lock
        val entry = lock.read { map[key] } ?: run {
            misses++
            return null
        }

        if (!entry.isExpired(nowMs)) {
            // Touch for LRU — needs write lock
            lock.write { map[key] } // access-order moves to tail
            hits++
            if (entry.isNegative) negativeHits++
            return CacheResult(
                response = entry.response.copyOf(),
                isStale = false,
                remainingTtlMs = entry.remainingTtlMs(nowMs)
            )
        }

        // Check stale-while-revalidate window
        if (nowMs < entry.expiresAtMs + staleTtlMs) {
            hits++
            staleServed++
            return CacheResult(
                response = entry.response.copyOf(),
                isStale = true,
                remainingTtlMs = 0
            )
        }

        // Hard expired — remove
        lock.write {
            val current = map[key]
            if (current?.expiresAtMs == entry.expiresAtMs) {
                map.remove(key)
                currentMemoryBytes -= entry.sizeBytes
                expirations++
            }
        }
        misses++
        return null
    }

    /**
     * Insert a response. Extracts TTL from DNS response if not provided.
     */
    fun put(
        key: String,
        response: ByteArray,
        ttlSeconds: Int? = null,
        protocol: String = "unknown",
        nowMs: Long = System.currentTimeMillis()
    ) {
        val resolvedTtl = ttlSeconds ?: extractTtl(response)
        val isNegative = isNegativeResponse(response)
        val effectiveTtl = when {
            isNegative -> negativeTtlSeconds
            else -> resolvedTtl.coerceIn(15, 3600)
        }
        val entry = CacheEntry(
            key = key,
            response = response.copyOf(),
            createdAtMs = nowMs,
            expiresAtMs = nowMs + effectiveTtl * 1000L,
            ttlSeconds = effectiveTtl,
            isNegative = isNegative,
            protocol = protocol,
            sizeBytes = response.size + key.length * 2 + 64 // estimate overhead
        )

        lock.write {
            val old = map.put(key, entry)
            if (old != null) currentMemoryBytes -= old.sizeBytes
            currentMemoryBytes += entry.sizeBytes

            // Enforce memory cap by evicting LRU entries
            while (currentMemoryBytes > maxMemoryBytes && map.size > 1) {
                val eldest = map.entries.firstOrNull() ?: break
                map.remove(eldest.key)
                currentMemoryBytes -= eldest.value.sizeBytes
                evictions++
            }
            // Enforce entry count cap
            while (map.size > maxEntries) {
                val eldest = map.entries.firstOrNull() ?: break
                map.remove(eldest.key)
                currentMemoryBytes -= eldest.value.sizeBytes
                evictions++
            }
        }
    }

    fun remove(key: String) {
        lock.write {
            val removed = map.remove(key)
            if (removed != null) currentMemoryBytes -= removed.sizeBytes
        }
    }

    fun clear() {
        lock.write {
            map.clear()
            currentMemoryBytes = 0L
        }
    }

    fun size(): Int = lock.read { map.size }

    fun memoryBytes(): Long = lock.read { currentMemoryBytes }

    /**
     * Remove all expired entries. Returns count removed.
     */
    fun evictExpired(nowMs: Long = System.currentTimeMillis()): Int {
        var removed = 0
        lock.write {
            val iter = map.entries.iterator()
            while (iter.hasNext()) {
                val e = iter.next()
                if (e.value.isExpired(nowMs) && nowMs >= e.value.expiresAtMs + staleTtlMs) {
                    currentMemoryBytes -= e.value.sizeBytes
                    iter.remove()
                    expirations++
                    removed++
                }
            }
        }
        return removed
    }

    /**
     * Trim to target size, evicting LRU entries first.
     */
    fun trimToSize(targetSize: Int): Int {
        var removed = 0
        lock.write {
            while (map.size > targetSize) {
                val eldest = map.entries.firstOrNull() ?: break
                map.remove(eldest.key)
                currentMemoryBytes -= eldest.value.sizeBytes
                evictions++
                removed++
            }
        }
        return removed
    }

    fun stats(): CacheStats = lock.read {
        CacheStats(
            hits = hits,
            misses = misses,
            expirations = expirations,
            evictions = evictions,
            negativeHits = negativeHits,
            staleServed = staleServed,
            currentEntries = map.size,
            currentMemoryBytes = currentMemoryBytes,
            hitRate = if (hits + misses > 0) hits.toDouble() / (hits + misses) else 0.0
        )
    }

    fun resetStats() {
        hits = 0L; misses = 0L; expirations = 0L; evictions = 0L
        negativeHits = 0L; staleServed = 0L
    }

    // ---- Internal helpers ----

    private fun extractTtl(response: ByteArray): Int {
        if (response.size < 12) return 60
        return try {
            DnsPacketCodec.extractResponseTtlSeconds(response)
        } catch (_: Exception) {
            60
        }
    }

    private fun isNegativeResponse(response: ByteArray): Boolean {
        if (response.size < 12) return false
        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        val rcode = flags and 0x000F
        return rcode == 3 // NXDOMAIN
    }
}
