package com.adshield.pro.engine.filter

import java.security.MessageDigest

/**
 * INFINITY DNS v3.1 — Memory-efficient pre-filter for large rule sets.
 *
 * When the merged rule set grows past ~500k (bundled + remote + custom),
 * a HashMap of 900k Strings costs ~40 MB. A Bloom filter stores the same
 * membership at ~2 MB with a tunable false-positive rate (default 1%).
 *
 * Contract: `mightContain == false` ⇒ definitely not blocked (skip HashMap).
 *           `mightContain == true`  ⇒ check HashMap to confirm (no false negatives).
 *
 * Pure JVM + Android compatible (no NDK). Thread-safe for concurrent reads
 * after construction; rebuilt atomically under FilterRuleEngine's write lock.
 */
class BloomFilter private constructor(
    private val bits: LongArray,
    private val bitCount: Int,
    private val hashCount: Int
) {
    fun mightContain(domain: String): Boolean {
        val norm = domain.lowercase().trim().trimEnd('.')
        if (norm.isEmpty()) return false
        val (h1, h2) = hashPair(norm)
        for (i in 0 until hashCount) {
            val combined = (h1 + i.toLong() * h2).let { if (it < 0) -it else it }
            val bit = (combined % bitCount).toInt()
            if ((bits[bit ushr 6] ushr (bit and 63)) and 1L == 0L) return false
        }
        return true
    }

    companion object {
        /** Build sized for `expectedInsertions` at `falsePositiveRate` (e.g. 0.01). */
        fun create(expectedInsertions: Int, falsePositiveRate: Double = 0.01): BloomFilter {
            require(expectedInsertions > 0)
            require(falsePositiveRate in 0.0001..0.5)
            val m = (-expectedInsertions * kotlin.math.ln(falsePositiveRate) / (kotlin.math.ln(2.0) * kotlin.math.ln(2.0))).toInt().coerceAtLeast(64)
            val k = ((m.toDouble() / expectedInsertions) * kotlin.math.ln(2.0)).toInt().coerceAtLeast(1)
            return BloomFilter(LongArray((m + 63) / 64), m, k)
        }

        fun fromDomains(domains: Iterable<String>, falsePositiveRate: Double = 0.01): BloomFilter {
            val list = domains.toList()
            val bf = create(list.size.coerceAtLeast(1), falsePositiveRate)
            for (d in list) bf.add(d)
            return bf
        }

        private fun hashPair(input: String): Pair<Long, Long> {
            val bytes = input.toByteArray(Charsets.UTF_8)
            val md = MessageDigest.getInstance("SHA-256").digest(bytes)
            var h1 = 0L; var h2 = 0L
            for (i in 0 until 8) h1 = (h1 shl 8) or (md[i].toLong() and 0xFF)
            for (i in 8 until 16) h2 = (h2 shl 8) or (md[i].toLong() and 0xFF)
            if (h1 == 0L) h1 = 0x9E3779B97F4A7C15UL.toLong()
            if (h2 == 0L) h2 = 0xBF58476D1CE4E5B9UL.toLong()
            return h1 to h2
        }
    }

    fun add(domain: String) {
        val norm = domain.lowercase().trim().trimEnd('.')
        if (norm.isEmpty()) return
        val (h1, h2) = hashPair(norm)
        for (i in 0 until hashCount) {
            val combined = (h1 + i.toLong() * h2).let { if (it < 0) -it else it }
            val bit = (combined % bitCount).toInt()
            bits[bit ushr 6] = bits[bit ushr 6] or (1L shl (bit and 63))
        }
    }

    /** Approximate memory in bytes. */
    fun memoryBytes(): Int = bits.size * 8
}
