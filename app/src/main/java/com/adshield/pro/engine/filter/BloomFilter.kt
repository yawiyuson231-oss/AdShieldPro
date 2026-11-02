package com.adshield.pro.engine.filter

/**
 * TitanShield Max — Space-efficient probabilistic set membership (Bloom filter).
 *
 * Used as an O(1) negative fast-path in front of the multi-million-entry DNS filter maps:
 * - If the bloom filter says "definitely not present", the evaluation pipeline short-circuits
 *   without walking the domain suffix chain through the hash maps.
 * - False positives are acceptable (they just fall through to the authoritative maps);
 *   false negatives are impossible with this construction.
 *
 * Pure Kotlin, lock-free readable (built off-thread, published via immutable reference).
 */
class BloomFilter(
    expectedEntries: Int,
    falsePositiveRate: Double = 0.01
) : java.io.Serializable {

    val expectedEntries: Int = expectedEntries.coerceAtLeast(1)

    private val bits: LongArray

    private val numHashFunctions: Int

    val bitCount: Long

    init {
        val m = optimalBitCount(expectedEntries, falsePositiveRate)
        bits = LongArray(((m + 63) / 64).toInt())
        bitCount = m
        numHashFunctions = optimalHashCount(expectedEntries, m)
    }

    fun add(element: String) {
        val bytes = element.toByteArray(Charsets.UTF_8)
        val h1 = murmur3_32(bytes, seed = 0x9747b28c)
        val h2 = murmur3_32(bytes, seed = 0x1b873593)
        var hash = h1.toLong() and 0xFFFFFFFFL
        val h2l = h2.toLong() and 0xFFFFFFFFL
        for (i in 0 until numHashFunctions) {
            val idx = hash % bitCount
            val word = (idx / 64).toInt()
            if (word in bits.indices) {
                bits[word] = bits[word] or (1L shl (idx % 64).toInt())
            }
            hash += h2l
        }
    }

    fun mightContain(element: String): Boolean {
        val bytes = element.toByteArray(Charsets.UTF_8)
        val h1 = murmur3_32(bytes, seed = 0x9747b28c)
        val h2 = murmur3_32(bytes, seed = 0x1b873593)
        var hash = h1.toLong() and 0xFFFFFFFFL
        val h2l = h2.toLong() and 0xFFFFFFFFL
        for (i in 0 until numHashFunctions) {
            val idx = hash % bitCount
            val word = (idx / 64).toInt()
            if (word !in bits.indices) return true
            if (bits[word] and (1L shl (idx % 64).toInt()) == 0L) return false
            hash += h2l
        }
        return true
    }

    companion object {
        fun optimalBitCount(expectedEntries: Int, fpp: Double): Long {
            val n = expectedEntries.coerceAtLeast(1).toDouble()
            val p = fpp.coerceIn(1e-9, 0.5)
            return (-n * kotlin.math.ln(p) / (kotlin.math.ln(2.0) * kotlin.math.ln(2.0)))
                .toLong().coerceAtLeast(64L)
        }

        fun optimalHashCount(expectedEntries: Int, bitCount: Long): Int {
            val n = expectedEntries.coerceAtLeast(1).toDouble()
            val m = bitCount.coerceAtLeast(64L).toDouble()
            return ((m / n) * kotlin.math.ln(2.0)).toInt().coerceIn(1, 16)
        }

        /** 32-bit MurmurHash3 (x86 variant) — fast, well-distributed for domain strings. */
        fun murmur3_32(data: ByteArray, seed: Int): Int {
            var h1 = seed
            val c1 = -0x3361d2af
            val c2 = 0x1b873593
            var i = 0
            val len = data.size
            while (i + 4 <= len) {
                var k1 = (data[i].toInt() and 0xFF) or
                    ((data[i + 1].toInt() and 0xFF) shl 8) or
                    ((data[i + 2].toInt() and 0xFF) shl 16) or
                    ((data[i + 3].toInt() and 0xFF) shl 24)
                k1 *= c1
                k1 = Integer.rotateLeft(k1, 15)
                k1 *= c2
                h1 = h1 xor k1
                h1 = Integer.rotateLeft(h1, 13)
                h1 = h1 * 5 + 0xe6546b64
                i += 4
            }
            var k1 = 0
            when (len and 3) {
                3 -> {
                    k1 = k1 xor ((data[i + 2].toInt() and 0xFF) shl 16)
                    k1 = k1 xor ((data[i + 1].toInt() and 0xFF) shl 8)
                    k1 = k1 xor (data[i].toInt() and 0xFF)
                    k1 *= c1; k1 = Integer.rotateLeft(k1, 15); k1 *= c2; h1 = h1 xor k1
                }
                2 -> {
                    k1 = k1 xor ((data[i + 1].toInt() and 0xFF) shl 8)
                    k1 = k1 xor (data[i].toInt() and 0xFF)
                    k1 *= c1; k1 = Integer.rotateLeft(k1, 15); k1 *= c2; h1 = h1 xor k1
                }
                1 -> {
                    k1 = k1 xor (data[i].toInt() and 0xFF)
                    k1 *= c1; k1 = Integer.rotateLeft(k1, 15); k1 *= c2; h1 = h1 xor k1
                }
            }
            h1 = h1 xor len
            h1 = h1 xor (h1 ushr 16)
            h1 *= -0x7a143595
            h1 = h1 xor (h1 ushr 13)
            h1 *= -0x3d4d51cb
            h1 = h1 xor (h1 ushr 16)
            return h1
        }
    }
}
