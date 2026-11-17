package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS v3.1 — On-Device Adaptive Learning
 *
 * Learns from user Allow/Block overrides to tune sensitivity, stays 100% on-device.
 * No telemetry leaves the device. User can wipe learned state in Settings.
 *
 * What it learns:
 * - Per-category threshold offset (e.g. user repeatedly Allows TRACKERS → lower threshold)
 * - Domain-level overrides (Allow wins persist — already handled by FilterRuleEngine priority 100)
 * - False-positive feedback: user Allow after Block → reduce future confidence for similar lexical pattern
 *
 * Storage: DataStore (tiny JSON, < 10 KB). No DB migration.
 */
@Singleton
class AdaptiveLearningEngine @Inject constructor() {

    enum class Feedback { ALLOW_AFTER_BLOCK, BLOCK_AFTER_ALLOW, CONFIRM_BLOCK, CONFIRM_ALLOW }

    data class LearnedProfile(
        val perCategoryOffset: Map<String, Float> = emptyMap(), // category name → -0.3..+0.3
        val domainTrust: Map<String, Float> = emptyMap(),       // domain → -1..+1 (negative = suspicious)
        val totalFeedbacks: Int = 0,
        val updatedAtMs: Long = System.currentTimeMillis()
    )

    @Volatile private var profile = LearnedProfile()

    fun getProfile(): LearnedProfile = profile

    fun record(feedback: Feedback, domain: String, category: String? = null) {
        val norm = domain.lowercase().trim().trimEnd('.')
        if (norm.isEmpty()) return
        synchronized(this) {
            val cur = profile
            val newTrust = cur.domainTrust.toMutableMap()
            val newOffset = cur.perCategoryOffset.toMutableMap()
            when (feedback) {
                Feedback.ALLOW_AFTER_BLOCK -> {
                    // User says "this was a false positive" → trust this domain + similar TLD
                    newTrust[norm] = (newTrust[norm] ?: 0f) + 0.4f
                    category?.let { newOffset[it] = (newOffset[it] ?: 0f) - 0.05f }
                }
                Feedback.BLOCK_AFTER_ALLOW -> {
                    newTrust[norm] = (newTrust[norm] ?: 0f) - 0.4f
                    category?.let { newOffset[it] = (newOffset[it] ?: 0f) + 0.05f }
                }
                Feedback.CONFIRM_BLOCK -> newTrust[norm] = (newTrust[norm] ?: 0f) - 0.15f
                Feedback.CONFIRM_ALLOW -> newTrust[norm] = (newTrust[norm] ?: 0f) + 0.15f
            }
            // Clamp & cap size (LRU eviction of oldest trust entries over 500)
            val clampedTrust = newTrust.mapValues { it.value.coerceIn(-1f, 1f) }
                .let { if (it.size > 500) it.entries.drop(it.size - 500).associate { e -> e.key to e.value } else it }
            val clampedOffset = newOffset.mapValues { it.value.coerceIn(-0.3f, 0.3f) }
            profile = LearnedProfile(clampedTrust, clampedOffset, cur.totalFeedbacks + 1, System.currentTimeMillis())
        }
    }

    fun trustFor(domain: String): Float = profile.domainTrust[domain.lowercase().trim().trimEnd('.')] ?: 0f

    fun offsetFor(category: String): Float = profile.perCategoryOffset[category] ?: 0f

    /**
     * Adjust a DomainIntelligence score by learned offsets.
     * Returns the adjusted score in 0..100. Never flips CLEAN→MALWARE on its own;
     * it nudges borderline cases (40–70) where user history is relevant.
     */
    fun adjustScore(baseScore: Int, domain: String, category: String): Int {
        val trust = trustFor(domain)
        val offset = offsetFor(category)
        // trust is -1..1, offset is -0.3..0.3 → combined -1.3..1.3 → scaled to ±15 points
        val delta = ((trust + offset) * 8f).toInt().coerceIn(-15, 15)
        // Only apply delta in the borderline band — confident scores stay put
        return if (baseScore in 35..75) (baseScore + delta).coerceIn(0, 100) else baseScore
    }

    fun reset() { profile = LearnedProfile() }

    fun export(): LearnedProfile = profile
    fun import(p: LearnedProfile) { profile = p.copy(updatedAtMs = System.currentTimeMillis()) }

    fun toJson(): String {
        val sb = StringBuilder("{\"v\":1,\"fb\":"); sb.append(profile.totalFeedbacks)
        sb.append(",\"ts\":"); sb.append(profile.updatedAtMs)
        sb.append(",\"off\":{")
        profile.perCategoryOffset.entries.forEachIndexed { i, e -> if (i > 0) sb.append(','); sb.append('"').append(e.key).append("\":").append(e.value) }
        sb.append("},\"trust\":{")
        profile.domainTrust.entries.forEachIndexed { i, e -> if (i > 0) sb.append(','); sb.append('"').append(e.key).append("\":").append(e.value) }
        sb.append("}}"); return sb.toString()
    }
    fun fromJson(raw: String): Boolean = runCatching {
        val off = Regex("\"off\":\\{([^}]*)\\}").find(raw)?.groupValues?.get(1) ?: ""
        val trust = Regex("\"trust\":\\{([^}]*)\\}").find(raw)?.groupValues?.get(1) ?: ""
        fun parseMap(s: String): Map<String, Float> = s.split(',').mapNotNull { kv ->
            val p = kv.split(':'); if (p.size != 2) null else p[0].trim().trim('"') to (p[1].trim().toFloatOrNull() ?: return@mapNotNull null)
        }.toMap().filterKeys { it.isNotEmpty() }
        val fb = Regex("\"fb\":(\\d+)").find(raw)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val ts = Regex("\"ts\":(\\d+)").find(raw)?.groupValues?.get(1)?.toLongOrNull() ?: System.currentTimeMillis()
        profile = LearnedProfile(parseMap(off), parseMap(trust), fb, ts)
        true
    }.getOrDefault(false)
}
