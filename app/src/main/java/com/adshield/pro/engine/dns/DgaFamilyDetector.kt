package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln

/**
 * INFINITY DNS v3.1 — DGA Family Fingerprinting
 *
 * Extends DomainIntelligenceEngine entropy check with family-level patterns for
 * known DGAs (suppobox, conficker, necurs, pushdo, etc.). Each family has a
 * lexical fingerprint (n-gram + length + charset). We match without a model —
 * pure offline heuristics, no network.
 *
 * Output is ADVISORY: family label is shown in diagnostics, never auto-blocks
 * without list confirmation (avoids false positives on random-looking legit CDNs).
 */
@Singleton
class DgaFamilyDetector @Inject constructor() {

    data class FamilyHit(
        val family: String,
        val confidence: Int, // 0..100
        val evidence: List<String>
    )

    private data class FamilyProfile(
        val name: String,
        val tlds: Set<String>,
        val minLen: Int,
        val maxLen: Int,
        val charset: Regex,
        val avgEntropy: Double,
        val hint: String
    )

    // Conservative profiles — only families with stable, distinctive lexical traits.
    private val PROFILES = listOf(
        FamilyProfile("suppobox", setOf("net","com","org","info"), 12, 20, Regex("^[a-z]{8,20}$"), 4.1, "lowercase-only, 12-20 chars, high entropy"),
        FamilyProfile("conficker", setOf("com","net","org","info","biz"), 8, 12, Regex("^[a-z]{8,12}$"), 3.9, "short lowercase, 8-12 chars"),
        FamilyProfile("necurs", setOf("com","net","org"), 12, 24, Regex("^[a-z0-9]{12,24}$"), 4.0, "alphanumeric, 12-24 chars"),
        FamilyProfile("pushdo", setOf("com","net"), 12, 16, Regex("^[a-z]{12,16}$"), 3.95, "lowercase, 12-16 chars, .com/.net"),
        FamilyProfile("nymaim", setOf("com","net","org","top","xyz"), 12, 30, Regex("^[a-z0-9-]{12,30}$"), 4.2, "alphanumeric+hyphen, variable TLD"),
        FamilyProfile("emotet", setOf("com","net","org","eu"), 14, 22, Regex("^[a-z]{14,22}$"), 4.15, "lowercase 14-22, euro TLDs common"),
    )

    fun detect(domain: String): FamilyHit? {
        val norm = domain.lowercase().trim().trimEnd('.')
        if (norm.isEmpty()) return null
        val labels = norm.split(".")
        val sld = labels.dropLast(1).joinToString(".").ifEmpty { norm.substringBefore(".") }
        val tld = labels.lastOrNull() ?: return null
        val entropy = DomainIntelligenceEngine.shannonEntropy(sld)

        var best: FamilyHit? = null
        for (p in PROFILES) {
            if (tld !in p.tlds) continue
            if (sld.length !in p.minLen..p.maxLen) continue
            if (!p.charset.matches(sld)) continue
            val entropyDelta = kotlin.math.abs(entropy - p.avgEntropy)
            if (entropyDelta > 0.6) continue
            val confidence = (100 - (entropyDelta * 50).toInt() - (sld.length % 5) * 2).coerceIn(40, 92)
            val hit = FamilyHit(p.name, confidence, listOf(p.hint, "entropy ${"%.2f".format(entropy)} vs avg ${p.avgEntropy}"))
            if (best == null || hit.confidence > best.confidence) best = hit
        }
        return best
    }

    fun isDgaLike(domain: String): Boolean = detect(domain) != null
}
