package com.adshield.pro.engine.aether

/**
 * OmniShield X — Advanced Threat Scoring Model (v4.7.0).
 *
 * A deterministic, fully-auditable multi-signal scoring model (no cloud, no
 * black box): every weight is a documented constant, every input is derived
 * from inspectable features of the domain itself.
 *
 *   score = W_DGA·dgaScore + W_LOOKALIKE·lookalike + W_NEWDOMAIN·newDomain   (0..100)
 *
 * Verdict bands: >=60 BLOCKABLE_IN_STRICT (never blocks in Balanced),
 * 30..59 OBSERVE, <30 ALLOW+observe. Blocking policy stays in the shields —
 * the model only ranks evidence.
 */
object ThreatScoringModel {

    // Documented weights (sum = 100). Changing them is a semantic release event.
    const val W_DGA = 40
    const val W_LOOKALIKE = 35
    const val W_NEW_DOMAIN = 25

    const val BLOCK_THRESHOLD = 60
    const val OBSERVE_THRESHOLD = 30

    enum class Action { ALLOW_OBSERVE, OBSERVE, BLOCKABLE_IN_STRICT }

    data class Result(
        val score: Int,
        val action: Action,
        val dgaComponent: Int,
        val lookalikeComponent: Int,
        val newDomainComponent: Int
    )

    /** Frequent English-language bigrams (top ~50) — the baseline of normal domains. */
    private val COMMON_BIGRAMS: Set<String> = setOf(
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or",
        "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha",
        "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne",
        "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur"
    )

    /**
     * Fraction of the label's bigrams that are RARE in normal language (0..1).
     * DGA strings ("xkqjvbmzpq") score near 1; real words near 0.
     */
    fun bigramRarity(label: String): Double {
        val l = label.lowercase()
        if (l.length < 4) return 0.0 // too short to judge — never punish short names
        var total = 0
        var rare = 0
        for (i in 0 until l.length - 1) {
            val bg = l.substring(i, i + 2)
            total++
            if (bg !in COMMON_BIGRAMS) rare++
        }
        return if (total == 0) 0.0 else rare.toDouble() / total
    }

    /**
     * DGA likelihood 0..1: half normalized Shannon entropy, half bigram rarity.
     * Labels shorter than 8 characters cannot score high (protects real short domains).
     */
    fun dgaScore(domain: String): Double {
        val label = StrictHeuristicsShield.baseLabelOf(domain)
        if (label.length < 8) return 0.0
        val entropy = com.adshield.pro.engine.aether.DnsAnomalyAnalyzer.labelEntropy(label)
        val entropyNorm = ((entropy - 2.5) / 2.5).coerceIn(0.0, 1.0)
        val rarity = bigramRarity(label)
        return (0.5 * entropyNorm + 0.5 * rarity).coerceIn(0.0, 1.0)
    }

    /** New-domain age component: <=30d full weight, <=90d partial, older/unknown zero. */
    fun newDomainComponent(ageDays: Int?): Int = when {
        ageDays == null -> 0
        ageDays <= 30 -> W_NEW_DOMAIN
        ageDays <= 90 -> W_NEW_DOMAIN / 2
        else -> 0
    }

    /**
     * Fusion. [dgaActive] gates the DGA component (Balanced observe still scores it),
     * [lookalikeBrand] is the detector output (null = none), [ageDays] the RDAP result.
     */
    fun score(
        domain: String,
        dgaActive: Boolean,
        lookalikeBrand: String?,
        ageDays: Int?
    ): Result {
        val dga = if (dgaActive) (W_DGA * dgaScore(domain)).toInt() else 0
        val look = if (lookalikeBrand != null) W_LOOKALIKE else 0
        val fresh = newDomainComponent(ageDays)
        val total = (dga + look + fresh).coerceAtMost(100)
        val action = when {
            total >= BLOCK_THRESHOLD -> Action.BLOCKABLE_IN_STRICT
            total >= OBSERVE_THRESHOLD -> Action.OBSERVE
            else -> Action.ALLOW_OBSERVE
        }
        return Result(total, action, dga, look, fresh)
    }
}
