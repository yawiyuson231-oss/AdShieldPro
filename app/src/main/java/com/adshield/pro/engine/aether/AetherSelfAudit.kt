package com.adshield.pro.engine.aether

/**
 * OmniShield X — AETHER Agent Upgrade (v4.6.0): Self-Audit + Explanation engines.
 *
 * World-class agent behavior, honestly implemented:
 *  1. FALSE-POSITIVE RADAR — AETHER audits ITS OWN blocking decisions from real
 *     query logs: any domain blocked repeatedly whose block came from a heuristic
 *     shield, or that belongs to a protected/authentications-critical domain,
 *     is surfaced for human one-tap review. Detection only — it NEVER auto-unblocks.
 *  2. EXPLAINER — plain-language, data-derived reasons for every verdict.
 *     It only states facts that are present in the evaluation (domain, category,
 *     source list, matched rule) and never invents threat claims.
 */
object AetherSelfAudit {

    /** Domains whose breakage is known to hurt users (auth/identity/payment rails). */
    val PROTECTED_CATALOG: Set<String> = setOf(
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "accounts.google.com", "login.microsoftonline.com", "live.com", "outlook.com",
        "office.com", "appleid.apple.com", "icloud.com", "okta.com", "auth0.com",
        "onelogin.com", "paypal.com", "visa.com", "mastercard.com",
        "youtube.com", "netflix.com", "whatsapp.com", "telegram.org", "signal.org",
        "gcash.com", "maya.ph", "bdo.com.ph", "bpi.com.ph"
    )

    /** Source-list names that come from heuristic (non-feed) shields — FP-prone by design. */
    private val HEURISTIC_SOURCES = listOf("heuristic shield", "strict heuristic", "encrypted-dns bypass shield")

    /** Registrable base of a domain (last two labels, PH-style TLDs kept 3-wide). */
    fun registrableBase(domain: String): String {
        val parts = domain.lowercase().trimEnd('.').split('.')
        if (parts.size <= 2) return parts.joinToString(".")
        val secondLevel = parts[parts.size - 2]
        val tld = parts.last()
        return if (tld == "ph" && secondLevel in setOf("com", "org", "gov", "net")) {
            parts.takeLast(3).joinToString(".")
        } else {
            parts.takeLast(2).joinToString(".")
        }
    }

    /**
     * Radar: from real blocked events [(domain, sourceList)], return domains that
     * were blocked >=3 times AND (came from a heuristic shield OR live inside the
     * protected catalog). Sorted by block count desc, max 5. Pure function.
     */
    fun possibleFalsePositives(blockedEvents: List<Pair<String, String>>): List<String> {
        val counts = HashMap<String, Int>()
        val sources = HashMap<String, String>()
        for ((domain, source) in blockedEvents) {
            if (domain.isBlank()) continue
            counts[domain] = (counts[domain] ?: 0) + 1
            sources[domain] = source
        }
        return counts.entries
            .filter { (domain, count) ->
                count >= 3 && run {
                    val src = sources[domain]?.lowercase().orEmpty()
                    val heuristic = HEURISTIC_SOURCES.any { src.contains(it) }
                    val protected_ = PROTECTED_CATALOG.any { catalogDomain ->
                        domain == catalogDomain || domain.endsWith(".$catalogDomain")
                    }
                    heuristic || protected_
                }
            }
            .sortedByDescending { it.value }
            .take(5)
            .map { "${it.key} (${it.value}×)" }
    }
}

/** Plain-language verdict explanations — only facts from the evaluation itself. */
object AetherExplainer {

    fun explain(
        domain: String,
        isBlocked: Boolean,
        category: String?,
        sourceList: String?,
        matchedRule: String?
    ): String {
        if (!isBlocked) {
            return "Allowed $domain — no protection rule matched it."
        }
        val sb = StringBuilder("Blocked $domain")
        if (!category.isNullOrBlank()) sb.append(" — type: $category")
        if (!sourceList.isNullOrBlank()) sb.append(", detected by $sourceList")
        if (!matchedRule.isNullOrBlank()) sb.append(" (rule: $matchedRule)")
        sb.append(". If this looks wrong, tap Allow on the Live tab and it is un-blocked instantly.")
        return sb.toString()
    }
}
