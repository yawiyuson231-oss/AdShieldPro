package com.adshield.pro.engine.aether

/**
 * OmniShield X — Strict-mode Heuristic Shield (platform spec: "Strict adds new domains,
 * random-looking names, and lookalikes").
 *
 * Honest semantics:
 * - In BALANCED mode these signals are OBSERVE-ONLY (flagged in logs, never blocked).
 * - In STRICT mode they can BLOCK, gated behind a user toggle, with conservative
 *   thresholds; every block is one-tap reversible via the existing false-positive
 *   report ("@@||domain^") and never fires for user's own custom allow rules.
 * - A DGA/random-looking signal comes from DnsAnomalyAnalyzer (entropy), lookalikes
 *   from the homoglyph+distance checks here, and new-domain age from NewDomainAgeChecker.
 */
object StrictHeuristicsShield {

    const val SOURCE_NAME = "Heuristic Shield (Strict)"

    /** Cyrillic/Greek look-alike Latin substitutions (homoglyph folding). */
    private val HOMOGLYPHS: Map<Char, Char> = mapOf(
        'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y',
        'х' to 'x', 'і' to 'i', 'ѕ' to 's', 'ј' to 'j', 'ԛ' to 'q', 'ԝ' to 'w',
        'о' to 'o', 'ь' to 'b', 'т' to 't', 'к' to 'k', 'м' to 'm', 'н' to 'h',
        'ο' to 'o', 'α' to 'a', 'е' to 'e', 'ρ' to 'p', 'ν' to 'v', 'χ' to 'x',
        'ɩ' to 'l', 'ⅼ' to 'l', '０' to '0', '１' to '1', '３' to '3', '５' to '5'
    )

    /** Well-known protected brands for lookalike detection (kept small & high-precision). */
    val PROTECTED_BRANDS: Set<String> = setOf(
        "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
        "amazon", "apple", "icloud", "microsoft", "outlook", "office365",
        "paypal", "netflix", "tiktok", "linkedin", "twitter", "bankofamerica",
        "chase", "wellsfargo", "hsbc", "bpi", "bdo", "gcash", "maya"
    )

    fun homoglyphFold(label: String): String = buildString(label.length) {
        for (ch in label) append(HOMOGLYPHS[ch] ?: ch)
    }

    /** The base label (second-level part) of a domain, homoglyph-folded. */
    fun baseLabelOf(domain: String): String {
        val d = homoglyphFold(domain.lowercase().trimEnd('.'))
        val parts = d.split('.')
        return when {
            parts.size >= 3 && parts[parts.size - 2].length <= 3 -> parts[parts.size - 3]
            parts.size >= 2 -> parts[parts.size - 2]
            else -> parts.first()
        }
    }

    /**
     * Lookalike detection: fold homoglyphs, then Damerau-Levenshtein distance of the
     * base label against protected brands. Distance 1 (or 2 for long labels) that is
     * NOT the real brand and NOT a legit subdomain = candidate impostor.
     */
    fun lookalikeBrandHit(domain: String): String? {
        val d = domain.lowercase().trimEnd('.')
        val parts = d.split('.')
        if (parts.size < 2) return null
        val rawLeftmost = parts.first()
        val leftmost = homoglyphFold(rawLeftmost)
        if (leftmost.isEmpty()) return null
        // Mixed-script impostor ("gооgle.com"): folding lands exactly on a brand the
        // real brand never needs — always an impostor.
        if (leftmost != rawLeftmost && leftmost in PROTECTED_BRANDS) return leftmost
        // If the brand appears as its own label elsewhere ("*.google.com"), the domain
        // is brand-owned; never flag it.
        if (parts.drop(1).any { homoglyphFold(it) in PROTECTED_BRANDS }) return null
        val suspicious = setOf(
            "secure", "login", "log-in", "signin", "sign-in", "verify", "verification",
            "account", "accounts", "billing", "update", "support", "wallet", "refund"
        )
        for (brand in PROTECTED_BRANDS) {
            if (leftmost == brand) return null // the real brand apex/subdomain label
            val maxDistance = if (brand.length >= 8) 2 else 1
            if (damerauLevenshtein(leftmost, brand) in 1..maxDistance) return brand
            // Adjacent-key typo: "goohle.com" (h sits next to g on qwerty)
            if (keyboardTypoMatch(leftmost, brand)) return brand
            // Compound token trick: "google-secure-login.com", "netflix-billing.top"
            val tokens = leftmost.split('-', '_', '.').filter { it.isNotBlank() }
            if (brand in tokens && tokens.any { it in suspicious }) return brand
        }
        return null
    }

    /** QWERTY neighbors for adjacent-key typo detection ("goohle" → google). */
    val QWERTY_NEIGHBORS: Map<Char, Set<Char>> = mapOf(
        'q' to setOf('w', 'a'), 'w' to setOf('q', 'e', 's', 'a'), 'e' to setOf('w', 'r', 's', 'd'),
        'r' to setOf('e', 't', 'd', 'f'), 't' to setOf('r', 'y', 'f', 'g'), 'y' to setOf('t', 'u', 'g', 'h'),
        'u' to setOf('y', 'i', 'h', 'j'), 'i' to setOf('u', 'o', 'j', 'k'), 'o' to setOf('i', 'p', 'k', 'l'),
        'p' to setOf('o', 'l'), 'a' to setOf('q', 's', 'z', 'w'), 's' to setOf('a', 'd', 'z', 'x', 'w', 'e'),
        'd' to setOf('s', 'f', 'x', 'c', 'e', 'r'), 'f' to setOf('d', 'g', 'c', 'v', 'r', 't'),
        'g' to setOf('f', 'h', 'v', 'b', 't', 'y'), 'h' to setOf('g', 'j', 'b', 'n', 'y', 'u'),
        'j' to setOf('h', 'k', 'n', 'm', 'u', 'i'), 'k' to setOf('j', 'l', 'm', 'o', 'i'),
        'l' to setOf('k', 'p', 'o'), 'z' to setOf('a', 'x', 's'), 'x' to setOf('z', 'c', 's', 'd'),
        'c' to setOf('x', 'v', 'd', 'f'), 'v' to setOf('c', 'b', 'f', 'g'), 'b' to setOf('v', 'n', 'g', 'h'),
        'n' to setOf('b', 'm', 'h', 'j'), 'm' to setOf('n', 'k', 'l', 'j')
    )

    /** Same length, exactly one substitution, and the swapped keys are qwerty-adjacent. */
    fun keyboardTypoMatch(label: String, brand: String): Boolean {
        if (label.length != brand.length) return false
        var diffIdx = -1
        var diffs = 0
        for (i in label.indices) {
            if (label[i] != brand[i]) {
                diffs++
                diffIdx = i
                if (diffs > 1) return false
            }
        }
        if (diffs != 1) return false
        return QWERTY_NEIGHBORS[brand[diffIdx]]?.contains(label[diffIdx]) == true
    }

    fun damerauLevenshtein(a: String, b: String): Int {
        val n = a.length
        val m = b.length
        if (n == 0) return m
        if (m == 0) return n
        val d = Array(n + 1) { IntArray(m + 1) }
        for (i in 0..n) d[i][0] = i
        for (j in 0..m) d[0][j] = j
        for (i in 1..n) {
            for (j in 1..m) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
                    d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1)
                }
            }
        }
        return d[n][m]
    }

    data class Verdict(
        val block: Boolean,
        val signal: String?,
        val detail: String?
    )

    /**
     * Combines the three spec signals. Blocking ONLY in strict mode; otherwise observe.
     */
    fun evaluate(
        domain: String,
        strictMode: Boolean,
        dgaLike: Boolean,
        lookalikeBrand: String?,
        newDomainAgeDays: Int?,
        checkNewDomains: Boolean
    ): Verdict {
        val look = lookalikeBrand ?: lookalikeBrandHit(domain)
        val ageDays = if (checkNewDomains) newDomainAgeDays else null
        val result = ThreatScoringModel.score(domain, dgaLike, look, ageDays)

        val signals = ArrayList<String>()
        if (result.dgaComponent > 0) signals.add("random-looking name (high entropy)")
        if (look != null) signals.add("lookalike of '$look'")
        if (ageDays != null && newDomainAgeDays != null && newDomainAgeDays <= 30) {
            signals.add("registered $newDomainAgeDays days ago (≤30)")
        }
        if (signals.isEmpty()) return Verdict(block = false, signal = null, detail = null)
        val detail = signals.joinToString("; ") +
            " — risk ${result.score}/${ThreatScoringModel.BLOCK_THRESHOLD}"
        // Model-gated: Strict-only blocking, and only when fused score clears the bar
        val block = strictMode && result.action == ThreatScoringModel.Action.BLOCKABLE_IN_STRICT
        return Verdict(block = block, signal = signals.first(), detail = detail)
    }
}
