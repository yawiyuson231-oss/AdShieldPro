package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.RuleCategory
import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — Domain Intelligence Engine
 *
 * Provides multi-signal domain classification, reputation scoring, and
 * suspicious pattern detection. All offline, no network required.
 *
 * Signals:
 * 1. Lexical analysis (entropy, hyphen count, length, TLD risk)
 * 2. Subdomain depth & structure
 * 3. Known infrastructure mapping (ad/tracker/malware infrastructure)
 * 4. Domain generation algorithm (DGA) likelihood
 * 5. Typosquatting / homograph detection
 * 6. Reputation scoring (0-100)
 * 7. Relationship mapping (first/third party, CDN, tracker)
 */
@Singleton
class DomainIntelligenceEngine @Inject constructor() {

    enum class DomainClass {
        CLEAN,
        ADVERTISING,
        TRACKING,
        ANALYTICS,
        TELEMETRY,
        MALWARE,
        PHISHING,
        SUSPICIOUS,
        CDN,
        UNKNOWN
    }

    enum class RiskLevel(val label: String, val color: Long) {
        SAFE("Safe", 0xFF10B981),
        LOW("Low", 0xFF84CC16),
        MEDIUM("Medium", 0xFFF59E0B),
        HIGH("High", 0xFFEF4444),
        CRITICAL("Critical", 0xFFDC2626)
    }

    data class DomainFeatures(
        val domain: String,
        val length: Int,
        val labelCount: Int,
        val maxLabelLength: Int,
        val hyphenCount: Int,
        val digitCount: Int,
        val entropy: Double,
        val tld: String,
        val tldRisk: Int,
        val subdomainDepth: Int,
        val hasConsecutiveHyphens: Boolean,
        val hasConsecutiveDots: Boolean,
        val isPunycode: Boolean,
        val hasHexPattern: Boolean,
        val hasBase64Pattern: Boolean
    )

    data class IntelligenceResult(
        val domain: String,
        val classification: DomainClass,
        val riskLevel: RiskLevel,
        val riskScore: Int, // 0-100
        val confidence: Int, // 0-100
        val features: DomainFeatures,
        val signals: List<Signal>,
        val recommendation: String,
        val isDgaLikely: Boolean,
        val isTyposquatRisk: Boolean,
        val relatedInfrastructure: String?
    )

    data class Signal(
        val code: String,
        val description: String,
        val weight: Int, // positive = suspicious, negative = benign
        val category: String
    )

    // Known infrastructure registries (offline, curated)
    companion object {
        // High-risk TLDs disproportionately used for abuse
        val HIGH_RISK_TLDS = setOf(
            "tk", "ml", "ga", "cf", "gq", "top", "click", "link", "work",
            "date", "stream", "download", "racing", "cricket", "win", "xyz",
            "buzz", "country", "kim", "rest", "party", "review", "science",
            "zip", "mov", "quest", "lol", "mom", "sbs", "icu", "cyou",
            "cam", "bar", "gdn", "loan", "bid", "trade", "webcam"
        )

        val SUSPICIOUS_TLDS = setOf(
            "info", "biz", "cc", "ws", "pw", "su", "cn", "ru", "br",
            "in", "pk", "ng", "ke", "ph"
        )

        // Ad network infrastructure patterns
        val AD_INFRA_PATTERNS = mapOf(
            "doubleclick" to "Google Ads",
            "googlesyndication" to "Google Ads",
            "googleadservices" to "Google Ads",
            "googletagmanager" to "Google Tags",
            "googletagservices" to "Google Tags",
            "adservice" to "Ad Serving",
            "pubmatic" to "PubMatic",
            "rubiconproject" to "Magnite",
            "openx" to "OpenX",
            "criteo" to "Criteo",
            "taboola" to "Taboola",
            "outbrain" to "Outbrain",
            "adnxs" to "AppNexus/Xandr",
            "scorecardresearch" to "Market Research",
            "quantserve" to "Quantcast",
            "moatads" to "Oracle Moat",
            "adsrvr" to "The Trade Desk",
            "demdex" to "Adobe Audience",
            "everesttech" to "Adobe Target"
        )

        val TRACKER_PATTERNS = mapOf(
            "google-analytics" to "Google Analytics",
            "hotjar" to "Hotjar",
            "mixpanel" to "Mixpanel",
            "segment" to "Segment",
            "amplitude" to "Amplitude",
            "sentry" to "Sentry",
            "bugsnag" to "BugSnag",
            "facebook.net" to "Meta Pixel",
            "connect.facebook" to "Meta Connect",
            "analytics.tiktok" to "TikTok Analytics",
            "clarity.ms" to "Microsoft Clarity",
            "stats.g.doubleclick" to "Google Stats"
        )

        // Legitimate high-value targets for typosquatting
        val PROTECTED_BRANDS = mapOf(
            "google" to listOf("google.com", "googleapis.com", "gstatic.com", "googlevideo.com"),
            "facebook" to listOf("facebook.com", "fbcdn.net", "facebook.net"),
            "apple" to listOf("apple.com", "icloud.com"),
            "microsoft" to listOf("microsoft.com", "live.com", "office.com", "outlook.com"),
            "amazon" to listOf("amazon.com", "amazonaws.com"),
            "netflix" to listOf("netflix.com", "nflxvideo.net"),
            "paypal" to listOf("paypal.com"),
            "bank" to listOf("bdo.com.ph", "bpi.com.ph", "metrobank.com.ph", "gcash.com"),
            "youtube" to listOf("youtube.com", "youtu.be", "googlevideo.com"),
            "tiktok" to listOf("tiktok.com", "tiktokcdn.com", "musical.ly")
        )

        // DGA heuristics thresholds
        const val DGA_ENTROPY_THRESHOLD = 3.8
        const val DGA_MIN_LENGTH = 12
        const val SUSPICIOUS_ENTROPY_THRESHOLD = 3.5

        fun shannonEntropy(input: String): Double {
            if (input.isEmpty()) return 0.0
            val freq = input.groupingBy { it }.eachCount()
            val len = input.length.toDouble()
            return -freq.values.sumOf { count ->
                val p = count / len
                p * (Math.log(p) / Math.log(2.0))
            }
        }

        fun levenshteinDistance(a: String, b: String): Int {
            val m = a.length; val n = b.length
            if (m == 0) return n; if (n == 0) return m
            var prev = IntArray(n + 1) { it }
            var curr = IntArray(n + 1)
            for (i in 1..m) {
                curr[0] = i
                for (j in 1..n) {
                    val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                    curr[j] = minOf(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
                }
                val tmp = prev; prev = curr; curr = tmp
            }
            return prev[n]
        }
    }

    fun analyze(domain: String): IntelligenceResult {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isEmpty() || normalized.length > 253) {
            return IntelligenceResult(
                domain = domain, classification = DomainClass.UNKNOWN,
                riskLevel = RiskLevel.MEDIUM, riskScore = 50, confidence = 10,
                features = emptyFeatures(normalized), signals = emptyList(),
                recommendation = "Invalid domain — cannot classify",
                isDgaLikely = false, isTyposquatRisk = false, relatedInfrastructure = null
            )
        }

        val features = extractFeatures(normalized)
        val signals = mutableListOf<Signal>()
        var riskScore = 0
        var classification = DomainClass.CLEAN
        var infrastructure: String? = null

        // 1. Infrastructure mapping
        val infraResult = classifyInfrastructure(normalized)
        if (infraResult != null) {
            classification = infraResult.first
            infrastructure = infraResult.second
            signals.add(Signal("infra:${normalized}", "Known ${infraResult.second} infrastructure", 30, "infrastructure"))
            riskScore += when (classification) {
                DomainClass.ADVERTISING -> 35
                DomainClass.TRACKING -> 30
                DomainClass.ANALYTICS -> 20
                DomainClass.TELEMETRY -> 25
                else -> 15
            }
        }

        // 2. TLD risk
        if (features.tld in HIGH_RISK_TLDS) {
            signals.add(Signal("high-risk-tld", "High-risk TLD .${features.tld} — disproportionately abused", 20, "tld"))
            riskScore += 20
        } else if (features.tld in SUSPICIOUS_TLDS) {
            signals.add(Signal("suspicious-tld", "TLD .${features.tld} has elevated abuse rates", 8, "tld"))
            riskScore += 8
        }

        // 3. Length anomalies
        if (features.length > 60) {
            signals.add(Signal("very-long-domain", "Very long domain (${features.length} chars)", 10, "lexical"))
            riskScore += 10
        } else if (features.length > 40) {
            signals.add(Signal("long-domain", "Long domain (${features.length} chars)", 5, "lexical"))
            riskScore += 5
        }

        // 4. Label count / subdomain depth
        if (features.labelCount >= 5) {
            signals.add(Signal("deep-subdomain", "Deep subdomain chain (${features.labelCount} labels)", 12, "structure"))
            riskScore += 12
        } else if (features.labelCount >= 4) {
            signals.add(Signal("moderate-subdomain", "Multiple subdomains (${features.labelCount} labels)", 5, "structure"))
            riskScore += 5
        }

        // 5. Entropy (DGA indicator)
        if (features.entropy >= DGA_ENTROPY_THRESHOLD && features.length >= DGA_MIN_LENGTH) {
            signals.add(Signal("high-entropy", "High entropy (${String.format("%.2f", features.entropy)}) — possible DGA", 25, "dga"))
            riskScore += 25
        } else if (features.entropy >= SUSPICIOUS_ENTROPY_THRESHOLD) {
            signals.add(Signal("elevated-entropy", "Elevated entropy (${String.format("%.2f", features.entropy)})", 8, "lexical"))
            riskScore += 8
        }

        // 6. Hyphen abuse
        if (features.hyphenCount >= 4) {
            signals.add(Signal("many-hyphens", "Many hyphens (${features.hyphenCount}) — lookalike pattern", 12, "lexical"))
            riskScore += 12
        } else if (features.hyphenCount >= 3) {
            signals.add(Signal("several-hyphens", "Several hyphens (${features.hyphenCount})", 6, "lexical"))
            riskScore += 6
        }

        // 7. Consecutive special chars
        if (features.hasConsecutiveHyphens) {
            signals.add(Signal("consecutive-hyphens", "Consecutive hyphens — suspicious pattern", 8, "lexical"))
            riskScore += 8
        }

        // 8. Punycode / IDN homograph risk
        if (features.isPunycode) {
            signals.add(Signal("punycode", "Punycode (xn--) — possible homograph attack", 22, "homograph"))
            riskScore += 22
        }

        // 9. Digit-heavy domains
        val digitRatio = if (features.length > 0) features.digitCount.toDouble() / features.length else 0.0
        if (digitRatio > 0.4 && features.length > 15) {
            signals.add(Signal("digit-heavy", "Digit-heavy domain (${(digitRatio * 100).toInt()}% digits)", 10, "lexical"))
            riskScore += 10
        }

        // 10. Hex / Base64 patterns (common in tracking subdomains)
        if (features.hasHexPattern && features.labelCount >= 3) {
            signals.add(Signal("hex-subdomain", "Hex-like subdomain — possible tracking ID", 10, "tracking"))
            riskScore += 10
        }

        // 11. Max label length
        if (features.maxLabelLength > 30) {
            signals.add(Signal("long-label", "Very long label (${features.maxLabelLength} chars) — possible encoded payload", 12, "lexical"))
            riskScore += 12
        }

        // Determine DGA likelihood
        val isDga = features.entropy >= DGA_ENTROPY_THRESHOLD &&
            features.length >= DGA_MIN_LENGTH &&
            features.hyphenCount == 0 &&
            digitRatio > 0.15

        // Determine typosquat risk
        val typosquat = detectTyposquat(normalized)
        if (typosquat != null) {
            signals.add(Signal("typosquat:$typosquat", "Possible typosquat of $typosquat", 30, "typosquat"))
            riskScore += 30
            if (classification == DomainClass.CLEAN) classification = DomainClass.SUSPICIOUS
        }

        riskScore = riskScore.coerceIn(0, 100)
        // Downgrade risk for known infrastructure already classified — it's blocked anyway
        if (classification in setOf(DomainClass.ADVERTISING, DomainClass.TRACKING)) {
            // Keep score but ensure at least MEDIUM for known bad
            riskScore = riskScore.coerceAtLeast(40)
        }

        val riskLevel = when {
            riskScore >= 75 -> RiskLevel.CRITICAL
            riskScore >= 50 -> RiskLevel.HIGH
            riskScore >= 30 -> RiskLevel.MEDIUM
            riskScore >= 10 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }

        // If no signals and no infrastructure match, it's clean
        if (signals.isEmpty() && infrastructure == null) {
            classification = DomainClass.CLEAN
        } else if (riskScore >= 60 && classification == DomainClass.CLEAN) {
            classification = DomainClass.SUSPICIOUS
        }

        val confidence = computeConfidence(signals, riskScore)
        val recommendation = buildRecommendation(classification, riskLevel, signals, isDga, typosquat)

        return IntelligenceResult(
            domain = normalized,
            classification = classification,
            riskLevel = riskLevel,
            riskScore = riskScore,
            confidence = confidence,
            features = features,
            signals = signals,
            recommendation = recommendation,
            isDgaLikely = isDga,
            isTyposquatRisk = typosquat != null,
            relatedInfrastructure = infrastructure
        )
    }

    fun extractFeatures(domain: String): DomainFeatures {
        val labels = domain.split('.').filter { it.isNotEmpty() }
        val tld = labels.lastOrNull() ?: ""
        val sld = if (labels.size >= 2) labels[labels.size - 2] else domain
        return DomainFeatures(
            domain = domain,
            length = domain.length,
            labelCount = labels.size,
            maxLabelLength = labels.maxOfOrNull { it.length } ?: 0,
            hyphenCount = domain.count { it == '-' },
            digitCount = domain.count { it.isDigit() },
            entropy = shannonEntropy(sld),
            tld = tld,
            tldRisk = when (tld) {
                in HIGH_RISK_TLDS -> 3
                in SUSPICIOUS_TLDS -> 2
                else -> 1
            },
            subdomainDepth = (labels.size - 2).coerceAtLeast(0),
            hasConsecutiveHyphens = domain.contains("--"),
            hasConsecutiveDots = domain.contains(".."),
            isPunycode = labels.any { it.startsWith("xn--") },
            hasHexPattern = labels.any { it.length >= 8 && it.all { c -> c.isDigit() || c in 'a'..'f' } },
            hasBase64Pattern = labels.any { it.length >= 12 && it.matches(Regex("^[A-Za-z0-9+/=]{12,}$")) }
        )
    }

    private fun classifyInfrastructure(domain: String): Pair<DomainClass, String>? {
        // Check ad patterns
        for ((pattern, name) in AD_INFRA_PATTERNS) {
            if (domain == pattern || domain.endsWith(".$pattern") || domain.contains(pattern)) {
                return DomainClass.ADVERTISING to name
            }
        }
        for ((pattern, name) in TRACKER_PATTERNS) {
            if (domain == pattern || domain.endsWith(".$pattern") || domain.contains(pattern)) {
                return when {
                    pattern.contains("analytics") || name.contains("Analytics") -> DomainClass.ANALYTICS to name
                    else -> DomainClass.TRACKING to name
                }
            }
        }
        return null
    }

    private fun detectTyposquat(domain: String): String? {
        val registrable = domain.split('.').takeLast(2).joinToString(".")
        val sld = registrable.substringBefore('.')
        if (sld.length < 4) return null

        for ((brand, legitDomains) in PROTECTED_BRANDS) {
            // Skip if it's actually the legitimate domain
            if (legitDomains.any { domain == it || domain.endsWith(".$it") }) continue

            // Check edit distance against brand name
            val distance = levenshteinDistance(sld, brand)
            if (sld.length >= brand.length - 1 && sld.length <= brand.length + 2) {
                if (distance in 1..2) return brand
                // Check for added/removed char patterns
                if (sld.contains(brand) && sld.length == brand.length + 1) return brand
                if (brand.contains(sld) && brand.length == sld.length + 1) return brand
            }
            // Homoglyph-adjacent: replace common confusables
            val normalized = sld
                .replace('0', 'o').replace('1', 'l').replace('3', 'e')
                .replace('5', 's').replace('8', 'b').replace('@', 'a')
            if (normalized == brand) return brand
            if (levenshteinDistance(normalized, brand) <= 1 && normalized.length >= 4) return brand
        }
        return null
    }

    private fun computeConfidence(signals: List<Signal>, riskScore: Int): Int {
        if (signals.isEmpty()) return if (riskScore == 0) 85 else 20
        val signalStrength = signals.sumOf { it.weight }
        val signalCount = signals.size
        return ((signalStrength * 0.6) + (signalCount * 5) + (riskScore * 0.3))
            .toInt().coerceIn(10, 95)
    }

    private fun buildRecommendation(
        classification: DomainClass,
        riskLevel: RiskLevel,
        signals: List<Signal>,
        isDga: Boolean,
        typosquat: String?
    ): String {
        if (typosquat != null) return "Possible typosquat of $typosquat — verify URL before interacting"
        if (isDga) return "High-entropy domain with DGA characteristics — treat as suspicious"
        return when (classification) {
            DomainClass.ADVERTISING -> "Known advertising infrastructure — safe to block"
            DomainClass.TRACKING -> "Known tracking infrastructure — safe to block"
            DomainClass.ANALYTICS -> "Analytics/tracking — blocking may affect site metrics only"
            DomainClass.MALWARE -> "Known malicious infrastructure — block immediately"
            DomainClass.PHISHING -> "Suspected phishing — block and warn user"
            DomainClass.SUSPICIOUS -> when (riskLevel) {
                RiskLevel.CRITICAL, RiskLevel.HIGH -> "High-risk suspicious domain — recommend blocking"
                RiskLevel.MEDIUM -> "Moderately suspicious — monitor or review"
                else -> "Low-risk anomaly — allow but log"
            }
            DomainClass.CDN -> "Content delivery network — do not block"
            DomainClass.CLEAN -> "No threat indicators — allow"
            DomainClass.UNKNOWN -> "Insufficient data — allow with monitoring"
            DomainClass.TELEMETRY -> "Telemetry endpoint — safe to block in strict mode"
        }
    }

    private fun emptyFeatures(domain: String) = DomainFeatures(
        domain = domain, length = 0, labelCount = 0, maxLabelLength = 0,
        hyphenCount = 0, digitCount = 0, entropy = 0.0, tld = "",
        tldRisk = 0, subdomainDepth = 0, hasConsecutiveHyphens = false,
        hasConsecutiveDots = false, isPunycode = false, hasHexPattern = false,
        hasBase64Pattern = false
    )

    fun shouldBlock(result: IntelligenceResult, strictMode: Boolean = false): Boolean {
        return when (result.classification) {
            DomainClass.ADVERTISING, DomainClass.TRACKING -> true
            DomainClass.MALWARE, DomainClass.PHISHING -> true
            DomainClass.SUSPICIOUS -> result.riskScore >= 60
            DomainClass.TELEMETRY -> strictMode
            DomainClass.ANALYTICS -> strictMode || result.riskScore >= 50
            else -> false
        }
    }
}
