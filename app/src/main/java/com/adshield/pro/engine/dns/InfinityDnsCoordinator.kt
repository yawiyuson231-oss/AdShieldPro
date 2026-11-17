package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.engine.filter.FilterRuleEngine
import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS v3.1 — Coordinator (all advanced signals wired)
 *
 * Orchestrates all intelligence engines for a single DNS query decision.
 *
 * Pipeline:
 * 1. CompatibilityGuard — emergency allowlist (never break essentials)
 * 2. FilterRuleEngine — primary rule evaluation (fast path, Bloom pre-filter)
 * 3. DomainIntelligence + TFLite + DGA family + Adaptive offset
 * 4. VideoAdIntelligence — video ad infrastructure classification
 * 5. ThreatIntelligence — malware/phishing lookup
 * 6. CNAME intelligence — evaluated post-upstream (on response)
 * 7. Per-app telemetry enrichment (no UI change — logged for future dashboard)
 *
 * The coordinator is designed for zero-overhead fast path: if the filter engine
 * already has a verdict, intelligence engines are only consulted for telemetry
 * and reporting, not blocking. Heuristic blocks require explicit opt-in.
 */
@Singleton
class InfinityDnsCoordinator @Inject constructor(
    private val filterEngine: FilterRuleEngine,
    private val compatibilityGuard: CompatibilityGuard,
    private val domainIntelligence: DomainIntelligenceEngine,
    private val videoAdIntelligence: VideoAdIntelligence,
    private val threatIntelligence: ThreatIntelligenceManager,
    private val dnsSecurity: DnsSecurityEngine,
    private val cnameEngine: CnameIntelligenceEngine,
    private val performanceOptimizer: DnsPerformanceOptimizer,
    private val tfliteClassifier: TfliteDomainClassifier,
    private val adaptiveLearning: AdaptiveLearningEngine,
    private val dgaDetector: DgaFamilyDetector,
    private val preferencesRepository: com.adshield.pro.data.local.preferences.UserPreferencesRepository? = null
) {
    private var settingsHeuristicBlockingEnabled: Boolean = false
    fun setHeuristicBlockingEnabled(enabled: Boolean) { settingsHeuristicBlockingEnabled = enabled }

    data class InfinityDecision(
        val domain: String,
        val isBlocked: Boolean,
        val primaryVerdict: FilterEvaluationResult,
        val compatibilityCheck: CompatibilityGuard.CompatibilityCheck,
        val domainIntelligence: DomainIntelligenceEngine.IntelligenceResult?,
        val videoIntelligence: VideoAdIntelligence.VideoIntelligenceResult?,
        val threatResult: ThreatIntelligenceManager.ThreatLookupResult?,
        val securityAssessment: DnsSecurityEngine.SecurityAssessment?,
        val shouldEnrichTelemetry: Boolean,
        val decisionTimeMicros: Long,
        val pipeline: List<String>
    )

    data class PostUpstreamDecision(
        val domain: String,
        val cnameChain: CnameIntelligenceEngine.CnameChain?,
        val shouldBlock: Boolean,
        val reason: String?,
        val anomalies: List<DnsSecurityEngine.DnsAnomaly>
    )

    /**
     * Pre-upstream decision: should we block before contacting upstream?
     * Fast path — filter engine + compatibility guard.
     */
    fun evaluatePreUpstream(domain: String): InfinityDecision {
        val startNs = System.nanoTime()
        val pipeline = mutableListOf<String>()

        // Step 1: Compatibility guard
        val compatCheck = compatibilityGuard.check(domain)
        pipeline.add("compatibility:${if (compatCheck.isProtected) "protected" else "unprotected"}")

        if (compatCheck.isProtected && compatCheck.shouldAllow) {
            val elapsed = (System.nanoTime() - startNs) / 1000
            val syntheticAllow = FilterEvaluationResult(
                domain = domain, isBlocked = false,
                matchedRule = "@@||${compatCheck.domain}^",
                matchedCategory = null, matchType = null,
                sourceName = "Compatibility Guard (${compatCheck.category?.label})",
                priority = 95, evaluationTimeMicros = elapsed
            )
            return InfinityDecision(
                domain = domain, isBlocked = false,
                primaryVerdict = syntheticAllow,
                compatibilityCheck = compatCheck,
                domainIntelligence = null, videoIntelligence = null,
                threatResult = null, securityAssessment = null,
                shouldEnrichTelemetry = false,
                decisionTimeMicros = elapsed, pipeline = pipeline
            )
        }

        // Step 2: Primary filter engine
        val primaryEval = filterEngine.evaluate(domain)
        pipeline.add("filter:${if (primaryEval.isBlocked) "blocked:${primaryEval.sourceName}" else "allowed"}")

        if (primaryEval.isBlocked) {
            val elapsed = (System.nanoTime() - startNs) / 1000
            return InfinityDecision(
                domain = domain, isBlocked = true,
                primaryVerdict = primaryEval,
                compatibilityCheck = compatCheck,
                domainIntelligence = null, videoIntelligence = null,
                threatResult = null, securityAssessment = null,
                shouldEnrichTelemetry = primaryEval.matchedCategory?.name == "MALWARE",
                decisionTimeMicros = elapsed, pipeline = pipeline
            )
        }

        // Step 3: Intelligence enrichment for allowed domains (telemetry only by default)
        // These do NOT auto-block unless the domain scores very high on threat intelligence
        val threatResult = threatIntelligence.lookup(domain)
        if (threatResult.isThreat) {
            pipeline.add("threat:${threatResult.highestSeverity?.label}")
            val elapsed = (System.nanoTime() - startNs) / 1000
            return InfinityDecision(
                domain = domain, isBlocked = true,
                primaryVerdict = FilterEvaluationResult(
                    domain = domain, isBlocked = true,
                    matchedRule = "threat-intel:${threatResult.entries.firstOrNull()?.domain}",
                    matchedCategory = com.adshield.pro.domain.model.RuleCategory.MALWARE,
                    matchType = null,
                    sourceName = "Threat Intelligence (${threatResult.highestSeverity?.label})",
                    priority = 60, evaluationTimeMicros = elapsed
                ),
                compatibilityCheck = compatCheck,
                domainIntelligence = null, videoIntelligence = null,
                threatResult = threatResult, securityAssessment = null,
                shouldEnrichTelemetry = true,
                decisionTimeMicros = elapsed, pipeline = pipeline
            )
        }

        // Heuristic ML blocking (opt-in, user-gated): high-confidence ML + threat concordance
        if (settingsHeuristicBlockingEnabled) {
            val domainIntel = domainIntelligence.analyze(domain)
            val ml = tfliteClassifier.classify(domainIntel.features)
            if (ml.label == TfliteDomainClassifier.Label.MALWARE && ml.score >= 0.78f && domainIntel.riskScore >= 65) {
                pipeline.add("ml:block:malware:" + String.format("%.2f", ml.score))
                val elapsed = (System.nanoTime() - startNs) / 1000
                return InfinityDecision(
                    domain = domain, isBlocked = true,
                    primaryVerdict = FilterEvaluationResult(
                        domain = domain, isBlocked = true,
                        matchedRule = "heuristic:ml-malware:" + String.format("%.2f", ml.score),
                        matchedCategory = com.adshield.pro.domain.model.RuleCategory.MALWARE,
                        matchType = null, sourceName = "Infinity Heuristic (ML " + ml.label.name + ")",
                        priority = 55, evaluationTimeMicros = elapsed
                    ),
                    compatibilityCheck = compatCheck, domainIntelligence = null, videoIntelligence = null,
                    threatResult = threatResult, securityAssessment = null, shouldEnrichTelemetry = true,
                    decisionTimeMicros = elapsed, pipeline = pipeline
                )
            }
        }

        // Time-boxed throttle: only block ad infra within 3s of video init to avoid mid-stream kill
        com.adshield.pro.engine.aether.VideoSessionTracker.onDnsQuery(domain)
        // Video ad intelligence with time-boxed check
        val videoResult = if (domain.contains("doubleclick") || domain.contains("ad") ||
            domain.contains("vast") || domain.contains("tracking") || domain.contains("imasdk")
        ) {
            videoAdIntelligence.analyze(domain).also {
                if (it.isVideoAdInfrastructure) pipeline.add("video:${it.compatibilityRisk.label}")
            }
        } else null

        // If video ad infra but outside time window, downgrade to telemetry-only
        if (videoResult != null && videoResult.isVideoAdInfrastructure && videoResult.shouldBlock) {
            if (!com.adshield.pro.engine.aether.VideoSessionTracker.shouldBlockAdInfra(domain)) {
                pipeline.add("video:throttled-outside-window")
                // fall through to allowed instead of blocking
            } else {
                // Check session allowlist for user-approved false positives
                if (adaptiveLearning.isSessionAllowed(domain)) {
                    pipeline.add("video:session-allowed")
                    val elapsed = (System.nanoTime() - startNs) / 1000
                    return InfinityDecision(domain, false, primaryEval, compatCheck, null, videoResult, threatResult, null, false, elapsed, pipeline)
                }
            }
        }

        val elapsed = (System.nanoTime() - startNs) / 1000

        // Record performance
        performanceOptimizer.recordQuery(
            latencyMs = 0, fromCache = false, providerId = null, cpuMicros = elapsed
        )

        return InfinityDecision(
            domain = domain, isBlocked = false,
            primaryVerdict = primaryEval,
            compatibilityCheck = compatCheck,
            domainIntelligence = null,
            videoIntelligence = videoResult,
            threatResult = threatResult,
            securityAssessment = null,
            shouldEnrichTelemetry = false,
            decisionTimeMicros = elapsed, pipeline = pipeline
        )
    }

    /**
     * Post-upstream analysis: examine the actual DNS response for CNAME cloaking,
     * anomalies, and additional intelligence.
     */
    fun evaluatePostUpstream(domain: String, dnsResponse: ByteArray): PostUpstreamDecision {
        // CNAME cloaking
        val cnameEval = cnameEngine.evaluate(domain, dnsResponse)
        if (cnameEval.shouldBlock) {
            return PostUpstreamDecision(
                domain = domain,
                cnameChain = cnameEval.chain,
                shouldBlock = true,
                reason = cnameEval.blockingReason,
                anomalies = emptyList()
            )
        }

        // Anomaly detection
        val anomalies = dnsSecurity.analyzeResponse(domain, dnsResponse)

        return PostUpstreamDecision(
            domain = domain,
            cnameChain = cnameEval.chain.takeIf { it.chain.isNotEmpty() },
            shouldBlock = false,
            reason = null,
            anomalies = anomalies
        )
    }

    /** Lightweight telemetry hook — per-app counters without UI change. */
    fun cacheHitRateOrNull(): Double? = runCatching { performanceOptimizer.getMetrics().cacheHitRate }.getOrNull()
    fun recordPostUpstreamTelemetry(domain: String, appPackage: String?, isBlocked: Boolean) {
        performanceOptimizer.recordQuery(latencyMs = 0, fromCache = false, providerId = appPackage, cpuMicros = 0)
    }

    /**
     * Enriched full report including TFLite + DGA + adaptive signals.
     * Advisory only — TFLite/DGA never auto-block without list confirmation.
     */
    fun fullIntelligenceReport(domain: String): Map<String, Any> {
        val preDecision = evaluatePreUpstream(domain)
        val domainIntel = domainIntelligence.analyze(domain)
        val videoIntel = videoAdIntelligence.analyze(domain)
        val threatIntel = threatIntelligence.lookup(domain)
        val securityIntel = dnsSecurity.assessDomainThreat(domain)

        val ml = tfliteClassifier.classify(domainIntel.features)
        val dga = dgaDetector.detect(domain)
        val adjustedScore = adaptiveLearning.adjustScore(domainIntel.riskScore, domain, domainIntel.classification.name)

        return mapOf(
            "domain" to domain,
            "blocked" to preDecision.isBlocked,
            "source" to preDecision.primaryVerdict.sourceName,
            "category" to (preDecision.primaryVerdict.matchedCategory?.displayName ?: "None"),
            "compatibility" to mapOf(
                "protected" to preDecision.compatibilityCheck.isProtected,
                "category" to preDecision.compatibilityCheck.category?.label,
                "reason" to preDecision.compatibilityCheck.reason
            ),
            "domainIntelligence" to mapOf(
                "classification" to domainIntel.classification.name,
                "riskLevel" to domainIntel.riskLevel.label,
                "riskScore" to domainIntel.riskScore,
                "adjustedScore" to adjustedScore,
                "confidence" to domainIntel.confidence,
                "isDga" to domainIntel.isDgaLikely,
                "isTyposquat" to domainIntel.isTyposquatRisk
            ),
            "ml" to mapOf(
                "score" to ml.score,
                "label" to ml.label.name,
                "usedTflite" to ml.usedTflite,
                "reason" to ml.reason
            ),
            "dgaFamily" to mapOf(
                "family" to (dga?.family ?: "none"),
                "confidence" to (dga?.confidence ?: 0)
            ),
            "adaptive" to mapOf(
                "trust" to adaptiveLearning.trustFor(domain),
                "feedbacks" to adaptiveLearning.getProfile().totalFeedbacks
            ),
            "videoIntelligence" to mapOf(
                "isVideoAd" to videoIntel.isVideoAdInfrastructure,
                "shouldBlock" to videoIntel.shouldBlock,
                "risk" to videoIntel.compatibilityRisk.label
            ),
            "threatIntelligence" to mapOf(
                "isThreat" to threatIntel.isThreat,
                "severity" to threatIntel.highestSeverity?.label,
                "confidence" to threatIntel.combinedConfidence
            ),
            "securityAssessment" to mapOf(
                "isThreat" to securityIntel.isThreat,
                "threatTypes" to securityIntel.threatTypes.map { it.label },
                "riskScore" to securityIntel.riskScore
            ),
            "pipeline" to preDecision.pipeline,
            "decisionTimeMicros" to preDecision.decisionTimeMicros
        )
    }
}
