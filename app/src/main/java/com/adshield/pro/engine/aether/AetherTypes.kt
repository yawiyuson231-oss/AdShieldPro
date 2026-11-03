package com.adshield.pro.engine.aether

/**
 * OmniShield X — AETHER Infinity core types.
 *
 * HONEST DEFINITION: AETHER is a deterministic, heuristic, evidence-based
 * orchestration layer over the real security engines of this app. It is NOT a
 * neural network and performs no fabricated "AI activity". Every finding carries
 * the engine/rule that produced it so decisions are independently verifiable
 * (Prime Directive: no fake AI, no invented capabilities).
 */

enum class AetherAgentId(val displayName: String, val responsibility: String) {
    X_AD_INTELLIGENCE("X-AD Intelligence", "Advertising detection via filter engine categories"),
    X_VIDEO_INTELLIGENCE("X-Video Intelligence", "Video advertising endpoint and signal detection"),
    X_DNS_INTELLIGENCE("X-DNS Intelligence", "DNS anomaly analysis: entropy, tunneling, rebinding"),
    X_TRACKER_INTELLIGENCE("X-Tracker Intelligence", "Tracking/analytics detection"),
    X_MALWARE_INTELLIGENCE("X-Malware Intelligence", "Malicious infrastructure detection"),
    X_DOMAIN_DNA("X-Domain DNA", "Domain reputation, relationships, typosquat/homoglyph signals"),
    X_APP_INTELLIGENCE("X-App Intelligence", "Application compatibility and protection coverage"),
    X_NETWORK_INTELLIGENCE("X-Network Intelligence", "Resolver health, latency, failover ranking"),
    X_PRIVACY_AUDITOR("X-Privacy Auditor", "Privacy posture of current configuration"),
    X_PREDICTIVE_DEFENSE("X-Predictive Defense", "Emerging-threat heuristics — OBSERVE-only, never auto-blocks"),
    X_SELF_HEALING("X-Self-Healing", "Zero-Breakage watchdog state and recovery actions"),
    X_VERIFICATION("X-Verification AI", "Independent re-validation of blocking decisions"),
    X_GLOBAL_LEARNING("X-Global Learning", "Local privacy-preserving frequency statistics (no cloud upload)"),
    X_DIGITAL_TWIN("X-Digital Twin", "Simulation of rule changes against the must-work corpus"),
    X_FAILSAFE("X-Failsafe AI", "Emergency posture and rollback readiness")
}

/** Verdict of a single finding. OBSERVE findings never block anything. */
enum class AetherVerdict { INFO, OBSERVE, BLOCK_EVIDENCE, PROTECTED, OVERRIDE_SAFE }

/**
 * One evidence-backed finding. [evidence] must reference the concrete engine,
 * rule, or measurement behind the conclusion — never a bare assertion.
 */
data class AetherFinding(
    val agent: AetherAgentId,
    val verdict: AetherVerdict,
    val confidence: Double, // 0.0..1.0 — heuristic confidence, not probability of truth
    val summary: String,
    val evidence: List<String>
)

/** A completed orchestration decision for one observed domain. */
data class AetherDecision(
    val domain: String,
    val finalVerdict: AetherVerdict,
    val engineBlocked: Boolean,
    val findings: List<AetherFinding>,
    val evaluationMicros: Long,
    val atEpochMs: Long
) {
    fun toAuditLine(): String =
        "${finalVerdict.name} ${domain} engine=${if (engineBlocked) "BLOCK" else "ALLOW"} agents=${findings.size}"
}

/** Real per-agent performance counters — no simulated values. */
data class AgentHealth(
    val id: AetherAgentId,
    var evaluations: Long = 0L,
    var findings: Long = 0L,
    var totalEvalNanos: Long = 0L
) {
    val avgEvalMicros: Long get() = if (evaluations == 0L) 0L else totalEvalNanos / evaluations / 1_000L
}

/** Inputs agents may inspect for one DNS observation. */
data class AgentContext(
    val domain: String,
    val engineBlocked: Boolean,
    val engineSource: String?,
    val engineCategory: String?,
    val answerIps: List<String>,
    val upstreamLatencyMs: Int
)

/** Control Center (Part 12) snapshot — every number comes from real events. */
data class ControlCenterReport(
    val totalAgents: Int,
    val agentsOnline: Int,
    val dnsObserved: Long,
    val blockedConfirmed: Long,
    val anomaliesObserved: Long,
    val verificationOverrides: Long,
    val rebindingBlocked: Long,
    val protectedOverrides: Long,
    val safeModeActive: Boolean,
    val autoRecoveries: Long,
    val bestResolverLabel: String?,
    val bestResolverLatencyMs: Int?,
    val topObservedDomains: List<String>,
    val recentAudit: List<String>,
    val updatedAtEpochMs: Long
)
