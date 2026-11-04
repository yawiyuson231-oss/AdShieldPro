package com.adshield.pro

import com.adshield.pro.engine.aether.AetherDecision
import com.adshield.pro.engine.aether.AetherVerdict
import com.adshield.pro.engine.aether.AutonomousAction
import com.adshield.pro.engine.aether.AutonomousResponsePolicy
import com.adshield.pro.engine.aether.ThreatClassification
import com.adshield.pro.engine.network.IpReputationAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InfinityUpgradeTest {
    private fun dnsDecision(blocked: Boolean, category: String?, source: String?) = AetherDecision(
        domain = "example.test",
        finalVerdict = if (blocked) AetherVerdict.BLOCK_EVIDENCE else AetherVerdict.INFO,
        engineBlocked = blocked,
        findings = emptyList(),
        evaluationMicros = 1,
        atEpochMs = 1,
        engineSource = source,
        engineCategory = category,
        answerIps = emptyList()
    )

    @Test
    fun concreteMalwareListEvidence_isVerified() {
        val core = com.adshield.pro.engine.aether.AetherGodCore(
            com.adshield.pro.engine.filter.FilterRuleEngine(),
            com.adshield.pro.engine.zero.ZeroBreakageEngine(),
            com.adshield.pro.engine.dns.ResolverHealthMonitor()
        )
        val result = core.observeDnsQuery("bad.test", true, "Threat feed", "MALWARE")
        assertEquals(ThreatClassification.VERIFIED, result.threatClassification)
        assertTrue(result.explanation.contains("malicious domain"))
    }

    @Test
    fun heuristicOnlyBlock_isSuspectedNotVerifiedMalware() {
        val core = com.adshield.pro.engine.aether.AetherGodCore(
            com.adshield.pro.engine.filter.FilterRuleEngine(),
            com.adshield.pro.engine.zero.ZeroBreakageEngine(),
            com.adshield.pro.engine.dns.ResolverHealthMonitor()
        )
        val result = core.observeDnsQuery("random.test", true, "Heuristic Shield (Strict)", null)
        assertEquals(ThreatClassification.SUSPECTED, result.threatClassification)
        assertTrue(result.confidenceScore <= 0.79)
        assertFalse(result.explanation.contains("VERIFIED malware"))
    }

    @Test
    fun noEvidence_isUnknownWithZeroConfidence() {
        val result = dnsDecision(false, null, null)
        assertEquals(ThreatClassification.UNKNOWN, result.threatClassification)
        assertEquals(0.0, result.confidenceScore, 0.0)
    }

    @Test
    fun unknownEvidence_neverCreatesAutonomousBlock() {
        val plan = AutonomousResponsePolicy.plan(dnsDecision(false, null, null), true, false)
        assertEquals(AutonomousAction.MONITOR, plan.action)
        assertFalse(plan.existingDnsBlockRemains)
    }

    @Test
    fun manualOverride_doesNotDisableExistingDnsPolicy() {
        val plan = AutonomousResponsePolicy.plan(dnsDecision(true, "MALWARE", "Threat feed"), true, true)
        assertEquals(AutonomousAction.MANUAL_OVERRIDE, plan.action)
        assertTrue(plan.existingDnsBlockRemains)
        assertTrue(plan.explanation.contains("existing DNS rules remain active"))
    }

    @Test
    fun suspectedEvidence_recommendsReview() {
        val plan = AutonomousResponsePolicy.plan(dnsDecision(false, null, null).copy(finalVerdict = AetherVerdict.OBSERVE), true, false)
        assertEquals(ThreatClassification.SUSPECTED, plan.classification)
        assertEquals(AutonomousAction.RECOMMEND_REVIEW, plan.action)
    }

    @Test
    fun recovery_isClaimedOnlyAfterConnectedVerification() {
        val pending = AutonomousResponsePolicy.evaluateRecovery(true, false, 0)
        assertTrue(pending.shouldRetry)
        val verified = AutonomousResponsePolicy.evaluateRecovery(true, true, 1)
        assertEquals(AutonomousResponsePolicy.RecoveryStatus.VERIFIED, verified.status)
        assertFalse(verified.shouldRetry)
    }

    @Test
    fun recovery_stopsAfterBoundedAttempts() {
        val failed = AutonomousResponsePolicy.evaluateRecovery(true, false, 3)
        assertEquals(AutonomousResponsePolicy.RecoveryStatus.FAILED, failed.status)
        assertFalse(failed.shouldRetry)
    }

    @Test
    fun publicIp_isUnverifiedNotSafeOrMalicious() {
        val result = IpReputationAnalyzer.assessLiteral("8.8.8.8")
        assertEquals(IpReputationAnalyzer.Reputation.UNVERIFIED_PUBLIC, result.reputation)
        assertTrue(result.explanation.contains("Unknown"))
    }

    @Test
    fun privateIp_isEvidenceSignalAndInvalidInputDoesNotResolve() {
        assertEquals(
            IpReputationAnalyzer.Reputation.LOCAL_OR_PRIVATE,
            IpReputationAnalyzer.assessLiteral("192.168.1.1").reputation
        )
        assertEquals(
            IpReputationAnalyzer.Reputation.INVALID,
            IpReputationAnalyzer.assessLiteral("example.com").reputation
        )
    }
}
