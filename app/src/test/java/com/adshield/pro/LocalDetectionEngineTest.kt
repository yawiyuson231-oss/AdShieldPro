package com.adshield.pro

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.engine.detection.LocalDetectionEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The local detection pipeline must be explainable and honest: every finding cites evidence,
 * stages without enough data say so, and nothing is invented to fill the dashboard.
 */
class LocalDetectionEngineTest {

    private val base = 1_700_000_000_000L

    private fun record(
        id: Long,
        domain: String,
        offsetMs: Long,
        blocked: Boolean = true,
        category: RuleCategory? = RuleCategory.ADS,
        source: String = "list-a"
    ) = DnsActivityRecord(
        id = id,
        timestampEpochMs = base + offsetMs,
        domain = domain,
        queryType = "A",
        isBlocked = blocked,
        category = category,
        matchedRule = "||$domain^",
        sourceList = source,
        latencyMs = 20,
        protocolUsed = "DOH"
    )

    @Test
    fun emptyLog_reportsInsufficientDataForEveryStage_andZeroCoverage() {
        val report = LocalDetectionEngine.run(emptyList(), nowEpochMs = base)
        assertEquals(4, report.stages.size)
        assertTrue(report.stages.all { it.status == LocalDetectionEngine.StageStatus.INSUFFICIENT_DATA })
        assertEquals(0f, report.coverage, 0.0001f)
        assertFalse(report.hasEnoughData)
        assertTrue(report.findings.isEmpty())
        assertEquals(0, report.analyzedEvents)
    }

    @Test
    fun behaviorStage_flagsRepeatedQueriesWithEvidence() {
        val logs = (1..10).map { record(it.toLong(), "tracker.example", it * 10_000L) }
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 200_000L)
        val behavior = report.stages.first { it.stage == LocalDetectionEngine.Stage.BEHAVIOR }
        assertEquals(LocalDetectionEngine.StageStatus.COMPLETE, behavior.status)
        val finding = report.findings.first { it.id == "behavior-repeat-tracker.example" }
        assertEquals(ThreatSeverity.MEDIUM, finding.severity)
        assertTrue(finding.evidence.any { it.contains("10 DNS queries") })
    }

    @Test
    fun behaviorStage_detectsBurstWithinSixtySeconds() {
        // 8 queries to one host inside 30 seconds.
        val logs = (1..8).map { record(it.toLong(), "beacon.example", it * 3_000L) }
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 60_000L)
        assertNotNull(report.findings.firstOrNull { it.id == "behavior-burst-beacon.example" })
    }

    @Test
    fun anomalyStage_flagsRateSpikeAgainstQuietBaseline() {
        // 40 quiet buckets of 1 query each, then one bucket with 30 queries.
        val logs = ArrayList<DnsActivityRecord>()
        var id = 1L
        for (bucket in 0 until 40) {
            logs += record(id++, "quiet-$bucket.example", bucket * 300_000L)
        }
        for (i in 0 until 30) {
            logs += record(id++, "spike.example", 40 * 300_000L + i * 1_000L, category = RuleCategory.MALWARE)
        }
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 41 * 300_000L)
        val anomaly = report.stages.first { it.stage == LocalDetectionEngine.Stage.ANOMALY }
        assertEquals(LocalDetectionEngine.StageStatus.COMPLETE, anomaly.status)
        val spike = report.findings.firstOrNull { it.id.startsWith("anomaly-rate-") }
        assertNotNull("a 30-query bucket against a 1-query baseline must be flagged", spike)
        assertTrue(spike!!.detail.contains("z="))
    }

    @Test
    fun anomalyStage_flagsHighUniqueDomainRatio() {
        val logs = (1..40).map { record(it.toLong(), "unique-$it.example", it * 1_000L) }
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 60_000L)
        assertNotNull(report.findings.firstOrNull { it.id == "anomaly-unique-ratio" })
    }

    @Test
    fun classificationStage_screensBlockedHostsWithHeuristics() {
        val logs = listOf(
            record(1, "paypal-secure-login.tk", 0, category = RuleCategory.MALWARE),
            record(2, "clean.example.com", 1_000)
        )
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 10_000L)
        val classification = report.stages.first { it.stage == LocalDetectionEngine.Stage.CLASSIFICATION }
        assertEquals(LocalDetectionEngine.StageStatus.COMPLETE, classification.status)
        val finding = report.findings.first { it.domain == "paypal-secure-login.tk" }
        assertEquals(ThreatSeverity.CRITICAL, finding.severity)
        assertTrue(finding.evidence.any { it.contains("curated malware list") })
    }

    @Test
    fun correlationStage_confirmsMultiSourceBlocks() {
        val logs = listOf(
            record(1, "bad.example", 0, category = RuleCategory.MALWARE, source = "list-a"),
            record(2, "bad.example", 300_000L, category = RuleCategory.MALWARE, source = "list-b"),
            record(3, "bad.example", 600_000L, category = RuleCategory.MALWARE, source = "list-a"),
            record(4, "other.example", 1_000, source = "list-a"),
            record(5, "another.example", 2_000, source = "list-a"),
            record(6, "more.example", 3_000, source = "list-a")
        )
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 700_000L)
        val finding = report.findings.first { it.id == "correlate-multi-bad.example" }
        assertEquals(ThreatSeverity.CRITICAL, finding.severity)
        assertEquals(2, finding.evidence.size)
    }

    @Test
    fun correlationStage_flagsPersistentBlockedActivity() {
        val logs = listOf(
            record(1, "persist.example", 0, source = "list-a"),
            record(2, "persist.example", 300_000L, source = "list-a"),
            record(3, "persist.example", 600_000L, source = "list-a"),
            record(4, "x.example", 1_000, source = "list-a"),
            record(5, "y.example", 2_000, source = "list-a"),
            record(6, "z.example", 3_000, source = "list-a")
        )
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 700_000L)
        assertNotNull(report.findings.firstOrNull { it.id == "correlate-persist-persist.example" })
    }

    @Test
    fun coverageReflectsStagesWithSufficientData_notFakeProgress() {
        // 3 events: only classification (>=1 blocked) can complete.
        val logs = (1..3).map { record(it.toLong(), "d$it.example", it * 1_000L) }
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 10_000L)
        assertEquals(1, report.completedStages)
        assertEquals(0.25f, report.coverage, 0.0001f)
    }

    @Test
    fun findingsAreSortedBySeverityDescending() {
        val logs = (1..10).map { record(it.toLong(), "tracker.example", it * 10_000L) } +
            listOf(record(99, "paypal-secure-login.tk", 5_000, category = RuleCategory.MALWARE))
        val report = LocalDetectionEngine.run(logs, nowEpochMs = base + 200_000L)
        val ranks = report.findings.map { it.severity.rank }
        assertEquals(ranks.sortedDescending(), ranks)
    }
}
