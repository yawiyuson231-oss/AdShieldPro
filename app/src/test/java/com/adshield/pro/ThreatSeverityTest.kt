package com.adshield.pro

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.SeverityCounts
import com.adshield.pro.domain.model.ThreatSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The severity mapping is the single source of truth shared by the VPN write path, the
 * dashboard donut and the Threats filters. Allowed queries are never threats.
 */
class ThreatSeverityTest {

    private fun record(blocked: Boolean, category: RuleCategory?) = DnsActivityRecord(
        id = 1L,
        timestampEpochMs = 1_700_000_000_000L,
        domain = "example.test",
        queryType = "A",
        isBlocked = blocked,
        category = category,
        matchedRule = null,
        sourceList = "test",
        latencyMs = 10,
        protocolUsed = "DOH"
    )

    @Test
    fun malwareBlocksAreCritical() {
        assertEquals(ThreatSeverity.CRITICAL, ThreatSeverity.of(true, RuleCategory.MALWARE))
    }

    @Test
    fun strictTelemetryIsHigh_adsAndCustomAreMedium_trackersAreLow() {
        assertEquals(ThreatSeverity.HIGH, ThreatSeverity.of(true, RuleCategory.STRICT_TELEMETRY))
        assertEquals(ThreatSeverity.MEDIUM, ThreatSeverity.of(true, RuleCategory.ADS))
        assertEquals(ThreatSeverity.MEDIUM, ThreatSeverity.of(true, RuleCategory.CUSTOM))
        assertEquals(ThreatSeverity.LOW, ThreatSeverity.of(true, RuleCategory.TRACKERS))
    }

    @Test
    fun blockedWithoutCategoryIsConservativelyMedium() {
        assertEquals(ThreatSeverity.MEDIUM, ThreatSeverity.of(true, null))
    }

    @Test
    fun allowedQueriesAreNotThreats() {
        assertNull(ThreatSeverity.of(false, RuleCategory.MALWARE))
        assertNull(ThreatSeverity.of(record(false, RuleCategory.ADS)))
    }

    @Test
    fun countsAggregateOnlyBlockedEvents() {
        val records = listOf(
            record(true, RuleCategory.MALWARE),
            record(true, RuleCategory.MALWARE),
            record(true, RuleCategory.STRICT_TELEMETRY),
            record(true, RuleCategory.ADS),
            record(true, RuleCategory.TRACKERS),
            record(false, RuleCategory.MALWARE)
        )
        val counts = SeverityCounts.from(records)
        assertEquals(2L, counts.critical)
        assertEquals(1L, counts.high)
        assertEquals(1L, counts.medium)
        assertEquals(1L, counts.low)
        assertEquals(5L, counts.total)
    }

    @Test
    fun countsAddPerSeverity() {
        val a = SeverityCounts(critical = 1, high = 2, medium = 3, low = 4)
        val b = SeverityCounts(critical = 10, high = 20, medium = 30, low = 40)
        val sum = a + b
        assertEquals(11L, sum.critical)
        assertEquals(22L, sum.high)
        assertEquals(33L, sum.medium)
        assertEquals(44L, sum.low)
        assertEquals(110L, sum.total)
    }

    @Test
    fun emptyCountsAreZero_notFabricated() {
        val counts = SeverityCounts.from(emptyList())
        assertEquals(0L, counts.total)
        assertEquals(0L, counts.countFor(ThreatSeverity.CRITICAL))
    }
}
