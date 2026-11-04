package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.DomainBlockCount
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.LiveNetworkModel
import com.adshield.pro.ui.model.DashboardPresentation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Dashboard honesty + motion contracts. These are the rules that keep the cyber-console UI from
 * turning into a fake SOC dashboard: real counters, one scope at a time, no idle animation.
 */
class DashboardPresentationTest {

    private fun record(
        id: Long = 1L,
        blocked: Boolean = true,
        category: RuleCategory? = RuleCategory.ADS
    ) = DnsActivityRecord(
        id = id,
        timestampEpochMs = 1_700_000_000_000L + id,
        domain = "example$id.test",
        queryType = "A",
        isBlocked = blocked,
        category = category,
        matchedRule = null,
        sourceList = "test-list",
        latencyMs = 25,
        protocolUsed = "DOH"
    )

    @Test
    fun overview_prefersDeviceHistoryAndNeverMixesSessionCounters() {
        val overview = DashboardPresentation.overview(
            allTimeTotal = 100, allTimeBlocked = 30, allTimeAllowed = 70,
            sessionTotal = 999, sessionBlocked = 999, sessionAllowed = 0,
            allTimeThreats = 5, recentThreats = 9
        )
        assertEquals(100, overview.total)
        assertEquals(30, overview.blocked)
        assertEquals(70, overview.allowed)
        assertEquals(5, overview.threats)
        assertEquals(DashboardPresentation.TrafficScope.DEVICE_HISTORY, overview.scope)
    }

    @Test
    fun overview_fallsBackToCurrentSessionOnlyWhenHistoryIsEmpty() {
        val overview = DashboardPresentation.overview(0, 0, 0, 12, 4, 8, 0, 2)
        assertEquals(12, overview.total)
        assertEquals(4, overview.blocked)
        assertEquals(8, overview.allowed)
        assertEquals(2, overview.threats)
        assertEquals(DashboardPresentation.TrafficScope.CURRENT_SESSION, overview.scope)
    }

    @Test
    fun overview_emptyStateIsExplicitAndZeroSafe() {
        val overview = DashboardPresentation.overview(0, 0, 0, 0, 0, 0, 0, 0)
        assertEquals(0, overview.total)
        assertEquals(0f, overview.blockPercent, 0.001f)
        assertEquals(DashboardPresentation.TrafficScope.EMPTY, overview.scope)
    }

    @Test
    fun overview_clampsImpossibleBlockedCounters() {
        val overview = DashboardPresentation.overview(10, 50, 0, 0, 0, 0, 99, 0)
        assertEquals(10, overview.total)
        assertEquals(10, overview.blocked)
        assertEquals(0, overview.allowed)
        assertEquals(10, overview.threats)
        assertEquals(100f, overview.blockPercent, 0.001f)
    }

    @Test
    fun overview_recomputesAllowedWhenReportedCounterContradictsTotal() {
        val overview = DashboardPresentation.overview(100, 20, 999, 0, 0, 0, 0, 0)
        assertEquals(80, overview.allowed)
    }

    @Test
    fun overview_threatsCannotExceedBlocked() {
        val overview = DashboardPresentation.overview(100, 10, 90, 0, 0, 0, 50, 0)
        assertEquals(10, overview.threats)
    }

    @Test
    fun overview_negativeInputsAreSanitized() {
        val overview = DashboardPresentation.overview(-5, -2, -3, 0, 0, 0, -1, 0)
        assertEquals(0, overview.total)
        assertEquals(0, overview.blocked)
        assertEquals(0, overview.allowed)
        assertEquals(0, overview.threats)
    }

    @Test
    fun eventTitlesDescribeRealOutcomes() {
        assertEquals("Allowed query", DashboardPresentation.eventTitle(record(blocked = false, category = null)))
        assertEquals("Advertising blocked", DashboardPresentation.eventTitle(record(category = RuleCategory.ADS)))
        assertEquals("Malware & Phishing blocked", DashboardPresentation.eventTitle(record(category = RuleCategory.MALWARE)))
        assertEquals("Blocked by policy", DashboardPresentation.eventTitle(record(category = null)))
    }

    @Test
    fun severityMappingIsStableAndNeverInventsCriticalForAllowedTraffic() {
        assertEquals("CRITICAL", DashboardPresentation.eventSeverity(record(category = RuleCategory.MALWARE)))
        assertEquals("HIGH", DashboardPresentation.eventSeverity(record(category = RuleCategory.STRICT_TELEMETRY)))
        assertEquals("MEDIUM", DashboardPresentation.eventSeverity(record(category = RuleCategory.ADS)))
        assertEquals("LOW", DashboardPresentation.eventSeverity(record(category = RuleCategory.TRACKERS)))
        assertEquals("CUSTOM", DashboardPresentation.eventSeverity(record(category = RuleCategory.CUSTOM)))
        assertEquals("LOW", DashboardPresentation.eventSeverity(record(blocked = false, category = null)))
    }

    @Test
    fun motionRequiresConnectedTunnelRealTrafficAndSystemAnimations() {
        assertTrue(DashboardPresentation.shouldAnimate(VpnStatus.CONNECTED, true, true))
        assertFalse(DashboardPresentation.shouldAnimate(VpnStatus.CONNECTED, false, true))
        assertFalse(DashboardPresentation.shouldAnimate(VpnStatus.PAUSED, true, true))
        assertFalse(DashboardPresentation.shouldAnimate(VpnStatus.DISCONNECTED, true, true))
        assertFalse(DashboardPresentation.shouldAnimate(VpnStatus.CONNECTED, true, false))
    }

    @Test
    fun navScrollTargetCentersSelectionAndClampsAtStart() {
        assertEquals(0, DashboardPresentation.navScrollTarget(0, 5))
        assertEquals(0, DashboardPresentation.navScrollTarget(2, 5))
        assertEquals(2, DashboardPresentation.navScrollTarget(4, 5))
        assertEquals(6, DashboardPresentation.navScrollTarget(8, 5))
        assertEquals(0, DashboardPresentation.navScrollTarget(-3, 0))
    }

    @Test
    fun percentLabelRoundsAndClamps() {
        assertEquals("0%", DashboardPresentation.percentLabel(-4f))
        assertEquals("33%", DashboardPresentation.percentLabel(33.4f))
        assertEquals("100%", DashboardPresentation.percentLabel(140f))
    }

    @Test
    fun liveEventsKeepDatabaseIdsForStableLazyKeys() {
        val snapshot = LiveNetworkModel.snapshot(
            VpnRuntimeState(status = VpnStatus.CONNECTED),
            listOf(record(id = 7), record(id = 8, blocked = false, category = null)),
            emptyList<AppDnsActivity>(),
            emptyList<DomainBlockCount>()
        )
        assertEquals(listOf(7L, 8L), snapshot.recentEvents.map { it.id })
        assertTrue(snapshot.hasData)
    }

    @Test
    fun idleLiveSnapshotDoesNotPretendToHaveTraffic() {
        val snapshot = LiveNetworkModel.snapshot(
            VpnRuntimeState(status = VpnStatus.CONNECTED),
            emptyList(), emptyList(), emptyList()
        )
        assertFalse(snapshot.hasData)
        assertTrue(snapshot.emptyReason!!.contains("idle"))
        assertFalse(DashboardPresentation.shouldAnimate(VpnStatus.CONNECTED, snapshot.hasData, true))
    }
}
