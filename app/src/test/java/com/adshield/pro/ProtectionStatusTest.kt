package com.adshield.pro

import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.dns.DnsProviderHealth
import com.adshield.pro.ui.model.ProtectionStatusEvaluator
import com.adshield.pro.ui.model.StageState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The live working status must be derived from real runtime state, never from a guess. */
class ProtectionStatusTest {

    private val now = 1_700_000_000_000L

    private fun connected(
        rules: Int = 12_000,
        sessionTotal: Long = 500L,
        sessionBlocked: Long = 125L,
        sessionCached: Long = 100L,
        latency: Int = 38,
        config: DnsResolverConfig = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)
    ) = VpnRuntimeState(
        status = VpnStatus.CONNECTED,
        connectedSinceEpochMs = now - 125_000L,
        activeMode = ProtectionMode.STANDARD,
        resolverConfig = config,
        activeNetworkLabel = "Wi-Fi",
        sessionTotalQueries = sessionTotal,
        sessionBlockedQueries = sessionBlocked,
        sessionAllowedQueries = sessionTotal - sessionBlocked,
        sessionCachedQueries = sessionCached,
        averageLatencyMs = latency,
        loadedRuleCount = rules
    )

    @Test
    fun aWorkingTunnelReportsActiveWithAFullHealthScore() {
        val status = ProtectionStatusEvaluator.evaluate(connected(), AppSettingsState(), emptyList(), now)
        assertEquals(StageState.ACTIVE, status.overall)
        assertEquals("PROTECTED · WORKING", status.headline)
        assertTrue(status.isLive)
        assertEquals(100, status.healthScore)
        assertEquals(6, status.stages.size)
        assertEquals(StageState.ACTIVE, status.stages.first { it.id == "tunnel" }.state)
        assertTrue(status.stages.first { it.id == "upstream" }.detail.contains("38 ms measured"))
        assertEquals("25%", status.metrics.first { it.label == "Blocked" }.value)
        assertEquals("20%", status.metrics.first { it.label == "Cache" }.value)
    }

    @Test
    fun anIdleTunnelIsNeverDescribedAsWorking() {
        val status = ProtectionStatusEvaluator.evaluate(
            connected(sessionTotal = 0L, sessionBlocked = 0L, sessionCached = 0L, latency = 0),
            AppSettingsState(),
            emptyList(),
            now
        )
        assertEquals(StageState.ACTIVE, status.overall)
        assertEquals("PROTECTED · IDLE", status.headline)
        assertFalse(status.isLive)
        assertEquals("—", status.metrics.first { it.label == "Latency" }.value)
    }

    @Test
    fun anOpenProviderCircuitIsReportedAsDegradedAndCostsHealth() {
        val health = listOf(
            DnsProviderHealth(
                providerId = DnsProviderPreset.CLOUDFLARE.id,
                protocol = DnsProtocol.DOH,
                consecutiveFailures = 3,
                circuitOpenUntilMs = now + 20_000L
            )
        )
        val status = ProtectionStatusEvaluator.evaluate(connected(), AppSettingsState(), health, now)
        assertEquals(StageState.DEGRADED, status.overall)
        assertEquals("PROTECTED · DEGRADED", status.headline)
        assertEquals(85, status.healthScore)
        assertTrue(status.stages.first { it.id == "upstream" }.detail.contains("circuit open"))
    }

    @Test
    fun missingRulesAreDegradedRatherThanSilentlyHealthy() {
        val status = ProtectionStatusEvaluator.evaluate(connected(rules = 0), AppSettingsState(), emptyList(), now)
        assertEquals(StageState.DEGRADED, status.overall)
        assertEquals(75, status.healthScore)
        assertTrue(status.stages.first { it.id == "filter" }.detail.contains("No rules loaded"))
    }

    @Test
    fun pausedAndOfflineStatesNeverClaimProtection() {
        val paused = ProtectionStatusEvaluator.evaluate(
            connected().copy(status = VpnStatus.PAUSED), AppSettingsState(), emptyList(), now
        )
        assertEquals(StageState.ATTENTION, paused.overall)
        assertEquals("FILTERING PAUSED", paused.headline)
        assertEquals(0, paused.healthScore)
        assertFalse(paused.isLive)

        val off = ProtectionStatusEvaluator.evaluate(VpnRuntimeState(), AppSettingsState(), emptyList(), now)
        assertEquals(StageState.OFFLINE, off.overall)
        assertEquals("PROTECTION OFF", off.headline)
        assertEquals(0, off.healthScore)

        val error = ProtectionStatusEvaluator.evaluate(
            VpnRuntimeState(status = VpnStatus.ERROR, lastError = "VPN consent revoked"),
            AppSettingsState(), emptyList(), now
        )
        assertEquals("NEEDS ATTENTION", error.headline)
        assertTrue(error.stages.first { it.id == "tunnel" }.detail.contains("VPN consent revoked"))
    }

    @Test
    fun emergencyLockdownIsAttentionNotAHealthFault() {
        val settings = AppSettingsState(
            dnsFirewallPolicy = DnsFirewallPolicy(emergencyAllowlistOnly = true)
        )
        val status = ProtectionStatusEvaluator.evaluate(connected(), settings, emptyList(), now)
        assertEquals(StageState.ATTENTION, status.overall)
        assertEquals("EMERGENCY LOCKDOWN", status.headline)
        assertEquals(95, status.healthScore)
        assertTrue(status.badges.contains("Emergency mode"))
        assertTrue(status.stages.first { it.id == "policy" }.detail.contains("Emergency allowlist-only"))
    }

    @Test
    fun policiesAndDnssecModeAreReflectedInBadgesAndStages() {
        val settings = AppSettingsState(
            dnsFirewallPolicy = DnsFirewallPolicy(
                appPolicies = mapOf("com.example" to AppDnsPolicy.BLOCK_ALL),
                protectedTransports = setOf(NetworkTransportPolicy.WIFI)
            )
        )
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.QUAD9,
            protocol = DnsProtocol.DOT,
            dnssecMode = DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS,
            failoverEnabled = true,
            failoverProviderIds = setOf(DnsProviderPreset.NEXTDNS.id, DnsProviderPreset.CONTROL_D.id)
        )
        val status = ProtectionStatusEvaluator.evaluate(connected(config = config), settings, emptyList(), now)
        assertTrue(status.badges.contains("DNSSEC strict"))
        assertTrue(status.badges.contains("Failover: 2 provider(s)"))
        assertTrue(status.badges.contains("1 app rule"))
        assertTrue(status.badges.contains("Network: Wi-Fi"))
        assertTrue(status.stages.first { it.id == "integrity" }.detail.contains("Strict"))
    }
}
