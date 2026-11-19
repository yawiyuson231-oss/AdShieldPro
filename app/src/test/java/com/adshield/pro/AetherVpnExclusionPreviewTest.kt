package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnTunnelReceipt
import com.adshield.pro.engine.aether.AetherDnsPolicyReview.ExclusionEvidence
import com.adshield.pro.engine.aether.AetherVpnExclusionPreview as Preview
import com.adshield.pro.engine.aether.AetherVpnExclusionPreview.Example
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AetherVpnExclusionPreviewTest {
    private val target = "com.example.selected"
    private val other = "com.example.selected.other"
    private val own = "com.adshield.pro.debug"

    @Test
    fun acceptsOnlyAnExactSavedUserExclusionNotAnAppRuleOrOldReceipt() {
        val dnsOnly = "com.example.dns"
        val noLongerSaved = "com.example.stale"
        val invalid = "com.example.\nother"
        val unavailablePackage = "com.example.absent"
        val exclusions = setOf(target, other, unavailablePackage, invalid, own, " ")
        val policy = DnsFirewallPolicy(appPolicies = mapOf(dnsOnly to AppDnsPolicy.ALLOW_ALL))
        val runtime = VpnRuntimeState(
            status = VpnStatus.CONNECTED,
            tunnelReceipt = VpnTunnelReceipt(1, 100, false, setOf(noLongerSaved, target), emptySet())
        )
        assertEquals(listOf(unavailablePackage, target, other), Preview.targets(exclusions, own))
        for (id in listOf(own, dnsOnly, noLongerSaved, "com.example.Selected", invalid, " ")) {
            assertNull(id, Preview.compare(id, own, exclusions, policy, runtime, 500))
        }
        assertEquals(target, Preview.compare(target, own, exclusions, policy, runtime, 500)?.packageName)
    }

    @Test
    fun allowOverrideWouldStopBypassingDomainFiltersWithoutMutatingSavedSettings() {
        val exclusions = linkedSetOf(target, other)
        val appRules = linkedMapOf(target to AppDnsPolicy.ALLOW_ALL, other to AppDnsPolicy.BLOCK_ALL)
        val networks = linkedSetOf(NetworkTransportPolicy.WIFI, NetworkTransportPolicy.ETHERNET)
        val policy = DnsFirewallPolicy(appPolicies = appRules, protectedTransports = networks)
        val report = requireNotNull(Preview.compare(target, own, exclusions, policy, VpnRuntimeState(), 500))

        assertEquals(AppDnsPolicy.ALLOW_ALL, report.savedAppPolicy)
        assertEquals(NetworkTransportPolicy.entries.toList(), report.examples.map { it.transport })
        val wifi = report.sample(NetworkTransportPolicy.WIFI, Example.DOMAIN_BLOCK)
        assertEquals("Per-App DNS Filter Bypass", wifi.saved.sourceName)
        assertTrue(wifi.saved.bypassDomainFilters)
        assertTrue(wifi.filtered.isBlocked)
        assertFalse(wifi.filtered.bypassDomainFilters)
        val cellular = report.sample(NetworkTransportPolicy.CELLULAR, Example.DOMAIN_BLOCK)
        assertEquals(cellular.saved, cellular.filtered)
        assertTrue(cellular.filtered.bypassDomainFilters)
        assertFalse(cellular.filtered.isBlocked)

        assertEquals(setOf(target, other), exclusions)
        assertEquals(mapOf(target to AppDnsPolicy.ALLOW_ALL, other to AppDnsPolicy.BLOCK_ALL), policy.appPolicies)
        assertEquals(setOf(NetworkTransportPolicy.WIFI, NetworkTransportPolicy.ETHERNET), policy.protectedTransports)
        assertTrue(check(policy, packageName = other).sample(NetworkTransportPolicy.WIFI, Example.NO_MATCH).saved.isBlocked)
    }

    @Test
    fun clearingBlockOverrideMayPassDnsButRetainsNormalDomainBlocking() {
        val policy = DnsFirewallPolicy(
            appPolicies = mapOf(target to AppDnsPolicy.BLOCK_ALL),
            protectedTransports = setOf(NetworkTransportPolicy.WIFI)
        )
        val report = check(policy)
        val wifi = report.sample(NetworkTransportPolicy.WIFI, Example.DOMAIN_BLOCK)
        assertEquals("Per-App DNS Block", wifi.saved.sourceName)
        assertEquals("Domain block rule", wifi.filtered.sourceName)
        assertTrue(wifi.filtered.isBlocked)
        val allowed = report.sample(NetworkTransportPolicy.WIFI, Example.EXPLICIT_ALLOW)
        assertTrue(allowed.saved.isBlocked)
        assertFalse(allowed.filtered.isBlocked)
        val cellular = report.sample(NetworkTransportPolicy.CELLULAR, Example.NO_MATCH)
        assertTrue(cellular.saved.isBlocked) // Per-app block beats network bypass.
        assertFalse(cellular.filtered.isBlocked)
        assertTrue(cellular.filtered.bypassDomainFilters)
    }

    @Test
    fun usesAllowlistOnlyPrecedenceBeforePerAppAndNetworkExceptions() {
        for (appRule in listOf(AppDnsPolicy.ALLOW_ALL, AppDnsPolicy.BLOCK_ALL)) {
            val report = check(DnsFirewallPolicy(
                appPolicies = mapOf(target to appRule),
                protectedTransports = setOf(NetworkTransportPolicy.WIFI),
                emergencyAllowlistOnly = true
            ))
            for (network in NetworkTransportPolicy.entries) {
                for (example in listOf(Example.NO_MATCH, Example.DOMAIN_BLOCK)) {
                    val row = report.sample(network, example)
                    assertEquals("Emergency Allowlist-Only DNS", row.saved.sourceName)
                    assertEquals(row.saved, row.filtered)
                    assertTrue(row.filtered.isBlocked)
                    assertFalse(row.filtered.bypassDomainFilters)
                }
                val allowed = report.sample(network, Example.EXPLICIT_ALLOW)
                assertEquals(appRule == AppDnsPolicy.BLOCK_ALL, allowed.saved.isBlocked)
                assertFalse(allowed.filtered.isBlocked)
                assertEquals(network != NetworkTransportPolicy.WIFI, allowed.filtered.bypassDomainFilters)
            }
        }
    }

    @Test
    fun reportsNoQueryPolicyChangeWhenThereIsNoOverride() {
        val report = check(DnsFirewallPolicy(appPolicies = mapOf(other to AppDnsPolicy.BLOCK_ALL)))
        assertEquals(AppDnsPolicy.DEFAULT, report.savedAppPolicy)
        assertTrue(report.examples.all { group -> group.comparisons.all { it.saved == it.filtered } })
    }

    @Test
    fun separatesAcceptedRejectedUnrecordedAndUnknownOnlyUsingTheSampledTunnel() {
        val receipt = VpnTunnelReceipt(8, 100, true, setOf(target), setOf(other))
        val runtime = VpnRuntimeState(status = VpnStatus.PAUSED, tunnelReceipt = receipt)
        val accepted = check(runtime = runtime)
        assertEquals(ExclusionEvidence.ACCEPTED, accepted.exclusionEvidence)
        assertEquals(8L, accepted.tunnelGeneration)
        assertEquals(500L, accepted.sampledAtMs)
        assertTrue(accepted.filteringPaused)
        assertEquals(ExclusionEvidence.REJECTED, check(runtime = runtime, packageName = other).exclusionEvidence)
        val unrecorded = check(runtime = runtime, packageName = "com.example.new")
        assertEquals(ExclusionEvidence.NOT_RECORDED, unrecorded.exclusionEvidence)

        for (status in VpnStatus.entries - setOf(VpnStatus.CONNECTED, VpnStatus.PAUSED)) {
            val preview = check(runtime = runtime.copy(status = status))
            assertEquals(ExclusionEvidence.UNKNOWN, preview.exclusionEvidence)
            assertNull(preview.tunnelGeneration)
            assertFalse(preview.filteringPaused)
        }
        assertEquals(ExclusionEvidence.UNKNOWN, check(runtime = VpnRuntimeState(status = VpnStatus.CONNECTED)).exclusionEvidence)
    }

    private fun check(
        policy: DnsFirewallPolicy = DnsFirewallPolicy(),
        runtime: VpnRuntimeState = VpnRuntimeState(),
        packageName: String = target
    ) = requireNotNull(Preview.compare(packageName, own, setOf(target, other, packageName), policy, runtime, 500))

    private fun Preview.Report.sample(transport: NetworkTransportPolicy, example: Example) =
        examples.single { it.transport == transport }.comparisons.single { it.example == example }
}
