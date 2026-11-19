package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnTunnelReceipt
import com.adshield.pro.engine.aether.AetherDnsPolicyReview as Review
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AetherDnsPolicyReviewTest {
    @Test
    fun usesEligibleProvidersFromTheActualSavedPlanNotAnInventedFallback() {
        val config = DnsResolverConfig(
            protocol = DnsProtocol.DOT,
            preset = DnsProviderPreset.CLOUDFLARE,
            failoverEnabled = true,
            failoverProviderIds = linkedSetOf("not-a-provider", "custom", "cloudflare", "quad9", "google")
        )
        val summary = Review.inspect(config, DnsFirewallPolicy(), emptySet(), aliasShieldOn = true).summary
        assertEquals(DnsProviderPreset.CLOUDFLARE.displayName, summary.primaryProvider)
        assertEquals(Review.Failover.CONFIGURED, summary.failover)
        assertEquals(listOf(DnsProviderPreset.QUAD9.displayName, DnsProviderPreset.GOOGLE.displayName), summary.backups)
        assertEquals(listOf(DnsProviderPreset.GOOGLE.displayName), summary.subnetForwardingProviders)

        val standard = Review.inspect(config.copy(protocol = DnsProtocol.UDP_TCP), DnsFirewallPolicy(), emptySet(), true).summary
        assertEquals(Review.Failover.NOT_AVAILABLE, standard.failover)
        assertTrue(standard.backups.isEmpty())
        assertTrue(standard.subnetForwardingProviders.isEmpty())

        val off = Review.inspect(config.copy(failoverEnabled = false), DnsFirewallPolicy(), emptySet(), true).summary
        assertEquals(Review.Failover.OFF, off.failover)
        assertTrue(off.backups.isEmpty())
    }

    @Test
    fun reportsOnlyTheSavedScopeAndDoesNotExposeCustomResolverEndpoints() {
        val privateEndpoint = "resolver.example.invalid"
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.DOH,
            customDohUrl = "https://$privateEndpoint/dns-query",
            customDotHost = privateEndpoint,
            dnssecMode = DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS,
            failoverEnabled = true,
            failoverProviderIds = setOf("custom", "not-a-provider")
        )
        val snapshot = Review.inspect(config, DnsFirewallPolicy(protectedTransports = setOf(NetworkTransportPolicy.WIFI)), emptySet(), false)
        assertEquals(DnsProviderPreset.CUSTOM.displayName, snapshot.summary.primaryProvider)
        assertEquals(Review.Failover.NO_BACKUPS, snapshot.summary.failover)
        assertTrue(snapshot.summary.backups.isEmpty())
        assertTrue(snapshot.summary.subnetForwardingProviders.isEmpty())
        assertEquals(listOf(NetworkTransportPolicy.CELLULAR, NetworkTransportPolicy.ETHERNET, NetworkTransportPolicy.OTHER),
            snapshot.summary.networksWithoutDomainFiltering)
        assertEquals(DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS, snapshot.summary.dnssecMode)
        assertFalse(snapshot.summary.aliasShieldOn)
        assertFalse(privateEndpoint in snapshot.summary.toString())
    }

    @Test
    fun savedExclusionsStayUnknownUntilTheCurrentTunnelHasAReceipt() {
        val saved = setOf("com.example.selected")
        val snapshot = Review.inspect(DnsResolverConfig(), DnsFirewallPolicy(), saved, true)
        val receipt = VpnTunnelReceipt(1, 100, false, saved, emptySet())
        for (status in listOf(VpnStatus.STARTING, VpnStatus.RECONNECTING, VpnStatus.DISCONNECTED, VpnStatus.ERROR)) {
            // Even an inconsistent runtime value must not expose stale evidence.
            val compared = snapshot.compareWith(VpnRuntimeState(status = status, tunnelReceipt = receipt))
            assertNull(compared.summary.tunnel)
            assertEquals(Review.ExclusionEvidence.UNKNOWN, compared.exclusionEvidenceFor(saved.single()))
        }
        val noReceipt = snapshot.compareWith(VpnRuntimeState(status = VpnStatus.CONNECTED))
        assertEquals(Review.ExclusionEvidence.UNKNOWN, noReceipt.exclusionEvidenceFor(saved.single()))
        val applied = snapshot.compareWith(VpnRuntimeState(status = VpnStatus.CONNECTED, tunnelReceipt = receipt))
        assertEquals(1, applied.summary.tunnel?.appliedSaved)
        assertEquals(Review.ExclusionEvidence.ACCEPTED, applied.exclusionEvidenceFor(saved.single()))
    }

    @Test
    fun separatesRejectedNewAndRemovedExclusionsAndDoesNotInferPerQueryPolicy() {
        val accepted = "com.example.accepted"
        val deleted = "com.example.deleted"
        val rejected = "com.example.rejected"
        val newlySaved = "com.example.new"
        val allowDns = "com.example.allowdns"
        val snapshot = Review.inspect(DnsResolverConfig(), DnsFirewallPolicy(appPolicies = mapOf(allowDns to AppDnsPolicy.ALLOW_ALL)),
            setOf(accepted, newlySaved, rejected), true)
        val receipt = VpnTunnelReceipt(92, 800, true, setOf(accepted, deleted), setOf(rejected))
        val compared = snapshot.compareWith(VpnRuntimeState(status = VpnStatus.PAUSED, tunnelReceipt = receipt))
        assertEquals(Review.TunnelComparison(92, 800, true, true, 1, 1, 1, 1), compared.summary.tunnel)
        assertEquals(Review.ExclusionEvidence.REJECTED, compared.exclusionEvidenceFor(rejected))
        assertEquals(Review.ExclusionEvidence.NOT_RECORDED, compared.exclusionEvidenceFor(newlySaved))
        assertEquals(Review.AppException.ACTIVE_ONLY, compared.exceptionFor(deleted))
        assertEquals(Review.ExclusionEvidence.ACCEPTED, compared.exclusionEvidenceFor(deleted))
        assertEquals(Review.AppException.ALLOW_DNS, compared.exceptionFor(allowDns))
        assertNull(compared.exclusionEvidenceFor(allowDns))
        assertNull(compared.exceptionFor("com.example.Accepted"))
        assertFalse(accepted in compared.summary.toString())
    }
}
