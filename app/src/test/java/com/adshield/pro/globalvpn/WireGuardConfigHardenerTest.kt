package com.adshield.pro.globalvpn

import com.adshield.pro.globalvpn.engine.WireGuardConfigHardener
import com.adshield.pro.globalvpn.model.SplitTunnelMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WireGuardConfigHardenerTest {

    private val sample = """
        [Interface]
        PrivateKey = abcdef
        Address = 10.0.0.2/32
        DNS = 9.9.9.9

        [Peer]
        PublicKey = xyz
        AllowedIPs = 10.0.0.0/24
        Endpoint = example.com:51820
    """.trimIndent()

    @Test
    fun parsesEndpoint() {
        val endpoint = WireGuardConfigHardener.endpointOf(sample)
        assertEquals("example.com", endpoint?.first)
        assertEquals(51820, endpoint?.second)
    }

    @Test
    fun detectsNoIpv6() {
        assertFalse(WireGuardConfigHardener.hasIpv6Address(sample))
    }

    @Test
    fun hardenForcesFullTunnelAndDns() {
        val hardened = WireGuardConfigHardener.harden(
            original = sample,
            leakProtection = true,
            blockIpv6WhenUnsupported = true,
            dnsServers = emptyList(),
            splitMode = SplitTunnelMode.OFF,
            splitPackages = emptySet()
        )
        assertTrue(hardened.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        assertTrue(hardened.contains("DNS = 1.1.1.1, 1.0.0.1"))
        assertFalse(hardened.contains("9.9.9.9"))
    }

    @Test
    fun hardenAppliesExcludedApps() {
        val hardened = WireGuardConfigHardener.harden(
            original = sample,
            leakProtection = false,
            blockIpv6WhenUnsupported = true,
            dnsServers = emptyList(),
            splitMode = SplitTunnelMode.EXCLUDE_SELECTED,
            splitPackages = setOf("com.example.app")
        )
        assertTrue(hardened.contains("ExcludedApplications = com.example.app"))
    }

    @Test
    fun hardenKeepsOriginalRoutingWhenLeakProtectionOff() {
        val hardened = WireGuardConfigHardener.harden(
            original = sample,
            leakProtection = false,
            blockIpv6WhenUnsupported = true,
            dnsServers = emptyList(),
            splitMode = SplitTunnelMode.OFF,
            splitPackages = emptySet()
        )
        assertTrue(hardened.contains("AllowedIPs = 10.0.0.0/24"))
    }
}
