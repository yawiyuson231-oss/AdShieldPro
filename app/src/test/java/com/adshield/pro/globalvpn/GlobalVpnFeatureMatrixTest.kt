package com.adshield.pro.globalvpn

import com.adshield.pro.globalvpn.model.AvailabilityStatus
import com.adshield.pro.globalvpn.model.GlobalVpnFeatureMatrix
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class GlobalVpnFeatureMatrixTest {

    private fun statusOf(feature: String): AvailabilityStatus {
        val entry = GlobalVpnFeatureMatrix.features.firstOrNull { it.feature == feature }
        assertNotNull("Missing feature entry: $feature", entry)
        return entry!!.status
    }

    @Test
    fun wireGuardTunnelIsReal() {
        assertEquals(AvailabilityStatus.IMPLEMENTED, statusOf("Real WireGuard tunnel"))
    }

    @Test
    fun windscribeFreeIsHonestlyUnavailable() {
        assertEquals(AvailabilityStatus.UNAVAILABLE, statusOf("Windscribe (free)"))
    }

    @Test
    fun openVpnEngineIsHonestlyUnavailable() {
        assertEquals(AvailabilityStatus.UNAVAILABLE, statusOf("In-app OpenVPN tunnel engine"))
    }

    @Test
    fun quantumIsNotFaked() {
        assertEquals(AvailabilityStatus.UNAVAILABLE, statusOf("Quantum-resistant cryptography"))
    }

    @Test
    fun multiHopIsNotFaked() {
        assertEquals(AvailabilityStatus.UNAVAILABLE, statusOf("Multi-hop VPN"))
    }

    @Test
    fun aiIsLabelledHeuristicNotImplementedMl() {
        assertEquals(AvailabilityStatus.PARTIAL, statusOf("Adaptive / 'AI-assisted' recommendation"))
    }

    @Test
    fun everyFeatureHasADetail() {
        GlobalVpnFeatureMatrix.features.forEach { feature ->
            assertNotNull(feature.detail)
            assertEquals(true, feature.detail.isNotBlank())
        }
    }
}
