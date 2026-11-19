package com.adshield.pro

import com.adshield.pro.domain.model.VpnExclusionSetup
import com.adshield.pro.domain.model.VpnStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class VpnExclusionSetupTest {
    @Test
    fun routeAndExclusionEditsCanInvalidatePendingOrInstalledTunnels() {
        assertEquals(
            setOf(VpnStatus.STARTING, VpnStatus.CONNECTED, VpnStatus.RECONNECTING, VpnStatus.PAUSED),
            VpnStatus.entries.filter { it.acceptsTunnelConfigReload }.toSet()
        )
    }

    @Test
    fun recordsOnlyActualUserExclusionAttemptsWithoutCountingTheAppItself() {
        val calls = mutableListOf<String>()
        val saved = linkedSetOf("com.adshield.pro.debug", " ", "com.example.first", "com.example.missing")
        val setup = VpnExclusionSetup.collect(saved, "com.adshield.pro.debug") { packageId ->
            calls.add(packageId)
            packageId != "com.example.missing"
        }
        assertEquals(listOf("com.example.first", "com.example.missing"), calls)
        assertEquals(setOf("com.example.first"), setup.accepted)
        assertEquals(setOf("com.example.missing"), setup.rejected)
    }
}
