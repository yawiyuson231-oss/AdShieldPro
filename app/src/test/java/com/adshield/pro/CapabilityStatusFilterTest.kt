package com.adshield.pro

import com.adshield.pro.engine.platform.CapabilityRegistry
import com.adshield.pro.engine.platform.CapabilityStatus
import com.adshield.pro.ui.model.CapabilityStatusFilter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilityStatusFilterTest {
    private val all = CapabilityRegistry.capabilities

    @Test fun emptySearchShowsEveryFeature() {
        assertEquals(all, CapabilityStatusFilter.filter(all, "  ", null))
    }

    @Test fun eachStatusFilterMatchesTheRegistry() {
        CapabilityStatus.entries.forEach { status ->
            assertEquals(all.filter { it.status == status }, CapabilityStatusFilter.filter(all, "", status))
        }
    }

    @Test fun searchIsCaseInsensitiveAndCombinesWithStatus() {
        val capability = all.first()
        val results = CapabilityStatusFilter.filter(all, "  ${capability.name.uppercase()}  ", capability.status)
        assertTrue(results.contains(capability))
        assertTrue(results.all { it.status == capability.status })
        assertTrue(CapabilityStatusFilter.filter(all, "no such feature 987654321", null).isEmpty())
    }

    @Test fun searchMatchesAreaAndLimitations() {
        val capability = all.first()
        assertTrue(CapabilityStatusFilter.filter(all, capability.area.label, null).contains(capability))
        assertTrue(CapabilityStatusFilter.filter(all, capability.limitations.first(), null).contains(capability))
    }
}
