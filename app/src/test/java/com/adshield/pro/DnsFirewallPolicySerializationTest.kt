package com.adshield.pro

import com.adshield.pro.domain.model.DnsFirewallPolicy
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Settings are stored as JSON, so a new field must survive a round trip and must not break the
 * settings a user already has on disk.
 */
class DnsFirewallPolicySerializationTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Test
    fun testVideoAdBaselineDefaultsToEnabled() {
        assertTrue(DnsFirewallPolicy().videoAdBaselineEnabled)
    }

    @Test
    fun testRoundTripKeepsTheBaselineSwitchedOff() {
        val policy = DnsFirewallPolicy(videoAdBaselineEnabled = false)
        val decoded = json.decodeFromString<DnsFirewallPolicy>(json.encodeToString(policy))
        assertFalse(decoded.videoAdBaselineEnabled)
        assertEquals(policy.protectedTransports, decoded.protectedTransports)
    }

    @Test
    fun testSettingsWrittenBeforeTheFieldExistedStillDecode() {
        val legacy = """{"appPolicies":{},"protectedTransports":["WIFI"],"emergencyAllowlistOnly":false}"""
        val decoded = json.decodeFromString<DnsFirewallPolicy>(legacy)
        assertTrue("an older settings blob must gain the default", decoded.videoAdBaselineEnabled)
        assertEquals(1, decoded.protectedTransports.size)
    }
}
