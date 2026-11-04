package com.adshield.pro

import com.adshield.pro.engine.aether.AetherExplainer
import com.adshield.pro.engine.aether.AetherSelfAudit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AETHER Agent Upgrade (v4.6.0): self-auditing false-positive radar + explainer.
 * The agent must audit its own decisions with REAL evidence and explain every
 * verdict using only facts present in that verdict — nothing invented.
 */
class AetherAgentUpgradeTest {

    @Test
    fun radar_flagsRepeatedHeuristicBlocks_andProtectedDomains_only() {
        val events = listOf(
            // 4x heuristic-shield blocks of one domain → must surface
            Pair("secure-login.example-info.xyz", "Heuristic Shield (Strict)"),
            Pair("secure-login.example-info.xyz", "Heuristic Shield (Strict)"),
            Pair("secure-login.example-info.xyz", "Heuristic Shield (Strict)"),
            Pair("secure-login.example-info.xyz", "Heuristic Shield (Strict)"),
            // 3x blocks of a PROTECTED domain (engine misfire scenario) → must surface
            Pair("auth.provider-example.net", "HaGeZi Pro"),
            Pair("accounts.google.com", "Heuristic Shield (Strict)"),
            Pair("accounts.google.com", "Heuristic Shield (Strict)"),
            Pair("accounts.google.com", "Heuristic Shield (Strict)"),
            // 5x blocks of a normal ad domain from a FEED → must NOT surface
            Pair("ads.doubleclick.net", "HaGeZi Pro"),
            Pair("ads.doubleclick.net", "HaGeZi Pro"),
            Pair("ads.doubleclick.net", "HaGeZi Pro"),
            Pair("ads.doubleclick.net", "HaGeZi Pro"),
            Pair("ads.doubleclick.net", "HaGeZi Pro"),
            // 2x heuristic block (below threshold) → must NOT surface
            Pair("once-twice.example.com", "Heuristic Shield (Strict)"),
            Pair("once-twice.example.com", "Heuristic Shield (Strict)")
        )
        val radar = AetherSelfAudit.possibleFalsePositives(events)
        assertTrue("heuristic-repeat must be flagged", radar.any { it.startsWith("secure-login.example-info.xyz") })
        assertTrue("protected-domain repeat must be flagged", radar.any { it.startsWith("accounts.google.com") })
        assertFalse("feed ad blocks must never be flagged", radar.any { it.contains("doubleclick") })
        assertFalse("sub-threshold must not be flagged", radar.any { it.contains("once-twice") })
        assertTrue("ranked entry includes count", radar.first().contains("×"))
    }

    @Test
    fun radar_emptyAndBlankInputs_safe() {
        assertTrue(AetherSelfAudit.possibleFalsePositives(emptyList()).isEmpty())
        assertTrue(AetherSelfAudit.possibleFalsePositives(listOf(Pair("", "Heuristic Shield (Strict)"))).isEmpty())
    }

    @Test
    fun registrableBase_handlesPhThreeLevel() {
        assertEquals("bdo.com.ph", AetherSelfAudit.registrableBase("www.bdo.com.ph"))
        assertEquals("google.com", AetherSelfAudit.registrableBase("accounts.google.com"))
        assertEquals("example.com", AetherSelfAudit.registrableBase("example.com"))
    }

    @Test
    fun explainer_statesOnlyRealFacts_andAlwaysOffersAllow() {
        val blocked = AetherExplainer.explain(
            domain = "ads.example.com",
            isBlocked = true,
            category = "ADS",
            sourceList = "HaGeZi Pro",
            matchedRule = "||ads.example.com^"
        )
        assertTrue(blocked.contains("ads.example.com"))
        assertTrue(blocked.contains("ADS"))
        assertTrue(blocked.contains("HaGeZi Pro"))
        assertTrue(blocked.contains("||ads.example.com^"))
        assertTrue(blocked.contains("Allow"))

        val blockedNoMeta = AetherExplainer.explain("mystery.example", true, null, null, null)
        assertFalse("must not fabricate a category", blockedNoMeta.contains("type:"))
        assertFalse("must not fabricate a source", blockedNoMeta.contains("detected by"))
        assertTrue(blockedNoMeta.contains("mystery.example"))

        val allowed = AetherExplainer.explain("youtube.com", false, null, null, null)
        assertTrue(allowed.startsWith("Allowed youtube.com"))
    }
}
