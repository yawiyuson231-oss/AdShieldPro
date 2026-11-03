package com.adshield.pro

import com.adshield.pro.engine.FeatureFlags
import com.adshield.pro.engine.aether.StrictHeuristicsShield
import com.adshield.pro.engine.aether.ThreatScoringModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Advanced Threat Scoring Model (v4.7.0) — deterministic, documented weights,
 * fused multi-signal scoring. Blocking remains Strict-only and threshold-gated.
 */
class AetherThreatModelTest {

    @Test
    fun dgaScore_highForRandomLabels_lowOrZeroForRealWords() {
        val dga = ThreatScoringModel.dgaScore("xkqjvbmzpqowierutasl.com")
        assertTrue("DGA string must score high, got $dga", dga > 0.6)
        // Short labels are never punished (protects real short domains)
        assertEquals(0.0, ThreatScoringModel.dgaScore("google.com"), 0.0)
        assertEquals(0.0, ThreatScoringModel.dgaScore("gcash.com"), 0.0)
        // Common-language words stay below DGA territory
        assertTrue(ThreatScoringModel.dgaScore("facebook.com") < 0.9)
        // Bigram rarity sanity: normal words are mostly common bigrams
        assertTrue(ThreatScoringModel.bigramRarity("there") < 0.5)
    }

    @Test
    fun keyboardAdjacentTypos_suspectsCaught_realWordsSafe() {
        val shield = StrictHeuristicsShield
        assertTrue(shield.keyboardTypoMatch("goohle", "google")) // h next to g
        assertTrue(shield.keyboardTypoMatch("gootle", "google")) // t next to g
        assertFalse(shield.keyboardTypoMatch("gogle", "google")) // wrong length
        assertFalse(shield.keyboardTypoMatch("goxgle", "google")) // x not adjacent to g
        assertFalse(shield.keyboardTypoMatch("google", "google")) // identical = real brand
        assertEquals("google", shield.lookalikeBrandHit("goohle.com"))
    }

    @Test
    fun fusionThresholds_observeBand_betweenAllowAndBlock() {
        // Lookalike alone: 35 → OBSERVE band (not blockable)
        val lookOnly = ThreatScoringModel.score("paypa1.com", dgaActive = false, lookalikeBrand = "paypal", ageDays = null)
        assertEquals(ThreatScoringModel.W_LOOKALIKE, lookOnly.score)
        assertEquals(ThreatScoringModel.Action.OBSERVE, lookOnly.action)

        // New domain alone: 25 → still ALLOW_OBSERVE (observe-only signal)
        val freshOnly = ThreatScoringModel.score("brand-new-site.net", dgaActive = false, lookalikeBrand = null, ageDays = 10)
        assertEquals(ThreatScoringModel.W_NEW_DOMAIN, freshOnly.score)
        assertEquals(ThreatScoringModel.Action.ALLOW_OBSERVE, freshOnly.action)

        // Aged domains contribute nothing
        assertEquals(0, ThreatScoringModel.newDomainComponent(400))

        // DGA + lookalike + fresh clears the block bar
        val fused = ThreatScoringModel.score("xkqjvbmzpqowierutasl.com", dgaActive = true, lookalikeBrand = "netflix", ageDays = 5)
        assertTrue("fused score must clear block bar, got ${fused.score}", fused.score >= ThreatScoringModel.BLOCK_THRESHOLD)
        assertEquals(ThreatScoringModel.Action.BLOCKABLE_IN_STRICT, fused.action)
    }

    @Test
    fun evaluate_usesModelBlocking_onlyInStrict() {
        // Fused signals clear the bar in Strict…
        val strict = StrictHeuristicsShield.evaluate(
            domain = "xkqjvbmzpqowierutasl.com", strictMode = true, dgaLike = true,
            lookalikeBrand = "netflix", newDomainAgeDays = 5, checkNewDomains = true
        )
        assertTrue(strict.block)
        assertTrue(strict.detail!!.contains("risk "))
        // …and NEVER block the same evidence in Balanced (observe only)
        val balanced = StrictHeuristicsShield.evaluate(
            domain = "xkqjvbmzpqowierutasl.com", strictMode = false, dgaLike = true,
            lookalikeBrand = "netflix", newDomainAgeDays = 5, checkNewDomains = true
        )
        assertFalse(balanced.block)
    }

    @Test
    fun featureFlags_documentedDefaults() {
        // Spec: new/off-by-default protections ship dark
        assertFalse(FeatureFlags.NEW_DOMAIN_CHECK_DEFAULT)
        assertFalse(FeatureFlags.RESOLVER_AUTO_TUNE_DEFAULT)
        // Established shields default on
        assertTrue(FeatureFlags.ENCRYPTED_DNS_BYPASS_SHIELD_DEFAULT)
        assertTrue(FeatureFlags.STRICT_HEURISTICS_SHIELD_DEFAULT)
        assertTrue(FeatureFlags.UNIVERSAL_AD_SKIP_DEFAULT)
        // Weights are documented and sum to 100
        assertEquals(100, ThreatScoringModel.W_DGA + ThreatScoringModel.W_LOOKALIKE + ThreatScoringModel.W_NEW_DOMAIN)
    }
}
