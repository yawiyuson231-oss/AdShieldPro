package com.adshield.pro

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.ui.model.BlockReasonExplainer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The "why was this blocked?" dialog may only name a component the engine actually has, and may
 * only promise an action that exists.
 */
class BlockReasonExplainerTest {

    @Test
    fun testEveryEngineSourceIsExplainedByTheComponentThatDecided() {
        val cases = mapOf(
            "Video ad infrastructure" to "video-ad baseline",
            "CNAME cloaking guard" to "CNAME",
            "DNS rebinding guard" to "private address",
            "Emergency Allowlist-Only DNS" to "Emergency",
            "Per-App DNS Block" to "block all",
            "System Safety Allowlist" to "safety list",
            "Per-App DNS Filter Bypass" to "allow all DNS",
            "Paused (Passthrough)" to "paused",
            "Network Policy Passthrough (Wi-Fi)" to "passthrough",
            "User Blocklist" to "blocklist",
            "Temporary allow" to "temporary lease"
        )
        cases.forEach { (source, expected) ->
            val explanation = BlockReasonExplainer.explain(
                sourceName = source,
                matchedRule = "example.com",
                category = RuleCategory.ADS,
                isBlocked = true
            )
            assertTrue(
                "$source must be explained in terms of itself, was: ${explanation.title} / ${explanation.body}",
                explanation.title.contains(expected, ignoreCase = true) ||
                    explanation.body.contains(expected, ignoreCase = true)
            )
            assertTrue("$source must suggest an action", explanation.action.isNotBlank())
        }
    }

    @Test
    fun testTheBaselineExplanationKeepsItsHonestBoundary() {
        val explanation = BlockReasonExplainer.explain(
            sourceName = "Video ad infrastructure",
            matchedRule = "doubleclick.net",
            category = RuleCategory.ADS,
            isBlocked = true
        )
        assertTrue(explanation.body.contains("doubleclick.net"))
        assertTrue("must say it works without lists", explanation.body.contains("no filter list"))
        assertTrue("must not imply playback zones are blocked", explanation.body.contains("playback"))
        assertTrue(explanation.isBlock)
    }

    @Test
    fun testRebindingExplanationSaysServfailBecauseTheNameExists() {
        val explanation = BlockReasonExplainer.explain(
            sourceName = "DNS rebinding guard",
            matchedRule = "192.168.1.1 (private (RFC 1918))",
            category = RuleCategory.MALWARE,
            isBlocked = true
        )
        assertTrue(explanation.body.contains("SERVFAIL"))
        assertTrue(explanation.body.contains("192.168.1.1"))
    }

    @Test
    fun testAllowedRowsAreNotDescribedAsBlocks() {
        listOf("System Safety Allowlist", "Paused (Passthrough)", "Network Policy Passthrough (Wi-Fi)").forEach { source ->
            val explanation = BlockReasonExplainer.explain(source, null, null, isBlocked = false)
            assertFalse("$source must not claim a block", explanation.isBlock)
            assertTrue(explanation.action.isNotBlank())
        }
    }

    @Test
    fun testATemporaryAllowIsNeverDescribedAsABlock() {
        val explanation = BlockReasonExplainer.explain(
            sourceName = "Temporary allow",
            matchedRule = "doubleclick.net (temporary allow, 14m left)",
            category = null,
            isBlocked = false
        )
        assertFalse("a lease is not a block", explanation.isBlock)
        assertTrue(explanation.body.contains("bounded"))
        assertTrue("the overridden rule must survive", explanation.body.contains("doubleclick.net"))
        assertTrue("the lease must be described as self-ending", explanation.body.contains("ends"))
    }

    @Test
    fun testAnUnknownListNameIsReportedAsAListName() {
        val explanation = BlockReasonExplainer.explain(
            sourceName = "Some Third-Party List",
            matchedRule = "||ads.example^",
            category = RuleCategory.TRACKERS,
            isBlocked = true
        )
        assertEquals("Blocked by Some Third-Party List", explanation.title)
        assertTrue(explanation.body.contains("Some Third-Party List"))
        assertTrue("the category must survive", explanation.body.contains("Tracking"))
        assertTrue("the rule must survive", explanation.body.contains("||ads.example^"))
    }

    @Test
    fun testAWholeRecordMapsThrough() {
        val record = DnsActivityRecord(
            timestampEpochMs = 1_700_000_000_000L,
            domain = "securepubads.g.doubleclick.net",
            queryType = "A",
            isBlocked = true,
            category = RuleCategory.ADS,
            matchedRule = "doubleclick.net",
            sourceList = "Video ad infrastructure",
            latencyMs = 0,
            protocolUsed = "Sinkhole 0.0.0.0"
        )
        val explanation = BlockReasonExplainer.explain(record)
        assertTrue(explanation.title.contains("video-ad baseline"))
        assertTrue(explanation.body.contains("doubleclick.net"))
    }
}
