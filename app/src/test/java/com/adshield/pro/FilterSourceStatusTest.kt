package com.adshield.pro

import com.adshield.pro.engine.filter.FilterSourceStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A trimmed list must say so where the user manages it, in plain wording.
 */
class FilterSourceStatusTest {

    @Test
    fun testAPlainSourceKeepsItsShortStatus() {
        assertEquals(
            "Updated (1200 rules)",
            FilterSourceStatus.describe("Updated", validRules = 1200, duplicateCount = 0, rejectedUnsafeRules = 0)
        )
    }

    @Test
    fun testRefusedPlaybackUnsafeLinesAreReported() {
        val status = FilterSourceStatus.describe(
            "Updated",
            validRules = 1200,
            duplicateCount = 0,
            rejectedUnsafeRules = 3
        )
        assertTrue(status, status.contains("3 unsafe lines ignored"))
        assertTrue(status, status.startsWith("Updated (1200 rules; "))
    }

    @Test
    fun testDuplicatesAndUnsafeLinesAreBothReported() {
        assertEquals(
            "Bundled Active (980 rules; 12 duplicates, 1 unsafe line ignored)",
            FilterSourceStatus.describe("Bundled Active", 980, duplicateCount = 12, rejectedUnsafeRules = 1)
        )
    }

    @Test
    fun testSingularWording() {
        assertEquals(
            "Updated (2 rules; 1 duplicate)",
            FilterSourceStatus.describe("Updated", 2, duplicateCount = 1, rejectedUnsafeRules = 0)
        )
        assertEquals("Updated (1 rule)", FilterSourceStatus.describe("Updated", 1, 0, 0))
    }

    @Test
    fun testTheStatusNeverClaimsPlaybackWasBlocked() {
        val status = FilterSourceStatus.describe("Updated", 5, duplicateCount = 0, rejectedUnsafeRules = 9)
        assertFalse("status must not claim playback was blocked: $status", status.contains("blocked", ignoreCase = true))
        assertTrue(status.contains("ignored"))
    }
}
