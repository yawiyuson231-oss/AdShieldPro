package com.adshield.pro

import com.adshield.pro.domain.model.FilterListSource
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.evolution.EvolutionRunStatus
import com.adshield.pro.engine.evolution.ProtectionEvolutionEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionEvolutionTest {
    private fun source(status: String) = FilterListSource(
        id = "source",
        name = "Test feed",
        description = "Test",
        url = "https://example.test/list.txt",
        licenseName = "Test",
        category = RuleCategory.ADS,
        isBuiltIn = false,
        isEnabled = true,
        lastStatusMessage = status
    )

    @Test
    fun healthySnapshot_reportsVerifiedRulesWithoutInventingLearning() {
        val (status, message, attention) = ProtectionEvolutionEngine.summarizeSources(
            42_000,
            listOf(source("Updated (42000 rules)"))
        )
        assertEquals(EvolutionRunStatus.SUCCESS, status)
        assertEquals(0, attention)
        assertTrue(message.contains("42000 active rules"))
        assertTrue(message.contains("atomic update"))
    }

    @Test
    fun failedRemoteSource_keepsCachedProtectionAndSurfacesWarning() {
        val (status, message, attention) = ProtectionEvolutionEngine.summarizeSources(
            39_000,
            listOf(source("Cached rules active (Update failed: HTTP 503)"))
        )
        assertEquals(EvolutionRunStatus.COMPLETED_WITH_WARNINGS, status)
        assertEquals(1, attention)
        assertTrue(message.contains("Cached or bundled rules remain active"))
    }

    @Test
    fun bundledFallback_isNotReportedAsSuccessfulRemoteUpdate() {
        val (status, _, attention) = ProtectionEvolutionEngine.summarizeSources(
            10_000,
            listOf(source("Bundled fallback active (network unavailable)"))
        )
        assertEquals(EvolutionRunStatus.COMPLETED_WITH_WARNINGS, status)
        assertEquals(1, attention)
    }
}
