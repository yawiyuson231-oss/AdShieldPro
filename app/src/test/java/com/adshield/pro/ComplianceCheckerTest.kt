package com.adshield.pro

import com.adshield.pro.engine.compliance.ComplianceChecker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Compliance honesty contract: unreadable signals are UNKNOWN (never passes), the score only
 * counts evaluated checks, and the exported report explicitly disclaims certification.
 */
class ComplianceCheckerTest {

    private val now = 1_700_000_000_000L // 2023-11-14

    private fun signals(
        screenLock: Boolean? = true,
        encrypted: Boolean? = true,
        adb: Boolean? = false,
        devOptions: Boolean? = false,
        patch: String? = "2023-10-01",
        vpn: Boolean = true,
        signatures: Int = 50_000,
        autoUpdate: Boolean = true,
        lastFilterUpdate: Long = now - 3_600_000L,
        bundled: Boolean = true,
        scheduledScan: Boolean = true,
        retention: Int = 7,
        highRisk: Int? = 0,
        canInstall: Boolean? = false
    ) = ComplianceChecker.DeviceSecuritySignals(
        deviceLabel = "Test Device",
        androidRelease = "14",
        sdkInt = 34,
        securityPatchLevel = patch,
        screenLockEnabled = screenLock,
        storageEncrypted = encrypted,
        adbEnabled = adb,
        developerOptionsEnabled = devOptions,
        vpnActive = vpn,
        threatSignatureCount = signatures,
        autoUpdateFiltersEnabled = autoUpdate,
        lastFilterUpdateEpochMs = lastFilterUpdate,
        bundledBaselineAvailable = bundled,
        scheduledScanEnabled = scheduledScan,
        detailedDnsLoggingEnabled = true,
        logRetentionDays = retention,
        highRiskAppCount = highRisk,
        appCanInstallUnknownSources = canInstall
    )

    @Test
    fun fullyHardenedDevice_passesAllEvaluatedChecks() {
        val report = ComplianceChecker.evaluate(signals(), nowEpochMs = now)
        assertTrue(report.checks.all { it.status == ComplianceChecker.CheckStatus.PASS })
        assertEquals(100, report.scorePercent)
        assertEquals(0, report.unknownCount)
        assertEquals(4, report.categories.size)
    }

    @Test
    fun unreadableSignals_areUnknownAndExcludedFromScore() {
        val report = ComplianceChecker.evaluate(
            signals(screenLock = null, encrypted = null, adb = null, devOptions = null, patch = null, highRisk = null, canInstall = null),
            nowEpochMs = now
        )
        val unknownIds = report.checks.filter { it.status == ComplianceChecker.CheckStatus.UNKNOWN }.map { it.id }
        assertTrue(unknownIds.containsAll(listOf("device-screen-lock", "device-encryption", "device-adb", "device-dev-options", "device-security-patch", "privacy-app-risk", "privacy-unknown-sources")))
        assertEquals(7, report.unknownCount)
        // Score is computed only over evaluated checks.
        val evaluated = report.checks.count { it.status != ComplianceChecker.CheckStatus.UNKNOWN }
        val passed = report.checks.count { it.status == ComplianceChecker.CheckStatus.PASS }
        assertEquals(Math.round(passed * 100f / evaluated), report.scorePercent)
    }

    @Test
    fun failingChecks_lowerTheScoreAndCarryRecommendations() {
        val report = ComplianceChecker.evaluate(
            signals(screenLock = false, vpn = false, adb = true, retention = 30, highRisk = 3),
            nowEpochMs = now
        )
        val fails = report.checks.filter { it.status == ComplianceChecker.CheckStatus.FAIL }
        assertTrue(fails.any { it.id == "device-screen-lock" })
        assertTrue(fails.any { it.id == "network-dns-filtering" })
        assertTrue(fails.any { it.id == "device-adb" })
        assertTrue(fails.any { it.id == "data-retention" })
        assertTrue(fails.any { it.id == "privacy-app-risk" })
        assertTrue(fails.all { it.recommendation != null })
        assertTrue(report.scorePercent!! < 100)
    }

    @Test
    fun staleSecurityPatch_fails_butRecentPatchPasses() {
        val old = ComplianceChecker.evaluate(signals(patch = "2022-01-01"), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.FAIL, old.checks.first { it.id == "device-security-patch" }.status)
        val recent = ComplianceChecker.evaluate(signals(patch = "2023-10-01"), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.PASS, recent.checks.first { it.id == "device-security-patch" }.status)
    }

    @Test
    fun unparseablePatchString_isUnknownNotPass() {
        val report = ComplianceChecker.evaluate(signals(patch = "not-a-date"), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.UNKNOWN, report.checks.first { it.id == "device-security-patch" }.status)
    }

    @Test
    fun neverSyncedFilters_passOnlyWhenBundledBaselineExists() {
        val withBaseline = ComplianceChecker.evaluate(signals(lastFilterUpdate = 0, bundled = true), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.PASS, withBaseline.checks.first { it.id == "network-filter-freshness" }.status)
        val withoutBaseline = ComplianceChecker.evaluate(signals(lastFilterUpdate = 0, bundled = false), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.UNKNOWN, withoutBaseline.checks.first { it.id == "network-filter-freshness" }.status)
        val staleSync = ComplianceChecker.evaluate(signals(lastFilterUpdate = now - 72 * 3_600_000L), nowEpochMs = now)
        assertEquals(ComplianceChecker.CheckStatus.FAIL, staleSync.checks.first { it.id == "network-filter-freshness" }.status)
    }

    @Test
    fun neverAuditedApps_isUnknownNeverClean() {
        val report = ComplianceChecker.evaluate(signals(highRisk = null), nowEpochMs = now)
        val check = report.checks.first { it.id == "privacy-app-risk" }
        assertEquals(ComplianceChecker.CheckStatus.UNKNOWN, check.status)
        assertTrue(check.detail.contains("unknown"))
    }

    @Test
    fun categoryRings_reflectOnlyTheirOwnChecks() {
        val report = ComplianceChecker.evaluate(signals(vpn = false), nowEpochMs = now)
        val network = report.categories.first { it.category == ComplianceChecker.Category.NETWORK }
        assertEquals(1, network.failed)
        val device = report.categories.first { it.category == ComplianceChecker.Category.DEVICE }
        assertEquals(0, device.failed)
        assertNotNull(device.passRatio)
        assertEquals(1f, device.passRatio!!, 0.0001f)
    }

    @Test
    fun textReport_disclaimsCertificationAndListsEveryCheck() {
        val report = ComplianceChecker.evaluate(signals(), nowEpochMs = now)
        val text = ComplianceChecker.buildTextReport(report, "2.8.0")
        assertTrue(text.contains("NOT an ISO 27001"))
        assertTrue(text.contains("SOC 2"))
        assertTrue(text.contains("Test Device"))
        report.checks.forEach { check ->
            assertTrue("report must list ${check.id}", text.contains(check.title))
        }
        assertTrue(text.contains("UNKNOWN means the signal was unavailable"))
    }

    @Test
    fun emptyEvaluation_neverFabricatesAPerfectScore() {
        val allUnknown = ComplianceChecker.evaluate(
            signals(
                screenLock = null, encrypted = null, adb = null, devOptions = null, patch = null,
                vpn = false, signatures = 0, autoUpdate = false, lastFilterUpdate = 0, bundled = false,
                scheduledScan = false, retention = 99, highRisk = null, canInstall = null
            ),
            nowEpochMs = now
        )
        // Even with everything unknown there are still evaluated FAILs; score must not be 100.
        assertFalse(allUnknown.scorePercent == 100)
        assertNull(allUnknown.categories.first { it.category == ComplianceChecker.Category.DEVICE }.passRatio)
    }
}
