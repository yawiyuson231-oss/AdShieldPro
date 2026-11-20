package com.adshield.pro

import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.engine.intelligence.SecurityConfigurationChanges
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.BoundedAuditCache
import com.adshield.pro.engine.security.EvolutionWorkPolicy
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EvolutionSafetyTest {
    private val healthy = EvolutionWorkPolicy.Conditions(
        lowMemory = false, availableRamBytes = 1024L * 1024 * 1024, batteryPercent = 80,
        severeThermal = false, appCpuFraction = 0.1, freeStorageBytes = 1024L * 1024 * 1024,
        networkValidated = true, networkMetered = false
    )

    @Test
    fun healthyReadingsAllowBoundedWorkNotUnlimitedResourceUse() {
        val plan = EvolutionWorkPolicy.plan(healthy)
        assertEquals(16, plan.batchSize)
        assertEquals(0L, plan.yieldMillis)
        assertEquals(128, plan.cacheEntries)
        assertTrue(plan.optionalResearchSyncAllowed)
        assertTrue(plan.essentialProtectionEnabled)
    }

    @Test
    fun missingAndAdverseReadingsNeverDisableEssentialProtection() {
        val cases = listOf(EvolutionWorkPolicy.Conditions(), healthy.copy(lowMemory = true),
            healthy.copy(batteryPercent = 3), healthy.copy(severeThermal = true),
            healthy.copy(appCpuFraction = 0.99), healthy.copy(availableRamBytes = 0),
            healthy.copy(appCpuFraction = Double.NaN), healthy.copy(batteryPercent = -1))
        for (conditions in cases) {
            val plan = EvolutionWorkPolicy.plan(conditions)
            assertTrue(plan.essentialProtectionEnabled)
            assertTrue(plan.batchSize in 1..16)
            assertTrue(plan.yieldMillis in 0L..50L)
            assertFalse(plan.optionalResearchSyncAllowed)
        }
    }

    @Test
    fun lowMemoryAndStorageAvoidCachingAndMeteredNetworksAvoidOptionalSync() {
        assertEquals(0, EvolutionWorkPolicy.plan(healthy.copy(lowMemory = true)).cacheEntries)
        assertEquals(0, EvolutionWorkPolicy.plan(healthy.copy(freeStorageBytes = 1)).cacheEntries)
        assertFalse(EvolutionWorkPolicy.plan(healthy.copy(networkMetered = true)).optionalResearchSyncAllowed)
        assertFalse(EvolutionWorkPolicy.plan(healthy.copy(networkValidated = null)).optionalResearchSyncAllowed)
    }

    @Test
    fun pacingAlwaysCompletesEveryItemUnderAllResourcePlans() {
        for (conditions in listOf(healthy, EvolutionWorkPolicy.Conditions(), healthy.copy(batteryPercent = 1))) {
            val plan = EvolutionWorkPolicy.plan(conditions)
            val inspected = mutableListOf<Int>()
            // Policy can change chunk boundaries, not coverage or ordering.
            (0 until 257).chunked(plan.batchSize).forEach { inspected.addAll(it) }
            assertEquals((0 until 257).toList(), inspected)
        }
    }

    @Test
    fun incrementalMetadataCacheUsesFullPermissionInputNotFileTimestamps() {
        val cache = BoundedAuditCache<AppRiskAuditor.AppSecurityProfile, AppRiskAuditor.AppRiskAudit>()
        val auditor = AppRiskAuditor()
        val clean = AppRiskAuditor.AppSecurityProfile("fixture.test", "Fixture", "1", 36,
            emptyList(), "com.android.vending", false)
        val changed = clean.copy(requestedPermissions = listOf("android.permission.RECEIVE_SMS"),
            declaredComponentPermissions = setOf("android.permission.BIND_ACCESSIBILITY_SERVICE"))
        var computations = 0
        fun audit(profile: AppRiskAuditor.AppSecurityProfile) = cache.getOrCompute(profile, 16) {
            computations++
            auditor.audit(profile)
        }
        assertEquals(0, audit(clean).riskScore)
        assertEquals(0, audit(clean).riskScore)
        assertTrue(audit(changed).riskScore >= 55)
        assertEquals(2, computations)
    }

    @Test
    fun cacheEvictsAndDoesNotRememberFailuresOrZeroCapacityEntries() {
        val cache = BoundedAuditCache<String, Int>()
        var computations = 0
        fun value(key: String, capacity: Int) = cache.getOrCompute(key, capacity) { ++computations }
        assertEquals(1, value("a", 1))
        assertEquals(1, value("a", 1))
        assertEquals(2, value("b", 1))
        assertEquals(3, value("a", 1))
        assertEquals(4, value("a", 0))
        assertEquals(5, value("a", 1))
        try { cache.getOrCompute("failed", 1) { error("fixture failure") } } catch (_: IllegalStateException) { }
        assertEquals(6, value("failed", 1))
    }

    @Test
    fun savedConfigurationHistoryDoesNotExposeEndpointsPackagesOrInventNetworkTrust() {
        val before = AppSettingsState()
        val after = before.copy(resolverConfig = before.resolverConfig.copy(customDotHost = "private.resolver.test"),
            excludedAppPackages = setOf("private.package.name"), cnameUncloakingEnabled = false,
            dnsFirewallPolicy = DnsFirewallPolicy(protectedTransports = setOf(NetworkTransportPolicy.WIFI)))
        val changes = SecurityConfigurationChanges.changedControls(before, after)
        assertEquals(listOf("resolver configuration", "alias inspection", "application exclusions", "network filtering scope"), changes)
        assertFalse(changes.joinToString().contains("private"))
        assertTrue(SecurityConfigurationChanges.changedControls(before, before).isEmpty())
        assertTrue(SecurityConfigurationChanges.changedControls(before,
            before.copy(dnsFirewallPolicy = before.dnsFirewallPolicy.copy(emergencyAllowlistOnly = true))).isEmpty())
    }

    @Test
    fun scanScheduleRestorationNoLongerRequiresDashboardCreation() {
        val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "app/src/main/java/com/adshield/pro/AdShieldApplication.kt").isFile }
        val application = File(root, "app/src/main/java/com/adshield/pro/AdShieldApplication.kt").readText()
        val viewModel = File(root, "app/src/main/java/com/adshield/pro/ui/viewmodel/AdShieldViewModel.kt").readText()
        assertEquals(1, Regex("ScheduledScanWorker\\.scheduleOrCancel\\(").findAll(application).count())
        // Keep the explicit user's setting-change path, not duplicate startup scheduling.
        assertEquals(1, Regex("ScheduledScanWorker\\.scheduleOrCancel\\(").findAll(viewModel).count())
        assertTrue(viewModel.lastIndexOf("private val _") < viewModel.indexOf("    init {"))
        assertTrue(application.contains("settings.scheduledScanEnabled, settings.scheduledScanIntervalHours"))
    }
}
