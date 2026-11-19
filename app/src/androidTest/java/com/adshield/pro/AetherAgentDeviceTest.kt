package com.adshield.pro

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToKey
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.service.AdShieldVpnService
import com.adshield.pro.ui.viewmodel.AdShieldViewModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Runs against the real debug application on the clean, offline CI emulator. */
@RunWith(AndroidJUnit4::class)
class AetherAgentDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val app get() = instrumentation.targetContext.applicationContext as AdShieldApplication

    @Test
    fun realReviewRequiresApprovalRunsOfflineAndClearsOnLeave() {
        val state = appViewModel()
        assertEquals(VpnStatus.DISCONNECTED, state.vpnState.value.status)
        assertNoValidatedNetwork()
        val before = savedSettings()
        val history = state.securityHistory.value
        openAgent()
        requestReview()
        compose.onNodeWithText("Run review").assertIsDisplayed()
        compose.onNodeWithText("Cancel").performClick()
        assertNoReviewResult()

        requestReview()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Run review").assertDoesNotExist()
        assertNoReviewResult()

        requestReview()
        approveAndWaitForReview()
        compose.onNodeWithText("Phone protection:", substring = true).assertExists()
        compose.onNodeWithText("Saved DNS policy: Read").assertExists()
        compose.onNodeWithText("visible apps inspected", substring = true).assertExists()
        scrollReview("review-tunnel")
        compose.onNodeWithText("Applied state unknown: no current tunnel setup receipt.").assertExists()
        val after = savedSettings()
        assertEquals(before.resolverConfig, after.resolverConfig)
        assertEquals(before.dnsFirewallPolicy, after.dnsFirewallPolicy)
        assertEquals(before.excludedAppPackages, after.excludedAppPackages)
        assertEquals(before.cnameUncloakingEnabled, after.cnameUncloakingEnabled)
        assertEquals(before.vpnShouldRemainActive, after.vpnShouldRemainActive)
        assertEquals(history, state.securityHistory.value)

        compose.onNodeWithText("Shield").performClick()
        compose.onNodeWithText("AI Agent").performClick()
        assertNoReviewResult()
    }

    @Test
    fun realPreviewWorksOfflineAndRefusesASelectionRemovedAfterOpeningThePicker() {
        val state = appViewModel()
        assertEquals(VpnStatus.DISCONNECTED, state.vpnState.value.status)
        assertNoValidatedNetwork()
        val original = savedSettings()
        check(original.excludedAppPackages.isEmpty()) { "Use a fresh debug install on a disposable emulator." }
        val target = "com.android.settings"
        val other = "com.adshield.test.preview.notinstalled"
        val prefs = app.preferencesRepository
        openAgent()
        openVpnPreview()
        awaitText("No saved app exclusions are available to preview.")
        closeVpnPreview()

        try {
            runBlocking { withTimeout(8_000) {
                prefs.toggleExcludedAppPackage(target, true)
                prefs.toggleExcludedAppPackage(other, true)
                prefs.updateDnsFirewallPolicy(original.dnsFirewallPolicy.copy(
                    appPolicies = mapOf(target to AppDnsPolicy.BLOCK_ALL, other to AppDnsPolicy.ALLOW_ALL),
                    protectedTransports = setOf(NetworkTransportPolicy.WIFI),
                    emergencyAllowlistOnly = false
                ))
            } }
            val before = savedSettings()
            val history = state.securityHistory.value
            openVpnPreview()
            selectPreviewTarget(target)
            awaitText("VPN exclusion: Saved → Removed")
            compose.onNodeWithText("Per-app DNS rule: Block all DNS for this app → Use global protection").assertExists()
            scrollVpnPreview("preview-tunnel")
            compose.onNodeWithText("Unknown: no current setup receipt").assertExists()
            scrollVpnPreview("preview-network:WIFI")
            compose.onNodeWithText("Saved: Blocked · Per-App DNS Block\nFiltered: Not blocked at this step").assertExists()
            assertEquals(VpnStatus.DISCONNECTED, state.vpnState.value.status)
            val after = savedSettings()
            assertEquals(before.excludedAppPackages, after.excludedAppPackages)
            assertEquals(before.dnsFirewallPolicy, after.dnsFirewallPolicy)
            assertEquals(before.vpnShouldRemainActive, after.vpnShouldRemainActive)
            assertEquals(before.resolverConfig, after.resolverConfig)
            assertEquals(history, state.securityHistory.value)

            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
            compose.onNodeWithText("Filtered mode preview").assertDoesNotExist()

            openVpnPreview()
            revealPreviewTarget(target)
            runBlocking { withTimeout(8_000) { prefs.toggleExcludedAppPackage(target, false) } }
            compose.onNodeWithTag("preview-choice:$target").performClick()
            awaitText("$target no longer has a saved VPN exclusion. Choose another app. Nothing was changed.")
            compose.onNodeWithText("VPN exclusion: Saved → Removed").assertDoesNotExist()
            assertEquals(setOf(other), savedSettings().excludedAppPackages)
            assertEquals(before.dnsFirewallPolicy, savedSettings().dnsFirewallPolicy)
            closeVpnPreview()
        } finally {
            runBlocking { withTimeout(8_000) {
                prefs.toggleExcludedAppPackage(target, false)
                prefs.toggleExcludedAppPackage(other, false)
                prefs.updateDnsFirewallPolicy(original.dnsFirewallPolicy)
            } }
        }
    }

    @Test
    fun realTunnelReportsAcceptedRejectedAndStaleSavedExclusions() {
        val state = appViewModel()
        assertEquals(VpnStatus.DISCONNECTED, state.vpnState.value.status)
        assertNoValidatedNetwork()
        val prefs = app.preferencesRepository
        val original = savedSettings()
        check(original.excludedAppPackages.isEmpty()) { "Use a fresh debug install on a disposable emulator." }
        val installed = "com.android.settings"
        val nextInstalled = instrumentation.context.packageName
        val missing = "com.adshield.test.receipt.notinstalled"
        allowVpnThroughAndroidConsent()
        try {
            runBlocking { withTimeout(8_000) {
                prefs.toggleExcludedAppPackage(installed, true)
                prefs.toggleExcludedAppPackage(missing, true)
            } }
            openAgent()
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("2 saved VPN exclusions").assertExists()
            compose.onNodeWithText("Applied state unknown: no current tunnel setup receipt.").assertExists()

            sendVpnAction(AdShieldVpnService.ACTION_START_VPN)
            awaitVpn(state) { it.status == VpnStatus.CONNECTED && it.activeTunnelReceipt != null }
            val first = requireNotNull(state.vpnState.value.activeTunnelReceipt)
            assertEquals(setOf(installed), first.acceptedExclusions)
            assertEquals(setOf(missing), first.rejectedExclusions)
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("Saved VPN exclusions accepted: 1/2").assertExists()
            compose.onNodeWithText("Saved exclusions rejected: 1").assertExists()

            val beforePreview = savedSettings()
            compose.onNodeWithText("Preview one saved VPN exclusion").performScrollTo().performClick()
            selectPreviewTarget(installed)
            awaitText("VPN exclusion: Saved → Removed")
            scrollVpnPreview("preview-tunnel")
            compose.onNodeWithText("Applied: accepted when the tunnel was set up").assertExists()
            compose.onNodeWithText("Tunnel #${first.generation} · Snapshot at", substring = true).assertExists()
            closeVpnPreview()
            assertEquals(first, state.vpnState.value.activeTunnelReceipt)
            assertEquals(VpnStatus.CONNECTED, state.vpnState.value.status)
            assertEquals(beforePreview.excludedAppPackages, savedSettings().excludedAppPackages)
            assertEquals(beforePreview.dnsFirewallPolicy, savedSettings().dnsFirewallPolicy)

            // Change the saved list without requesting reload, to exercise the pre-rebuild gap.
            runBlocking { withTimeout(8_000) {
                prefs.toggleExcludedAppPackage(installed, false)
                prefs.toggleExcludedAppPackage(nextInstalled, true)
            } }
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("Saved VPN exclusions accepted: 0/2").assertExists()
            compose.onNodeWithText("Saved exclusions not recorded at setup: 1").assertExists()
            compose.onNodeWithText("Accepted at setup but no longer saved: 1").assertExists()

            sendVpnAction(AdShieldVpnService.ACTION_RELOAD_TUNNEL_CONFIG)
            awaitVpn(state) { it.activeTunnelReceipt?.generation?.let { generation -> generation > first.generation } == true }
            val rebuilt = requireNotNull(state.vpnState.value.activeTunnelReceipt)
            assertEquals(setOf(nextInstalled), rebuilt.acceptedExclusions)
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("Saved VPN exclusions accepted: 1/2").assertExists()
            compose.onNodeWithText("Accepted at setup but no longer saved: 0").assertExists()

            sendVpnAction(AdShieldVpnService.ACTION_PAUSE_VPN)
            awaitVpn(state) { it.status == VpnStatus.PAUSED }
            assertEquals(rebuilt.generation, state.vpnState.value.activeTunnelReceipt?.generation)
            sendVpnAction(AdShieldVpnService.ACTION_RESUME_VPN)
            awaitVpn(state) { it.status == VpnStatus.CONNECTED }
            assertEquals(rebuilt.generation, state.vpnState.value.activeTunnelReceipt?.generation)

            // A configuration rebuild must also work without silently unpausing protection.
            sendVpnAction(AdShieldVpnService.ACTION_PAUSE_VPN)
            awaitVpn(state) { it.status == VpnStatus.PAUSED }
            sendVpnAction(AdShieldVpnService.ACTION_RELOAD_TUNNEL_CONFIG)
            val newMode = if (original.protectionMode == ProtectionMode.STRICT) ProtectionMode.STANDARD else ProtectionMode.STRICT
            runBlocking { withTimeout(8_000) { prefs.setProtectionMode(newMode) } }
            awaitVpn(state) { it.activeTunnelReceipt?.generation?.let { generation -> generation > rebuilt.generation } == true }
            awaitVpn(state) { it.activeMode == newMode }
            val pausedRebuild = requireNotNull(state.vpnState.value.activeTunnelReceipt)
            assertEquals(VpnStatus.PAUSED, state.vpnState.value.status)
            assertEquals(rebuilt.acceptedExclusions, pausedRebuild.acceptedExclusions)
            assertEquals(rebuilt.rejectedExclusions, pausedRebuild.rejectedExclusions)
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("DNS filtering was paused; the Android tunnel was still installed.").assertExists()

            sendVpnAction(AdShieldVpnService.ACTION_STOP_VPN)
            awaitVpn(state) { it.status == VpnStatus.DISCONNECTED }
            assertNull(state.vpnState.value.activeTunnelReceipt)
            requestReview()
            approveAndWaitForReview()
            scrollReview("review-tunnel")
            compose.onNodeWithText("Applied state unknown: no current tunnel setup receipt.").assertExists()
        } finally {
            if (state.vpnState.value.status != VpnStatus.DISCONNECTED) {
                sendVpnAction(AdShieldVpnService.ACTION_STOP_VPN)
                awaitVpn(state) { it.status == VpnStatus.DISCONNECTED }
            }
            runBlocking { withTimeout(8_000) {
                for (entry in listOf(installed, nextInstalled, missing)) prefs.toggleExcludedAppPackage(entry, false)
                prefs.setProtectionMode(original.protectionMode)
            } }
        }
    }

    private fun awaitText(text: String) {
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun openVpnPreview() {
        scrollReview("agent-controls")
        compose.onNodeWithText("Preview restoring an app").performScrollTo().performClick()
    }

    private fun scrollVpnPreview(key: String) {
        compose.onNodeWithTag("aether-vpn-preview-list").performScrollToKey(key)
    }

    private fun revealPreviewTarget(packageName: String) {
        compose.onNodeWithText("Choose a VPN-excluded app").assertExists()
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.onAllNodesWithText("Reading saved VPN exclusions…").fetchSemanticsNodes().isEmpty()
        }
        scrollVpnPreview("preview-choice:$packageName")
    }

    private fun selectPreviewTarget(packageName: String) {
        revealPreviewTarget(packageName)
        compose.onNodeWithTag("preview-choice:$packageName").performClick()
    }

    private fun closeVpnPreview() {
        compose.onNodeWithText("Close").performClick()
    }

    private fun assertNoValidatedNetwork() {
        val cm = app.getSystemService(ConnectivityManager::class.java)
        compose.waitUntil(timeoutMillis = 15_000) {
            cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) != true
        }
    }

    private fun appViewModel(): AdShieldViewModel {
        assertTrue(com.adshield.pro.BuildConfig.DEBUG && app.packageName == "com.adshield.pro.debug")
        lateinit var result: AdShieldViewModel
        compose.activityRule.scenario.onActivity { result = ViewModelProvider(it)[AdShieldViewModel::class.java] }
        return result
    }

    private fun savedSettings() = runBlocking { withTimeout(8_000) { app.preferencesRepository.settingsFlow.first() } }

    private fun openAgent() {
        compose.onNodeWithTag("main-navigation").performScrollToKey("SECURITY")
        compose.onNodeWithText("Security").performClick()
        compose.onNodeWithText("AI Agent").performClick()
    }

    private fun scrollReview(key: String) {
        compose.onNodeWithTag("aether-agent-list").performScrollToKey(key)
    }

    private fun requestReview() {
        scrollReview("agent-controls")
        compose.onNodeWithText("Review phone, DNS and apps").performScrollTo().performClick()
    }

    private fun approveAndWaitForReview() {
        compose.onNodeWithText("Run review").performClick()
        compose.waitUntil(timeoutMillis = 40_000) {
            compose.onAllNodesWithText("View latest result").fetchSemanticsNodes().isNotEmpty()
        }
        scrollReview("review-coverage")
        compose.onNodeWithText("Security review results").assertIsDisplayed()
    }

    private fun assertNoReviewResult() {
        compose.onNodeWithText("View latest result").assertDoesNotExist()
        compose.onNodeWithText("Security review results").assertDoesNotExist()
    }

    private fun sendVpnAction(action: String) {
        val intent = Intent(app, AdShieldVpnService::class.java).setAction(action)
        compose.activityRule.scenario.onActivity {
            if (action == AdShieldVpnService.ACTION_START_VPN) it.startForegroundService(intent) else it.startService(intent)
        }
    }

    private fun awaitVpn(state: AdShieldViewModel, predicate: (VpnRuntimeState) -> Boolean) {
        compose.waitUntil(timeoutMillis = 20_000) { predicate(state.vpnState.value) }
    }

    /** Approve only the system VPN dialogue returned by prepare(); do not pre-grant app ops. */
    @Suppress("DEPRECATION") // The Android 10 consent activity requires getCallingPackage().
    private fun allowVpnThroughAndroidConsent() {
        val consent = VpnService.prepare(app) ?: return
        val packageName = requireNotNull(consent.component?.packageName)
        val automation = instrumentation.uiAutomation
        val serviceInfo = automation.serviceInfo
        serviceInfo.flags = serviceInfo.flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
        automation.serviceInfo = serviceInfo
        compose.activityRule.scenario.onActivity { it.startActivityForResult(consent, 7840) }
        compose.waitUntil(timeoutMillis = 15_000) {
            val root = automation.rootInActiveWindow ?: return@waitUntil false
            root.packageName?.toString() == packageName &&
                root.findAccessibilityNodeInfosByViewId("android:id/button1").any {
                    it.isEnabled && it.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                }
        }
        compose.waitUntil(timeoutMillis = 10_000) { VpnService.prepare(app) == null }
    }
}
