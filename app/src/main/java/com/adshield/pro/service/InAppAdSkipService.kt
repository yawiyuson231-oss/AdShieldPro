package com.adshield.pro.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.engine.adskip.AdSkipDecisionEngine
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * OmniShield X — In-App Ad Skip service (Accessibility).
 *
 * The ONLY non-root mechanism that can act on ads inside OTHER apps' video
 * players: it taps the same on-screen buttons a human could (Skip ad, close
 * overlay) inside the YouTube apps — plus any extra packages the user adds
 * in Settings. Every tap is decided by the deterministic AdSkipDecisionEngine,
 * throttled to at most one tap per 900ms, counted, and disclosed in Settings.
 * It reads button labels only, never types, and never opens anything.
 *
 * Android requires the user to enable this service in system settings; the
 * in-app switch deep-links there and the UI reflects the real grant state.
 */
@AndroidEntryPoint
class InAppAdSkipService : AccessibilityService() {

    @Inject lateinit var prefs: UserPreferencesRepository

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val throttle = AdSkipDecisionEngine.Throttle(minIntervalMs = 900L)

    @Volatile private var enabled = false
    @Volatile private var extraPackages: Set<String> = emptySet()
    @Volatile private var universalMode: Boolean = true

    companion object {
        const val COMPONENT_ID = "com.adshield.pro/.service.InAppAdSkipService"

        /** Real grant state from the OS — the app UI displays exactly this. */
        fun isEnabledOnSystem(context: Context): Boolean {
            return runCatching {
                val enabled = Settings.Secure.getString(
                    context.contentResolver,
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
                ) ?: return false
                enabled.split(':').any {
                    it.equals(COMPONENT_ID, ignoreCase = true) || it.endsWith(".service.InAppAdSkipService")
                }
            }.getOrDefault(false)
        }
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
            notificationTimeout = 150
        }
        refreshConfigFromSettings()
    }

    /** Live config: settings changes apply without re-enabling the service. */
    fun refreshConfigFromSettings() {
        scope.launch {
            val settings = prefs.getSettingsSnapshot()
            enabled = settings.inAppAdSkipEnabled
            extraPackages = settings.adSkipExtraPackages
            universalMode = settings.inAppAdSkipUniversal
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!enabled || event == null) return
        val pkg = event.packageName?.toString() ?: return
        if (!universalMode && pkg !in (AdSkipDecisionEngine.TARGET_PACKAGES + extraPackages)) return
        if (AdSkipDecisionEngine.isProtectedPackage(pkg)) return
        scanAndAct(rootInActiveWindow, pkg)
    }

    override fun onInterrupt() { /* no continuous feedback to interrupt */ }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    /**
     * Bounded scan: at most 220 nodes per event, then at most ONE tap on the
     * best candidate (Skip beats Close). References to live nodes are held
     * only within this function — no state leaks between events.
     */
    private fun scanAndAct(root: AccessibilityNodeInfo?, pkg: String) {
        if (root == null) return
        val allowed = AdSkipDecisionEngine.TARGET_PACKAGES + extraPackages // used only in non-universal mode
        val candidates = ArrayList<Triple<AdSkipDecisionEngine.Action, AdSkipDecisionEngine.NodeInfo, AccessibilityNodeInfo>>(4)

        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        var visited = 0
        while (queue.isNotEmpty() && visited < 220 && candidates.size < 4) {
            val node = queue.removeFirst()
            visited++
            val info = AdSkipDecisionEngine.NodeInfo(
                viewIdResourceName = runCatching { node.viewIdResourceName }.getOrNull(),
                text = runCatching { node.text?.toString() }.getOrNull(),
                contentDescription = runCatching { node.contentDescription?.toString() }.getOrNull(),
                isClickable = runCatching { node.isClickable }.getOrDefault(false),
                packageName = pkg
            )
            val decision = AdSkipDecisionEngine.decide(info, pkg, allowed, universalMode = universalMode)
            if (decision.type != AdSkipDecisionEngine.ActionType.NONE) {
                candidates.add(Triple(decision, info, node))
            }
            val childCount = runCatching { node.childCount }.getOrDefault(0)
            for (i in 0 until childCount) {
                runCatching { node.getChild(i) }.getOrNull()?.let { queue.add(it) }
            }
        }

        val bestPair = AdSkipDecisionEngine.pickBest(candidates.map { it.second to it.first }) ?: return
        val target = candidates.firstOrNull { it.first.type == bestPair.second.type }?.third ?: return
        val clicked = runCatching { target.performAction(AccessibilityNodeInfo.ACTION_CLICK) }.getOrDefault(false)
        if (clicked && bestPair.second.type == AdSkipDecisionEngine.ActionType.CLICK_SKIP) {
            scope.launch { prefs.incrementInAppAdsSkipped() }
        }
    }
}
