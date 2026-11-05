package com.adshield.pro.universal

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Master Security Control — ONE central ON/OFF switch.
 *
 * When ON:
 * - All supported protection modules activated
 * - Background security services started (where permitted)
 * - Real-time monitoring enabled
 * - Threat detection activated
 * - Automatic security checks running
 *
 * When OFF:
 * - Optional modules safely disabled
 * - Essential system functionality preserved
 * - Clear explanation of disabled protections
 */
@Singleton
class MasterSecurityController @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("universal_master_control", Context.MODE_PRIVATE)

    companion object {
        const val KEY_MASTER_ENABLED = "master_enabled"
        const val KEY_LAST_TOGGLE_MS = "last_toggle_ms"
        const val KEY_TOGGLE_COUNT = "toggle_count"
        const val KEY_DISABLED_REASON = "disabled_reason"
    }

    private val _isEnabled = MutableStateFlow(isMasterEnabled())
    val isEnabled: StateFlow<Boolean> = _isEnabled

    private val _toggleHistory = MutableStateFlow(loadToggleHistory())
    val toggleHistory: StateFlow<List<MasterToggleEvent>> = _toggleHistory

    fun isMasterEnabled(): Boolean = prefs.getBoolean(KEY_MASTER_ENABLED, true)

    fun getDisabledProtections(): List<String> {
        if (isMasterEnabled()) return emptyList()
        return listOf(
            "Real-time threat detection paused",
            "DNS filtering inactive — ads/trackers not blocked",
            "Malware scanning suspended",
            "Network attack monitoring disabled",
            "Privacy monitoring reduced",
            "Automatic threat response off",
            "Intrusion detection standby"
        )
    }

    fun getEnabledProtections(): List<String> = listOf(
        "All 50 security modules active",
        "Real-time monitoring running",
        "Threat detection enabled",
        "Background security services active",
        "Automatic security checks every 5 minutes",
        "DNS filtering protecting all apps"
    )

    fun setMasterEnabled(enabled: Boolean, reason: String = ""): Boolean {
        val previous = isMasterEnabled()
        prefs.edit()
            .putBoolean(KEY_MASTER_ENABLED, enabled)
            .putLong(KEY_LAST_TOGGLE_MS, System.currentTimeMillis())
            .putInt(KEY_TOGGLE_COUNT, prefs.getInt(KEY_TOGGLE_COUNT, 0) + 1)
            .putString(KEY_DISABLED_REASON, reason)
            .apply()
        _isEnabled.value = enabled

        val event = MasterToggleEvent(
            timestampMs = System.currentTimeMillis(),
            enabled = enabled,
            previousState = previous,
            reason = reason
        )
        val updated = (_toggleHistory.value + event).takeLast(100)
        _toggleHistory.value = updated
        saveToggleHistory(updated)
        return true
    }

    fun getToggleCount(): Int = prefs.getInt(KEY_TOGGLE_COUNT, 0)
    fun getLastToggleMs(): Long = prefs.getLong(KEY_LAST_TOGGLE_MS, 0L)
    fun getUptimeSinceToggleMs(): Long {
        val last = getLastToggleMs()
        return if (last == 0L) 0L else System.currentTimeMillis() - last
    }

    fun shouldStartBackgroundServices(): Boolean = isMasterEnabled()
    fun shouldEnableRealTimeMonitoring(): Boolean = isMasterEnabled()
    fun shouldActivateThreatDetection(): Boolean = isMasterEnabled()
    fun shouldRunAutomaticChecks(): Boolean = isMasterEnabled()

    private fun loadToggleHistory(): List<MasterToggleEvent> {
        val raw = prefs.getString("toggle_history_json", null) ?: return emptyList()
        return try {
            raw.lines().filter { it.isNotBlank() }.mapNotNull { line ->
                val parts = line.split("|")
                if (parts.size >= 4) MasterToggleEvent(
                    timestampMs = parts[0].toLongOrNull() ?: return@mapNotNull null,
                    enabled = parts[1].toBoolean(),
                    previousState = parts[2].toBoolean(),
                    reason = parts[3]
                ) else null
            }
        } catch (e: Exception) { emptyList() }
    }

    private fun saveToggleHistory(events: List<MasterToggleEvent>) {
        val raw = events.joinToString("\n") { "${it.timestampMs}|${it.enabled}|${it.previousState}|${it.reason}" }
        prefs.edit().putString("toggle_history_json", raw).apply()
    }
}

data class MasterToggleEvent(
    val timestampMs: Long,
    val enabled: Boolean,
    val previousState: Boolean,
    val reason: String
)
