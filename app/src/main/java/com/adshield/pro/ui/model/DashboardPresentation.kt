package com.adshield.pro.ui.model

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus
import kotlin.math.roundToInt

/**
 * Pure presentation rules for the cyber dashboard. Keeping them out of Compose makes the
 * honest-data and motion contracts unit-testable on the JVM.
 */
object DashboardPresentation {

    enum class TrafficScope(val label: String) {
        DEVICE_HISTORY("Recorded on this device"),
        CURRENT_SESSION("Current session"),
        EMPTY("Waiting for traffic")
    }

    data class TrafficOverview(
        val total: Long,
        val blocked: Long,
        val allowed: Long,
        val threats: Long,
        val blockPercent: Float,
        val scope: TrafficScope
    )

    /**
     * Prefer persistent device history. Fall back to the live session only when history is empty
     * (for example right after the user clears statistics). Never mix the two counters together:
     * the old `max(session, allTime)` display could show a larger blocked count than total.
     */
    fun overview(
        allTimeTotal: Long,
        allTimeBlocked: Long,
        allTimeAllowed: Long,
        sessionTotal: Long,
        sessionBlocked: Long,
        sessionAllowed: Long,
        allTimeThreats: Long,
        recentThreats: Long
    ): TrafficOverview {
        val useHistory = allTimeTotal > 0L
        val rawTotal = if (useHistory) allTimeTotal else sessionTotal
        val rawBlocked = if (useHistory) allTimeBlocked else sessionBlocked
        val rawAllowed = if (useHistory) allTimeAllowed else sessionAllowed
        val total = rawTotal.coerceAtLeast(0L)
        val blocked = rawBlocked.coerceIn(0L, total)
        // Trust the reported allowed counter only when it agrees with total-blocked; otherwise
        // recompute it so a stale/partial counter cannot contradict the same-scope total.
        val derivedAllowed = (total - blocked).coerceAtLeast(0L)
        val allowed = if (rawAllowed == derivedAllowed) rawAllowed else derivedAllowed
        val threats = (if (useHistory) allTimeThreats else recentThreats).coerceIn(0L, blocked)
        val percent = if (total > 0L) blocked * 100f / total else 0f
        val scope = when {
            total == 0L -> TrafficScope.EMPTY
            useHistory -> TrafficScope.DEVICE_HISTORY
            else -> TrafficScope.CURRENT_SESSION
        }
        return TrafficOverview(total, blocked, allowed, threats, percent, scope)
    }

    fun eventTitle(record: DnsActivityRecord): String = when {
        !record.isBlocked -> "Allowed query"
        record.category == null -> "Blocked by policy"
        else -> "${record.category.displayName} blocked"
    }

    fun eventSeverity(record: DnsActivityRecord): String = when {
        !record.isBlocked -> "LOW"
        record.category == RuleCategory.MALWARE -> "CRITICAL"
        record.category == RuleCategory.STRICT_TELEMETRY -> "HIGH"
        record.category == RuleCategory.ADS -> "MEDIUM"
        record.category == RuleCategory.TRACKERS -> "LOW"
        else -> "CUSTOM"
    }

    /** Motion is a comfort feature, not a data source: never animate an idle or disconnected shield. */
    fun shouldAnimate(status: VpnStatus, hasTraffic: Boolean, systemAnimationsEnabled: Boolean): Boolean =
        systemAnimationsEnabled && status == VpnStatus.CONNECTED && hasTraffic

    /** Keeps the selected bottom-nav item near the middle of the scrollable bar. */
    fun navScrollTarget(selectedIndex: Int, visibleItems: Int): Int =
        (selectedIndex - (visibleItems.coerceAtLeast(1) / 2)).coerceAtLeast(0)

    fun percentLabel(value: Float): String = "${value.coerceIn(0f, 100f).roundToInt()}%"
}
