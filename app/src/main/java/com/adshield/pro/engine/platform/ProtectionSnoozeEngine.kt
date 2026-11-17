package com.adshield.pro.engine.platform

import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.AppExclusionInfo
import com.adshield.pro.domain.model.TileVisualState
import com.adshield.pro.domain.model.VpnStatus
import java.util.Locale

/**
 * Pure, deterministic state and presentation engine for:
 * 1. Timed protection pause (snooze) with automatic VPN resumption.
 * 2. The no-ADB AdShield VPN Quick Settings tile ([com.adshield.pro.service.AdShieldTileService]).
 * 3. The Home-Screen live protection widget ([com.adshield.pro.service.AdShieldWidgetProvider]).
 * 4. Per-App Firewall & Split-Tunnel filtering and summary counts.
 */
object ProtectionSnoozeEngine {

    val PRESET_MINUTES: List<Int> = listOf(5, 15, 30, 60)
    const val MIN_SNOOZE_MINUTES = 1
    const val MAX_SNOOZE_MINUTES = 720 // 12 hours max

    data class ShieldTilePresentation(
        val state: TileVisualState,
        val label: String,
        val subtitle: String,
        val contentDescription: String
    )

    data class ShieldWidgetPresentation(
        val statusBadge: String,
        val statusTone: StatusTone,
        val subtitle: String,
        val blockedCountLabel: String,
        val totalAndRateLabel: String,
        val primaryActionLabel: String,
        val primaryAction: WidgetAction,
        val secondaryActionLabel: String,
        val secondaryAction: WidgetAction
    )

    enum class StatusTone { ACTIVE, PAUSED, INACTIVE, ALERT }

    enum class WidgetAction {
        START_VPN,
        STOP_VPN,
        RESUME_VPN,
        SNOOZE_15M,
        OPEN_APP
    }

    enum class AppFirewallFilter(val label: String) {
        ALL("All"),
        CONFIGURED("Custom"),
        BYPASSED("Bypass VPN"),
        DNS_BLOCKED("Block DNS"),
        ACTIVE_TRAFFIC("Active")
    }

    data class AppFirewallSummary(
        val totalApps: Int,
        val bypassedCount: Int,
        val dnsBlockedCount: Int,
        val dnsAllowAllCount: Int,
        val activeTrafficCount: Int
    ) {
        val customRuleCount: Int
            get() = bypassedCount + dnsBlockedCount + dnsAllowAllCount
    }

    fun clampMinutes(minutes: Int): Int = minutes.coerceIn(MIN_SNOOZE_MINUTES, MAX_SNOOZE_MINUTES)

    fun computeDeadline(nowEpochMs: Long, minutes: Int): Long {
        val clamped = clampMinutes(minutes)
        return nowEpochMs + clamped * 60_000L
    }

    fun isSnoozeActive(snoozeUntilEpochMs: Long, nowEpochMs: Long): Boolean =
        snoozeUntilEpochMs > nowEpochMs

    fun isSnoozeDue(
        snoozeUntilEpochMs: Long,
        vpnShouldRemainActive: Boolean,
        nowEpochMs: Long
    ): Boolean = vpnShouldRemainActive && snoozeUntilEpochMs in 1..nowEpochMs

    fun formatRemaining(snoozeUntilEpochMs: Long, nowEpochMs: Long): String {
        val remainingMs = snoozeUntilEpochMs - nowEpochMs
        if (remainingMs <= 0L) return "Resuming…"
        val totalSeconds = ((remainingMs + 999L) / 1_000L).coerceAtLeast(1L)
        val hours = totalSeconds / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return when {
            hours > 0L -> "${hours}h ${minutes}m left"
            minutes > 0L -> "${minutes}m ${seconds}s left"
            else -> "${seconds}s left"
        }
    }

    fun formatRemainingCompact(snoozeUntilEpochMs: Long, nowEpochMs: Long): String {
        val remainingMs = snoozeUntilEpochMs - nowEpochMs
        if (remainingMs <= 0L) return "Resuming"
        val totalMinutes = ((remainingMs + 59_999L) / 60_000L).coerceAtLeast(1L)
        val hours = totalMinutes / 60L
        val minutes = totalMinutes % 60L
        return when {
            hours > 0L && minutes > 0L -> "${hours}h ${minutes}m"
            hours > 0L -> "${hours}h"
            else -> "${minutes}m"
        }
    }

    fun presentShieldTile(
        vpnStatus: VpnStatus,
        vpnShouldRemainActive: Boolean,
        snoozeUntilEpochMs: Long,
        sessionBlockedQueries: Long,
        hasVpnConsent: Boolean,
        nowEpochMs: Long
    ): ShieldTilePresentation {
        val snoozed = isSnoozeActive(snoozeUntilEpochMs, nowEpochMs)
        return when {
            !hasVpnConsent -> ShieldTilePresentation(
                state = TileVisualState.INACTIVE,
                label = "AdShield",
                subtitle = "Tap to allow VPN",
                contentDescription = "AdShield Pro protection off. Tap to grant VPN permission and enable DNS filtering."
            )
            vpnStatus == VpnStatus.PAUSED || (snoozed && vpnShouldRemainActive) -> {
                val sub = if (snoozed) {
                    "Paused · ${formatRemainingCompact(snoozeUntilEpochMs, nowEpochMs)}"
                } else {
                    "Paused · Tap to resume"
                }
                ShieldTilePresentation(
                    state = TileVisualState.INACTIVE,
                    label = "AdShield",
                    subtitle = sub,
                    contentDescription = "AdShield Pro filtering paused ($sub). Tap to resume immediately."
                )
            }
            vpnStatus == VpnStatus.CONNECTED || vpnStatus == VpnStatus.STARTING ||
                vpnStatus == VpnStatus.RECONNECTING -> {
                val blocked = sessionBlockedQueries.coerceAtLeast(0L)
                val sub = if (blocked > 0L) {
                    "Active · ${formatCompactCount(blocked)} blocked"
                } else {
                    "Active"
                }
                ShieldTilePresentation(
                    state = TileVisualState.ACTIVE,
                    label = "AdShield",
                    subtitle = sub,
                    contentDescription = "AdShield Pro active ($sub). Tap to stop protection."
                )
            }
            vpnStatus == VpnStatus.ERROR -> ShieldTilePresentation(
                state = TileVisualState.INACTIVE,
                label = "AdShield",
                subtitle = "Attention needed",
                contentDescription = "AdShield Pro encountered a VPN error. Tap to retry."
            )
            else -> ShieldTilePresentation(
                state = TileVisualState.INACTIVE,
                label = "AdShield",
                subtitle = "Off",
                contentDescription = "AdShield Pro protection is off. Tap to start local DNS filtering."
            )
        }
    }

    fun presentWidget(
        vpnStatus: VpnStatus,
        vpnShouldRemainActive: Boolean,
        snoozeUntilEpochMs: Long,
        sessionBlocked: Long,
        sessionTotal: Long,
        allTimeBlocked: Long,
        allTimeTotal: Long,
        modeTitle: String,
        protocolName: String,
        nowEpochMs: Long
    ): ShieldWidgetPresentation {
        val snoozed = isSnoozeActive(snoozeUntilEpochMs, nowEpochMs)
        val useSession = (vpnStatus == VpnStatus.CONNECTED || vpnStatus == VpnStatus.PAUSED) &&
            sessionTotal > 0L
        val blocked = (if (useSession) sessionBlocked else maxOf(allTimeBlocked, sessionBlocked)).coerceAtLeast(0L)
        val total = (if (useSession) sessionTotal else maxOf(allTimeTotal, sessionTotal)).coerceAtLeast(blocked)
        val pct = if (total > 0L) ((blocked * 100L) / total).coerceIn(0L, 100L) else 0L
        val scope = if (useSession) "session" else "total"
        val rateLine = if (total > 0L) {
            "$pct% of ${formatCompactCount(total)} $scope queries"
        } else {
            "Local non-root DNS firewall"
        }
        val cleanMode = modeTitle.removeSuffix(" Mode")

        return when {
            vpnStatus == VpnStatus.PAUSED || (snoozed && vpnShouldRemainActive) -> {
                val badge = if (snoozed) {
                    "PAUSED · ${formatRemainingCompact(snoozeUntilEpochMs, nowEpochMs)}"
                } else {
                    "PAUSED"
                }
                val sub = if (snoozed) {
                    "Auto-resume in ${formatRemainingCompact(snoozeUntilEpochMs, nowEpochMs)}"
                } else {
                    "Filtering paused · tap Resume"
                }
                ShieldWidgetPresentation(
                    statusBadge = badge,
                    statusTone = StatusTone.PAUSED,
                    subtitle = sub,
                    blockedCountLabel = formatCompactCount(blocked),
                    totalAndRateLabel = rateLine,
                    primaryActionLabel = "Resume",
                    primaryAction = WidgetAction.RESUME_VPN,
                    secondaryActionLabel = "Open",
                    secondaryAction = WidgetAction.OPEN_APP
                )
            }
            vpnStatus == VpnStatus.CONNECTED || vpnStatus == VpnStatus.STARTING ||
                vpnStatus == VpnStatus.RECONNECTING -> ShieldWidgetPresentation(
                statusBadge = "PROTECTED",
                statusTone = StatusTone.ACTIVE,
                subtitle = "$cleanMode · $protocolName",
                blockedCountLabel = formatCompactCount(blocked),
                totalAndRateLabel = rateLine,
                primaryActionLabel = "Turn Off",
                primaryAction = WidgetAction.STOP_VPN,
                secondaryActionLabel = "Pause 15m",
                secondaryAction = WidgetAction.SNOOZE_15M
            )
            vpnStatus == VpnStatus.ERROR -> ShieldWidgetPresentation(
                statusBadge = "ERROR",
                statusTone = StatusTone.ALERT,
                subtitle = "Tap Protect to reconnect",
                blockedCountLabel = formatCompactCount(blocked),
                totalAndRateLabel = rateLine,
                primaryActionLabel = "Protect",
                primaryAction = WidgetAction.START_VPN,
                secondaryActionLabel = "Open",
                secondaryAction = WidgetAction.OPEN_APP
            )
            else -> ShieldWidgetPresentation(
                statusBadge = "OFF",
                statusTone = StatusTone.INACTIVE,
                subtitle = "Tap Protect to enable DNS shield",
                blockedCountLabel = formatCompactCount(blocked),
                totalAndRateLabel = rateLine,
                primaryActionLabel = "Protect",
                primaryAction = WidgetAction.START_VPN,
                secondaryActionLabel = "Open",
                secondaryAction = WidgetAction.OPEN_APP
            )
        }
    }

    fun summarizeFirewall(
        apps: List<AppExclusionInfo>,
        activityByPackage: Map<String, AppDnsActivity>
    ): AppFirewallSummary {
        var bypassed = 0
        var blocked = 0
        var allowed = 0
        var active = 0
        for (app in apps) {
            when {
                app.isExcludedFromVpn -> bypassed++
                app.dnsPolicy == AppDnsPolicy.BLOCK_ALL -> blocked++
                app.dnsPolicy == AppDnsPolicy.ALLOW_ALL -> allowed++
            }
            if ((activityByPackage[app.packageName]?.totalQueries ?: 0L) > 0L) {
                active++
            }
        }
        return AppFirewallSummary(
            totalApps = apps.size,
            bypassedCount = bypassed,
            dnsBlockedCount = blocked,
            dnsAllowAllCount = allowed,
            activeTrafficCount = active
        )
    }

    fun filterFirewallApps(
        apps: List<AppExclusionInfo>,
        activityByPackage: Map<String, AppDnsActivity>,
        searchQuery: String,
        filter: AppFirewallFilter,
        includeSystemApps: Boolean
    ): List<AppExclusionInfo> {
        val needle = searchQuery.trim().lowercase(Locale.ROOT)
        return apps.filter { app ->
            val hasCustomConfig = app.isExcludedFromVpn || app.dnsPolicy != AppDnsPolicy.DEFAULT
            if (!includeSystemApps && app.isSystemApp && !hasCustomConfig) return@filter false
            if (needle.isNotEmpty() &&
                !app.appName.lowercase(Locale.ROOT).contains(needle) &&
                !app.packageName.lowercase(Locale.ROOT).contains(needle)
            ) {
                return@filter false
            }
            when (filter) {
                AppFirewallFilter.ALL -> true
                AppFirewallFilter.CONFIGURED -> hasCustomConfig
                AppFirewallFilter.BYPASSED -> app.isExcludedFromVpn
                AppFirewallFilter.DNS_BLOCKED -> !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.BLOCK_ALL
                AppFirewallFilter.ACTIVE_TRAFFIC -> (activityByPackage[app.packageName]?.totalQueries ?: 0L) > 0L
            }
        }
    }

    fun formatCompactCount(value: Long): String {
        val safe = value.coerceAtLeast(0L)
        return when {
            safe >= 1_000_000L -> String.format(Locale.US, "%.1fM", safe / 1_000_000.0)
            safe >= 10_000L -> String.format(Locale.US, "%.1fK", safe / 1_000.0)
            safe >= 1_000L -> String.format(Locale.US, "%,d", safe)
            else -> safe.toString()
        }
    }
}
