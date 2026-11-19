package com.adshield.pro.engine.platform

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.ProtectionMode

/**
 * Context-Aware Protection & Workload Automation Engine.
 *
 * Deterministically adapts AdShield's own DNS protection posture and background sync behavior to
 * real measured device context — without claiming to control OS power states or other apps' CPUs:
 *
 * Priority order:
 * 1. **Untrusted / Open Wi-Fi Shield (`OPEN_WIFI_STRICT_DOH`)**: On open or WEP Wi-Fi, elevates
 *    filtering to [ProtectionMode.STRICT] and upgrades plaintext UDP/TCP to encrypted [DnsProtocol.DOH].
 * 2. **Active Game Session (`GAME_LOW_LATENCY`)**: When the active app is in [favoriteGamePackages],
 *    selects [ProtectionMode.STANDARD] (avoiding aggressive telemetry false positives mid-match)
 *    and defers background filter/connector syncs.
 * 3. **Critical Battery Conservation (`LOW_BATTERY_DEFER_SYNC`)**: When battery <= 15% (not charging)
 *    or Android Battery Saver is on, defers background syncs while keeping local DNS filtering up.
 * 4. **Overnight Quiet Schedule (`QUIET_HOURS_PRIVACY`)**: During configured quiet hours (default
 *    `22:00..06:00`), elevates [ProtectionMode.STANDARD] to [ProtectionMode.PRIVACY] to neutralize
 *    overnight analytics beacons.
 */
object ContextAutomationEngine {

    data class AutomationContext(
        val automationEnabled: Boolean,
        val baseMode: ProtectionMode,
        val baseResolverConfig: DnsResolverConfig,
        val transport: NetworkTransportPolicy,
        val isWifiOpenOrWep: Boolean = false,
        val isNetworkMetered: Boolean = false,
        val activeForegroundPackage: String? = null,
        val favoriteGamePackages: Set<String> = emptySet(),
        val batteryLevelPercent: Int? = null,
        val isCharging: Boolean = false,
        val isSystemBatterySaverOn: Boolean = false,
        val localHourOfDay: Int = 12,
        val enableQuietHoursPrivacy: Boolean = true,
        val quietStartHour: Int = 22,
        val quietEndHour: Int = 6
    )

    data class AutomationDecision(
        val isTriggered: Boolean,
        val matchedRuleId: String?,
        val effectiveMode: ProtectionMode,
        val effectiveResolverConfig: DnsResolverConfig,
        val deferBackgroundSync: Boolean,
        val explanation: String
    )

    fun evaluate(ctx: AutomationContext): AutomationDecision {
        if (!ctx.automationEnabled) {
            return AutomationDecision(
                isTriggered = false,
                matchedRuleId = null,
                effectiveMode = ctx.baseMode,
                effectiveResolverConfig = ctx.baseResolverConfig,
                deferBackgroundSync = false,
                explanation = "Context automation is off; using user-selected settings."
            )
        }

        // Rule 1: Untrusted / Open / WEP Wi-Fi -> Strict Mode + Encrypted DoH (never downgrade DoT/DoH)
        if (ctx.transport == NetworkTransportPolicy.WIFI && ctx.isWifiOpenOrWep) {
            val hardenedResolver = if (ctx.baseResolverConfig.protocol == DnsProtocol.UDP_TCP) {
                ctx.baseResolverConfig.copy(protocol = DnsProtocol.DOH)
            } else {
                ctx.baseResolverConfig
            }
            return AutomationDecision(
                isTriggered = true,
                matchedRuleId = "OPEN_WIFI_STRICT_DOH",
                effectiveMode = ProtectionMode.STRICT,
                effectiveResolverConfig = hardenedResolver,
                deferBackgroundSync = true,
                explanation = "Open/WEP Wi-Fi detected: elevated to Strict Mode, enforced encrypted DNS, and paused background list downloads on untrusted Wi-Fi."
            )
        }

        // Rule 2: Active Favorite Game -> Low-latency Standard Mode + Defer Sync
        val fg = ctx.activeForegroundPackage?.trim().orEmpty()
        if (fg.isNotEmpty() && fg in ctx.favoriteGamePackages) {
            val gameMode = if (ctx.baseMode == ProtectionMode.STRICT) ProtectionMode.STANDARD else ctx.baseMode
            return AutomationDecision(
                isTriggered = true,
                matchedRuleId = "GAME_LOW_LATENCY",
                effectiveMode = gameMode,
                effectiveResolverConfig = ctx.baseResolverConfig,
                deferBackgroundSync = true,
                explanation = "Game session active ($fg): deferred background list syncs and avoided Strict telemetry blocks."
            )
        }

        // Rule 3: Low Battery / Battery Saver -> Defer Sync
        val lowBattery = !ctx.isCharging && ctx.batteryLevelPercent != null && ctx.batteryLevelPercent in 1..15
        if (lowBattery || (!ctx.isCharging && ctx.isSystemBatterySaverOn)) {
            return AutomationDecision(
                isTriggered = true,
                matchedRuleId = "LOW_BATTERY_DEFER_SYNC",
                effectiveMode = ctx.baseMode,
                effectiveResolverConfig = ctx.baseResolverConfig,
                deferBackgroundSync = true,
                explanation = "Low battery / Battery Saver active: local DNS protection stays active while background sync jobs are deferred."
            )
        }

        // Rule 4: Overnight Quiet Hours -> Privacy Mode (when base is Standard)
        if (ctx.enableQuietHoursPrivacy && isHourInWindow(ctx.localHourOfDay, ctx.quietStartHour, ctx.quietEndHour)) {
            val nightMode = if (ctx.baseMode == ProtectionMode.STANDARD) ProtectionMode.PRIVACY else ctx.baseMode
            return AutomationDecision(
                isTriggered = true,
                matchedRuleId = "QUIET_HOURS_PRIVACY",
                effectiveMode = nightMode,
                effectiveResolverConfig = ctx.baseResolverConfig,
                deferBackgroundSync = ctx.isNetworkMetered,
                explanation = "Quiet hours active (${formatHour(ctx.quietStartHour)}–${formatHour(ctx.quietEndHour)}): elevated overnight telemetry protection to ${nightMode.title}."
            )
        }

        return AutomationDecision(
            isTriggered = false,
            matchedRuleId = null,
            effectiveMode = ctx.baseMode,
            effectiveResolverConfig = ctx.baseResolverConfig,
            deferBackgroundSync = false,
            explanation = "Normal device context; applying configured ${ctx.baseMode.title}."
        )
    }

    fun isHourInWindow(hour: Int, startHour: Int, endHour: Int): Boolean {
        val h = ((hour % 24) + 24) % 24
        val s = ((startHour % 24) + 24) % 24
        val e = ((endHour % 24) + 24) % 24
        return if (s <= e) h in s until e else (h >= s || h < e)
    }

    private fun formatHour(hour: Int): String = "%02d:00".format(((hour % 24) + 24) % 24)
}
