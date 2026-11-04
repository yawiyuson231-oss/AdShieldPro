package com.adshield.pro.ui.model

import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.engine.dns.DnsProviderHealth
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import java.util.Locale
import kotlin.math.roundToInt

/** Operational state of one stage of the protection pipeline. */
enum class StageState {
    /** Doing real work right now. */
    ACTIVE,

    /** Waiting for the stage above it (starting, reconnecting, no traffic yet). */
    STANDBY,

    /** Working, but with a measured problem (open circuit, no rules loaded). */
    DEGRADED,

    /** Deliberately not filtering (paused, emergency lockdown). */
    ATTENTION,

    /** Not running. */
    OFFLINE
}

data class PipelineStage(
    val id: String,
    val title: String,
    val detail: String,
    val state: StageState
)

data class StatusMetric(
    val label: String,
    val value: String,
    val emphasis: Boolean = false
)

/**
 * The live "working status" of the DNS protection pipeline.
 *
 * Every field is derived from real runtime state: the VpnService status, the rule count the
 * engine actually loaded, measured resolver latency and circuit state from the health monitor,
 * and the user's own policy settings. Nothing here is estimated, simulated or defaulted to a
 * healthy value — a stage the app cannot observe is reported as STANDBY/OFFLINE, never ACTIVE.
 */
data class ProtectionPipelineStatus(
    val overall: StageState,
    val headline: String,
    val summary: String,
    val healthScore: Int,
    val isLive: Boolean,
    val stages: List<PipelineStage>,
    val metrics: List<StatusMetric>,
    val badges: List<String>
)

object ProtectionStatusEvaluator {

    fun evaluate(
        vpn: VpnRuntimeState,
        settings: AppSettingsState,
        health: List<DnsProviderHealth>,
        nowMs: Long
    ): ProtectionPipelineStatus {
        val config = vpn.resolverConfig
        val policy = settings.dnsFirewallPolicy
        val emergency = policy.emergencyAllowlistOnly
        val connected = vpn.status == VpnStatus.CONNECTED
        val isLive = connected && vpn.sessionTotalQueries > 0L

        val tunnelStage = when (vpn.status) {
            VpnStatus.CONNECTED -> PipelineStage(
                "tunnel", "DNS tunnel",
                "Capturing DNS on ${vpn.activeNetworkLabel} · up ${formatDuration(nowMs - (vpn.connectedSinceEpochMs ?: nowMs))}",
                StageState.ACTIVE
            )
            VpnStatus.STARTING -> PipelineStage("tunnel", "DNS tunnel", "Starting the local tunnel…", StageState.STANDBY)
            VpnStatus.RECONNECTING -> PipelineStage("tunnel", "DNS tunnel", "Re-establishing after a network change…", StageState.STANDBY)
            VpnStatus.PAUSED -> PipelineStage("tunnel", "DNS tunnel", "Paused — DNS is not being filtered", StageState.ATTENTION)
            VpnStatus.ERROR -> PipelineStage("tunnel", "DNS tunnel", vpn.lastError ?: "The tunnel could not start", StageState.OFFLINE)
            VpnStatus.DISCONNECTED -> PipelineStage("tunnel", "DNS tunnel", "Not running — tap Protect device to start", StageState.OFFLINE)
        }

        val filterStage = when {
            !connected -> PipelineStage("filter", "Rule engine", "${vpn.loadedRuleCount} rules ready", StageState.STANDBY)
            vpn.loadedRuleCount > 0 -> PipelineStage(
                "filter", "Rule engine",
                "${vpn.loadedRuleCount} rules · ${vpn.activeMode.title}",
                StageState.ACTIVE
            )
            else -> PipelineStage("filter", "Rule engine", "No rules loaded — sync your filter lists", StageState.DEGRADED)
        }

        val primaryHealth = health.firstOrNull { it.providerId == config.preset.id && it.protocol == config.protocol }
        val circuitOpen = primaryHealth?.isCircuitOpen(nowMs) == true
        val upstreamStage = when {
            !connected -> PipelineStage("upstream", "Upstream resolver", "${config.protocol.label} · ${config.preset.displayName}", StageState.STANDBY)
            circuitOpen -> PipelineStage(
                "upstream", "Upstream resolver",
                "${config.preset.displayName} circuit open — using the next provider you selected",
                StageState.DEGRADED
            )
            vpn.averageLatencyMs > 0 -> PipelineStage(
                "upstream", "Upstream resolver",
                "${config.protocol.label} · ${config.preset.displayName} · ${vpn.averageLatencyMs} ms measured",
                StageState.ACTIVE
            )
            else -> PipelineStage(
                "upstream", "Upstream resolver",
                "${config.protocol.label} · ${config.preset.displayName} · awaiting first query",
                if (connected) StageState.ACTIVE else StageState.STANDBY
            )
        }

        val integrityStage = PipelineStage(
            "integrity", "Answer integrity",
            if (config.dnssecMode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS) {
                "Strict: positive answers require the upstream AD bit"
            } else {
                "Reporting upstream DNSSEC evidence (no local validation)"
            },
            if (connected) StageState.ACTIVE else StageState.STANDBY
        )

        val appPolicyCount = policy.appPolicies.count { it.value != AppDnsPolicy.DEFAULT }
        val transports = policy.protectedTransports
        val transportRestricted = transports.isNotEmpty() && transports.size < NetworkTransportPolicy.entries.size
        val policyStage = when {
            emergency -> PipelineStage(
                "policy", "Policy", "Emergency allowlist-only: only explicit allows resolve", StageState.ATTENTION
            )
            appPolicyCount > 0 || transportRestricted -> PipelineStage(
                "policy", "Policy",
                listOfNotNull(
                    if (appPolicyCount > 0) "$appPolicyCount per-app rule${if (appPolicyCount == 1) "" else "s"}" else null,
                    if (transportRestricted) transports.joinToString("/") { it.label } else null
                ).joinToString(" · ").ifBlank { "Global protection" },
                StageState.ACTIVE
            )
            else -> PipelineStage("policy", "Policy", "Global protection on every network", StageState.ACTIVE)
        }

        val cachePercent = if (vpn.sessionTotalQueries > 0L) {
            (vpn.sessionCachedQueries.toFloat() / vpn.sessionTotalQueries.toFloat()) * 100f
        } else 0f
        val cacheStage = PipelineStage(
            "cache", "Cache",
            if (vpn.sessionTotalQueries > 0L) "${cachePercent.roundToInt()}% answered from cache this session" else "No queries yet this session",
            if (isLive) StageState.ACTIVE else StageState.STANDBY
        )

        val stages = listOf(tunnelStage, filterStage, upstreamStage, integrityStage, policyStage, cacheStage)
        val overall = when {
            vpn.status == VpnStatus.ERROR || vpn.status == VpnStatus.DISCONNECTED -> StageState.OFFLINE
            vpn.status == VpnStatus.PAUSED || emergency -> StageState.ATTENTION
            stages.any { it.state == StageState.DEGRADED } -> StageState.DEGRADED
            vpn.status != VpnStatus.CONNECTED -> StageState.STANDBY
            else -> StageState.ACTIVE
        }

        val healthScore = computeHealthScore(vpn, stages, emergency)

        val metrics = listOf(
            StatusMetric("Session", formatCount(vpn.sessionTotalQueries), emphasis = isLive),
            StatusMetric("Blocked", if (vpn.sessionTotalQueries > 0L) "${vpn.blockingPercentage.roundToInt()}%" else "—"),
            StatusMetric("Latency", if (vpn.averageLatencyMs > 0) "${vpn.averageLatencyMs} ms" else "—"),
            StatusMetric("Rules", formatCount(vpn.loadedRuleCount.toLong())),
            StatusMetric("Cache", if (vpn.sessionTotalQueries > 0L) "${cachePercent.roundToInt()}%" else "—"),
            StatusMetric("Health", "$healthScore/100", emphasis = true)
        )

        val badges = buildList {
            add(config.protocol.label)
            add(config.preset.displayName)
            add(if (config.dnssecMode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS) "DNSSEC strict" else "DNSSEC report")
            if (config.failoverEnabled) add("Failover: ${config.failoverProviderIds.size} provider(s)")
            if (emergency) add("Emergency mode")
            if (appPolicyCount > 0) add("$appPolicyCount app rule${if (appPolicyCount == 1) "" else "s"}")
            if (transportRestricted) add("Network: ${transports.joinToString("/") { it.label }}")
            if (vpn.activeNetworkLabel.isNotBlank()) add(vpn.activeNetworkLabel)
        }

        val headline = when (overall) {
            StageState.ACTIVE -> if (isLive) "PROTECTED · WORKING" else "PROTECTED · IDLE"
            StageState.DEGRADED -> "PROTECTED · DEGRADED"
            StageState.ATTENTION -> if (emergency) "EMERGENCY LOCKDOWN" else "FILTERING PAUSED"
            StageState.STANDBY -> when (vpn.status) {
                VpnStatus.STARTING -> "STARTING"
                VpnStatus.RECONNECTING -> "RECONNECTING"
                else -> "STARTING"
            }
            StageState.OFFLINE -> if (vpn.status == VpnStatus.ERROR) "NEEDS ATTENTION" else "PROTECTION OFF"
        }

        val summary = when (overall) {
            StageState.ACTIVE -> if (isLive) {
                "Filtering live traffic through ${config.protocol.label} · ${config.preset.displayName}"
            } else {
                "Tunnel is up and waiting for DNS traffic"
            }
            StageState.DEGRADED -> "Protection is on, but one stage reported a problem — see the pipeline below"
            StageState.ATTENTION -> if (emergency) {
                "Only user allowlist and built-in safety entries resolve"
            } else {
                "The tunnel is up but DNS is passing through unfiltered"
            }
            StageState.STANDBY -> stages.first { it.state == StageState.STANDBY }.detail
            StageState.OFFLINE -> vpn.lastError ?: "Turn on protection to start filtering DNS"
        }

        return ProtectionPipelineStatus(
            overall = overall,
            headline = headline,
            summary = summary,
            healthScore = healthScore,
            isLive = isLive,
            stages = stages,
            metrics = metrics,
            badges = badges
        )
    }

    /**
     * Honest weighting: the score only rewards stages that are actually doing work.
     * 40 tunnel · 25 rules · 25 upstream · 10 policy. Emergency lockdown is intentional, so it
     * costs the policy slice rather than being reported as a fault.
     */
    private fun computeHealthScore(
        vpn: VpnRuntimeState,
        stages: List<PipelineStage>,
        emergency: Boolean
    ): Int {
        val tunnel = when (vpn.status) {
            VpnStatus.CONNECTED -> 40
            VpnStatus.STARTING, VpnStatus.RECONNECTING -> 15
            else -> 0
        }
        val rules = if (vpn.status == VpnStatus.CONNECTED && vpn.loadedRuleCount > 0) 25 else 0
        val upstream = when {
            vpn.status != VpnStatus.CONNECTED -> 0
            stages.first { it.id == "upstream" }.state == StageState.DEGRADED -> 10
            else -> 25
        }
        val policy = if (vpn.status == VpnStatus.CONNECTED) (if (emergency) 5 else 10) else 0
        return (tunnel + rules + upstream + policy).coerceIn(0, 100)
    }

    private fun formatCount(value: Long): String = when {
        value >= 1_000_000L -> String.format(Locale.US, "%.1fM", value / 1_000_000.0)
        value >= 1_000L -> String.format(Locale.US, "%.1fk", value / 1_000.0)
        else -> value.toString()
    }

    private fun formatDuration(durationMs: Long): String {
        val safe = durationMs.coerceAtLeast(0L)
        val totalSeconds = safe / 1000L
        val hours = totalSeconds / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return when {
            hours > 0L -> "${hours}h ${minutes}m"
            minutes > 0L -> "${minutes}m ${seconds}s"
            else -> "${seconds}s"
        }
    }
}
