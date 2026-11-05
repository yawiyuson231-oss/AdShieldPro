package com.adshield.pro.globalvpn.engine

import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.ServerProbe
import com.adshield.pro.globalvpn.model.VpnServer
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * Transparent, inspectable server ranking. This is deliberately a heuristic, not a trained model,
 * and the UI labels it as such. Every factor that moves a score is returned in [ScoredServer.reasons]
 * so the recommendation can be audited on-device. No "AI" is simulated.
 */
object ServerScorer {

    enum class CongestionTrend { RISING, STABLE, FALLING, UNKNOWN }

    data class ProbeHistory(
        val ewmaFastMs: Double? = null,
        val ewmaSlowMs: Double? = null,
        val failures: Int = 0,
        val samples: Int = 0
    ) {
        fun record(probe: ServerProbe): ProbeHistory {
            val latency = probe.latencyMs?.toDouble()
            return if (!probe.reachable || latency == null) {
                copy(failures = min(failures + 1, 20), samples = samples + 1)
            } else {
                val fast = ewmaFastMs?.let { it * 0.6 + latency * 0.4 } ?: latency
                val slow = ewmaSlowMs?.let { it * 0.9 + latency * 0.1 } ?: latency
                copy(
                    ewmaFastMs = fast,
                    ewmaSlowMs = slow,
                    failures = max(0, failures - 1),
                    samples = samples + 1
                )
            }
        }

        fun trend(): CongestionTrend {
            val fast = ewmaFastMs ?: return CongestionTrend.UNKNOWN
            val slow = ewmaSlowMs ?: return CongestionTrend.UNKNOWN
            if (samples < 3) return CongestionTrend.UNKNOWN
            val delta = fast - slow
            return when {
                delta > max(8.0, slow * 0.20) -> CongestionTrend.RISING
                delta < -max(8.0, slow * 0.20) -> CongestionTrend.FALLING
                else -> CongestionTrend.STABLE
            }
        }
    }

    data class ScoredServer(
        val server: VpnServer,
        val score: Int,
        val reasons: List<String>,
        val trend: CongestionTrend
    )

    fun score(
        server: VpnServer,
        history: ProbeHistory?,
        settings: GlobalVpnSettings
    ): ScoredServer {
        val reasons = mutableListOf<String>()
        var score = 50.0

        val latency = server.measuredLatencyMs ?: history?.ewmaSlowMs?.toLong() ?: server.reportedPingMs?.toLong()
        if (latency != null) {
            val latencyBonus = (25.0 - latency / 8.0).coerceIn(-15.0, 25.0)
            score += latencyBonus
            reasons.add("latency ${latency}ms -> ${latencyBonus.toInt()}")
        } else {
            reasons.add("no latency sample (neutral)")
        }

        val load = server.loadPercent
        if (load != null) {
            val loadBonus = (100 - load) / 100.0 * 15.0
            score += loadBonus
            reasons.add("load ${load}% -> +${loadBonus.toInt()}")
        }

        if (history != null) {
            if (history.samples > 0 && history.failures == 0 && history.ewmaFastMs != null) {
                score += 8
                reasons.add("reachable recently -> +8")
            }
            if (history.failures > 0) {
                val penalty = min(20, history.failures * 5)
                score -= penalty
                reasons.add("${history.failures} recent failures -> -$penalty")
            }
            when (history.trend()) {
                CongestionTrend.RISING -> {
                    score -= 6
                    reasons.add("rising congestion -> -6")
                }
                CongestionTrend.FALLING -> {
                    score += 3
                    reasons.add("improving latency -> +3")
                }
                else -> Unit
            }
        }

        if (settings.preferredProvider == server.provider) {
            score += 5
            reasons.add("preferred provider -> +5")
        }
        if (settings.preferredCountryCode != null &&
            settings.preferredCountryCode.equals(server.countryCode, ignoreCase = true)
        ) {
            score += 5
            reasons.add("preferred country -> +5")
        }
        if (settings.protocolPreference == server.protocol) {
            score += 3
            reasons.add("preferred protocol -> +3")
        }
        if (!server.isConnectable) {
            score -= 100
            reasons.add("not connectable in-app")
        }

        val clamped = score.coerceIn(0.0, 100.0).toInt()
        return ScoredServer(server, clamped, reasons, history?.trend() ?: CongestionTrend.UNKNOWN)
    }

    fun rank(
        servers: List<VpnServer>,
        histories: Map<String, ProbeHistory>,
        settings: GlobalVpnSettings
    ): List<ScoredServer> =
        servers.map { score(it, histories[it.id], settings) }
            .sortedWith(compareByDescending<ScoredServer> { it.score }.thenBy { it.server.displayName })

    fun fastestConnectable(
        servers: List<VpnServer>,
        histories: Map<String, ProbeHistory>,
        settings: GlobalVpnSettings
    ): ScoredServer? =
        rank(servers, histories, settings).firstOrNull { it.server.isConnectable }

    /** Simple jitter helper used by diagnostics. */
    fun jitterMs(samples: List<Long>): Long {
        if (samples.size < 2) return 0
        val diffs = samples.zipWithNext { a, b -> abs(a - b) }
        return diffs.average().toLong()
    }
}
