package com.adshield.pro.cybershield

/**
 * Derives the central shield state from the REAL VPN runtime status.
 * The shield never claims protection that is not actually running.
 */
object ShieldStateEvaluator {

    fun evaluate(
        vpnStatus: String,
        lastError: String?,
        aetherEnabled: Boolean,
        blockedLastHour: Int,
        loadedRuleCount: Int
    ): ShieldState {
        val recentSuffix = if (blockedLastHour > 0) {
            " · $blockedLastHour threat${if (blockedLastHour > 1) "s" else ""} blocked in the last hour"
        } else ""
        return when (vpnStatus) {
            "CONNECTED" -> ShieldState(
                mode = ShieldMode.ACTIVE,
                headline = "PROTECTION ACTIVE",
                subtitle = (if (aetherEnabled) "DNS filtering + AETHER on-device analysis"
                else "DNS filtering active · AETHER analysis disabled") + recentSuffix,
                recentBlocked = blockedLastHour
            )
            "STARTING", "RECONNECTING" -> ShieldState(
                mode = ShieldMode.STARTING,
                headline = if (vpnStatus == "RECONNECTING") "RECONNECTING" else "STARTING PROTECTION",
                subtitle = "Bringing up the local DNS filter tunnel…",
                recentBlocked = 0
            )
            "PAUSED" -> ShieldState(
                mode = ShieldMode.PAUSED,
                headline = "PROTECTION PAUSED",
                subtitle = "DNS queries are passing through unfiltered. Resume to re-enable blocking.",
                recentBlocked = 0
            )
            "ERROR" -> ShieldState(
                mode = ShieldMode.ERROR,
                headline = "PROTECTION ERROR",
                subtitle = "The DNS filter tunnel failed to start.",
                recentBlocked = 0,
                error = lastError ?: "Unknown tunnel error"
            )
            else -> ShieldState(
                mode = ShieldMode.OFF,
                headline = "PROTECTION OFF",
                subtitle = if (loadedRuleCount > 0) {
                    "$loadedRuleCount filter rules ready. Activate to start on-device DNS protection."
                } else "Activate to start on-device DNS protection.",
                recentBlocked = 0
            )
        }
    }
}
