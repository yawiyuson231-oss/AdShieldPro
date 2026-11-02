package com.adshield.pro.engine.zero

import javax.inject.Inject

/**
 * TitanShield Max — Zero-Breakage Engine (Module 7).
 *
 * Pure decision logic + probe accounting for the VPN service watchdog:
 * - The service probes a always-up connectivity endpoint through the *filtered*
 *   resolver every 30s (60s while in safe mode).
 * - 3 consecutive probe failures (while the unfiltered path is expected to work)
 *   indicate a probable false-positive storm / bad filter update → the engine
 *   orders SAFE_MODE_FILTERING: filter lists are dropped atomically while user
 *   custom rules and Critical Protection stay active. Internet keeps working.
 * - The first stable probe after safe mode orders RESTORE_FULL_FILTERING, which
 *   re-syncs the full lists from the on-device database.
 *
 * The engine never silently *adds* blocking (spec guard) — it only relaxes
 * filtering when breakage is detected, and every relaxation is counted for the
 * dashboard and surfaced to the user via a toast + counters.
 */
class ZeroBreakageEngine @Inject constructor() {

    enum class WatchdogAction {
        NONE,
        SAFE_MODE_FILTERING,
        RESTORE_FULL_FILTERING
    }

    data class WatchdogState(
        val consecutiveFailures: Int,
        val consecutiveSuccesses: Int,
        val totalProbeFailures: Long,
        val totalProbes: Long,
        val safeModeActive: Boolean,
        val lastProbeEpochMs: Long,
        val lastAction: WatchdogAction
    )

    private var consecutiveFailures = 0
    private var consecutiveSuccesses = 0
    private var totalProbeFailures = 0L
    private var totalProbes = 0L
    private var safeModeActive = false
    private var lastProbeEpochMs = 0L
    private var lastAction = WatchdogAction.NONE

    /** Probe failures required before relaxing filtering. */
    var failureThreshold: Int = 3

    fun onProbeResult(succeeded: Boolean, atEpochMs: Long = System.currentTimeMillis()): WatchdogAction {
        totalProbes++
        lastProbeEpochMs = atEpochMs

        if (succeeded) {
            consecutiveSuccesses++
            consecutiveFailures = 0
            if (safeModeActive) {
                // Connectivity verified again — restore the full lists exactly once.
                safeModeActive = false
                lastAction = WatchdogAction.RESTORE_FULL_FILTERING
                return lastAction
            }
            lastAction = WatchdogAction.NONE
            return WatchdogAction.NONE
        }

        consecutiveFailures++
        consecutiveSuccesses = 0
        totalProbeFailures++

        if (!safeModeActive && consecutiveFailures >= failureThreshold) {
            safeModeActive = true
            lastAction = WatchdogAction.SAFE_MODE_FILTERING
            return lastAction
        }
        lastAction = WatchdogAction.NONE
        return WatchdogAction.NONE
    }

    fun currentState(): WatchdogState = WatchdogState(
        consecutiveFailures = consecutiveFailures,
        consecutiveSuccesses = consecutiveSuccesses,
        totalProbeFailures = totalProbeFailures,
        totalProbes = totalProbes,
        safeModeActive = safeModeActive,
        lastProbeEpochMs = lastProbeEpochMs,
        lastAction = lastAction
    )

    fun isSafeModeActive(): Boolean = safeModeActive
}
