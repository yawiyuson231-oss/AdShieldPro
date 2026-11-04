package com.adshield.pro.engine.aether

/**
 * Bounded, explainable automation policy. It cannot create a new block from UNKNOWN
 * evidence and it cannot disable the user's existing DNS policy in manual mode.
 */
object AutonomousResponsePolicy {

    data class ResponsePlan(
        val action: AutonomousAction,
        val classification: ThreatClassification,
        val confidenceScore: Double,
        val explanation: String,
        val existingDnsBlockRemains: Boolean
    )

    fun plan(
        decision: AetherDecision,
        autonomousEnabled: Boolean,
        manualOverride: Boolean
    ): ResponsePlan {
        val classification = decision.threatClassification
        val action = when {
            manualOverride -> AutonomousAction.MANUAL_OVERRIDE
            decision.engineBlocked && classification == ThreatClassification.VERIFIED && autonomousEnabled ->
                AutonomousAction.ENFORCE_EXISTING_BLOCK
            decision.engineBlocked -> AutonomousAction.ENFORCE_EXISTING_BLOCK
            classification == ThreatClassification.SUSPECTED -> AutonomousAction.RECOMMEND_REVIEW
            else -> AutonomousAction.MONITOR
        }
        val automationNote = when {
            manualOverride -> " Manual override stops new automated changes; existing DNS rules remain active."
            !autonomousEnabled -> " Autonomous changes are disabled by the user."
            else -> " User-approved autonomous response is enabled."
        }
        return ResponsePlan(
            action = action,
            classification = classification,
            confidenceScore = decision.confidenceScore,
            explanation = decision.explanation + automationNote,
            existingDnsBlockRemains = decision.engineBlocked
        )
    }

    enum class RecoveryStatus { NOT_ATTEMPTED, RECOVERING, VERIFIED, FAILED }

    data class RecoveryDecision(
        val status: RecoveryStatus,
        val shouldRetry: Boolean,
        val explanation: String
    )

    /** Recovery is claimed only when the post-restart tunnel state is independently observed. */
    fun evaluateRecovery(
        restartRequested: Boolean,
        tunnelConnectedAfterRestart: Boolean,
        attempts: Int,
        maxAttempts: Int = 3
    ): RecoveryDecision = when {
        !restartRequested -> RecoveryDecision(
            RecoveryStatus.NOT_ATTEMPTED,
            false,
            "No recovery was requested; existing protection state was not changed."
        )
        tunnelConnectedAfterRestart -> RecoveryDecision(
            RecoveryStatus.VERIFIED,
            false,
            "Protection recovery verified by a connected tunnel after restart."
        )
        attempts < maxAttempts -> RecoveryDecision(
            RecoveryStatus.RECOVERING,
            true,
            "Tunnel is not yet verified; retry ${attempts + 1} of $maxAttempts is permitted."
        )
        else -> RecoveryDecision(
            RecoveryStatus.FAILED,
            false,
            "Recovery could not be verified after $attempts attempts; user action is required."
        )
    }
}
