package com.adshield.pro.engine.evolution

import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.FilterListSource
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.first

/** Outcome of one real protection-data evolution run. */
enum class EvolutionRunStatus { SUCCESS, COMPLETED_WITH_WARNINGS, FAILED }

data class EvolutionRunReport(
    val finishedAtEpochMs: Long,
    val activeRuleCount: Int,
    val status: EvolutionRunStatus,
    val message: String,
    val sourcesNeedingAttention: Int
)

/**
 * Coordinates non-executable protection evolution for manual and WorkManager runs.
 *
 * This deliberately does not rewrite application code or generate blocking rules from unknown
 * domains. It evolves the verified filter snapshot through the repository's HTTPS validation,
 * atomic swap and rollback path, then records what actually happened. Signed application updates
 * remain a separate, user-reviewed Android installation flow.
 */
@Singleton
class ProtectionEvolutionEngine @Inject constructor(
    private val repository: AdShieldRepository,
    private val preferences: UserPreferencesRepository
) {
    suspend fun evolveNow(): EvolutionRunReport {
        val result = repository.updateAllEnabledFilterLists()
        val finishedAt = System.currentTimeMillis()
        val report = result.fold(
            onSuccess = { activeRules ->
                val sources = repository.filterSourcesFlow.first().filter { it.isEnabled }
                val (status, message, attention) = summarizeSources(activeRules, sources)
                EvolutionRunReport(finishedAt, activeRules, status, message, attention)
            },
            onFailure = { error ->
                EvolutionRunReport(
                    finishedAtEpochMs = finishedAt,
                    activeRuleCount = 0,
                    status = EvolutionRunStatus.FAILED,
                    message = "Update rolled back; previous rules remain active. " +
                        (error.message?.take(140) ?: "Unknown update error"),
                    sourcesNeedingAttention = 0
                )
            }
        )
        preferences.recordEvolutionRun(report)
        return report
    }

    companion object {
        /** Pure source-health classification, shared by JVM tests and the runtime report. */
        fun summarizeSources(
            activeRuleCount: Int,
            enabledSources: List<FilterListSource>
        ): Triple<EvolutionRunStatus, String, Int> {
            val attention = enabledSources.count { source ->
                val status = source.lastStatusMessage.lowercase()
                "update failed" in status || "fallback active" in status || "cached rules active" in status
            }
            return if (attention > 0) {
                Triple(
                    EvolutionRunStatus.COMPLETED_WITH_WARNINGS,
                    "$activeRuleCount active rules; $attention enabled source(s) need attention. " +
                        "Cached or bundled rules remain active.",
                    attention
                )
            } else {
                Triple(
                    EvolutionRunStatus.SUCCESS,
                    "$activeRuleCount active rules verified through the atomic update pipeline.",
                    0
                )
            }
        }
    }
}
