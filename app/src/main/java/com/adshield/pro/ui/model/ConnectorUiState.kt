package com.adshield.pro.ui.model

import com.adshield.pro.domain.connectors.ConnectorSnapshot
import com.adshield.pro.domain.connectors.LookupFinding
import com.adshield.pro.domain.intelligence.IntelligenceModule

/** A user-initiated check of a domain/URL/IP/hash against the cached intelligence index. */
data class IndicatorCheckResult(
    val value: String,
    val verdict: String,
    val score: Int,
    val reasons: List<String>,
    val checkedAtEpochMs: Long,
    /** Live per-provider answers from key-free lookup connectors; empty until a check runs. */
    val providers: List<LookupFinding> = emptyList(),
    val lookupNotes: List<String> = emptyList(),
    val offline: Boolean = false
)

data class ConnectorUiState(
    val connectors: List<ConnectorSnapshot>,
    val moduleFilter: IntelligenceModule?,
    val query: String,
    val syncingId: String?,
    val syncingModule: IntelligenceModule?,
    val message: String?,
    val check: IndicatorCheckResult?,
    val checking: Boolean,
    val totalIndicators: Int
) {
    val visible: List<ConnectorSnapshot>
        get() = connectors.filter { snapshot ->
            val moduleOk = moduleFilter == null || snapshot.spec.module == moduleFilter
            val queryOk = query.isBlank() ||
                snapshot.spec.name.contains(query, ignoreCase = true) ||
                snapshot.spec.provider.contains(query, ignoreCase = true) ||
                snapshot.spec.id.contains(query, ignoreCase = true)
            moduleOk && queryOk
        }

    val implementedCount: Int get() = connectors.count { it.spec.implemented }
    val connectedCount: Int get() = connectors.count { it.effectiveStatus.name == "CONNECTED" }
    val implementedWithTestEvidence: Int
        get() = connectors.count {
            it.spec.implemented &&
                (it.spec.verification == com.adshield.pro.domain.connectors.VerificationClass.IMPLEMENTED_AND_TESTED ||
                    it.spec.verification == com.adshield.pro.domain.connectors.VerificationClass.FREE_WITH_RESTRICTIONS)
        }

    fun summaryFor(module: IntelligenceModule): ConnectorModuleSummaryUi {
        val items = connectors.filter { it.spec.module == module }
        return ConnectorModuleSummaryUi(
            module = module,
            total = items.size,
            implemented = items.count { it.spec.implemented },
            connected = items.count { it.effectiveStatus.name == "CONNECTED" },
            lastSuccessEpochMs = items.mapNotNull { it.runtime.lastSuccessEpochMs }.maxOrNull()
        )
    }
}

data class ConnectorModuleSummaryUi(
    val module: IntelligenceModule,
    val total: Int,
    val implemented: Int,
    val connected: Int,
    val lastSuccessEpochMs: Long?
)
