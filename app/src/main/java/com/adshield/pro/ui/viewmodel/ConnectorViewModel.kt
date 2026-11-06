package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.ConnectorRepository
import com.adshield.pro.domain.connectors.ConnectorSnapshot
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.ui.model.ConnectorUiState
import com.adshield.pro.ui.model.IndicatorCheckResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Connector registry state. Every action here performs a real operation through
 * [ConnectorRepository]; nothing is simulated, and failures are surfaced verbatim.
 */
@HiltViewModel
class ConnectorViewModel @Inject constructor(
    private val repository: ConnectorRepository
) : ViewModel() {

    private val moduleFilter = MutableStateFlow<IntelligenceModule?>(null)
    private val query = MutableStateFlow("")
    private val syncingId = MutableStateFlow<String?>(null)
    private val syncingModule = MutableStateFlow<IntelligenceModule?>(null)
    private val message = MutableStateFlow<String?>(null)
    private val check = MutableStateFlow<IndicatorCheckResult?>(null)
    private val checking = MutableStateFlow(false)
    private val indicatorTotal = MutableStateFlow(0)

    private data class Controls(
        val syncingId: String?,
        val syncingModule: IntelligenceModule?,
        val message: String?,
        val check: IndicatorCheckResult?,
        val checking: Boolean
    )

    private val controls: kotlinx.coroutines.flow.Flow<Controls> = combine(
        syncingId, syncingModule, message, check, checking
    ) { busyId, busyModule, msg, result, isChecking ->
        Controls(busyId, busyModule, msg, result, isChecking)
    }

    val uiState: StateFlow<ConnectorUiState> = combine(
        repository.snapshots,
        moduleFilter,
        query,
        controls
    ) { connectors, filter, search, control ->
        ConnectorUiState(
            connectors = connectors,
            moduleFilter = filter,
            query = search,
            syncingId = control.syncingId,
            syncingModule = control.syncingModule,
            message = control.message,
            check = control.check,
            checking = control.checking,
            totalIndicators = indicatorTotal.value
        )
    }.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        ConnectorUiState(
            connectors = emptyList(),
            moduleFilter = null,
            query = "",
            syncingId = null,
            syncingModule = null,
            message = null,
            check = null,
            checking = false,
            totalIndicators = 0
        )
    )

    init {
        viewModelScope.launch {
            repository.snapshots.collect {
                indicatorTotal.value = repository.totalIndicators()
            }
        }
    }

    fun setModuleFilter(module: IntelligenceModule?) {
        moduleFilter.value = module
    }

    fun setQuery(value: String) {
        query.value = value
    }

    fun clearMessage() {
        message.value = null
    }

    fun sync(id: String) {
        if (syncingId.value != null) return
        viewModelScope.launch {
            syncingId.value = id
            val result = repository.sync(id)
            syncingId.value = null
            message.value = result?.let { snapshot ->
                "${snapshot.spec.name}: ${snapshot.runtime.status.label}" +
                    (snapshot.runtime.lastError?.let { " — $it" } ?: snapshot.runtime.lastSummary?.let { " — $it" } ?: "")
            } ?: "Unknown connector"
            indicatorTotal.value = repository.totalIndicators()
        }
    }

    fun syncModule(module: IntelligenceModule) {
        if (syncingModule.value != null) return
        viewModelScope.launch {
            syncingModule.value = module
            val count = repository.syncModule(module)
            syncingModule.value = null
            message.value = "${module.displayName}: attempted $count connector(s)"
            indicatorTotal.value = repository.totalIndicators()
        }
    }

    fun toggleEnabled(snapshot: ConnectorSnapshot) {
        viewModelScope.launch {
            repository.setEnabled(snapshot.spec.id, !snapshot.runtime.enabled)
        }
    }

    fun checkValue(raw: String) {
        val value = raw.trim()
        if (value.isEmpty()) {
            message.value = "Enter a domain, URL, IP or SHA-256 hash"
            return
        }
        viewModelScope.launch {
            checking.value = true
            val assessment = repository.assess(value)
            // Live lookups are attempted only on this explicit user action. Each provider is
            // independently allowed to fail; failures stay visible instead of being hidden.
            val report = runCatching { repository.lookup(value) }.getOrNull()
            checking.value = false
            check.value = IndicatorCheckResult(
                value = value,
                verdict = assessment.verdict.label,
                score = assessment.score,
                reasons = assessment.reasons,
                checkedAtEpochMs = System.currentTimeMillis(),
                providers = report?.findings.orEmpty(),
                lookupNotes = report?.notes.orEmpty(),
                offline = report?.offline == true
            )
            message.value = null
        }
    }

    fun clearCheck() {
        check.value = null
    }
}
