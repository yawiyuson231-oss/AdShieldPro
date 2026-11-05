package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.data.repository.CloudStatusRepository
import com.adshield.pro.data.repository.ThreatIntelRepository
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.SeverityCounts
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.engine.cloud.CloudProvider
import com.adshield.pro.engine.cloud.CloudStatusState
import com.adshield.pro.engine.compliance.ComplianceChecker
import com.adshield.pro.engine.compliance.ComplianceSignalCollector
import com.adshield.pro.engine.detection.LocalDetectionEngine
import com.adshield.pro.engine.intel.CountryThreat
import com.adshield.pro.engine.intel.IndicatorKind
import com.adshield.pro.engine.intel.ThreatIntelAggregation
import com.adshield.pro.engine.intel.ThreatIntelState
import com.adshield.pro.engine.security.SecurityEngine
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** Which intelligence the world map is currently filtered to. */
enum class IntelMapFilter(val label: String) {
    ALL("All threats"),
    BOTNET_C2("Botnet C2"),
    MALWARE_URLS("Malware URLs")
}

/**
 * State holder for the CyberShield command center. Everything it exposes is derived from a real
 * source: the device's own DNS log (detection, severity, threats), Room-cached abuse.ch feeds
 * (map + intelligence), official provider status pages (cloud), and live Android signals
 * (compliance). Empty and error states are first-class — nothing is simulated.
 */
@HiltViewModel
class CyberShieldViewModel @Inject constructor(
    private val repository: AdShieldRepository,
    private val intelRepository: ThreatIntelRepository,
    private val cloudStatusRepository: CloudStatusRepository,
    private val complianceSignalCollector: ComplianceSignalCollector,
    private val securityEngine: SecurityEngine
) : ViewModel() {

    // ---------------------------------------------------------------- Intelligence

    val intelState: StateFlow<ThreatIntelState> = intelRepository.state
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ThreatIntelState())

    private val _mapFilter = MutableStateFlow(IntelMapFilter.ALL)
    val mapFilter: StateFlow<IntelMapFilter> = _mapFilter.asStateFlow()

    private val _selectedCountry = MutableStateFlow<String?>(null)
    val selectedCountry: StateFlow<String?> = _selectedCountry.asStateFlow()

    /** Indicators after the active map/list filter. */
    val filteredIndicators = combine(intelState, _mapFilter) { state, filter ->
        when (filter) {
            IntelMapFilter.ALL -> state.indicators
            IntelMapFilter.BOTNET_C2 -> state.indicators.filter { it.kind == IndicatorKind.BOTNET_C2 }
            IntelMapFilter.MALWARE_URLS -> state.indicators.filter { it.kind == IndicatorKind.MALWARE_URL }
        }
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val countryThreats: StateFlow<List<CountryThreat>> = filteredIndicators
        .map { ThreatIntelAggregation.byCountry(it) }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _intelFeedback = MutableStateFlow<String?>(null)
    val intelFeedback: StateFlow<String?> = _intelFeedback.asStateFlow()

    fun setMapFilter(filter: IntelMapFilter) {
        _mapFilter.value = filter
        _selectedCountry.value = null
    }

    fun selectCountry(code: String?) {
        _selectedCountry.value = code
    }

    fun refreshIntel() {
        if (intelState.value.isRefreshing) return
        viewModelScope.launch {
            val result = intelRepository.refresh()
            _intelFeedback.value = result.fold(
                onSuccess = { count -> "Threat intelligence synced: $count indicators from abuse.ch feeds." },
                onFailure = { error -> error.message ?: "Threat-intel sync failed. Cached data was kept." }
            )
        }
    }

    fun clearIntelFeedback() {
        _intelFeedback.value = null
    }

    // ---------------------------------------------------------------- Detection

    val detectionReport: StateFlow<LocalDetectionEngine.DetectionReport> = repository.recentLogsFlow
        .map { logs -> LocalDetectionEngine.run(logs) }
        .flowOn(Dispatchers.Default)
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            LocalDetectionEngine.run(emptyList())
        )

    val severityTotals: StateFlow<SeverityCounts> = repository.severityTotalsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), SeverityCounts())

    // ---------------------------------------------------------------- Threats list

    private val _threatQuery = MutableStateFlow("")
    val threatQuery: StateFlow<String> = _threatQuery.asStateFlow()

    private val _severityFilter = MutableStateFlow<ThreatSeverity?>(null)
    val severityFilter: StateFlow<ThreatSeverity?> = _severityFilter.asStateFlow()

    private val _includeAllowed = MutableStateFlow(false)
    val includeAllowed: StateFlow<Boolean> = _includeAllowed.asStateFlow()

    val filteredThreats: StateFlow<List<DnsActivityRecord>> = combine(
        repository.recentLogsFlow,
        _threatQuery,
        _severityFilter,
        _includeAllowed
    ) { logs, query, severity, includeAllowed ->
        val needle = query.trim().lowercase()
        logs.filter { record ->
            val matchesSeverity = severity == null || ThreatSeverity.of(record) == severity
            val matchesAllowed = includeAllowed || record.isBlocked
            val matchesQuery = needle.isEmpty() ||
                record.domain.lowercase().contains(needle) ||
                record.sourceList.lowercase().contains(needle) ||
                (record.matchedRule?.lowercase()?.contains(needle) == true)
            matchesSeverity && matchesAllowed && matchesQuery
        }
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun setThreatQuery(query: String) {
        _threatQuery.value = query
    }

    fun setSeverityFilter(severity: ThreatSeverity?) {
        _severityFilter.value = severity
    }

    fun setIncludeAllowed(include: Boolean) {
        _includeAllowed.value = include
    }

    /** Real event history for one domain, from the same persisted log. */
    fun historyForDomain(domain: String): List<DnsActivityRecord> =
        filteredThreats.value.filter { it.domain == domain }

    // ---------------------------------------------------------------- Cloud

    val cloudStatuses: StateFlow<CloudStatusState> = cloudStatusRepository.state

    fun refreshCloud(provider: CloudProvider? = null) {
        if (cloudStatuses.value.isRefreshing) return
        viewModelScope.launch {
            runCatching { cloudStatusRepository.refresh(provider) }
        }
    }

    // ---------------------------------------------------------------- Compliance

    private val _complianceReport = MutableStateFlow<ComplianceChecker.ComplianceReport?>(null)
    val complianceReport: StateFlow<ComplianceChecker.ComplianceReport?> = _complianceReport.asStateFlow()

    private val _isEvaluatingCompliance = MutableStateFlow(false)
    val isEvaluatingCompliance: StateFlow<Boolean> = _isEvaluatingCompliance.asStateFlow()

    /**
     * Evaluates the device checklist from live signals. [highRiskAppCount] is null until an app
     * audit has actually run — the report then says "unknown", never "clean".
     */
    fun evaluateCompliance(highRiskAppCount: Int?) {
        if (_isEvaluatingCompliance.value) return
        viewModelScope.launch {
            _isEvaluatingCompliance.value = true
            val report = withContext(Dispatchers.IO) {
                val signals = complianceSignalCollector.collect(
                    vpnState = repository.vpnRuntimeState.value,
                    settings = repository.settingsFlow.first(),
                    threatSignatureCount = securityEngine.activeThreatSignatureCount(),
                    highRiskAppCount = highRiskAppCount,
                    bundledBaselineAvailable = repository.vpnRuntimeState.value.loadedRuleCount > 0
                )
                ComplianceChecker.evaluate(signals)
            }
            _complianceReport.value = report
            _isEvaluatingCompliance.value = false
        }
    }

    suspend fun buildComplianceReportText(): String = withContext(Dispatchers.Default) {
        val report = _complianceReport.value
        if (report == null) {
            "No compliance evaluation has been run yet. Open the Reports tab and tap Evaluate."
        } else {
            ComplianceChecker.buildTextReport(report, com.adshield.pro.BuildConfig.VERSION_NAME)
        }
    }
}
