package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.local.preferences.IntelligenceMapPreferences
import com.adshield.pro.data.local.preferences.ScanJournalStore
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.data.repository.IntelligenceRepository
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceFilters
import com.adshield.pro.domain.intelligence.IntelligenceInputs
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.domain.intelligence.IntelligenceSystemState
import com.adshield.pro.domain.intelligence.IntelligenceTimeRange
import com.adshield.pro.domain.intelligence.NodePosition
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.intelligence.IntelligenceAggregator
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.ui.model.IntelligenceMapUiState
import com.adshield.pro.ui.model.MapCameraCommand
import com.adshield.pro.ui.model.MapCameraTarget
import com.adshield.pro.ui.screens.intelligence.MapGeometry
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject

/** Internal control state, kept out of the rendering model. */
private data class MapControls(
    val isLive: Boolean = true,
    val pausedAtEpochMs: Long? = null,
    val frozenSystem: IntelligenceSystemState? = null,
    val isEditingLayout: Boolean = false,
    val selectedModule: IntelligenceModule? = null,
    val selectedEventId: Long? = null,
    val cameraCommand: MapCameraCommand? = null
)

private data class RuntimeSignals(
    val vpnStatus: VpnStatus,
    val protectionExpected: Boolean,
    val connectedSinceEpochMs: Long?,
    val vpnLastError: String?,
    val loadedRuleCount: Int,
    val sessionQueries: Long,
    val sessionBlocked: Long,
    val averageLatency: Int,
    val resolverLabel: String,
    val protocolLabel: String,
    val emergencyLockdown: Boolean,
    val autoUpdateFilters: Boolean,
    val lastFilterUpdateEpochMs: Long,
    val scheduledScanEnabled: Boolean,
    val scheduledScanIntervalHours: Int,
    val smartAutoOptimizeEnabled: Boolean,
    val browserCosmetic: Boolean,
    val browserThirdPartyCookies: Boolean,
    val browserExceptionCount: Int,
    val perAppDnsRules: Int,
    val thermalThreshold: Float,
    val malwareBlocksTotal: Long
)

private data class EvidenceSignals(
    val scans: List<SecurityScanRecord>,
    val quarantine: List<QuarantinedItem>,
    val trackerBlocksRecent: Long
)

/**
 * ViewModel for the OMNISHIELD X Live Intelligence Map.
 *
 * It owns visual state only: camera commands, filters, selection, pause and node layout. It never
 * starts or stops protection, and it never writes an event — events arrive from module services
 * through [com.adshield.pro.data.repository.IntelligenceRecorder]. Every screen subscription is
 * lifecycle-aware through `collectAsStateWithLifecycle`, and the aggregation runs on
 * [Dispatchers.Default] behind `WhileSubscribed(5_000)`.
 */
@HiltViewModel
class IntelligenceMapViewModel @Inject constructor(
    private val intelligenceRepository: IntelligenceRepository,
    private val adShieldRepository: AdShieldRepository,
    private val journalStore: ScanJournalStore,
    private val preferencesRepository: UserPreferencesRepository,
    private val batteryRepository: BatteryIntelligenceRepository,
    private val mapPreferences: IntelligenceMapPreferences
) : ViewModel() {

    private val controls = MutableStateFlow(MapControls())
    private val filtersState = MutableStateFlow(IntelligenceFilters.DEFAULT)
    private val cameraToken = AtomicLong(0L)

    private val settings = preferencesRepository.settingsFlow
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            com.adshield.pro.data.local.preferences.AppSettingsState()
        )

    private val runtimeSignals = combine(
        adShieldRepository.vpnRuntimeState,
        settings,
        adShieldRepository.malwareBlocksFlow
    ) { vpn, currentSettings, malwareBlocks ->
        RuntimeSignals(
            vpnStatus = vpn.status,
            protectionExpected = currentSettings.vpnShouldRemainActive,
            connectedSinceEpochMs = vpn.connectedSinceEpochMs,
            vpnLastError = vpn.lastError,
            loadedRuleCount = vpn.loadedRuleCount,
            sessionQueries = vpn.sessionTotalQueries,
            sessionBlocked = vpn.sessionBlockedQueries,
            averageLatency = vpn.averageLatencyMs,
            resolverLabel = vpn.resolverConfig.preset.displayName,
            protocolLabel = vpn.resolverConfig.protocol.label,
            emergencyLockdown = currentSettings.dnsFirewallPolicy.emergencyAllowlistOnly,
            autoUpdateFilters = currentSettings.autoUpdateFiltersEnabled,
            lastFilterUpdateEpochMs = currentSettings.lastFilterUpdateEpochMs,
            scheduledScanEnabled = currentSettings.scheduledScanEnabled,
            scheduledScanIntervalHours = currentSettings.scheduledScanIntervalHours,
            smartAutoOptimizeEnabled = currentSettings.smartAutoOptimizeEnabled,
            browserCosmetic = currentSettings.browserCosmeticFilteringEnabled,
            browserThirdPartyCookies = currentSettings.browserBlockThirdPartyCookies,
            browserExceptionCount = currentSettings.browserSiteExceptions.size,
            perAppDnsRules = currentSettings.dnsFirewallPolicy.appPolicies.count {
                it.value != com.adshield.pro.domain.model.AppDnsPolicy.DEFAULT
            },
            thermalThreshold = currentSettings.gameBoosterTempWarningCelsius.toFloat(),
            malwareBlocksTotal = malwareBlocks
        )
    }

    private val evidenceSignals = combine(
        journalStore.historyFlow,
        journalStore.quarantineFlow,
        adShieldRepository.recentLogsFlow
    ) { scans, quarantine, logs ->
        EvidenceSignals(
            scans = scans,
            quarantine = quarantine,
            trackerBlocksRecent = logs.count { it.isBlocked && it.category == RuleCategory.TRACKERS }.toLong()
        )
    }

    private val baseSignals = combine(
        runtimeSignals,
        evidenceSignals,
        batteryRepository.telemetry
    ) { runtime, evidence, telemetry ->
        runtime to (evidence to telemetry)
    }

    /** Live (unpaused) aggregate. Recomputed when real inputs or stored events change. */
    private val liveSystem: StateFlow<IntelligenceSystemState> = combine(
        baseSignals,
        intelligenceRepository.events,
        filtersState
    ) { base, events, filters ->
        val (runtime, rest) = base
        val (evidence, telemetry) = rest
        val inputs = IntelligenceInputs(
            nowEpochMs = System.currentTimeMillis(),
            vpnStatus = runtime.vpnStatus,
            protectionExpected = runtime.protectionExpected,
            connectedSinceEpochMs = runtime.connectedSinceEpochMs,
            vpnLastError = runtime.vpnLastError,
            loadedRuleCount = runtime.loadedRuleCount,
            sessionTotalQueries = runtime.sessionQueries,
            sessionBlockedQueries = runtime.sessionBlocked,
            averageLatencyMs = runtime.averageLatency,
            resolverLabel = runtime.resolverLabel,
            dnsProtocolLabel = runtime.protocolLabel,
            emergencyAllowlistOnly = runtime.emergencyLockdown,
            autoUpdateFiltersEnabled = runtime.autoUpdateFilters,
            lastFilterUpdateEpochMs = runtime.lastFilterUpdateEpochMs,
            scheduledScanEnabled = runtime.scheduledScanEnabled,
            scheduledScanIntervalHours = runtime.scheduledScanIntervalHours,
            smartAutoOptimizeEnabled = runtime.smartAutoOptimizeEnabled,
            browserCosmeticFilteringEnabled = runtime.browserCosmetic,
            browserBlockThirdPartyCookies = runtime.browserThirdPartyCookies,
            browserSiteExceptionCount = runtime.browserExceptionCount,
            perAppDnsRuleCount = runtime.perAppDnsRules,
            trackerBlocksRecent = evidence.trackerBlocksRecent,
            malwareBlocksTotal = runtime.malwareBlocksTotal,
            scans = evidence.scans,
            quarantine = evidence.quarantine,
            batteryTelemetry = telemetry,
            thermalWarningCelsius = runtime.thermalThreshold
        )
        buildStateTimed(inputs, events, filters)
    }.flowOn(Dispatchers.Default).stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        initialState()
    )

    private val layout = mapPreferences.layoutFlow.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        emptyMap()
    )

    val uiState: StateFlow<IntelligenceMapUiState> = combine(
        liveSystem,
        intelligenceRepository.events,
        layout,
        controls,
        filtersState
    ) { live, events, overrides, control, filters ->
        val paused = !control.isLive
        val displayed = if (paused) control.frozenSystem ?: live else live
        val positions = MapGeometry.resolvedPositions(overrides)
        val selectedEvent = control.selectedEventId?.let { id -> events.firstOrNull { it.id == id } }
        IntelligenceMapUiState(
            system = displayed.copy(filters = filters),
            allEvents = events,
            nodePositions = positions,
            filters = filters,
            isLive = control.isLive,
            pausedAtEpochMs = control.pausedAtEpochMs,
            newEventsWhilePaused = if (paused && control.pausedAtEpochMs != null) {
                events.count { it.timestampEpochMs > control.pausedAtEpochMs }
            } else {
                0
            },
            isEditingLayout = control.isEditingLayout,
            selectedModule = control.selectedModule,
            selectedEvent = selectedEvent,
            cameraCommand = control.cameraCommand,
            isHistoryEmpty = events.isEmpty()
        )
    }.flowOn(Dispatchers.Default).stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        IntelligenceMapUiState(
            system = initialState(),
            allEvents = emptyList(),
            nodePositions = MapGeometry.defaultPositions(),
            filters = IntelligenceFilters.DEFAULT,
            isLive = true,
            pausedAtEpochMs = null,
            newEventsWhilePaused = 0,
            isEditingLayout = false,
            selectedModule = null,
            selectedEvent = null,
            cameraCommand = null,
            isHistoryEmpty = true
        )
    )

    private fun buildStateTimed(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        filters: IntelligenceFilters
    ): IntelligenceSystemState {
        val started = System.nanoTime()
        val state = IntelligenceAggregator.buildState(inputs, events, filters, 0L)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000L
        return state.copy(buildDurationMs = elapsedMs)
    }

    private fun initialState(): IntelligenceSystemState = IntelligenceAggregator.buildState(
        inputs = IntelligenceInputs.empty(System.currentTimeMillis()),
        events = emptyList(),
        filters = IntelligenceFilters.DEFAULT,
        buildDurationMs = 0L
    )

    // ------------------------------------------------------------------ visual controls

    fun pauseVisualUpdates() {
        val now = System.currentTimeMillis()
        controls.update {
            if (!it.isLive) it else it.copy(
                isLive = false,
                pausedAtEpochMs = now,
                frozenSystem = liveSystem.value
            )
        }
    }

    fun resumeVisualUpdates() {
        controls.update {
            it.copy(isLive = true, pausedAtEpochMs = null, frozenSystem = null)
        }
    }

    fun toggleLive() {
        if (controls.value.isLive) pauseVisualUpdates() else resumeVisualUpdates()
    }

    fun setEditingLayout(editing: Boolean) {
        controls.update { it.copy(isEditingLayout = editing) }
    }

    fun selectModule(module: IntelligenceModule?) {
        controls.update {
            it.copy(selectedModule = module, selectedEventId = if (module == null) null else it.selectedEventId)
        }
    }

    fun clearSelection() {
        controls.update { it.copy(selectedModule = null, selectedEventId = null) }
    }

    fun selectEvent(event: IntelligenceEvent) {
        controls.update {
            it.copy(
                selectedModule = event.module,
                selectedEventId = event.id,
                cameraCommand = nextCommand(MapCameraTarget.OnEvent(event.module, event.id))
            )
        }
    }

    fun centerOnModule(module: IntelligenceModule) {
        controls.update { it.copy(cameraCommand = nextCommand(MapCameraTarget.OnModule(module))) }
    }

    fun resetCamera() {
        controls.update { it.copy(cameraCommand = nextCommand(MapCameraTarget.FitAll)) }
    }

    fun setModuleFilter(module: IntelligenceModule?) {
        filtersState.update { it.copy(module = module) }
    }

    fun setSeverityFilter(severity: IntelligenceSeverity?) {
        filtersState.update { it.copy(severity = severity) }
    }

    fun setTimeRange(range: IntelligenceTimeRange) {
        filtersState.update { it.copy(range = range) }
    }

    fun setSearchQuery(query: String) {
        filtersState.update { it.copy(query = query.take(64)) }
    }

    fun clearFilters() {
        filtersState.value = IntelligenceFilters.DEFAULT
    }

    fun moveNode(module: IntelligenceModule, position: NodePosition) {
        if (!module.isNode) return
        viewModelScope.launch(Dispatchers.IO) {
            mapPreferences.saveNode(module, position)
        }
    }

    fun resetNodeLayout() {
        viewModelScope.launch(Dispatchers.IO) { mapPreferences.resetLayout() }
    }

    /** Sensitive: permanently deletes the stored intelligence history (UI asks for confirmation). */
    fun clearHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            intelligenceRepository.clear()
        }
    }

    private fun nextCommand(target: MapCameraTarget): MapCameraCommand =
        MapCameraCommand(token = cameraToken.incrementAndGet(), target = target)

    /** Exposed for tests / diagnostics: current filter snapshot. */
    internal fun currentFilters(): IntelligenceFilters = filtersState.value
}
