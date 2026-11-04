package com.adshield.pro.ui.viewmodel

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.data.local.preferences.DarkThemePreference
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.data.repository.NetworkIntelligenceRepository
import com.adshield.pro.BuildConfig
import com.adshield.pro.domain.model.AppExclusionInfo
import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.BatteryMode
import com.adshield.pro.domain.model.BatteryThermalSnapshot
import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.DeviceHealthAssessment
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DomainBlockCount
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.FilterListSource
import com.adshield.pro.domain.model.GameAppInfo
import com.adshield.pro.domain.model.GamingProfile
import com.adshield.pro.domain.model.JunkCleanMode
import com.adshield.pro.domain.model.JunkScanReport
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RamOptimizationResult
import com.adshield.pro.domain.model.RamSnapshot
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleConflictReport
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.domain.model.SmartBoostResult
import com.adshield.pro.domain.model.SourceEffectiveness
import com.adshield.pro.domain.model.StorageMetrics
import com.adshield.pro.domain.model.TimeBucketStat
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.LiveNetworkModel
import com.adshield.pro.engine.battery.BatteryDiagnostic
import com.adshield.pro.engine.battery.BatteryDiagnostics
import com.adshield.pro.engine.battery.BatterySession
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.optimizer.RuleBasedOptimizationPredictor
import com.adshield.pro.engine.optimizer.SystemOptimizerEngine
import com.adshield.pro.service.AdShieldVpnService
import com.adshield.pro.ui.UpdatePromptActivity
import com.adshield.pro.update.GitHubReleaseClient
import com.adshield.pro.worker.FilterUpdateWorker
import com.adshield.pro.worker.SmartOptimizationWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

enum class StatsChartRange(val label: String, val days: Int) {
    DAILY_7D("7 Days", 7),
    WEEKLY_14D("14 Days", 14),
    MONTHLY_30D("30 Days", 30)
}

@HiltViewModel
class AdShieldViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val repository: AdShieldRepository,
    private val preferencesRepository: UserPreferencesRepository,
    private val filterRuleEngine: FilterRuleEngine,
    private val upstreamDnsResolver: UpstreamDnsResolver,
    val browserContentBlocker: BrowserContentBlocker,
    private val optimizerEngine: SystemOptimizerEngine,
    private val securityEngine: com.adshield.pro.engine.security.SecurityEngine,
    private val gameTurboEngine: com.adshield.pro.engine.optimizer.GameTurboEngine,
    val aetherCore: com.adshield.pro.engine.aether.AetherGodCore,
    private val batteryRepository: BatteryIntelligenceRepository,
    private val securityLocalStore: com.adshield.pro.engine.security.SecurityLocalStore,
    private val networkIntelligenceRepository: NetworkIntelligenceRepository
) : ViewModel() {

    val vpnState: StateFlow<VpnRuntimeState> = repository.vpnRuntimeState

    // --- Zero-Breakage Engine (Module 7) ---
    private val _shadowVerdicts = MutableStateFlow<List<String>>(emptyList())
    val shadowVerdicts: StateFlow<List<String>> = _shadowVerdicts.asStateFlow()

    // --- AETHER GodCore Control Center (Part 12): live, real metrics only ---
    private val _aetherReport = MutableStateFlow(
        com.adshield.pro.engine.aether.ControlCenterReport(
            totalAgents = 15, agentsOnline = 0, dnsObserved = 0, blockedConfirmed = 0,
            anomaliesObserved = 0, verificationOverrides = 0, rebindingBlocked = 0,
            protectedOverrides = 0, safeModeActive = false, autoRecoveries = 0,
            bestResolverLabel = null, bestResolverLatencyMs = null,
            topObservedDomains = emptyList(), recentAudit = emptyList(),
            updatedAtEpochMs = 0L
        )
    )
    val aetherReport: StateFlow<com.adshield.pro.engine.aether.ControlCenterReport> = _aetherReport.asStateFlow()

    // --- DNS bypass diagnostics (real system state, refreshed live) ---
    private val _dnsBypassWarning = MutableStateFlow<String?>(null)
    val dnsBypassWarning: StateFlow<String?> = _dnsBypassWarning.asStateFlow()
    val networkAudit: StateFlow<NetworkIntelligenceRepository.NetworkAudit> = networkIntelligenceRepository.audit

    val dnsFallbackActive: StateFlow<Boolean> = repository.dnsFallbackActive

    /** Honest speed stat: blocked lookups answered instantly (no upstream round-trip). */
    val dnsTimeSavedEstimate: StateFlow<String?> = kotlinx.coroutines.flow.combine(
        repository.blockedLoggedCountFlow,
        repository.avgAllowedLatencyFlow
    ) { blocked, avgMs ->
        if (blocked > 0L && avgMs != null && avgMs > 0.0) {
            val savedMs = blocked.toDouble() * avgMs
            val label = if (savedMs >= 60_000.0) String.format("%.1f minutes", savedMs / 60_000.0)
                        else String.format("%.0f seconds", savedMs / 1000.0)
            "$blocked ad/tracker lookups answered instantly — about $label of lookup time avoided (estimate: blocked × your measured average lookup time)."
        } else null
    }.stateIn(viewModelScope, kotlinx.coroutines.flow.SharingStarted.WhileSubscribed(5_000), null)

    

    init {
        // Shadow verdicts recorded from the filter engine (never blocking — report only).
        filterRuleEngine.shadowDecisionListener = { domain, result ->
            _shadowVerdicts.value =
                (listOf("$domain :: ${result.sourceName.take(80)}") + _shadowVerdicts.value).take(25)
        }
        viewModelScope.launch {
            runCatching { networkIntelligenceRepository.refresh() }
        }
        viewModelScope.launch {
            filterRuleEngine.setShadowModeEnabled(preferencesRepository.getSettingsSnapshot().shadowModeEnabled)
        }
        viewModelScope.launch {
            val settings = preferencesRepository.getSettingsSnapshot()
            aetherCore.upstreamEncrypted = settings.resolverConfig.protocol != com.adshield.pro.domain.model.DnsProtocol.UDP_TCP
            aetherCore.detailedLoggingEnabled = settings.detailedDnsLoggingEnabled
            aetherCore.autonomousResponseEnabled = settings.autonomousResponseEnabled
            aetherCore.manualOverrideEnabled = settings.manualOverrideEnabled
        }
        // Live Control Center refresh while the dashboard is open (real counters, no simulation)
        viewModelScope.launch {
            while (true) {
                kotlinx.coroutines.delay(10_000L)
                val recoveries = preferencesRepository.getSettingsSnapshot().autoRecoveryCount
                // AETHER self-audit: feed REAL blocked events into the false-positive radar
                val radar = com.adshield.pro.engine.aether.AetherSelfAudit.possibleFalsePositives(
                    recentLogs.value.filter { it.isBlocked }.map { it.domain to it.sourceList }
                )
                _aetherReport.value = aetherCore.controlCenterReport(recoveries.toLong(), radar)
                runCatching { networkIntelligenceRepository.refresh() }
                refreshDnsBypassWarning()
            }
        }
    }

    /** Reads the REAL Android Private DNS state — strict mode silently bypasses any DNS VPN. */
    fun refreshDnsBypassWarning() {
        viewModelScope.launch(Dispatchers.IO) {
            val assessment = runCatching {
                val resolver = appContext.contentResolver
                val mode = android.provider.Settings.Global.getString(resolver, "private_dns_mode")
                val host = android.provider.Settings.Global.getString(resolver, "private_dns_provider_hostname")
                com.adshield.pro.engine.aether.PrivateDnsGuard.parse(mode, host)
            }.getOrElse {
                com.adshield.pro.engine.aether.PrivateDnsGuard.parse(null, null)
            }
            _dnsBypassWarning.value = assessment.userGuidance
        }
    }

    fun refreshAetherReportNow() {
        viewModelScope.launch(Dispatchers.IO) {
            val recoveries = preferencesRepository.getSettingsSnapshot().autoRecoveryCount
            _aetherReport.value = aetherCore.controlCenterReport(recoveries.toLong())
        }
    }

    val settingsState: StateFlow<AppSettingsState> = repository.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettingsState())

    val recentLogs: StateFlow<List<DnsActivityRecord>> = repository.recentLogsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val liveTopApps: StateFlow<List<AppDnsActivity>> = repository.liveTopAppsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val topBlockedDomains: StateFlow<List<DomainBlockCount>> = repository.topBlockedDomainsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val sourceEffectiveness: StateFlow<List<SourceEffectiveness>> = repository.sourceEffectivenessFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val allTimeTotalQueries: StateFlow<Long> = repository.allTimeTotalQueriesFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

    val allTimeBlockedQueries: StateFlow<Long> = repository.allTimeBlockedQueriesFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

    val allTimeAllowedQueries: StateFlow<Long> = repository.allTimeAllowedQueriesFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0L)

    val customRules: StateFlow<List<CustomRule>> = repository.customRulesFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val filterSources: StateFlow<List<FilterListSource>> = repository.filterSourcesFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _selectedChartRange = MutableStateFlow(StatsChartRange.DAILY_7D)
    val selectedChartRange: StateFlow<StatsChartRange> = _selectedChartRange.asStateFlow()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val chartBuckets: StateFlow<List<TimeBucketStat>> = _selectedChartRange
        .flatMapLatest { range -> repository.observeDailyChartBuckets(range.days) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _ruleConflicts = MutableStateFlow<List<RuleConflictReport>>(emptyList())
    val ruleConflicts: StateFlow<List<RuleConflictReport>> = _ruleConflicts.asStateFlow()

    private val _installedApps = MutableStateFlow<List<AppExclusionInfo>>(emptyList())
    val installedApps: StateFlow<List<AppExclusionInfo>> = _installedApps.asStateFlow()

    private val _isUpdatingFilters = MutableStateFlow(false)
    val isUpdatingFilters: StateFlow<Boolean> = _isUpdatingFilters.asStateFlow()

    private val _uiFeedbackMessage = MutableStateFlow<String?>(null)
    val uiFeedbackMessage: StateFlow<String?> = _uiFeedbackMessage.asStateFlow()

    private val _isCheckingForUpdates = MutableStateFlow(false)
    val isCheckingForUpdates: StateFlow<Boolean> = _isCheckingForUpdates.asStateFlow()

    private val _sandboxTestResult = MutableStateFlow<FilterEvaluationResult?>(null)
    val sandboxTestResult: StateFlow<FilterEvaluationResult?> = _sandboxTestResult.asStateFlow()


    // --- Phone Optimizer & AI Smart Boost Live States ---
    private val _ramSnapshot = MutableStateFlow(optimizerEngine.readRamSnapshot())
    val ramSnapshot: StateFlow<RamSnapshot> = _ramSnapshot.asStateFlow()

    private val _ramUsageTrend = MutableStateFlow(optimizerEngine.getRamUsageTrend())
    val ramUsageTrend: StateFlow<List<Float>> = _ramUsageTrend.asStateFlow()

    private val _storageMetrics = MutableStateFlow(optimizerEngine.readStorageMetrics())
    val storageMetrics: StateFlow<StorageMetrics> = _storageMetrics.asStateFlow()

    private val _batterySnapshot = MutableStateFlow(optimizerEngine.readBatteryThermalSnapshot())
    val batterySnapshot: StateFlow<BatteryThermalSnapshot> = _batterySnapshot.asStateFlow()

    private val _temperatureTrend = MutableStateFlow(optimizerEngine.getTemperatureTrend())
    val temperatureTrend: StateFlow<List<Float>> = _temperatureTrend.asStateFlow()

    private val _healthAssessment = MutableStateFlow(optimizerEngine.evaluateCurrentHealth(0L))
    val healthAssessment: StateFlow<DeviceHealthAssessment> = _healthAssessment.asStateFlow()

    private val _smartBoostResult = MutableStateFlow<SmartBoostResult?>(null)
    val smartBoostResult: StateFlow<SmartBoostResult?> = _smartBoostResult.asStateFlow()

    private val _isRunningSmartBoost = MutableStateFlow(false)
    val isRunningSmartBoost: StateFlow<Boolean> = _isRunningSmartBoost.asStateFlow()

    private val _junkScanReport = MutableStateFlow<JunkScanReport?>(null)
    val junkScanReport: StateFlow<JunkScanReport?> = _junkScanReport.asStateFlow()

    private val _isScanningJunk = MutableStateFlow(false)
    val isScanningJunk: StateFlow<Boolean> = _isScanningJunk.asStateFlow()

    private val _ramOptimizationResult = MutableStateFlow<RamOptimizationResult?>(null)
    val ramOptimizationResult: StateFlow<RamOptimizationResult?> = _ramOptimizationResult.asStateFlow()

    private val _installedGames = MutableStateFlow<List<GameAppInfo>>(emptyList())
    val installedGames: StateFlow<List<GameAppInfo>> = _installedGames.asStateFlow()

    private val _isDndPolicyGranted = MutableStateFlow(optimizerEngine.isDoNotDisturbAccessGranted())
    val isDndPolicyGranted: StateFlow<Boolean> = _isDndPolicyGranted.asStateFlow()

    // --- OmniShield X Infinity Security Center state ---
    val malwareBlocks: StateFlow<Long> = repository.malwareBlocksFlow.stateIn(
        viewModelScope, SharingStarted.Eagerly, 0L
    )

    private val _securityPosture = MutableStateFlow(
        com.adshield.pro.engine.security.SecurityPosture(
            protectionScore = if (repository.vpnRuntimeState.value.status == VpnStatus.CONNECTED) 60 else 0,
            highRiskApps = 0,
            threatSignatures = 0,
            webProtectionActive = false
        )
    )
    val securityPosture: StateFlow<com.adshield.pro.engine.security.SecurityPosture> = _securityPosture.asStateFlow()

    private val _appAudits = MutableStateFlow<List<com.adshield.pro.engine.security.AppRiskAuditor.AppRiskAudit>>(emptyList())
    val appAudits: StateFlow<List<com.adshield.pro.engine.security.AppRiskAuditor.AppRiskAudit>> = _appAudits.asStateFlow()

    private val _isAuditingApps = MutableStateFlow(false)
    val isAuditingApps: StateFlow<Boolean> = _isAuditingApps.asStateFlow()

    private val _urlScanResult = MutableStateFlow<com.adshield.pro.engine.security.UrlThreatScanner.UrlVerdict?>(null)
    val urlScanResult: StateFlow<com.adshield.pro.engine.security.UrlThreatScanner.UrlVerdict?> = _urlScanResult.asStateFlow()

    private val _fileScanResult = MutableStateFlow<com.adshield.pro.engine.security.SecurityScanRecord?>(null)
    val fileScanResult: StateFlow<com.adshield.pro.engine.security.SecurityScanRecord?> = _fileScanResult.asStateFlow()

    private val _isScanningSecurity = MutableStateFlow(false)
    val isScanningSecurity: StateFlow<Boolean> = _isScanningSecurity.asStateFlow()

    private val _securityHistory = MutableStateFlow(securityLocalStore.loadHistory())
    val securityHistory: StateFlow<List<com.adshield.pro.engine.security.SecurityScanRecord>> = _securityHistory.asStateFlow()

    private val _isQuarantining = MutableStateFlow(false)
    val isQuarantining: StateFlow<Boolean> = _isQuarantining.asStateFlow()
    private val _quarantineItems = MutableStateFlow(securityLocalStore.quarantineItems())
    val quarantineItems: StateFlow<List<com.adshield.pro.engine.security.SecurityLocalStore.QuarantineItem>> = _quarantineItems.asStateFlow()

    // --- OmniShield X Infinity Game Turbo state ---
    private val _turboSession = MutableStateFlow(gameTurboEngine.getSessionState())
    val turboSession: StateFlow<com.adshield.pro.engine.optimizer.GameTurboEngine.TurboSessionState> = _turboSession.asStateFlow()

    // --- OmniShield X Infinity battery saver state ---
    private val _extremeBatteryActions = MutableStateFlow<List<String>>(emptyList())
    val extremeBatteryActions: StateFlow<List<String>> = _extremeBatteryActions.asStateFlow()

    init {
        viewModelScope.launch {
            customRules.collect {
                refreshRuleConflicts()
            }
        }
        // Initial Junk quick scan & periodic lightweight telemetry refresh while UI is open
        viewModelScope.launch {
            scanJunk(JunkCleanMode.QUICK_CLEAN)
            loadInstalledGames()
            while (isActive) {
                refreshSystemTelemetry()
                delay(5000L)
            }
        }
    }

    fun showFeedback(message: String) {
        _uiFeedbackMessage.value = message
    }

    fun clearFeedback() {
        _uiFeedbackMessage.value = null
    }

    fun checkForUpdates() {
        if (_isCheckingForUpdates.value) return
        viewModelScope.launch {
            _isCheckingForUpdates.value = true
            try {
                val release = withContext(Dispatchers.IO) { GitHubReleaseClient.latest() }
                when {
                    release == null -> showFeedback("Couldn't check for updates. Check your internet connection and try again.")
                    release.code <= BuildConfig.VERSION_CODE -> showFeedback("OmniShield X Infinity is up to date.")
                    else -> {
                        val intent = Intent(appContext, UpdatePromptActivity::class.java).apply {
                            putExtra(UpdatePromptActivity.TAG, release.tag)
                            putExtra(UpdatePromptActivity.NAME, release.name)
                            putExtra(UpdatePromptActivity.CODE, release.code)
                            putExtra(UpdatePromptActivity.APK, release.apk)
                            putExtra(UpdatePromptActivity.SHA, release.sha256)
                            putExtra(UpdatePromptActivity.NOTES, release.notes)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        }
                        appContext.startActivity(intent)
                    }
                }
            } catch (_: Exception) {
                showFeedback("Couldn't check for updates. Check your internet connection and try again.")
            } finally {
                _isCheckingForUpdates.value = false
            }
        }
    }

    // --- System Optimizer & AI Smart Boost Actions ---

    fun refreshSystemTelemetry() {
        _ramSnapshot.value = optimizerEngine.readRamSnapshot()
        _ramUsageTrend.value = optimizerEngine.getRamUsageTrend()
        _storageMetrics.value = optimizerEngine.readStorageMetrics()
        _batterySnapshot.value = optimizerEngine.readBatteryThermalSnapshot()
        _temperatureTrend.value = optimizerEngine.getTemperatureTrend()
        _isDndPolicyGranted.value = optimizerEngine.isDoNotDisturbAccessGranted()
        val junkBytes = _junkScanReport.value?.totalRecoverableBytes ?: 0L
        _healthAssessment.value = optimizerEngine.evaluateCurrentHealth(junkBytes)
    }

    fun runOneTapSmartBoost() {
        if (_isRunningSmartBoost.value) return
        viewModelScope.launch {
            _isRunningSmartBoost.value = true
            val result = optimizerEngine.runOneTapSmartBoost(forceRun = false)
            _smartBoostResult.value = result
            // Refresh junk scan and telemetry after boost
            val updatedScan = optimizerEngine.scanJunkFiles(
                mode = _junkScanReport.value?.mode ?: JunkCleanMode.QUICK_CLEAN,
                excludedPaths = settingsState.value.excludedJunkPaths
            )
            _junkScanReport.value = updatedScan
            refreshSystemTelemetry()
            _isRunningSmartBoost.value = false

            if (result.wasSkippedDueToRecentBoost) {
                showFeedback("Device is already optimized (boosted recently).")
            } else {
                showFeedback(
                    "Smart Boost complete: ${RuleBasedOptimizationPredictor.formatBytes(result.bytesRecoveredAutomatically)} cleaned, DNS & RAM caches optimized."
                )
            }
        }
    }

    fun scanJunk(mode: JunkCleanMode) {
        if (_isScanningJunk.value) return
        viewModelScope.launch {
            _isScanningJunk.value = true
            val report = optimizerEngine.scanJunkFiles(
                mode = mode,
                excludedPaths = settingsState.value.excludedJunkPaths
            )
            _junkScanReport.value = report
            _healthAssessment.value = optimizerEngine.evaluateCurrentHealth(report.totalRecoverableBytes)
            _isScanningJunk.value = false
        }
    }

    fun toggleJunkCandidateSelection(candidateId: String, selected: Boolean) {
        val current = _junkScanReport.value ?: return
        val updatedList = current.candidates.map { item ->
            if (item.id == candidateId) item.copy(isSelected = selected) else item
        }
        _junkScanReport.value = current.copy(candidates = updatedList)
    }

    fun cleanSelectedJunk() {
        val current = _junkScanReport.value ?: return
        viewModelScope.launch {
            _isScanningJunk.value = true
            val record = optimizerEngine.executeJunkClean(
                candidates = current.candidates,
                mode = current.mode,
                autoOnly = false
            )
            val refreshed = optimizerEngine.scanJunkFiles(
                mode = current.mode,
                excludedPaths = settingsState.value.excludedJunkPaths
            )
            _junkScanReport.value = refreshed
            refreshSystemTelemetry()
            _isScanningJunk.value = false
            showFeedback(record.summary)
        }
    }

    fun addExcludedJunkPath(pathPattern: String) {
        viewModelScope.launch {
            preferencesRepository.addExcludedJunkPath(pathPattern)
            scanJunk(_junkScanReport.value?.mode ?: JunkCleanMode.QUICK_CLEAN)
            showFeedback("Excluded '$pathPattern' from junk cleanup.")
        }
    }

    fun removeExcludedJunkPath(pathPattern: String) {
        viewModelScope.launch {
            preferencesRepository.removeExcludedJunkPath(pathPattern)
            scanJunk(_junkScanReport.value?.mode ?: JunkCleanMode.QUICK_CLEAN)
        }
    }

    fun updateSmartAutoOptimizeSchedule(enabled: Boolean, intervalHours: Int) {
        viewModelScope.launch {
            preferencesRepository.setSmartAutoOptimizeSchedule(enabled, intervalHours)
            SmartOptimizationWorker.scheduleOrCancelSmartMaintenance(appContext, enabled, intervalHours)
            showFeedback(
                if (enabled) "Automatic Smart Maintenance scheduled every $intervalHours hours."
                else "Automatic Smart Maintenance paused."
            )
        }
    }

    fun runSmartRamOptimize() {
        viewModelScope.launch {
            val res = optimizerEngine.optimizeRam()
            _ramOptimizationResult.value = res
            refreshSystemTelemetry()
            showFeedback("RAM Manager trimmed ${res.dnsCacheEntriesReleased} cache entries & compacted AdShield heap.")
        }
    }

    fun loadInstalledGames() {
        viewModelScope.launch {
            val favs = settingsState.value.favoriteGamePackages
            _installedGames.value = optimizerEngine.discoverInstalledGames(favs)
        }
    }

    fun toggleFavoriteGame(packageName: String, isFavorite: Boolean) {
        viewModelScope.launch {
            preferencesRepository.toggleFavoriteGame(packageName, isFavorite)
            val updatedFavs = if (isFavorite) {
                settingsState.value.favoriteGamePackages + packageName
            } else {
                settingsState.value.favoriteGamePackages - packageName
            }
            _installedGames.value = optimizerEngine.discoverInstalledGames(updatedFavs)
            showFeedback(
                if (isFavorite) "Added to Favorite Games."
                else "Removed from Favorite Games."
            )
        }
    }

    fun updateGamingBoosterSettings(
        profile: GamingProfile,
        suppressNotifications: Boolean,
        tempWarningCelsius: Int
    ) {
        viewModelScope.launch {
            preferencesRepository.updateGamingBoosterSettings(profile, suppressNotifications, tempWarningCelsius)
            showFeedback("Game Booster set to ${profile.title} profile.")
        }
    }

    fun triggerGameBoost(packageName: String? = null, appName: String? = null) {
        viewModelScope.launch {
            val actions = optimizerEngine.applyGameBoostAndLaunch(packageName, appName)
            refreshSystemTelemetry()
            loadInstalledGames()
            showFeedback(actions.firstOrNull() ?: "Game Booster applied.")
        }
    }

    // --- OmniShield X Infinity Game Turbo (Zero-Lag Mode) ---

    fun activateGameTurboAndLaunch(packageName: String, appName: String) {
        viewModelScope.launch {
            val report = gameTurboEngine.activateTurboAndLaunch(
                gamePackage = packageName,
                gameName = appName,
                resolverConfig = settingsState.value.resolverConfig,
                suppressNotifications = settingsState.value.gameBoosterSuppressNotifications
            )
            _turboSession.value = gameTurboEngine.getSessionState()
            refreshSystemTelemetry()
            optimizerEngine.applyGameBoostAndLaunch(packageName, appName)
            showFeedback(
                "TURBO engaged for ${report.gameName}: ${report.stepsExecuted.size} optimizations " +
                    "(~${report.ramFreedEstimateMb} MB RAM headroom, ${report.dnsCacheWarmedEntries} servers pre-resolved)."
            )
        }
    }

    fun endGameTurbo() {
        viewModelScope.launch(Dispatchers.IO) {
            val steps = runCatching { gameTurboEngine.endTurbo() }.getOrDefault(emptyList())
            _turboSession.value = gameTurboEngine.getSessionState()
            showFeedback(steps.firstOrNull() ?: "Turbo session ended.")
        }
    }

    fun refreshTurboSession() {
        if (_turboSession.value.isActive && !gameTurboEngine.isTurboActive()) {
            endGameTurbo()
        } else {
            _turboSession.value = gameTurboEngine.getSessionState()
        }
    }

    fun thermalGuardSummary(): String = gameTurboEngine.thermalGuardSummary()

    // --- OmniShield X Infinity Security Center ---

    fun scanUrl(rawUrl: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isScanningSecurity.value = true
            val verdict = securityEngine.scanUrl(rawUrl)
            _urlScanResult.value = verdict
            val record = com.adshield.pro.engine.security.SecurityScanRecord(
                id = System.currentTimeMillis(),
                kind = com.adshield.pro.engine.security.ScanKind.URL,
                target = rawUrl.take(120),
                threatLevel = when (verdict.threatLevel) {
                    com.adshield.pro.engine.security.UrlThreatScanner.ThreatLevel.DANGEROUS ->
                        com.adshield.pro.engine.security.SecurityLevel.DANGEROUS
                    com.adshield.pro.engine.security.UrlThreatScanner.ThreatLevel.SUSPICIOUS ->
                        com.adshield.pro.engine.security.SecurityLevel.SUSPICIOUS
                    else -> com.adshield.pro.engine.security.SecurityLevel.CLEAN
                },
                riskScore = verdict.riskScore,
                threatName = verdict.findings.firstOrNull(),
                findings = verdict.findings,
                recommendation = verdict.recommendation,
                timestampEpochMs = System.currentTimeMillis()
            )
            _securityHistory.value = securityLocalStore.appendHistory(record)
            _isScanningSecurity.value = false
        }
    }

    fun scanFile(file: java.io.File) {
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val record = securityEngine.scanFile(file)
            _fileScanResult.value = record
            _securityHistory.value = securityLocalStore.appendHistory(record)
            refreshSecurityPosture()
            _isScanningSecurity.value = false
            showFeedback(
                when (record.threatLevel) {
                    com.adshield.pro.engine.security.SecurityLevel.DANGEROUS ->
                        "THREAT: ${record.threatName ?: record.target} — do not open or install."
                    com.adshield.pro.engine.security.SecurityLevel.SUSPICIOUS ->
                        "Suspicious file: ${record.findings.firstOrNull() ?: "risk indicators found"}."
                    else -> "File is clean: no signatures or structural threats found."
                }
            )
        }
    }

    fun scanUri(uri: android.net.Uri, displayName: String) {
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val record = securityEngine.scanUriContent(uri, displayName)
            if (record != null) {
                _fileScanResult.value = record
                _securityHistory.value = securityLocalStore.appendHistory(record)
                showFeedback(
                    when (record.threatLevel) {
                        com.adshield.pro.engine.security.SecurityLevel.DANGEROUS ->
                            "THREAT: ${record.threatName ?: displayName} — do not open or install."
                        com.adshield.pro.engine.security.SecurityLevel.SUSPICIOUS ->
                            "Suspicious file: ${record.findings.firstOrNull() ?: "risk indicators found"}."
                        else -> "File is clean: no signatures or structural threats found."
                    }
                )
            } else {
                showFeedback("Could not read the selected file for scanning.")
            }
            _isScanningSecurity.value = false
        }
    }

    fun quarantineUri(uri: android.net.Uri, displayName: String) {
        if (_isQuarantining.value) return
        viewModelScope.launch {
            _isQuarantining.value = true
            try {
                val result = securityLocalStore.quarantine(uri, displayName)
                _quarantineItems.value = securityLocalStore.quarantineItems()
                showFeedback("Quarantined ${result.item.originalName}. ${result.originalRemovalNote}")
            } catch (error: Exception) {
                showFeedback("Quarantine failed safely: ${error.message ?: "document access error"}")
            } finally {
                _isQuarantining.value = false
            }
        }
    }

    fun deleteQuarantined(item: com.adshield.pro.engine.security.SecurityLocalStore.QuarantineItem) {
        viewModelScope.launch(Dispatchers.IO) {
            _quarantineItems.value = securityLocalStore.deleteQuarantined(item)
            showFeedback("Quarantined copy permanently deleted.")
        }
    }

    fun auditInstalledApps() {
        if (_isAuditingApps.value) return
        viewModelScope.launch {
            _isAuditingApps.value = true
            val audits = securityEngine.auditInstalledApps()
            _appAudits.value = audits
            refreshSecurityPosture(highRisk = audits.count { it.riskLevel == com.adshield.pro.engine.security.AppRiskAuditor.RiskLevel.HIGH })
            _isAuditingApps.value = false
            val flagged = audits.count { it.riskLevel == com.adshield.pro.engine.security.AppRiskAuditor.RiskLevel.HIGH }
            showFeedback(
                if (flagged > 0) "Full app audit complete: $flagged high-risk app(s) found — review them in Security."
                else "Full app audit complete: no high-risk apps detected."
            )
        }
    }

    fun refreshSecurityPosture(highRisk: Int? = null) {
        val riskApps = highRisk ?: _securityPosture.value.highRiskApps
        val vpnActive = repository.vpnRuntimeState.value.status == VpnStatus.CONNECTED
        val signatures = securityEngine.activeThreatSignatureCount()
        _securityPosture.value = com.adshield.pro.engine.security.SecurityEngine.buildSecurityPosture(
            highRiskApps = riskApps,
            threatSignatures = signatures,
            vpnActive = vpnActive
        )
    }

    // --- OmniShield X Infinity Extreme Battery Saver ---

    fun runExtremeBatterySaver() {
        viewModelScope.launch {
            val actions = optimizerEngine.runExtremeBatterySaver()
            _extremeBatteryActions.value = actions
            refreshSystemTelemetry()
            showFeedback("Extreme Battery Saver active — background power use minimized, protection unchanged.")
        }
    }

    fun restoreBalancedPower() {
        viewModelScope.launch {
            val actions = optimizerEngine.restoreBalancedPower()
            _extremeBatteryActions.value = actions
            refreshSystemTelemetry()
            showFeedback("Balanced power restored.")
        }
    }

    fun isAllFilesAccessGranted(): Boolean = optimizerEngine.hasAllFilesAccess()

    fun createAllFilesAccessIntent(): android.content.Intent? = optimizerEngine.createAllFilesAccessIntent()

    fun selectAndApplyBatteryMode(mode: BatteryMode) {
        viewModelScope.launch {
            val actions = optimizerEngine.runAutoBatteryOptimize(mode)
            refreshSystemTelemetry()
            showFeedback(actions.firstOrNull() ?: "Applied ${mode.title} battery profile.")
        }
    }

    // --- VPN Lifecycle Controls ---

    fun startVpnService() {
        val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_START_VPN
        }
        ContextCompat.startForegroundService(appContext, intent)
    }

    fun stopVpnService() {
        val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_STOP_VPN
        }
        appContext.startService(intent)
    }

    fun pauseVpnService() {
        val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_PAUSE_VPN
        }
        appContext.startService(intent)
    }

    fun resumeVpnService() {
        val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_RESUME_VPN
        }
        appContext.startService(intent)
    }

    // --- Protection Modes ---

    fun setProtectionMode(mode: ProtectionMode) {
        viewModelScope.launch {
            repository.selectProtectionMode(mode)
            upstreamDnsResolver.clearCache()
            showFeedback("Switched to ${mode.title} (applied immediately without VPN restart)")
        }
    }

    // --- DNS Resolver Settings ---

    fun updateDnsResolverConfig(config: DnsResolverConfig) {
        viewModelScope.launch {
            val prevIpv6 = settingsState.value.resolverConfig.enableIpv6
            preferencesRepository.updateResolverConfig(config)
            upstreamDnsResolver.clearCache()
            repository.syncRuntimeModeAndResolver(settingsState.value.protectionMode, settingsState.value.copy(resolverConfig = config))
            if (prevIpv6 != config.enableIpv6) {
                reloadTunnelIfConnected()
            }
            showFeedback("DNS Resolver updated to ${config.preset.displayName} (${config.protocol.label})")
        }
    }

    // --- Filter List Updates & Sources ---

    fun triggerManualFilterUpdate() {
        if (_isUpdatingFilters.value) return
        viewModelScope.launch {
            _isUpdatingFilters.value = true
            val res = repository.updateAllEnabledFilterLists()
            _isUpdatingFilters.value = false
            res.fold(
                onSuccess = { totalRules ->
                    upstreamDnsResolver.clearCache()
                    showFeedback("Filter lists synchronized: $totalRules active rules loaded.")
                },
                onFailure = { err ->
                    showFeedback("Filter update rolled back safely: ${err.message}")
                }
            )
        }
    }

    fun toggleFilterSource(source: FilterListSource, enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleFilterSourceEnabled(source, enabled)
            upstreamDnsResolver.clearCache()
        }
    }

    fun addCustomFilterSource(name: String, url: String, category: RuleCategory) {
        viewModelScope.launch {
            val res = repository.addCustomFilterSource(name, url, category)
            res.fold(
                onSuccess = {
                    showFeedback("Added filter source '${it.name}'. Syncing rules...")
                    triggerManualFilterUpdate()
                },
                onFailure = { err ->
                    showFeedback(err.message ?: "Invalid filter list URL")
                }
            )
        }
    }

    fun deleteCustomFilterSource(sourceId: String) {
        viewModelScope.launch {
            repository.deleteCustomFilterSource(sourceId)
            showFeedback("Custom filter source removed.")
        }
    }

    fun updateAutoSyncSchedule(enabled: Boolean, intervalHours: Int) {
        viewModelScope.launch {
            preferencesRepository.setAutoUpdateFilters(enabled, intervalHours)
            FilterUpdateWorker.scheduleOrCancelPeriodicUpdates(appContext, enabled, intervalHours)
            showFeedback(
                if (enabled) "Automatic filter updates scheduled every $intervalHours hours."
                else "Automatic filter updates paused."
            )
        }
    }

    // --- Zero-Breakage user actions ---

    fun toggleShadowMode(enabled: Boolean) {
        viewModelScope.launch {
            filterRuleEngine.setShadowModeEnabled(enabled)
            preferencesRepository.setShadowModeEnabled(enabled)
            showFeedback(if (enabled) "Shadow Mode ON: risky list rules are reported, not enforced. Validate them, then allowlist or keep."
                else "Shadow Mode OFF: full filtering enforced.")
        }
    }

    fun reportFalsePositive(rawDomain: String) {
        val domain = rawDomain.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/')
        if (domain.isBlank() || !domain.contains('.')) {
            showFeedback("Enter a valid domain that broke, e.g. cdn.example.com")
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                repository.addCustomRule("@@||$domain^", RuleType.ALLOW, RuleMatchType.SUBDOMAIN, "Zero-Breakage false-positive report")
                preferencesRepository.incrementFalsePositiveReports()
                showFeedback("$domain allowlisted — it will never be blocked by filter lists again.")
            }
        }
    }

    // --- In-App Ad Defense (non-DNS) ---

    fun toggleInAppAdSkip(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setInAppAdSkipEnabled(enabled)
            showFeedback(
                if (enabled) "In-App Ad Skip enabled — now activate the Accessibility service when Android asks."
                else "In-App Ad Skip disabled."
            )
        }
    }

    fun toggleHeuristicShield(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setBlockHeuristicThreats(enabled)
            showFeedback(
                if (enabled) "Strict Heuristic Shield ON: in Strict mode, random-looking, lookalike and new domains can be blocked (one tap to allow any false positive)."
                else "Strict Heuristic Shield OFF: heuristic signals are only observed, never blocked."
            )
        }
    }

    fun toggleResolverAutoTune(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setResolverAutoTune(enabled)
            showFeedback(
                if (enabled) "Speed mode ON: resolver changes also require Autonomous response and respect Manual override. Custom resolvers are never replaced."
                else "Speed mode OFF."
            )
        }
    }

    fun toggleAutonomousResponse(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setAutonomousResponseEnabled(enabled)
            aetherCore.autonomousResponseEnabled = enabled
            refreshAetherReportNow()
            showFeedback(
                if (enabled) "Autonomous response enabled for user-approved resolver recovery and optimization. UNKNOWN signals are never auto-blocked."
                else "Autonomous response disabled. Existing DNS protection remains active."
            )
        }
    }

    fun toggleManualOverride(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setManualOverrideEnabled(enabled)
            aetherCore.manualOverrideEnabled = enabled
            refreshAetherReportNow()
            showFeedback(
                if (enabled) "Manual override enabled: new autonomous resolver changes stop; existing DNS protection stays active."
                else "Manual override released. Your autonomous-response preference applies again."
            )
        }
    }

    fun toggleEmergencyProtection(enabled: Boolean) {
        viewModelScope.launch {
            val current = preferencesRepository.getSettingsSnapshot()
            if (enabled) {
                preferencesRepository.setEmergencyProtectionEnabled(
                    enabled = true,
                    previousMode = current.protectionMode,
                    previousHeuristicEnabled = current.blockHeuristicThreats
                )
                preferencesRepository.setBlockHeuristicThreats(true)
                repository.selectProtectionMode(ProtectionMode.STRICT)
                showFeedback("Emergency protection active: Strict filtering and heuristic review enabled. Manual override remains available.")
            } else {
                val restoreMode = current.emergencyPreviousMode ?: ProtectionMode.STANDARD
                preferencesRepository.setBlockHeuristicThreats(current.emergencyPreviousHeuristicEnabled)
                preferencesRepository.setEmergencyProtectionEnabled(false)
                repository.selectProtectionMode(restoreMode)
                showFeedback("Emergency protection ended; previous protection settings restored.")
            }
            upstreamDnsResolver.clearCache()
        }
    }

    /** Universal in-app ad skip: ANY video app, same strict ad-evidence rules. */
    fun toggleInAppAdSkipUniversal(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setInAppAdSkipUniversal(enabled)
            showFeedback(
                if (enabled) "Universal video ad-skip ON: every app gets the same strict ad-skip rules. System UIs (dialer, keyboard, launcher) are never touched."
                else "Universal video ad-skip OFF: only YouTube apps and your added packages are managed."
            )
        }
    }

    fun toggleCheckNewDomains(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setCheckNewDomains(enabled)
            showFeedback(
                if (enabled) "New-domain check ON: Strict mode may look up registration age via RDAP (2s cap, cached). Unknown ages are never blocked."
                else "New-domain check OFF."
            )
        }
    }

    /** Platform spec pause options: 5, 15, or 60 minutes with automatic resume. */
    fun pauseVpnFor(minutes: Int) {
        val intent = android.content.Intent(appContext, com.adshield.pro.service.AdShieldVpnService::class.java).apply {
            action = com.adshield.pro.service.AdShieldVpnService.ACTION_PAUSE_VPN
            putExtra(com.adshield.pro.service.AdShieldVpnService.EXTRA_PAUSE_MINUTES, minutes)
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
        showFeedback(if (minutes > 0) "Filtering paused — resumes automatically in $minutes min." else "Filtering paused.")
    }

    fun toggleEncryptedDnsBypass(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setBlockEncryptedDnsBypass(enabled)
            showFeedback(
                if (enabled) "Encrypted-DNS Bypass Shield ON: apps with private secure DNS fall back to the filtered system resolver."
                else "Encrypted-DNS Bypass Shield OFF: apps may bypass filtering with their own DoH."
            )
            runCatching { repository.restoreFullFilterListsAfterSafeMode() }
        }
    }

    fun saveAdSkipExtraPackages(raw: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val pkgs = raw.split(',', ';', ' ')
                .map { it.trim() }
                .filter { it.matches(Regex("[A-Za-z0-9._]+")) }
                .toSet()
            preferencesRepository.setAdSkipExtraPackages(pkgs)
            showFeedback(
                if (pkgs.isEmpty()) "Default targets only (YouTube apps)."
                else "Ad-skip active for ${pkgs.size + 2} apps (YouTube + ${pkgs.size} added)."
            )
        }
    }

    // --- Custom Rules Management ---

    fun addCustomRule(
        rawPattern: String,
        ruleType: RuleType,
        matchType: RuleMatchType?,
        comment: String
    ) {
        viewModelScope.launch {
            val res = repository.addCustomRule(rawPattern, ruleType, matchType, comment)
            res.fold(
                onSuccess = { rule ->
                    upstreamDnsResolver.clearCache()
                    refreshRuleConflicts()
                    showFeedback("Rule '${rule.normalizedPattern}' (${rule.ruleType}) applied immediately.")
                },
                onFailure = { err ->
                    showFeedback(err.message ?: "Malformed domain rule")
                }
            )
        }
    }

    fun updateCustomRule(rule: CustomRule) {
        viewModelScope.launch {
            val res = repository.updateCustomRule(rule)
            res.fold(
                onSuccess = {
                    upstreamDnsResolver.clearCache()
                    refreshRuleConflicts()
                    showFeedback("Updated rule '${rule.normalizedPattern}'.")
                },
                onFailure = { err ->
                    showFeedback(err.message ?: "Invalid rule edit")
                }
            )
        }
    }

    fun toggleCustomRule(rule: CustomRule, enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleCustomRuleEnabled(rule, enabled)
            upstreamDnsResolver.clearCache()
            refreshRuleConflicts()
        }
    }

    fun deleteCustomRule(ruleId: Long) {
        viewModelScope.launch {
            repository.deleteCustomRule(ruleId)
            upstreamDnsResolver.clearCache()
            refreshRuleConflicts()
            showFeedback("Rule deleted.")
        }
    }

    fun deduplicateCustomRules() {
        viewModelScope.launch {
            val removed = repository.removeDuplicateCustomRules()
            refreshRuleConflicts()
            showFeedback(
                if (removed > 0) "Removed $removed duplicate custom rule(s)."
                else "No duplicate rules found."
            )
        }
    }

    fun refreshRuleConflicts() {
        viewModelScope.launch {
            _ruleConflicts.value = repository.analyzeCustomRuleConflicts()
        }
    }

    fun importRulesText(text: String) {
        viewModelScope.launch {
            val count = repository.importRulesFromText(text)
            upstreamDnsResolver.clearCache()
            refreshRuleConflicts()
            showFeedback("Imported $count valid domain rule(s).")
        }
    }

    suspend fun exportRulesText(): String = repository.exportRulesAsText()

    fun testDomainInSandbox(domainInput: String) {
        _sandboxTestResult.value = filterRuleEngine.evaluate(domainInput)
    }

    // --- Statistics & Privacy Controls ---

    fun selectChartRange(range: StatsChartRange) {
        _selectedChartRange.value = range
    }

    fun setDetailedLogging(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setDetailedDnsLogging(enabled)
            showFeedback(
                if (enabled) "Local DNS activity logging enabled."
                else "Detailed domain logging disabled. Only anonymous aggregate totals will be counted."
            )
        }
    }

    fun setLogRetentionDays(days: Int) {
        viewModelScope.launch {
            preferencesRepository.setLogRetentionDays(days)
            repository.enforceLogRetentionPolicy()
            showFeedback("Log retention set to $days days.")
        }
    }

    fun clearAllHistory() {
        viewModelScope.launch {
            repository.clearAllStatisticsAndLogs()
            showFeedback("All local DNS logs and statistics history cleared.")
        }
    }

    // --- Per-App Exclusions & System Settings ---

    fun loadInstalledApps() {
        viewModelScope.launch {
            val excluded = settingsState.value.excludedAppPackages
            _installedApps.value = repository.getInstalledApps(excluded)
        }
    }

    fun toggleAppExclusion(packageName: String, excluded: Boolean) {
        viewModelScope.launch {
            preferencesRepository.toggleExcludedAppPackage(packageName, excluded)
            loadInstalledApps()
            reloadTunnelIfConnected()
            showFeedback(
                if (excluded) "Excluded $packageName from VPN tunnel."
                else "Included $packageName in VPN protection."
            )
        }
    }

    fun setAutoStartOnBoot(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setAutoStartOnBoot(enabled)
        }
    }

    fun setDarkThemePreference(pref: DarkThemePreference) {
        viewModelScope.launch {
            preferencesRepository.setDarkThemePreference(pref)
        }
    }

    // --- Browser Controls ---

    fun toggleBrowserSiteException(host: String, allowlisted: Boolean) {
        viewModelScope.launch {
            preferencesRepository.toggleBrowserSiteException(host, allowlisted)
            showFeedback(
                if (allowlisted) "Added $host to browser allowlist exceptions."
                else "Removed $host from browser exceptions."
            )
        }
    }

    fun updateBrowserPrivacySettings(
        cosmetic: Boolean,
        popups: Boolean,
        blockThirdPartyCookies: Boolean,
        jsEnabled: Boolean
    ) {
        viewModelScope.launch {
            preferencesRepository.updateBrowserPrivacyOptions(
                cosmeticFiltering = cosmetic,
                popupBlocking = popups,
                blockThirdPartyCookies = blockThirdPartyCookies,
                javaScriptEnabled = jsEnabled
            )
        }
    }

    fun addCustomCosmeticSelector(selector: String) {
        viewModelScope.launch {
            preferencesRepository.addCustomCosmeticSelector(selector)
            showFeedback("Added custom CSS element-hiding selector: $selector")
        }
    }

    fun removeCustomCosmeticSelector(selector: String) {
        viewModelScope.launch {
            preferencesRepository.removeCustomCosmeticSelector(selector)
        }
    }

    // --- Backup & Restore ---

    suspend fun exportFullBackupJson(): String = repository.createConfigurationBackupJson()

    fun restoreFullBackupJson(rawJson: String) {
        viewModelScope.launch {
            val res = repository.restoreConfigurationFromJson(rawJson)
            res.fold(
                onSuccess = { ruleCount ->
                    upstreamDnsResolver.clearCache()
                    refreshRuleConflicts()
                    showFeedback("Restored configuration backup ($ruleCount custom rules).")
                },
                onFailure = { err ->
                    showFeedback("Restore failed: ${err.message}")
                }
            )
        }
    }

    private fun reloadTunnelIfConnected() {
        val currentStatus = vpnState.value.status
        if (currentStatus == com.adshield.pro.domain.model.VpnStatus.CONNECTED ||
            currentStatus == com.adshield.pro.domain.model.VpnStatus.PAUSED
        ) {
            val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
                action = AdShieldVpnService.ACTION_RELOAD_TUNNEL_CONFIG
            }
            appContext.startService(intent)
        }
    }

    // --- Battery Intelligence: measured hardware values with explicit provenance ---
    val batteryTelemetry: StateFlow<BatteryTelemetry> = batteryRepository.telemetry
    val batteryHistory: StateFlow<List<BatteryDiagnostics.Sample>> = batteryRepository.history
    val batterySessions: StateFlow<List<BatterySession>> = batteryRepository.sessions
    val batteryDiagnostics: StateFlow<List<BatteryDiagnostic>> = batteryRepository.diagnostics
    val batteryLastDiagnosticAtMs: StateFlow<Long> = batteryRepository.lastDiagnosticAtMs

    private val _isDiagnosingBattery = MutableStateFlow(false)
    val isDiagnosingBattery: StateFlow<Boolean> = _isDiagnosingBattery.asStateFlow()
    private val _batteryHealthScore = MutableStateFlow(batteryRepository.healthScore())
    val batteryHealthScore: StateFlow<Int> = _batteryHealthScore.asStateFlow()
    private val _batteryMinutesToFull = MutableStateFlow<Int?>(null)
    val batteryMinutesToFull: StateFlow<Int?> = _batteryMinutesToFull.asStateFlow()
    private val _batteryMinutesToEmpty = MutableStateFlow<Int?>(null)
    val batteryMinutesToEmpty: StateFlow<Int?> = _batteryMinutesToEmpty.asStateFlow()
    private val _batteryChargeRate = MutableStateFlow<Float?>(null)
    val batteryChargeRate: StateFlow<Float?> = _batteryChargeRate.asStateFlow()

    private fun refreshBatteryDerived() {
        _batteryHealthScore.value = batteryRepository.healthScore()
        _batteryChargeRate.value = batteryRepository.chargeRatePercentPerHour()
        _batteryMinutesToFull.value = batteryRepository.minutesToFull()
        _batteryMinutesToEmpty.value = batteryRepository.minutesToEmpty()
    }

    fun runBatteryDiagnosis() {
        if (_isDiagnosingBattery.value) return
        viewModelScope.launch {
            _isDiagnosingBattery.value = true
            try {
                batteryRepository.runDiagnostics()
                refreshBatteryDerived()
                val worst = batteryRepository.diagnostics.value.maxByOrNull { it.severity.ordinal }
                showFeedback(worst?.let { "Battery diagnostic: ${it.title}" }
                    ?: "Battery diagnostic complete — no faults found in the measured readings.")
            } catch (error: Exception) {
                showFeedback("Battery diagnostic unavailable: ${error.message ?: "sensor error"}")
            } finally {
                _isDiagnosingBattery.value = false
            }
        }
    }

    fun refreshBatteryReadings() {
        batteryRepository.refreshNow()
        refreshBatteryDerived()
    }

    fun clearBatterySessions() {
        batteryRepository.clearSessions()
        showFeedback("Battery session history cleared.")
    }

    /** Live network state is derived only from VPN runtime and measured DNS records. */
    val liveNetwork: StateFlow<LiveNetworkModel.NetworkSnapshot> = combine(
        repository.vpnRuntimeState,
        recentLogs,
        liveTopApps,
        topBlockedDomains
    ) { runtime, logs, apps, blocked ->
        LiveNetworkModel.snapshot(runtime, logs, apps, blocked)
    }.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        LiveNetworkModel.snapshot(repository.vpnRuntimeState.value, emptyList(), emptyList(), emptyList())
    )
}
