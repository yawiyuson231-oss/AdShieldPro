package com.adshield.pro.ui.viewmodel

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.BuildConfig
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.data.local.preferences.DarkThemePreference
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.AppExclusionInfo
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
import com.adshield.pro.engine.aether.DnsAnomalyScorer
import com.adshield.pro.engine.aether.LiveNetworkModel
import com.adshield.pro.engine.battery.BatteryDiagnostic
import com.adshield.pro.engine.battery.BatteryDiagnostics
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatterySession
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.browser.SearchProvider
import com.adshield.pro.engine.dns.DnsLeakDetector
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.downloader.MediaDownloaderEngine
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.optimizer.RuleBasedOptimizationPredictor
import com.adshield.pro.engine.optimizer.SystemOptimizerEngine
import com.adshield.pro.engine.platform.DeviceCompatibility
import com.adshield.pro.engine.platform.DeviceProfiler
import com.adshield.pro.engine.platform.DiagnosticReportBuilder
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityEngine
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityPosture
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.security.SystemScannerEngine
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.engine.storage.PrivateCloudBoxEngine
import com.adshield.pro.engine.storage.UniversalFileManager
import com.adshield.pro.service.AdShieldVpnService
import com.adshield.pro.ui.UpdatePromptActivity
import com.adshield.pro.update.GitHubReleaseClient
import com.adshield.pro.worker.FilterUpdateWorker
import com.adshield.pro.worker.SmartOptimizationWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
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
    private val securityEngine: SecurityEngine,
    private val batteryRepository: BatteryIntelligenceRepository,
    private val deviceProfiler: DeviceProfiler,
    private val privateCloudBoxEngine: PrivateCloudBoxEngine,
    private val universalFileManager: UniversalFileManager,
    private val mediaDownloaderEngine: MediaDownloaderEngine,
    private val dnsLeakDetector: DnsLeakDetector
) : ViewModel() {

    val vpnState: StateFlow<VpnRuntimeState> = repository.vpnRuntimeState

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

    val ruleSuggestions: StateFlow<List<DnsAnomalyScorer.RuleSuggestion>> = combine(
        recentLogs,
        customRules
    ) { logs, rules ->
        DnsAnomalyScorer.suggestRulesFromLogs(
            recentLogs = logs,
            existingCustomDomains = rules.mapTo(HashSet()) { it.normalizedPattern }
        )
    }.flowOn(Dispatchers.Default)
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

    // --- DNS Leak & Bypass Audit ---
    private val _dnsLeakReport = MutableStateFlow<DnsLeakDetector.LeakAuditReport?>(null)
    val dnsLeakReport: StateFlow<DnsLeakDetector.LeakAuditReport?> = _dnsLeakReport.asStateFlow()

    private val _isRunningDnsLeakAudit = MutableStateFlow(false)
    val isRunningDnsLeakAudit: StateFlow<Boolean> = _isRunningDnsLeakAudit.asStateFlow()

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

    // --- Security Center + Complete System Scanner ---
    private val _malwareBlocks = MutableStateFlow(0L)
    val malwareBlocks: StateFlow<Long> = _malwareBlocks.asStateFlow()

    private val _securityPosture = MutableStateFlow(
        SecurityPosture(
            protectionScore = 0,
            highRiskApps = 0,
            threatSignatures = 0,
            webProtectionActive = false
        )
    )
    val securityPosture: StateFlow<SecurityPosture> = _securityPosture.asStateFlow()

    private val _appAudits = MutableStateFlow<List<AppRiskAuditor.AppRiskAudit>>(emptyList())
    val appAudits: StateFlow<List<AppRiskAuditor.AppRiskAudit>> = _appAudits.asStateFlow()

    private val _isAuditingApps = MutableStateFlow(false)
    val isAuditingApps: StateFlow<Boolean> = _isAuditingApps.asStateFlow()

    private val _urlScanResult = MutableStateFlow<UrlThreatScanner.UrlVerdict?>(null)
    val urlScanResult: StateFlow<UrlThreatScanner.UrlVerdict?> = _urlScanResult.asStateFlow()

    private val _fileScanResult = MutableStateFlow<SecurityScanRecord?>(null)
    val fileScanResult: StateFlow<SecurityScanRecord?> = _fileScanResult.asStateFlow()

    private val _isScanningSecurity = MutableStateFlow(false)
    val isScanningSecurity: StateFlow<Boolean> = _isScanningSecurity.asStateFlow()

    private val _securityHistory = MutableStateFlow(securityEngine.historyStore.getScanRecords())
    val securityHistory: StateFlow<List<SecurityScanRecord>> = _securityHistory.asStateFlow()

    private val _systemScanReports = MutableStateFlow(securityEngine.historyStore.getSystemReports())
    val systemScanReports: StateFlow<List<SystemScannerEngine.SystemScanReport>> = _systemScanReports.asStateFlow()

    private val _systemScanProgress = MutableStateFlow<SystemScannerEngine.SystemScanProgress?>(null)
    val systemScanProgress: StateFlow<SystemScannerEngine.SystemScanProgress?> = _systemScanProgress.asStateFlow()

    // --- Private Cloud Storage Box ---
    private val _vaultSelectedFolder = MutableStateFlow<String?>(null)
    val vaultSelectedFolder: StateFlow<String?> = _vaultSelectedFolder.asStateFlow()

    private val _vaultSelectedCategory = MutableStateFlow<PrivateCloudBoxEngine.VaultCategory?>(null)
    val vaultSelectedCategory: StateFlow<PrivateCloudBoxEngine.VaultCategory?> = _vaultSelectedCategory.asStateFlow()

    private val _vaultSearchQuery = MutableStateFlow("")
    val vaultSearchQuery: StateFlow<String> = _vaultSearchQuery.asStateFlow()

    private val _vaultItems = MutableStateFlow(privateCloudBoxEngine.listItems())
    val vaultItems: StateFlow<List<PrivateCloudBoxEngine.VaultItem>> = _vaultItems.asStateFlow()

    private val _vaultSummary = MutableStateFlow(privateCloudBoxEngine.storageSummary())
    val vaultSummary: StateFlow<PrivateCloudBoxEngine.VaultStorageSummary> = _vaultSummary.asStateFlow()

    private val _vaultCloudConfig = MutableStateFlow(privateCloudBoxEngine.getCloudEndpointConfig())
    val vaultCloudConfig: StateFlow<PrivateCloudBoxEngine.CloudEndpointConfig> = _vaultCloudConfig.asStateFlow()

    private val _vaultPreview = MutableStateFlow<PrivateCloudBoxEngine.VaultPreview?>(null)
    val vaultPreview: StateFlow<PrivateCloudBoxEngine.VaultPreview?> = _vaultPreview.asStateFlow()

    private val _isVaultBusy = MutableStateFlow(false)
    val isVaultBusy: StateFlow<Boolean> = _isVaultBusy.asStateFlow()

    // --- Universal App & File Support ---
    private val _managedFileKindFilter = MutableStateFlow<UniversalFileManager.ManagedMediaKind?>(null)
    val managedFileKindFilter: StateFlow<UniversalFileManager.ManagedMediaKind?> = _managedFileKindFilter.asStateFlow()

    private val _managedFiles = MutableStateFlow(universalFileManager.listManagedFiles())
    val managedFiles: StateFlow<List<UniversalFileManager.ManagedFileItem>> = _managedFiles.asStateFlow()

    // --- Universal Video & Music Downloader ---
    val mediaDownloadTasks: StateFlow<List<MediaDownloaderEngine.MediaDownloadTask>> = mediaDownloaderEngine.tasks

    private val _mediaProbeResult = MutableStateFlow<MediaDownloaderEngine.MediaProbeResult?>(null)
    val mediaProbeResult: StateFlow<MediaDownloaderEngine.MediaProbeResult?> = _mediaProbeResult.asStateFlow()

    private val _mediaProbeError = MutableStateFlow<String?>(null)
    val mediaProbeError: StateFlow<String?> = _mediaProbeError.asStateFlow()

    private val _isProbingMedia = MutableStateFlow(false)
    val isProbingMedia: StateFlow<Boolean> = _isProbingMedia.asStateFlow()

    init {
        viewModelScope.launch {
            customRules.collect {
                refreshRuleConflicts()
            }
        }
        viewModelScope.launch {
            repository.malwareBlocksFlow.collect { count ->
                _malwareBlocks.value = count
                refreshSecurityPosture()
            }
        }
        // Keep security posture synchronized with VPN connection changes and filter list updates
        viewModelScope.launch {
            repository.vpnRuntimeState.collect {
                refreshSecurityPosture()
            }
        }
        viewModelScope.launch {
            repository.filterSourcesFlow.collect {
                refreshSecurityPosture()
            }
        }
        // Keep derived battery rates & ETAs live whenever hardware battery broadcasts arrive
        viewModelScope.launch {
            batteryRepository.telemetry.collect {
                refreshBatteryDerived()
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
                    release.code <= BuildConfig.VERSION_CODE -> showFeedback("AdShield Pro is up to date.")
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

    fun scanUserSelectedSafFolder(treeUri: Uri) {
        if (_isScanningJunk.value) return
        viewModelScope.launch {
            _isScanningJunk.value = true
            val report = optimizerEngine.scanSafFolderTree(treeUri)
            _junkScanReport.value = report
            _healthAssessment.value = optimizerEngine.evaluateCurrentHealth(report.totalRecoverableBytes)
            _isScanningJunk.value = false
            showFeedback("Scanned selected folder: ${report.candidates.size} reviewable item(s) found.")
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

    fun endGameTurboSession() {
        viewModelScope.launch {
            val actions = optimizerEngine.endGameTurboSession()
            showFeedback(actions.firstOrNull() ?: "Game Turbo session ended.")
        }
    }

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
            refreshSecurityPosture()
            showFeedback("Switched to ${mode.title} (applied immediately without VPN restart)")
        }
    }

    // --- DNS Resolver Settings & DNS Leak Audit ---

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

    fun runDnsLeakAudit() {
        if (_isRunningDnsLeakAudit.value) return
        viewModelScope.launch {
            _isRunningDnsLeakAudit.value = true
            val currentSettings = preferencesRepository.getSettingsSnapshot()
            val connected = vpnState.value.status == VpnStatus.CONNECTED
            val report = dnsLeakDetector.runAudit(
                vpnConnected = connected,
                config = currentSettings.resolverConfig,
                runLiveUpstreamProbe = true
            )
            _dnsLeakReport.value = report
            _isRunningDnsLeakAudit.value = false
            showFeedback("DNS Audit: ${report.verdict.name} (${report.findings.firstOrNull() ?: "No leak risk detected"})")
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
                    refreshSecurityPosture()
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
            refreshSecurityPosture()
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
            refreshSecurityPosture()
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
                    refreshSecurityPosture()
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
            val excluded = preferencesRepository.getSettingsSnapshot().excludedAppPackages
            _installedApps.value = repository.getInstalledApps(excluded)
        }
    }

    fun toggleAppExclusion(packageName: String, excluded: Boolean) {
        viewModelScope.launch {
            preferencesRepository.toggleExcludedAppPackage(packageName, excluded)
            val refreshedExcluded = preferencesRepository.getSettingsSnapshot().excludedAppPackages
            _installedApps.value = repository.getInstalledApps(refreshedExcluded)
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

    // --- Browser & Private Search Controls ---

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
        jsEnabled: Boolean,
        httpsUpgradeEnabled: Boolean = settingsState.value.browserHttpsUpgradeEnabled
    ) {
        viewModelScope.launch {
            preferencesRepository.updateBrowserPrivacyOptions(
                cosmeticFiltering = cosmetic,
                popupBlocking = popups,
                blockThirdPartyCookies = blockThirdPartyCookies,
                javaScriptEnabled = jsEnabled,
                httpsUpgradeEnabled = httpsUpgradeEnabled
            )
        }
    }

    fun setPreferredSearchProvider(provider: SearchProvider) {
        viewModelScope.launch {
            preferencesRepository.setPreferredSearchProvider(provider)
            showFeedback("Private Search provider set to ${provider.displayName}.")
        }
    }

    fun setBrowserHttpsUpgradeEnabled(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setBrowserHttpsUpgradeEnabled(enabled)
            showFeedback(if (enabled) "HTTPS-only automatic upgrade enabled." else "HTTPS-only automatic upgrade disabled.")
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

    // --- Backup, Restore & Diagnostic Report ---

    suspend fun exportFullBackupJson(): String = repository.createConfigurationBackupJson()

    fun exportDiagnosticReportJson(screenWidthDp: Int, smallestWidthDp: Int): String {
        val profile = deviceProfile(screenWidthDp, smallestWidthDp)
        val telemetry = batteryRepository.telemetry.value
        return DiagnosticReportBuilder.buildJson(
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            deviceProfile = profile,
            vpnState = vpnState.value,
            batteryLevelPercent = telemetry.levelPercent.rawValue,
            batteryTempCelsius = telemetry.temperatureCelsius.rawValue,
            batteryHealthLabel = telemetry.healthLabel
        )
    }

    fun restoreFullBackupJson(rawJson: String) {
        viewModelScope.launch {
            val res = repository.restoreConfigurationFromJson(rawJson)
            res.fold(
                onSuccess = { ruleCount ->
                    upstreamDnsResolver.clearCache()
                    val snap = preferencesRepository.getSettingsSnapshot()
                    FilterUpdateWorker.scheduleOrCancelPeriodicUpdates(
                        appContext,
                        snap.autoUpdateFiltersEnabled,
                        snap.updateIntervalHours
                    )
                    refreshRuleConflicts()
                    refreshSecurityPosture()
                    loadInstalledApps()
                    reloadTunnelIfConnected()
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
        if (currentStatus == VpnStatus.CONNECTED || currentStatus == VpnStatus.PAUSED) {
            val intent = Intent(appContext, AdShieldVpnService::class.java).apply {
                action = AdShieldVpnService.ACTION_RELOAD_TUNNEL_CONFIG
            }
            appContext.startService(intent)
        }
    }

    // --- Security Center & Complete System Scanner ---

    fun scanUrl(rawUrl: String) {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            showFeedback("Enter a link to scan.")
            return
        }
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val verdict = securityEngine.scanUrl(trimmed)
            _urlScanResult.value = verdict
            val record = SecurityScanRecord(
                id = System.currentTimeMillis(),
                kind = ScanKind.URL,
                target = trimmed.take(120),
                threatLevel = when (verdict.threatLevel) {
                    UrlThreatScanner.ThreatLevel.DANGEROUS -> SecurityLevel.DANGEROUS
                    UrlThreatScanner.ThreatLevel.SUSPICIOUS -> SecurityLevel.SUSPICIOUS
                    else -> SecurityLevel.CLEAN
                },
                riskScore = verdict.riskScore,
                threatName = verdict.findings.firstOrNull(),
                findings = verdict.findings,
                recommendation = verdict.recommendation,
                timestampEpochMs = System.currentTimeMillis()
            )
            _securityHistory.value = securityEngine.historyStore.recordItemScan(record)
            _isScanningSecurity.value = false
        }
    }

    fun scanFile(file: File) {
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val record = securityEngine.scanFile(file)
            _fileScanResult.value = record
            _securityHistory.value = securityEngine.historyStore.recordItemScan(record)
            refreshSecurityPosture()
            _isScanningSecurity.value = false
            showFeedback(scanFeedback(record, record.target))
        }
    }

    fun scanUri(uri: Uri, displayName: String) {
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val record = securityEngine.scanUriContent(uri, displayName)
            if (record != null) {
                _fileScanResult.value = record
                _securityHistory.value = securityEngine.historyStore.recordItemScan(record)
                showFeedback(scanFeedback(record, displayName))
            } else {
                showFeedback("Could not read the selected file for scanning.")
            }
            _isScanningSecurity.value = false
        }
    }

    fun auditInstalledApps() {
        if (_isAuditingApps.value) return
        viewModelScope.launch {
            _isAuditingApps.value = true
            val audits = securityEngine.auditInstalledApps()
            _appAudits.value = audits
            val flagged = audits.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }
            refreshSecurityPosture(highRisk = flagged)
            val record = SecurityScanRecord(
                id = System.currentTimeMillis(),
                kind = ScanKind.APP_AUDIT,
                target = "Installed Apps (${audits.size} packages)",
                threatLevel = when {
                    flagged > 0 -> SecurityLevel.DANGEROUS
                    audits.any { it.riskLevel == AppRiskAuditor.RiskLevel.MEDIUM } -> SecurityLevel.SUSPICIOUS
                    else -> SecurityLevel.CLEAN
                },
                riskScore = (flagged * 30).coerceAtMost(100),
                threatName = if (flagged > 0) "$flagged high-risk app(s) detected" else null,
                findings = audits.filter { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }
                    .take(5)
                    .map { "${it.profile.appName}: ${it.findings.firstOrNull() ?: "high-risk permissions"}" },
                recommendation = if (flagged > 0) "Review and uninstall untrusted high-risk apps." else "No high-risk permission stacks detected.",
                timestampEpochMs = System.currentTimeMillis()
            )
            _securityHistory.value = securityEngine.historyStore.recordItemScan(record)
            _isAuditingApps.value = false
            showFeedback(
                if (flagged > 0) "Full app audit complete: $flagged high-risk app(s) found — review them in Security."
                else "Full app audit complete: no high-risk apps detected."
            )
        }
    }

    fun runCompleteSystemScan() {
        if (_systemScanProgress.value?.isRunning == true) return
        viewModelScope.launch {
            val currentSettings = preferencesRepository.getSettingsSnapshot()
            val storage = optimizerEngine.readStorageMetrics()
            val ram = optimizerEngine.readRamSnapshot()
            val junk = optimizerEngine.scanJunkFiles(JunkCleanMode.QUICK_CLEAN, currentSettings.excludedJunkPaths)
            val batTelemetry = batteryRepository.telemetry.value
            val sources = filterSources.value
            val conflicts = repository.analyzeCustomRuleConflicts()

            val scanDirs = buildList {
                add(File(appContext.filesDir, "managed_files/items"))
                add(File(appContext.filesDir, "media_downloads"))
                appContext.getExternalFilesDir(null)?.let { add(it) }
                runCatching {
                    val dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                    if (dl != null) add(dl)
                }
            }

            var auditedAppsCache: List<AppRiskAuditor.AppRiskAudit> = emptyList()
            val inputs = SystemScannerEngine.ScanInputs(
                vpnConnected = vpnState.value.status == VpnStatus.CONNECTED,
                protectionMode = currentSettings.protectionMode,
                dnsProtocol = currentSettings.resolverConfig.protocol,
                threatSignatureCount = securityEngine.activeThreatSignatureCount(),
                httpsUpgradeEnabled = currentSettings.browserHttpsUpgradeEnabled,
                blockThirdPartyCookies = currentSettings.browserBlockThirdPartyCookies,
                auditAppsProvider = {
                    val list = securityEngine.auditInstalledApps()
                    auditedAppsCache = list
                    list
                },
                scanDirectories = scanDirs,
                storageUsedPercent = storage.usedPercent,
                storageAvailableBytes = storage.availableBytes,
                recoverableJunkBytes = junk.totalRecoverableBytes,
                ramUsagePercent = ram.usagePercent,
                isLowMemory = ram.isLowMemoryCondition,
                sdkInt = Build.VERSION.SDK_INT,
                supportedPlatform = DeviceCompatibility.isSupportedPlatform(Build.VERSION.SDK_INT),
                batteryTempCelsius = batTelemetry.temperatureCelsius.rawValue,
                batteryHealthGood = batTelemetry.health == BatteryHealthStatus.GOOD || batTelemetry.health == BatteryHealthStatus.UNKNOWN,
                enabledFilterListCount = sources.count { it.isEnabled },
                totalLoadedRules = filterRuleEngine.getCurrentSnapshot().totalLoadedRules,
                ruleConflictCount = conflicts.size,
                lastFilterSyncEpochMs = currentSettings.lastFilterUpdateEpochMs
            )

            val report = securityEngine.systemScanner.runCompleteScan(inputs) { progress ->
                _systemScanProgress.value = progress
            }

            if (auditedAppsCache.isNotEmpty()) {
                _appAudits.value = auditedAppsCache
                refreshSecurityPosture(
                    highRisk = auditedAppsCache.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }
                )
            } else {
                refreshSecurityPosture()
            }

            _systemScanReports.value = securityEngine.historyStore.recordSystemScan(report)
            val summaryRecord = SecurityScanRecord(
                id = report.id,
                kind = ScanKind.SYSTEM,
                target = "Complete System Scan (${report.totalItemsScanned} items)",
                threatLevel = report.overallLevel,
                riskScore = report.overallRiskScore,
                threatName = if (report.totalFindings > 0) "${report.totalFindings} finding(s) across ${report.modules.size} modules" else null,
                findings = report.modules.flatMap { it.findings }.take(12),
                recommendation = report.summary,
                timestampEpochMs = report.timestampEpochMs
            )
            _securityHistory.value = securityEngine.historyStore.recordItemScan(summaryRecord)
            showFeedback(report.summary)
        }
    }

    fun clearSecurityScanHistory() {
        securityEngine.historyStore.clearAll()
        _securityHistory.value = emptyList()
        _systemScanReports.value = emptyList()
        showFeedback("Cleared security scan history and reports.")
    }

    fun refreshSecurityPosture(highRisk: Int? = null) {
        val riskApps = highRisk ?: _securityPosture.value.highRiskApps
        val vpnActive = repository.vpnRuntimeState.value.status == VpnStatus.CONNECTED
        val signatures = securityEngine.activeThreatSignatureCount()
        _securityPosture.value = SecurityEngine.buildSecurityPosture(
            highRiskApps = riskApps,
            threatSignatures = signatures,
            vpnActive = vpnActive
        )
    }

    private fun scanFeedback(record: SecurityScanRecord, label: String): String = when (record.threatLevel) {
        SecurityLevel.DANGEROUS -> "THREAT: ${record.threatName ?: label} — do not open or install."
        SecurityLevel.SUSPICIOUS -> "Suspicious file: ${record.findings.firstOrNull() ?: "risk indicators found"}."
        else -> "File is clean: no signatures or structural threats found."
    }

    // --- Private Cloud Storage Box Actions ---

    private fun refreshVaultStates() {
        _vaultItems.value = privateCloudBoxEngine.listItems(
            folder = _vaultSelectedFolder.value,
            category = _vaultSelectedCategory.value,
            searchQuery = _vaultSearchQuery.value
        )
        _vaultSummary.value = privateCloudBoxEngine.storageSummary()
        _vaultCloudConfig.value = privateCloudBoxEngine.getCloudEndpointConfig()
    }

    fun selectVaultFolder(folder: String?) {
        _vaultSelectedFolder.value = folder
        refreshVaultStates()
    }

    fun selectVaultCategory(category: PrivateCloudBoxEngine.VaultCategory?) {
        _vaultSelectedCategory.value = category
        refreshVaultStates()
    }

    fun setVaultSearchQuery(query: String) {
        _vaultSearchQuery.value = query
        refreshVaultStates()
    }

    fun createVaultFolder(name: String) {
        privateCloudBoxEngine.createFolder(name).fold(
            onSuccess = {
                refreshVaultStates()
                showFeedback("Created folder '$it'.")
            },
            onFailure = { showFeedback(it.message ?: "Could not create folder.") }
        )
    }

    fun moveVaultItem(itemId: String, targetFolder: String) {
        privateCloudBoxEngine.moveItemToFolder(itemId, targetFolder).fold(
            onSuccess = {
                refreshVaultStates()
                showFeedback("Moved '${it.displayName}' to '${it.folder}'.")
            },
            onFailure = { showFeedback(it.message ?: "Move failed.") }
        )
    }

    fun uploadUriToVault(uri: Uri, targetFolder: String? = null) {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val name = queryDisplayName(uri) ?: "vault_file_${System.currentTimeMillis()}"
            val mime = appContext.contentResolver.getType(uri)
            val result = withContext(Dispatchers.IO) {
                val stream = appContext.contentResolver.openInputStream(uri)
                    ?: return@withContext Result.failure<PrivateCloudBoxEngine.VaultItem>(
                        IllegalStateException("Could not open selected file.")
                    )
                stream.use { input ->
                    privateCloudBoxEngine.uploadStream(input, name, mime, targetFolder)
                }
            }
            _isVaultBusy.value = false
            refreshVaultStates()
            result.fold(
                onSuccess = { item ->
                    showFeedback("Encrypted & stored '${item.displayName}' in ${item.folder}.")
                },
                onFailure = { showFeedback(it.message ?: "Vault upload failed.") }
            )
        }
    }

    fun exportVaultItemToUri(itemId: String, destUri: Uri) {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = withContext(Dispatchers.IO) {
                val out = appContext.contentResolver.openOutputStream(destUri)
                    ?: return@withContext Result.failure<PrivateCloudBoxEngine.VaultItem>(
                        IllegalStateException("Cannot write to destination URI.")
                    )
                out.use { stream ->
                    privateCloudBoxEngine.downloadToStream(itemId, stream)
                }
            }
            _isVaultBusy.value = false
            res.fold(
                onSuccess = { showFeedback("Exported '${it.displayName}' with verified SHA-256 checksum.") },
                onFailure = { showFeedback(it.message ?: "Export failed.") }
            )
        }
    }

    fun previewVaultItem(itemId: String) {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = privateCloudBoxEngine.buildPreview(itemId)
            _isVaultBusy.value = false
            res.fold(
                onSuccess = { _vaultPreview.value = it },
                onFailure = { showFeedback(it.message ?: "Could not decrypt preview.") }
            )
        }
    }

    fun closeVaultPreview() {
        _vaultPreview.value = null
        privateCloudBoxEngine.clearPreviewTempFiles()
    }

    fun deleteVaultItem(itemId: String, deleteRemote: Boolean = false) {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = privateCloudBoxEngine.deleteItem(itemId, deleteRemote)
            _isVaultBusy.value = false
            refreshVaultStates()
            res.fold(
                onSuccess = { showFeedback("Deleted file from Private Cloud Storage Box.") },
                onFailure = { showFeedback(it.message ?: "Delete failed.") }
            )
        }
    }

    fun setVaultPin(pin: String) {
        privateCloudBoxEngine.setOrUpdatePin(pin).fold(
            onSuccess = {
                refreshVaultStates()
                showFeedback("Vault PIN protection enabled.")
            },
            onFailure = { showFeedback(it.message ?: "Invalid PIN.") }
        )
    }

    fun unlockVault(pin: String) {
        if (privateCloudBoxEngine.unlockVault(pin)) {
            refreshVaultStates()
            showFeedback("Private Cloud Storage Box unlocked.")
        } else {
            showFeedback("Incorrect Vault PIN.")
        }
    }

    fun lockVault() {
        privateCloudBoxEngine.lockVault()
        _vaultPreview.value = null
        refreshVaultStates()
        showFeedback("Private Cloud Storage Box locked.")
    }

    fun removeVaultPin(currentPin: String) {
        privateCloudBoxEngine.clearPin(currentPin).fold(
            onSuccess = {
                refreshVaultStates()
                showFeedback("Vault PIN lock removed.")
            },
            onFailure = { showFeedback(it.message ?: "Incorrect current PIN.") }
        )
    }

    fun configureVaultCloud(config: PrivateCloudBoxEngine.CloudEndpointConfig) {
        privateCloudBoxEngine.configureCloudEndpoint(config).fold(
            onSuccess = {
                refreshVaultStates()
                showFeedback(
                    if (it.isConfigured) "Saved HTTPS WebDAV cloud endpoint."
                    else "Cleared WebDAV cloud endpoint."
                )
            },
            onFailure = { showFeedback(it.message ?: "Invalid cloud endpoint configuration.") }
        )
    }

    fun syncVaultItemToCloud(itemId: String) {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = privateCloudBoxEngine.syncItemToCloud(itemId)
            _isVaultBusy.value = false
            refreshVaultStates()
            res.fold(
                onSuccess = { showFeedback("Synced '${it.displayName}' to Private Cloud.") },
                onFailure = { showFeedback(it.message ?: "Cloud sync failed.") }
            )
        }
    }

    fun syncAllVaultToCloud() {
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = privateCloudBoxEngine.syncAllUnsyncedToCloud()
            _isVaultBusy.value = false
            refreshVaultStates()
            res.fold(
                onSuccess = { showFeedback("Synced $it item(s) to Private Cloud.") },
                onFailure = { showFeedback(it.message ?: "Cloud sync failed.") }
            )
        }
    }

    // --- Universal App & File Support Actions ---

    private fun refreshManagedFilesState() {
        _managedFiles.value = universalFileManager.listManagedFiles(_managedFileKindFilter.value)
    }

    fun setManagedFileKindFilter(kind: UniversalFileManager.ManagedMediaKind?) {
        _managedFileKindFilter.value = kind
        refreshManagedFilesState()
    }

    fun importUriToManagedFiles(uri: Uri) {
        viewModelScope.launch {
            _isScanningSecurity.value = true
            val name = queryDisplayName(uri) ?: "imported_file"
            val mime = appContext.contentResolver.getType(uri)
            val res = withContext(Dispatchers.IO) {
                val stream = appContext.contentResolver.openInputStream(uri)
                    ?: return@withContext Result.failure<UniversalFileManager.ManagedFileItem>(
                        IllegalStateException("Could not open selected file.")
                    )
                stream.use { input ->
                    universalFileManager.importStream(input, name, mime)
                }
            }
            _isScanningSecurity.value = false
            refreshManagedFilesState()
            res.fold(
                onSuccess = { item ->
                    val rec = SecurityScanRecord(
                        id = System.currentTimeMillis(),
                        kind = if (item.kind == UniversalFileManager.ManagedMediaKind.APK) ScanKind.APK else ScanKind.FILE,
                        target = item.displayName,
                        threatLevel = item.securityLevel,
                        riskScore = item.riskScore,
                        threatName = item.findings.firstOrNull(),
                        findings = item.findings,
                        recommendation = if (item.securityLevel == SecurityLevel.CLEAN) "Verified clean (${item.mimeType})." else "Review findings before opening or installing.",
                        timestampEpochMs = item.importedAtEpochMs
                    )
                    _fileScanResult.value = rec
                    _securityHistory.value = securityEngine.historyStore.recordItemScan(rec)
                    showFeedback("Imported & verified '${item.displayName}' (${item.securityLevel.name}).")
                },
                onFailure = { showFeedback(it.message ?: "File import failed.") }
            )
        }
    }

    fun deleteManagedFile(itemId: String) {
        if (universalFileManager.deleteManagedItem(itemId)) {
            refreshManagedFilesState()
            showFeedback("Removed managed file.")
        }
    }

    fun sendManagedFileToVault(itemId: String) {
        val file = universalFileManager.getFileForItem(itemId)
        val item = _managedFiles.value.firstOrNull { it.id == itemId }
        if (file == null || item == null) {
            showFeedback("Managed file is no longer present.")
            return
        }
        viewModelScope.launch {
            _isVaultBusy.value = true
            val res = withContext(Dispatchers.IO) {
                file.inputStream().use { s ->
                    privateCloudBoxEngine.uploadStream(s, item.displayName, item.mimeType)
                }
            }
            _isVaultBusy.value = false
            refreshVaultStates()
            res.fold(
                onSuccess = { showFeedback("Stored '${it.displayName}' in Private Cloud Storage Box.") },
                onFailure = { showFeedback(it.message ?: "Could not copy to Vault.") }
            )
        }
    }

    fun openFileExternally(file: File, mimeType: String) {
        runCatching {
            val contentUri = FileProvider.getUriForFile(
                appContext,
                "${appContext.packageName}.fileprovider",
                file
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(contentUri, mimeType.ifBlank { "*/*" })
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            appContext.startActivity(Intent.createChooser(intent, "Open with").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure {
            showFeedback("No compatible viewer app installed for $mimeType.")
        }
    }

    fun openManagedItemExternally(itemId: String) {
        val file = universalFileManager.getFileForItem(itemId) ?: return
        val item = _managedFiles.value.firstOrNull { it.id == itemId } ?: return
        if (item.kind == UniversalFileManager.ManagedMediaKind.APK) {
            requestInstallApk(file, item.securityLevel)
        } else {
            openFileExternally(file, item.mimeType)
        }
    }

    fun requestInstallApk(apkFile: File, securityLevel: SecurityLevel) {
        if (securityLevel == SecurityLevel.DANGEROUS) {
            showFeedback("Installation blocked: APK flagged as DANGEROUS by static security scan.")
            return
        }
        if (!appContext.packageManager.canRequestPackageInstalls()) {
            runCatching {
                val permIntent = Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${appContext.packageName}")
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                appContext.startActivity(permIntent)
                showFeedback("Grant 'Install unknown apps' permission if you trust this APK.")
            }.onFailure {
                showFeedback("Enable 'Install unknown apps' in Android Settings to install APKs.")
            }
            return
        }
        runCatching {
            val apkUri = FileProvider.getUriForFile(
                appContext,
                "${appContext.packageName}.fileprovider",
                apkFile
            )
            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(apkUri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            appContext.startActivity(installIntent)
        }.onFailure {
            showFeedback("Could not launch Android Package Installer: ${it.message}")
        }
    }

    fun openSystemAppSettings(packageName: String) {
        runCatching {
            val intent = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:$packageName")
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            appContext.startActivity(intent)
        }
    }

    // --- Universal Video & Music Downloader Actions ---

    fun probeMediaUrl(rawUrl: String) {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            showFeedback("Paste a video or audio URL first.")
            return
        }
        viewModelScope.launch {
            _isProbingMedia.value = true
            _mediaProbeError.value = null
            _mediaProbeResult.value = null
            val res = mediaDownloaderEngine.probeUrl(trimmed)
            _isProbingMedia.value = false
            res.fold(
                onSuccess = { probe ->
                    _mediaProbeResult.value = probe
                    showFeedback("Detected ${probe.formats.size} downloadable format(s) from ${probe.sourceHost}.")
                },
                onFailure = { err ->
                    _mediaProbeError.value = err.message ?: "Could not inspect media URL."
                }
            )
        }
    }

    fun startMediaDownload(
        probe: MediaDownloaderEngine.MediaProbeResult,
        format: MediaDownloaderEngine.MediaFormatOption,
        destinationKind: MediaDownloaderEngine.DownloadDestinationKind,
        safTreeUri: Uri? = null
    ) {
        val task = mediaDownloaderEngine.startDownload(
            probe = probe,
            format = format,
            destinationKind = destinationKind
        )
        showFeedback("Started downloading '${task.fileName}' (${format.qualityLabel}).")

        if (destinationKind == MediaDownloaderEngine.DownloadDestinationKind.SYSTEM_MEDIASTORE ||
            (destinationKind == MediaDownloaderEngine.DownloadDestinationKind.CUSTOM_DIRECTORY && safTreeUri != null)
        ) {
            viewModelScope.launch(Dispatchers.IO) {
                mediaDownloaderEngine.awaitTaskSettlement(task.id)
                val finished = mediaDownloaderEngine.tasks.value.firstOrNull { it.id == task.id } ?: return@launch
                if (finished.status != MediaDownloaderEngine.DownloadStatus.COMPLETED) return@launch
                val localFile = File(finished.outputFilePath)
                if (!localFile.exists()) return@launch

                if (destinationKind == MediaDownloaderEngine.DownloadDestinationKind.SYSTEM_MEDIASTORE) {
                    val saved = exportFileToMediaStoreDownloads(localFile, finished.fileName, finished.mimeType, finished.mediaKind)
                    if (saved) showFeedback("Saved '${finished.fileName}' to device Downloads / Media library.")
                } else if (safTreeUri != null) {
                    val saved = exportFileToSafTree(localFile, safTreeUri, finished.fileName, finished.mimeType)
                    if (saved) showFeedback("Saved '${finished.fileName}' to selected folder.")
                }
            }
        }
    }

    fun pauseMediaDownload(taskId: String) = mediaDownloaderEngine.pauseDownload(taskId)

    fun resumeMediaDownload(taskId: String) = mediaDownloaderEngine.resumeDownload(taskId)

    fun cancelMediaDownload(taskId: String) = mediaDownloaderEngine.cancelDownload(taskId)

    fun removeMediaDownload(taskId: String, deleteFile: Boolean) =
        mediaDownloaderEngine.removeTaskFromHistory(taskId, deleteFile)

    fun clearCompletedMediaDownloads() {
        mediaDownloaderEngine.clearCompletedAndCancelledHistory()
        showFeedback("Cleared finished download history.")
    }

    fun saveDownloadedMediaToVault(taskId: String) {
        val task = mediaDownloadTasks.value.firstOrNull { it.id == taskId } ?: return
        val file = File(task.outputFilePath)
        if (!file.exists()) {
            showFeedback("Downloaded file is no longer on disk.")
            return
        }
        viewModelScope.launch {
            val res = privateCloudBoxEngine.uploadFile(file, task.mimeType)
            refreshVaultStates()
            res.fold(
                onSuccess = { showFeedback("Encrypted '${it.displayName}' into Private Cloud Storage Box.") },
                onFailure = { showFeedback(it.message ?: "Could not store in Vault.") }
            )
        }
    }

    private fun exportFileToMediaStoreDownloads(
        sourceFile: File,
        displayName: String,
        mimeType: String,
        kind: MediaDownloaderEngine.MediaKind
    ): Boolean = runCatching {
        val resolver = appContext.contentResolver
        val (collection, relPath) = when (kind) {
            MediaDownloaderEngine.MediaKind.AUDIO ->
                MediaStore.Audio.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY) to "${Environment.DIRECTORY_MUSIC}/AdShieldPro"
            MediaDownloaderEngine.MediaKind.VIDEO ->
                MediaStore.Downloads.EXTERNAL_CONTENT_URI to "${Environment.DIRECTORY_DOWNLOADS}/AdShieldPro"
        }
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relPath)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
        }
        val uri = resolver.insert(collection, values) ?: return false
        resolver.openOutputStream(uri)?.use { out ->
            sourceFile.inputStream().use { input -> input.copyTo(out) }
        } ?: return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val done = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            resolver.update(uri, done, null, null)
        }
        true
    }.getOrDefault(false)

    private fun exportFileToSafTree(
        sourceFile: File,
        treeUri: Uri,
        displayName: String,
        mimeType: String
    ): Boolean = runCatching {
        val docId = android.provider.DocumentsContract.getTreeDocumentId(treeUri)
        val parentDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
        val created = android.provider.DocumentsContract.createDocument(
            appContext.contentResolver,
            parentDocUri,
            mimeType,
            displayName
        ) ?: return false
        appContext.contentResolver.openOutputStream(created)?.use { out ->
            sourceFile.inputStream().use { input -> input.copyTo(out) }
        } ?: return false
        true
    }.getOrDefault(false)

    private fun queryDisplayName(uri: Uri): String? = runCatching {
        appContext.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()

    // --- Battery Intelligence (real hardware telemetry only) ---

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
            batteryRepository.runDiagnostics()
            refreshBatteryDerived()
            val worst = batteryRepository.diagnostics.value.maxByOrNull { it.severity.ordinal }
            showFeedback(
                when (worst?.severity) {
                    null -> "Battery diagnostic complete."
                    com.adshield.pro.engine.battery.BatteryDiagnosticSeverity.CRITICAL ->
                        "Battery alert: ${worst.title}."
                    com.adshield.pro.engine.battery.BatteryDiagnosticSeverity.WARNING ->
                        "Battery diagnostic: ${worst.title}."
                    else -> "Battery diagnostic complete — no faults found in the measured readings."
                }
            )
            _isDiagnosingBattery.value = false
        }
    }

    fun refreshBatteryReadings() {
        batteryRepository.telemetry.value.let { refreshBatteryDerived() }
    }

    fun deviceProfile(screenWidthDp: Int, smallestWidthDp: Int) =
        deviceProfiler.profile(batteryRepository.telemetry.value, screenWidthDp, smallestWidthDp)

    fun clearBatterySessions() {
        batteryRepository.clearSessions()
        showFeedback("Battery session history cleared.")
    }

    // --- Aether AI (live network intelligence) ---

    val liveNetwork: StateFlow<LiveNetworkModel.NetworkSnapshot> = combine(
        repository.vpnRuntimeState,
        recentLogs,
        liveTopApps,
        topBlockedDomains
    ) { runtime, logs, apps, blocked ->
        LiveNetworkModel.snapshot(runtime, logs, apps, blocked)
    }.flowOn(Dispatchers.Default).stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        LiveNetworkModel.snapshot(
            repository.vpnRuntimeState.value,
            emptyList(),
            emptyList(),
            emptyList()
        )
    )
}
