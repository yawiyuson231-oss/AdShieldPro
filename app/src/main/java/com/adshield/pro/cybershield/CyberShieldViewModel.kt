package com.adshield.pro.cybershield

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.aether.AetherPolicy
import com.adshield.pro.aether.AetherThreatEngine
import com.adshield.pro.aether.AetherVerdict
import com.adshield.pro.cybershield.data.CloudStatusRepository
import com.adshield.pro.cybershield.data.CyberShieldPrefs
import com.adshield.pro.cybershield.data.DeviceSecurityCollector
import com.adshield.pro.cybershield.data.ThreatIntelRepository
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.DomainBlockCount
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.domain.model.TimeBucketStat
import com.adshield.pro.worker.ThreatIntelRefreshWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * CyberShield AI dashboard state. Everything is derived from real sources:
 * Room DNS history, the live VPN runtime state, DataStore settings, public
 * Android device APIs, the bundled AETHER baseline and attributed external
 * intelligence. No simulated counters, no fake scanning progress.
 */
@HiltViewModel
class CyberShieldViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val repository: AdShieldRepository,
    private val aetherEngine: AetherThreatEngine,
    private val aetherPolicy: AetherPolicy,
    private val threatIntel: ThreatIntelRepository,
    private val cloudStatus: CloudStatusRepository,
    private val deviceCollector: DeviceSecurityCollector,
    private val csPrefs: CyberShieldPrefs
) : ViewModel() {

    private val nowTicker = MutableStateFlow(System.currentTimeMillis())
    private val dashboardVisible = MutableStateFlow(false)
    private var lastCloudRefreshMs = 0L

    /** Shared "now" for relative timestamps; ticks only while the dashboard is visible. */
    val now: StateFlow<Long> = nowTicker.asStateFlow()

    val settings: StateFlow<AppSettingsState> = repository.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AppSettingsState())

    val vpnState = repository.vpnRuntimeState
    val intelState = threatIntel.state
    val cloudStatuses = cloudStatus.statuses
    val cloudRefreshing = cloudStatus.isRefreshing

    private val _deviceSnapshot = MutableStateFlow(DeviceSecuritySnapshot())
    val deviceSnapshot: StateFlow<DeviceSecuritySnapshot> = _deviceSnapshot.asStateFlow()

    private val _isDeviceScanning = MutableStateFlow(false)
    val isDeviceScanning: StateFlow<Boolean> = _isDeviceScanning.asStateFlow()

    private val _demoMapOverlay = MutableStateFlow(csPrefs.demoMapOverlay)
    val demoMapOverlay: StateFlow<Boolean> = _demoMapOverlay.asStateFlow()

    private val _feedback = MutableStateFlow<String?>(null)
    val feedback: StateFlow<String?> = _feedback.asStateFlow()

    val threatQuery = MutableStateFlow("")
    val severityFilter = MutableStateFlow<CsSeverity?>(null)

    /** Real persisted DNS events projected into pure snapshots. */
    private val dnsSnapshots: StateFlow<List<DnsEventSnapshot>> = repository.recentLogsFlow
        .map { logs ->
            logs.map {
                DnsEventSnapshot(
                    id = it.id,
                    timestampEpochMs = it.timestampEpochMs,
                    domain = it.domain,
                    queryType = it.queryType,
                    isBlocked = it.isBlocked,
                    category = it.category?.name,
                    matchedRule = it.matchedRule,
                    sourceList = it.sourceList,
                    latencyMs = it.latencyMs,
                    protocolUsed = it.protocolUsed,
                    appPackageName = it.appPackageName,
                    appName = it.appName
                )
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val threatEvents: StateFlow<List<ThreatEvent>> = dnsSnapshots
        .map { ThreatEventMapper.mapAll(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val threatStats: StateFlow<ThreatStats> = combine(threatEvents, nowTicker) { events, now ->
        ThreatEventMapper.summarize(events, now)
    }.stateIn(
        viewModelScope, SharingStarted.WhileSubscribed(5_000),
        ThreatStats("Last 24 h", 0, 0, 0, CsSeverity.entries.associateWith { 0L }, 0, 0, 0)
    )

    val incidents: StateFlow<List<ThreatIncident>> = combine(threatEvents, nowTicker) { events, now ->
        CorrelationEngine.correlate(events, now)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val filteredIncidents: StateFlow<List<ThreatIncident>> =
        combine(incidents, threatQuery, severityFilter) { list, query, severity ->
            list.filter { incident ->
                (severity == null || incident.severity == severity) &&
                    (query.isBlank() || incident.domain.contains(query.trim(), ignoreCase = true) ||
                        incident.apps.any { it.contains(query.trim(), ignoreCase = true) })
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val anomalies: StateFlow<List<AnomalyFinding>> = combine(dnsSnapshots, nowTicker) { events, now ->
        BehavioralAnomalyDetector.detect(events, now)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val attackVectors: StateFlow<List<CategoryCount>> = combine(threatEvents, nowTicker) { events, now ->
        ThreatEventMapper.attackVectors(events, now)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val hourlyBuckets: StateFlow<List<HourBucket>> = combine(threatEvents, nowTicker) { events, now ->
        ThreatEventMapper.hourlyBuckets(events, now)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val dailyTrend: StateFlow<List<TimeBucketStat>> = repository.observeDailyChartBuckets(7)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val topBlockedDomains: StateFlow<List<DomainBlockCount>> = repository.topBlockedDomainsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val shieldState: StateFlow<ShieldState> =
        combine(repository.vpnRuntimeState, settings, threatEvents, nowTicker) { vpn, s, events, now ->
            val blockedLastHour = events.count {
                it.action == CsEventAction.BLOCKED && now - it.timestampEpochMs <= 3_600_000L
            }
            ShieldStateEvaluator.evaluate(
                vpnStatus = vpn.status.name,
                lastError = vpn.lastError,
                aetherEnabled = s.aetherEnabled,
                blockedLastHour = blockedLastHour,
                loadedRuleCount = vpn.loadedRuleCount
            )
        }.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(5_000),
            ShieldState(ShieldMode.OFF, "PROTECTION OFF", "Loading runtime state…", 0)
        )

    val complianceReport: StateFlow<ComplianceReport?> =
        combine(_deviceSnapshot, settings, repository.vpnRuntimeState, nowTicker) { device, s, vpn, now ->
            if (device.collectedAtEpochMs == 0L) null
            else ComplianceEvaluator.evaluate(
                device = device,
                settings = CsSettingsSnapshot(
                    vpnStatus = vpn.status.name,
                    protectionMode = s.protectionMode.name,
                    resolverProtocol = s.resolverConfig.protocol.name,
                    aetherEnabled = s.aetherEnabled,
                    aetherAutoBlock = s.aetherAutoBlockConfirmed,
                    autoUpdateFilters = s.autoUpdateFiltersEnabled,
                    detailedLogging = s.detailedDnsLoggingEnabled,
                    logRetentionDays = s.logRetentionDays,
                    loadedRuleCount = vpn.loadedRuleCount
                ),
                nowEpochMs = now
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    val networkSummary: StateFlow<NetworkSummary> =
        combine(dnsSnapshots, threatEvents, repository.vpnRuntimeState, nowTicker) { snaps, events, vpn, now ->
            val dayEvents = snaps.filter { now - it.timestampEpochMs <= ThreatEventMapper.DAY_MS }
            val blocked = events.filter {
                it.action == CsEventAction.BLOCKED && now - it.timestampEpochMs <= ThreatEventMapper.DAY_MS
            }
            val resolved = dayEvents.filter { it.latencyMs > 0 }
            NetworkSummary(
                windowEvents = dayEvents.size.toLong(),
                windowBlocked = blocked.size.toLong(),
                averageLatencyMs = if (resolved.isEmpty()) 0 else resolved.sumOf { it.latencyMs } / resolved.size,
                cachedShare = if (dayEvents.isEmpty()) 0f
                else dayEvents.count { it.protocolUsed.contains("cache", true) }.toFloat() / dayEvents.size,
                protocols = ThreatEventMapper.protocolDistribution(snaps, now),
                upstreamLabel = vpn.resolverConfig.preset.displayName,
                encryptedUpstream = vpn.resolverConfig.protocol.name != "UDP_TCP",
                protectionActive = vpn.status.name == "CONNECTED",
                blockedHistory = blocked.take(6)
            )
        }.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(5_000),
            NetworkSummary(0, 0, 0, 0f, emptyList(), "", true, false, emptyList())
        )

    /** Local AETHER analysis of the most recent distinct allowed domains. */
    val aiVerdicts: StateFlow<List<AetherVerdict>> =
        combine(dnsSnapshots, settings) { snaps, s ->
            val recentDomains = snaps.asSequence()
                .filter { !it.isBlocked }
                .map { it.domain }
                .distinct()
                .take(6)
                .toList()
            recentDomains.map { aetherEngine.analyze(it, s, aetherPolicy) }
        }
            .flowOn(Dispatchers.Default)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val aetherInfo: Map<String, String> by lazy { aetherEngine.baselineInfo() }

    init {
        // Pre-warm the bundled AETHER baseline off the main thread so the first
        // dashboard frame never parses assets synchronously.
        viewModelScope.launch(Dispatchers.IO) { aetherEngine.baselineInfo() }
        // Lightweight foreground-only refresh loop. No extra background service:
        // periodic intel updates run through WorkManager instead.
        viewModelScope.launch {
            while (isActive) {
                delay(30_000L)
                if (dashboardVisible.value) {
                    nowTicker.value = System.currentTimeMillis()
                    refreshDevice()
                }
            }
        }
    }

    /** Called from the dashboard composable lifecycle. */
    fun onDashboardVisible() {
        dashboardVisible.value = true
        nowTicker.value = System.currentTimeMillis()
        refreshDevice()
        threatIntel.refresh(force = false)
        if (System.currentTimeMillis() - lastCloudRefreshMs > 5 * 60_000L) {
            refreshCloud()
        }
    }

    fun onDashboardHidden() {
        dashboardVisible.value = false
    }

    fun refreshAll() {
        nowTicker.value = System.currentTimeMillis()
        refreshDevice()
        threatIntel.refresh(force = true)
        refreshCloud()
    }

    fun refreshIntel() = threatIntel.refresh(force = true)

    fun refreshCloud() {
        lastCloudRefreshMs = System.currentTimeMillis()
        cloudStatus.refreshAll()
    }

    fun refreshDevice() {
        if (_isDeviceScanning.value) return
        viewModelScope.launch {
            _isDeviceScanning.value = true
            try {
                _deviceSnapshot.value = deviceCollector.collect()
            } finally {
                _isDeviceScanning.value = false
            }
        }
    }

    fun setIntelEnabled(enabled: Boolean) {
        threatIntel.setEnabled(enabled)
        ThreatIntelRefreshWorker.scheduleOrCancel(appContext, enabled)
    }

    fun setDemoMapOverlay(enabled: Boolean) {
        csPrefs.demoMapOverlay = enabled
        _demoMapOverlay.value = enabled
    }

    fun addCloudEndpoint(name: String, url: String, token: String?) {
        val error = cloudStatus.addCustomEndpoint(name, url, token)
        _feedback.value = error ?: "Endpoint added. Fetching real status…"
    }

    fun removeCloudEndpoint(id: String) = cloudStatus.removeCustomEndpoint(id)

    /** On-demand domain reputation check using the local AETHER engine. */
    suspend fun reputationCheck(domain: String): AetherVerdict = withContext(Dispatchers.Default) {
        aetherEngine.analyze(domain, settings.value, aetherPolicy)
    }

    fun blockDomain(domain: String) {
        viewModelScope.launch {
            val result = repository.addCustomRule(
                domain,
                RuleType.BLOCK,
                RuleMatchType.SUBDOMAIN,
                "Blocked from CyberShield dashboard"
            )
            _feedback.value = result.fold(
                onSuccess = { "Block rule for $domain applied immediately." },
                onFailure = { it.message ?: "Could not create block rule." }
            )
        }
    }

    /** Explicit, expiring override through the audited AETHER policy. */
    fun allowTemporary(domain: String, minutes: Int, reason: String): Boolean {
        return runCatching {
            aetherPolicy.approveTemporaryAllow(
                domain = domain,
                minutes = minutes,
                approver = "device user (dashboard)",
                reason = reason,
                approvalPhrase = AetherPolicy.APPROVAL_PHRASE
            )
        }.onSuccess {
            _feedback.value = "$domain temporarily allowed for $minutes min (audited, auto-expires)."
        }.onFailure {
            _feedback.value = it.message ?: "Allowlist approval failed."
        }.isSuccess
    }

    fun reportFalsePositive(domain: String) {
        aetherPolicy.markFalsePositive(domain)
        aetherPolicy.appendUserAudit("feedback.dashboard_false_positive domain=$domain")
        _feedback.value = "$domain marked as verified false positive. Auto-blocking suppressed."
    }

    fun exportComplianceJson(): String? =
        complianceReport.value?.let { ComplianceReportJson.render(it) }

    fun clearFeedback() {
        _feedback.value = null
    }
}
