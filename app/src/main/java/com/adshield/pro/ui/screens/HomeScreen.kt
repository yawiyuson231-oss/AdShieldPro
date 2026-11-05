package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Https
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.OfflineBolt
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.LiveNetworkModel
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.PrivacyBadge
import com.adshield.pro.ui.components.ProtectionShield
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.cybershield.ActiveThreatsPanel
import com.adshield.pro.ui.cybershield.ActivityFeedPanel
import com.adshield.pro.ui.cybershield.AttackVectorsPanel
import com.adshield.pro.ui.cybershield.CompliancePanel
import com.adshield.pro.ui.cybershield.CyberShieldHeader
import com.adshield.pro.ui.cybershield.CyberShieldTab
import com.adshield.pro.ui.cybershield.CyberShieldTabStrip
import com.adshield.pro.ui.cybershield.DetectionEnginePanel
import com.adshield.pro.ui.cybershield.GlobalThreatMapPanel
import com.adshield.pro.ui.cybershield.StatusCardsRow
import com.adshield.pro.ui.cybershield.ThreatOverviewPanel
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.theme.formatInteger
import com.adshield.pro.ui.viewmodel.AdShieldViewModel
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * CyberShield AI command center — the reference console recreated for Android.
 *
 * Portrait phones get a single lazy column in the reference's reading order; wider screens
 * (landscape phones, tablets, desktops) get the reference's multi-column console layout. Every
 * panel is fed by a real data source; empty, offline and disconnected states are explicit.
 * The legacy app areas (Ad Blocker, Optimizer, Battery, Statistics, Security, Settings) remain
 * reachable from the bottom navigation and from the console's own tabs.
 */
@Composable
fun HomeScreen(
    viewModel: AdShieldViewModel,
    cyberViewModel: CyberShieldViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onPauseResumeVpn: () -> Unit,
    onOpenSettingsTab: () -> Unit,
    onOpenSecurityTab: () -> Unit,
    onOpenLiveTab: () -> Unit,
    onOpenOptimizerTab: () -> Unit,
    onOpenStatisticsTab: () -> Unit,
    onOpenStatusTab: () -> Unit
) {
    var tab by rememberSaveable { mutableStateOf(CyberShieldTab.DASHBOARD) }
    val recentLogs by viewModel.recentLogs.collectAsStateWithLifecycle()
    val isCheckingForUpdates by viewModel.isCheckingForUpdates.collectAsStateWithLifecycle()
    val criticalAlerts = recentLogs.count { it.isBlocked && it.category == RuleCategory.MALWARE }

    // Load the installed-app inventory once for the Endpoints card (real PackageManager data).
    LaunchedEffect(Unit) { viewModel.loadInstalledApps() }

    Column(Modifier.fillMaxSize()) {
        CyberShieldHeader(
            criticalAlertCount = criticalAlerts,
            isCheckingForUpdates = isCheckingForUpdates,
            onAlertsClick = {
                cyberViewModel.setSeverityFilter(ThreatSeverity.CRITICAL)
                cyberViewModel.setIncludeAllowed(false)
                tab = CyberShieldTab.THREATS
            },
            onCheckForUpdates = viewModel::checkForUpdates,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 10.dp)
        )
        Spacer(Modifier.height(8.dp))
        CyberShieldTabStrip(
            selected = tab,
            onSelect = { selected ->
                if (selected == CyberShieldTab.SETTINGS) onOpenSettingsTab() else tab = selected
            },
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        Spacer(Modifier.height(8.dp))
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when (tab) {
                CyberShieldTab.DASHBOARD -> DashboardTab(
                    viewModel = viewModel,
                    cyberViewModel = cyberViewModel,
                    onToggleVpn = onToggleVpn,
                    onPauseResumeVpn = onPauseResumeVpn,
                    onOpenTab = { tab = it },
                    onOpenLiveTab = onOpenLiveTab
                )
                CyberShieldTab.THREATS -> ThreatsScreen(
                    cyberViewModel = cyberViewModel,
                    onShowFeedback = viewModel::showFeedback
                )
                CyberShieldTab.ENDPOINTS -> EndpointsScreen(
                    viewModel = viewModel,
                    cyberViewModel = cyberViewModel,
                    onOpenSecurityTab = onOpenSecurityTab
                )
                CyberShieldTab.CLOUD -> CloudScreen(cyberViewModel = cyberViewModel)
                CyberShieldTab.NETWORK -> NetworkTab(
                    viewModel = viewModel,
                    onToggleVpn = onToggleVpn,
                    onPauseResumeVpn = onPauseResumeVpn,
                    onOpenLiveTab = onOpenLiveTab,
                    onOpenOptimizerTab = onOpenOptimizerTab
                )
                CyberShieldTab.INTELLIGENCE -> IntelligenceScreen(cyberViewModel = cyberViewModel)
                CyberShieldTab.REPORTS -> ReportsScreen(
                    viewModel = viewModel,
                    cyberViewModel = cyberViewModel,
                    onOpenStatusTab = onOpenStatusTab,
                    onOpenStatisticsTab = onOpenStatisticsTab
                )
                CyberShieldTab.SETTINGS -> Unit // handled by the bottom navigation
            }
        }
    }
}

// --------------------------------------------------------------------- Dashboard tab

@Composable
private fun DashboardTab(
    viewModel: AdShieldViewModel,
    cyberViewModel: CyberShieldViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onPauseResumeVpn: () -> Unit,
    onOpenTab: (CyberShieldTab) -> Unit,
    onOpenLiveTab: () -> Unit
) {
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val allTimeBlocked by viewModel.allTimeBlockedQueries.collectAsStateWithLifecycle()
    val chartBuckets by viewModel.chartBuckets.collectAsStateWithLifecycle()
    val recentLogs by viewModel.recentLogs.collectAsStateWithLifecycle()
    val liveNetwork by viewModel.liveNetwork.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()
    val appAudits by viewModel.appAudits.collectAsStateWithLifecycle()

    val severityTotals by cyberViewModel.severityTotals.collectAsStateWithLifecycle()
    val detectionReport by cyberViewModel.detectionReport.collectAsStateWithLifecycle()
    val intelState by cyberViewModel.intelState.collectAsStateWithLifecycle()
    val countryThreats by cyberViewModel.countryThreats.collectAsStateWithLifecycle()
    val mapFilter by cyberViewModel.mapFilter.collectAsStateWithLifecycle()
    val selectedCountry by cyberViewModel.selectedCountry.collectAsStateWithLifecycle()
    val filteredIndicators by cyberViewModel.filteredIndicators.collectAsStateWithLifecycle()
    val cloudStatuses by cyberViewModel.cloudStatuses.collectAsStateWithLifecycle()
    val complianceReport by cyberViewModel.complianceReport.collectAsStateWithLifecycle()
    val isEvaluatingCompliance by cyberViewModel.isEvaluatingCompliance.collectAsStateWithLifecycle()
    val intelFeedback by cyberViewModel.intelFeedback.collectAsStateWithLifecycle()

    val flaggedApps = appAudits.takeIf { it.isNotEmpty() }
        ?.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }

    // First-run convenience: fetch the public feeds once when nothing has ever been synced.
    // The periodic WorkManager job keeps them fresh afterwards; failures stay visible.
    var autoSyncAttempted by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(intelState.feeds) {
        if (!autoSyncAttempted &&
            intelState.feeds.all { it.status == com.adshield.pro.engine.intel.FeedFetchStatus.NOT_FETCHED }
        ) {
            autoSyncAttempted = true
            cyberViewModel.refreshIntel()
        }
    }
    LaunchedEffect(Unit) {
        if (complianceReport == null) cyberViewModel.evaluateCompliance(flaggedApps)
    }
    LaunchedEffect(intelFeedback) {
        intelFeedback?.let {
            viewModel.showFeedback(it)
            cyberViewModel.clearIntelFeedback()
        }
    }

    val screenWidth = LocalConfiguration.current.screenWidthDp
    val today = chartBuckets.lastOrNull()

    val openSeverity: (ThreatSeverity) -> Unit = { severity ->
        cyberViewModel.setSeverityFilter(severity)
        cyberViewModel.setIncludeAllowed(false)
        onOpenTab(CyberShieldTab.THREATS)
    }

    if (screenWidth >= 1000) {
        // Reference console: three independent lazy columns.
        Row(Modifier.fillMaxSize().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ConsoleColumn(Modifier.weight(1f).fillMaxHeight()) {
                item(key = "left-overview") {
                    ThreatOverviewPanel(allTimeBlocked, severityTotals, chartBuckets, recentLogs)
                }
                item(key = "left-active") {
                    ActiveThreatsPanel(severityTotals, openSeverity)
                }
                item(key = "left-feed") {
                    ActivityFeedPanel(recentLogs, settings.detailedDnsLoggingEnabled, { onOpenTab(CyberShieldTab.THREATS) })
                }
            }
            ConsoleColumn(Modifier.weight(1.4f).fillMaxHeight()) {
                item(key = "center-map") {
                    GlobalThreatMapPanel(
                        intelState, countryThreats, mapFilter, selectedCountry, filteredIndicators.size,
                        cyberViewModel::setMapFilter, cyberViewModel::selectCountry, cyberViewModel::refreshIntel
                    )
                }
                item(key = "center-shield") {
                    ShieldPanel(vpnState, liveNetwork, onToggleVpn, onPauseResumeVpn, onOpenLiveTab)
                }
                item(key = "center-cards") {
                    StatusCardsRow(
                        endpointCount = installedApps.size,
                        endpointFlagged = flaggedApps,
                        cloud = cloudStatuses,
                        networkTotalToday = today?.totalQueries ?: 0L,
                        networkBlockedToday = today?.blockedQueries ?: 0L,
                        networkActive = vpnState.status == VpnStatus.CONNECTED,
                        chartBuckets = chartBuckets,
                        onOpenEndpoints = { onOpenTab(CyberShieldTab.ENDPOINTS) },
                        onOpenCloud = { onOpenTab(CyberShieldTab.CLOUD) },
                        onOpenNetwork = { onOpenTab(CyberShieldTab.NETWORK) }
                    )
                }
            }
            ConsoleColumn(Modifier.weight(1f).fillMaxHeight()) {
                item(key = "right-detection") {
                    DetectionEnginePanel(detectionReport) { onOpenTab(CyberShieldTab.THREATS) }
                }
                item(key = "right-vectors") {
                    AttackVectorsPanel(liveNetwork.categories)
                }
                item(key = "right-compliance") {
                    CompliancePanel(
                        complianceReport, isEvaluatingCompliance,
                        { cyberViewModel.evaluateCompliance(flaggedApps) },
                        { onOpenTab(CyberShieldTab.REPORTS) }
                    )
                }
            }
        }
    } else if (screenWidth >= 600) {
        // Landscape phones / small tablets: two columns.
        Row(Modifier.fillMaxSize().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ConsoleColumn(Modifier.weight(1f).fillMaxHeight()) {
                item(key = "l-overview") { ThreatOverviewPanel(allTimeBlocked, severityTotals, chartBuckets, recentLogs) }
                item(key = "l-active") { ActiveThreatsPanel(severityTotals, openSeverity) }
                item(key = "l-feed") { ActivityFeedPanel(recentLogs, settings.detailedDnsLoggingEnabled, onViewAll = { onOpenTab(CyberShieldTab.THREATS) }) }
                item(key = "l-compliance") {
                    CompliancePanel(complianceReport, isEvaluatingCompliance, onEvaluate = { cyberViewModel.evaluateCompliance(flaggedApps) }, onViewReport = { onOpenTab(CyberShieldTab.REPORTS) })
                }
            }
            ConsoleColumn(Modifier.weight(1.2f).fillMaxHeight()) {
                item(key = "r-map") {
                    GlobalThreatMapPanel(
                        intelState, countryThreats, mapFilter, selectedCountry, filteredIndicators.size,
                        cyberViewModel::setMapFilter, cyberViewModel::selectCountry, cyberViewModel::refreshIntel
                    )
                }
                item(key = "r-shield") { ShieldPanel(vpnState, liveNetwork, onToggleVpn, onPauseResumeVpn, onOpenLiveTab) }
                item(key = "r-detection") { DetectionEnginePanel(detectionReport) { onOpenTab(CyberShieldTab.THREATS) } }
                item(key = "r-vectors") { AttackVectorsPanel(liveNetwork.categories) }
                item(key = "r-cards") {
                    StatusCardsRow(
                        installedApps.size, flaggedApps, cloudStatuses,
                        today?.totalQueries ?: 0L, today?.blockedQueries ?: 0L,
                        vpnState.status == VpnStatus.CONNECTED, chartBuckets,
                        { onOpenTab(CyberShieldTab.ENDPOINTS) }, { onOpenTab(CyberShieldTab.CLOUD) }, { onOpenTab(CyberShieldTab.NETWORK) }
                    )
                }
            }
        }
    } else {
        // Portrait phone: one lazy column in the reference reading order.
        val listState = rememberLazyListState()
        Box(Modifier.fillMaxSize()) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item(key = "overview", contentType = "panel") {
                    ThreatOverviewPanel(allTimeBlocked, severityTotals, chartBuckets, recentLogs)
                }
                item(key = "map", contentType = "panel") {
                    GlobalThreatMapPanel(
                        intelState, countryThreats, mapFilter, selectedCountry, filteredIndicators.size,
                        cyberViewModel::setMapFilter, cyberViewModel::selectCountry, cyberViewModel::refreshIntel
                    )
                }
                item(key = "shield", contentType = "panel") {
                    ShieldPanel(vpnState, liveNetwork, onToggleVpn, onPauseResumeVpn, onOpenLiveTab)
                }
                item(key = "detection", contentType = "panel") {
                    DetectionEnginePanel(detectionReport) { onOpenTab(CyberShieldTab.THREATS) }
                }
                item(key = "active", contentType = "panel") {
                    ActiveThreatsPanel(severityTotals, openSeverity)
                }
                item(key = "vectors", contentType = "panel") {
                    AttackVectorsPanel(liveNetwork.categories)
                }
                item(key = "feed", contentType = "panel") {
                    ActivityFeedPanel(recentLogs, settings.detailedDnsLoggingEnabled, onViewAll = { onOpenTab(CyberShieldTab.THREATS) })
                }
                item(key = "cards", contentType = "cards") {
                    StatusCardsRow(
                        installedApps.size, flaggedApps, cloudStatuses,
                        today?.totalQueries ?: 0L, today?.blockedQueries ?: 0L,
                        vpnState.status == VpnStatus.CONNECTED, chartBuckets,
                        { onOpenTab(CyberShieldTab.ENDPOINTS) }, { onOpenTab(CyberShieldTab.CLOUD) }, { onOpenTab(CyberShieldTab.NETWORK) }
                    )
                }
                item(key = "compliance", contentType = "panel") {
                    CompliancePanel(complianceReport, isEvaluatingCompliance, onEvaluate = { cyberViewModel.evaluateCompliance(flaggedApps) }, onViewReport = { onOpenTab(CyberShieldTab.REPORTS) })
                }
            }
            ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
        }
    }
}

/** One independently-scrolling console column; every item is keyed by the caller. */
@Composable
private fun ConsoleColumn(
    modifier: Modifier,
    content: LazyListScope.() -> Unit
) {
    val listState = rememberLazyListState()
    Box(modifier) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content
        )
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp))
    }
}

// --------------------------------------------------------------------- Central shield

@Composable
private fun ShieldPanel(
    vpnState: VpnRuntimeState,
    liveNetwork: LiveNetworkModel.NetworkSnapshot,
    onToggleVpn: (Boolean) -> Unit,
    onPauseResumeVpn: () -> Unit,
    onOpenLiveTab: () -> Unit
) {
    val isConnected = vpnState.status == VpnStatus.CONNECTED
    val isPaused = vpnState.status == VpnStatus.PAUSED
    val isActiveOrPaused = isConnected || isPaused
    val statusColor = when (vpnState.status) {
        VpnStatus.CONNECTED -> EmeraldPrimary
        VpnStatus.PAUSED -> WarningAmber
        VpnStatus.STARTING, VpnStatus.RECONNECTING -> CyberCyan
        VpnStatus.ERROR -> AlertRed
        VpnStatus.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val statusLabel = when (vpnState.status) {
        VpnStatus.CONNECTED -> "SYSTEM PROTECTED"
        VpnStatus.PAUSED -> "FILTERING PAUSED"
        VpnStatus.STARTING -> "STARTING PROTECTION"
        VpnStatus.RECONNECTING -> "RECONNECTING"
        VpnStatus.ERROR -> "NEEDS ATTENTION"
        VpnStatus.DISCONNECTED -> "PROTECTION OFF"
    }
    CyberPanel(
        title = "Local threat shield",
        subtitle = "On-device DNS · ${vpnState.activeNetworkLabel}",
        trailing = { StatusPill(if (isConnected) "LIVE" else "IDLE", statusColor) }
    ) {
        ProtectionShield(
            status = vpnState.status,
            hasTraffic = liveNetwork.hasData,
            threatSignals = liveNetwork.threatsBlocked.toInt(),
            onClick = { onToggleVpn(!isActiveOrPaused) },
            modifier = Modifier.fillMaxWidth().height(240.dp)
        )
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            // The plate mirrors the reference, but the text is the real tunnel state — it is
            // never a permanent "SYSTEM PROTECTED".
            Box(
                Modifier
                    .padding(vertical = 4.dp)
                    .background(statusColor.copy(alpha = 0.10f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 16.dp, vertical = 8.dp)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(statusLabel, color = statusColor, fontWeight = FontWeight.Bold, letterSpacing = 1.sp, fontSize = 14.sp)
                    Text(
                        if (isConnected) "AI THREAT DETECTION ACTIVE" else "DNS FILTERING STANDBY",
                        color = statusColor.copy(alpha = 0.8f),
                        fontSize = 9.sp,
                        letterSpacing = 0.8.sp
                    )
                }
            }
            Text(
                text = when (vpnState.status) {
                    VpnStatus.CONNECTED -> "AI threat detection active · ${formatInteger(vpnState.loadedRuleCount)} rules loaded"
                    VpnStatus.PAUSED -> "Tunnel is paused. Resume to keep filtering."
                    VpnStatus.ERROR -> vpnState.lastError ?: "The tunnel could not start."
                    else -> "Tap the shield or the button to start non-root DNS protection."
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 4.dp, bottom = 12.dp)
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = { onToggleVpn(!isActiveOrPaused) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = if (isActiveOrPaused) AlertRed.copy(alpha = 0.85f) else ElectricBlue)
                ) {
                    Icon(if (isActiveOrPaused) Icons.Default.Shield else Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(if (isActiveOrPaused) "Turn off" else "Protect device", maxLines = 1)
                }
                OutlinedButton(onClick = onPauseResumeVpn, enabled = isActiveOrPaused, modifier = Modifier.weight(1f)) {
                    Icon(if (isPaused) Icons.Default.PlayArrow else Icons.Default.Pause, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(if (isPaused) "Resume" else "Pause", maxLines = 1)
                }
            }
            TextButton(onClick = onOpenLiveTab) { Text("Open live network dashboard", fontSize = 12.sp) }
        }
    }
}

// --------------------------------------------------------------------- Network tab

@Composable
private fun NetworkTab(
    viewModel: AdShieldViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onPauseResumeVpn: () -> Unit,
    onOpenLiveTab: () -> Unit,
    onOpenOptimizerTab: () -> Unit
) {
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val liveNetwork by viewModel.liveNetwork.collectAsStateWithLifecycle()
    val isUpdatingFilters by viewModel.isUpdatingFilters.collectAsStateWithLifecycle()
    val isRunningSmartBoost by viewModel.isRunningSmartBoost.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "net-shield", contentType = "panel") {
                ShieldPanel(vpnState, liveNetwork, onToggleVpn, onPauseResumeVpn, onOpenLiveTab)
            }
            item(key = "net-resolver", contentType = "panel") {
                CyberPanel(
                    title = "DNS resolver",
                    subtitle = "${settings.resolverConfig.preset.displayName} · IPv6 ${if (settings.resolverConfig.enableIpv6) "on" else "off"}"
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Dns, contentDescription = null, tint = CyberCyan)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(settings.resolverConfig.protocol.label, color = androidx.compose.ui.graphics.Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                            Text(
                                if (settings.lastFilterUpdateEpochMs > 0L) "Lists synced ${SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(settings.lastFilterUpdateEpochMs))}"
                                else "Bundled offline baseline ready",
                                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                            )
                        }
                        IconButton(onClick = viewModel::triggerManualFilterUpdate, enabled = !isUpdatingFilters) {
                            Icon(Icons.Default.Refresh, contentDescription = "Sync filter lists", tint = SkyBlueGlow)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Connection filtering is DNS-level: ad, tracker and malware domains are sinkholed. Encrypted app traffic is not decrypted, and apps using hardcoded IPs bypass DNS filtering.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                    )
                }
            }
            item(key = "net-mode", contentType = "panel") {
                CyberPanel(title = "Protection profile", subtitle = "Applies immediately to the in-memory filter engine") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        ProtectionMode.entries.forEach { mode ->
                            val selected = settings.protectionMode == mode
                            androidx.compose.material3.Surface(
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                                color = if (selected) ElectricBlue.copy(alpha = 0.14f) else androidx.compose.ui.graphics.Color(0xFF08182B),
                                modifier = Modifier.fillMaxWidth().clickable { viewModel.setProtectionMode(mode) }
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            if (selected) Icons.Default.Security else Icons.Default.Security,
                                            contentDescription = null,
                                            tint = if (selected) SkyBlueGlow else MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        Text(mode.title, color = androidx.compose.ui.graphics.Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                                    }
                                    Text(mode.subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp, modifier = Modifier.padding(top = 3.dp))
                                    if (selected && mode.warningNote != null) {
                                        Text(mode.warningNote, color = WarningAmber, fontSize = 11.sp, modifier = Modifier.padding(top = 5.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            item(key = "net-actions", contentType = "panel") {
                CyberPanel(title = "Quick actions", subtitle = "Optimizer and filter maintenance") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = viewModel::runOneTapSmartBoost, enabled = !isRunningSmartBoost, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(if (isRunningSmartBoost) "Optimizing…" else "Optimize now", maxLines = 1)
                        }
                        OutlinedButton(onClick = viewModel::triggerManualFilterUpdate, enabled = !isUpdatingFilters, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(if (isUpdatingFilters) "Syncing…" else "Sync lists", maxLines = 1)
                        }
                    }
                    if (isUpdatingFilters || isRunningSmartBoost) {
                        Spacer(Modifier.height(10.dp))
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = ElectricBlue)
                    }
                    TextButton(onClick = onOpenOptimizerTab) { Text("Open full optimizer") }
                }
            }
            item(key = "net-privacy", contentType = "panel") {
                CyberPanel(title = "Privacy & coverage", subtitle = "What this build actually does — not a certification claim") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PrivacyBadge("Local only", Icons.Default.Lock, true, Modifier.weight(1f))
                        PrivacyBadge("No root", Icons.Default.Shield, true, Modifier.weight(1f))
                        PrivacyBadge("No MITM", Icons.Default.Https, true, Modifier.weight(1f))
                        PrivacyBadge("Offline rules", Icons.Default.OfflineBolt, vpnState.loadedRuleCount > 0, Modifier.weight(1f))
                    }
                }
            }
            item(key = "net-disclosure", contentType = "panel") {
                CyberPanel(title = "Coverage disclosure", subtitle = "DNS-level protection has real limits") {
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "AdShield blocks third-party ad, tracker and malicious domains without root or HTTPS decryption. Apps that serve video ads from the same first-party servers as their content (for example some YouTube, Facebook, TikTok and streaming apps) cannot be fully blocked by DNS alone.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }
}
