package com.adshield.pro

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Monitor
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.ui.model.DashboardPresentation
import com.adshield.pro.ui.screens.ActivityScreen
import com.adshield.pro.ui.screens.AdBlockerHubScreen
import com.adshield.pro.ui.screens.BatteryScreen
import com.adshield.pro.ui.screens.CapabilitiesScreen
import com.adshield.pro.ui.screens.HomeScreen
import com.adshield.pro.ui.screens.LiveNetworkScreen
import com.adshield.pro.ui.screens.OptimizerScreen
import com.adshield.pro.ui.screens.SecurityScreen
import com.adshield.pro.ui.screens.SettingsScreen
import com.adshield.pro.ui.theme.AdShieldProTheme
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.viewmodel.AdShieldViewModel
import dagger.hilt.android.AndroidEntryPoint

enum class MainNavDestination(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Default.Home),
    AD_BLOCKER("Ad Blocker", Icons.Default.Shield),
    LIVE("Live", Icons.Default.Monitor),
    SECURITY("Security", Icons.Default.Security),
    OPTIMIZER("Optimizer", Icons.Default.Bolt),
    BATTERY("Battery", Icons.Default.BatteryChargingFull),
    STATISTICS("Statistics", Icons.Default.Analytics),
    SETTINGS("Settings", Icons.Default.Settings),
    STATUS("Status", Icons.Default.VerifiedUser)
}

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: AdShieldViewModel = hiltViewModel()
            val settings by viewModel.settingsState.collectAsStateWithLifecycle()
            AdShieldProTheme(themePreference = settings.darkThemeMode) {
                AdShieldMainApp(viewModel = viewModel)
            }
        }
    }
}

/**
 * Shell only: navigation, VPN consent and snackbars. Each destination collects just the state it
 * renders, so a DNS tick on Home does not recompose Battery/Settings/Optimizer state holders.
 */
@Composable
fun AdShieldMainApp(viewModel: AdShieldViewModel) {
    val context = LocalContext.current
    var currentTab by rememberSaveable { mutableStateOf(MainNavDestination.HOME) }
    var showAboutScreen by rememberSaveable { mutableStateOf(false) }
    var showVpnConsentHelp by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }
    val uiFeedback by viewModel.uiFeedbackMessage.collectAsStateWithLifecycle()

    BackHandler(enabled = showAboutScreen) { showAboutScreen = false }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ -> viewModel.startVpnService() }

    val startAfterConsent: () -> Unit = {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            viewModel.startVpnService()
        }
    }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK || VpnService.prepare(context) == null) {
            startAfterConsent()
        } else {
            showVpnConsentHelp = true
        }
    }

    val launchVpnConsent: () -> Unit = {
        val prepareIntent = try {
            VpnService.prepare(context)
        } catch (e: Exception) {
            null.also { showVpnConsentHelp = true }
        }
        if (prepareIntent != null) {
            try {
                vpnConsentLauncher.launch(prepareIntent)
            } catch (e: Exception) {
                showVpnConsentHelp = true
            }
        } else if (!showVpnConsentHelp) {
            startAfterConsent()
        }
    }

    val handleToggleVpn: (Boolean) -> Unit = { enable ->
        if (enable) launchVpnConsent() else viewModel.stopVpnService()
    }

    if (showVpnConsentHelp) {
        AlertDialog(
            onDismissRequest = { showVpnConsentHelp = false },
            title = { Text("VPN permission needed") },
            text = {
                Text(
                    "AdShield Pro filters ads through a local, on-device VPN. Android didn't grant " +
                        "the VPN permission. This usually happens when:\n\n" +
                        "• \"Cancel\" was tapped on the connection request, or\n" +
                        "• Another VPN app is set as \"Always-on VPN\" (often with \"Block connections " +
                        "without VPN\" enabled).\n\n" +
                        "Tap Try Again and choose OK. If no dialog appears, open VPN settings, turn off " +
                        "Always-on for the other VPN app, then try again."
                )
            },
            confirmButton = {
                TextButton(onClick = { showVpnConsentHelp = false; launchVpnConsent() }) { Text("Try Again") }
            },
            dismissButton = {
                TextButton(onClick = {
                    showVpnConsentHelp = false
                    try {
                        context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    } catch (e: Exception) {
                        context.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                }) { Text("Open VPN Settings") }
            }
        )
    }

    LaunchedEffect(uiFeedback) {
        val msg = uiFeedback
        if (!msg.isNullOrBlank()) {
            snackbarHostState.showSnackbar(msg)
            viewModel.clearFeedback()
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        bottomBar = {
            if (!showAboutScreen) {
                CyberBottomNav(currentTab = currentTab, onSelect = { currentTab = it })
            }
        }
    ) { innerPadding ->
        Box(Modifier.fillMaxSize().padding(innerPadding)) {
            when (currentTab) {
                MainNavDestination.HOME -> HomeDestination(
                    viewModel = viewModel,
                    onToggleVpn = handleToggleVpn,
                    onPauseResumeVpn = {
                        if (viewModel.vpnState.value.status == VpnStatus.PAUSED) viewModel.resumeVpnService()
                        else viewModel.pauseVpnService()
                    },
                    onOpenOptimizer = { currentTab = MainNavDestination.OPTIMIZER },
                    onOpenLive = { currentTab = MainNavDestination.LIVE },
                    onOpenStatistics = { currentTab = MainNavDestination.STATISTICS },
                    onOpenStatus = { currentTab = MainNavDestination.STATUS }
                )
                MainNavDestination.AD_BLOCKER -> AdBlockerDestination(viewModel)
                MainNavDestination.LIVE -> LiveDestination(viewModel)
                MainNavDestination.SECURITY -> SecurityDestination(viewModel)
                MainNavDestination.OPTIMIZER -> OptimizerDestination(viewModel)
                MainNavDestination.BATTERY -> BatteryDestination(viewModel)
                MainNavDestination.STATISTICS -> StatisticsDestination(viewModel)
                MainNavDestination.SETTINGS -> SettingsDestination(
                    viewModel = viewModel,
                    showAboutScreen = showAboutScreen,
                    onOpenAbout = { showAboutScreen = true },
                    onCloseAbout = { showAboutScreen = false }
                )
                MainNavDestination.STATUS -> StatusDestination(viewModel)
            }
        }
    }
}

@Composable
private fun CyberBottomNav(currentTab: MainNavDestination, onSelect: (MainNavDestination) -> Unit) {
    val screenWidth = LocalConfiguration.current.screenWidthDp
    val visibleTarget = if (screenWidth >= 600) 7 else 5
    val itemWidth = ((screenWidth - 16) / visibleTarget).coerceIn(64, 96).dp
    val listState = rememberLazyListState()
    LaunchedEffect(currentTab, visibleTarget) {
        listState.animateScrollToItem(DashboardPresentation.navScrollTarget(currentTab.ordinal, visibleTarget))
    }
    NavigationBar(containerColor = Color(0xFF040D1A), tonalElevation = 0.dp) {
        LazyRow(
            state = listState,
            modifier = Modifier.fillMaxWidth().height(80.dp),
            horizontalArrangement = Arrangement.spacedBy(0.dp)
        ) {
            itemsIndexed(MainNavDestination.entries, key = { _, destination -> destination.name }) { _, destination ->
                Row(modifier = Modifier.width(itemWidth).fillMaxHeight()) {
                    NavigationBarItem(
                        modifier = Modifier.fillMaxWidth(),
                        selected = currentTab == destination,
                        onClick = { onSelect(destination) },
                        icon = { Icon(destination.icon, contentDescription = destination.label, modifier = Modifier.size(20.dp)) },
                        label = { Text(destination.label, fontSize = 10.sp, maxLines = 1) },
                        alwaysShowLabel = true,
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = SkyBlueGlow,
                            selectedTextColor = SkyBlueGlow,
                            indicatorColor = ElectricBlue.copy(alpha = 0.18f),
                            unselectedIconColor = Color(0xFF7C93AF),
                            unselectedTextColor = Color(0xFF7C93AF)
                        )
                    )
                }
            }
        }
    }
}

@Composable
private fun HomeDestination(
    viewModel: AdShieldViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onPauseResumeVpn: () -> Unit,
    onOpenOptimizer: () -> Unit,
    onOpenLive: () -> Unit,
    onOpenStatistics: () -> Unit,
    onOpenStatus: () -> Unit
) {
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val allTimeTotal by viewModel.allTimeTotalQueries.collectAsStateWithLifecycle()
    val allTimeBlocked by viewModel.allTimeBlockedQueries.collectAsStateWithLifecycle()
    val allTimeAllowed by viewModel.allTimeAllowedQueries.collectAsStateWithLifecycle()
    val malwareBlocks by viewModel.malwareBlocks.collectAsStateWithLifecycle()
    val chartBuckets by viewModel.chartBuckets.collectAsStateWithLifecycle()
    val recentLogs by viewModel.recentLogs.collectAsStateWithLifecycle()
    val liveNetwork by viewModel.liveNetwork.collectAsStateWithLifecycle()
    val isUpdatingFilters by viewModel.isUpdatingFilters.collectAsStateWithLifecycle()
    val smartBoostResult by viewModel.smartBoostResult.collectAsStateWithLifecycle()
    val isRunningSmartBoost by viewModel.isRunningSmartBoost.collectAsStateWithLifecycle()
    val isCheckingForUpdates by viewModel.isCheckingForUpdates.collectAsStateWithLifecycle()
    HomeScreen(
        vpnState = vpnState,
        settings = settings,
        allTimeTotal = allTimeTotal,
        allTimeBlocked = allTimeBlocked,
        allTimeAllowed = allTimeAllowed,
        malwareBlocks = malwareBlocks,
        chartBuckets = chartBuckets,
        recentLogs = recentLogs,
        liveNetwork = liveNetwork,
        isUpdatingFilters = isUpdatingFilters,
        smartBoostResult = smartBoostResult,
        isRunningSmartBoost = isRunningSmartBoost,
        isCheckingForUpdates = isCheckingForUpdates,
        onCheckForUpdates = viewModel::checkForUpdates,
        onToggleVpn = onToggleVpn,
        onPauseResumeVpn = onPauseResumeVpn,
        onSelectProtectionMode = viewModel::setProtectionMode,
        onTriggerFilterSync = viewModel::triggerManualFilterUpdate,
        onRunOptimizeNow = viewModel::runOneTapSmartBoost,
        onOpenOptimizerTab = onOpenOptimizer,
        onOpenLiveTab = onOpenLive,
        onOpenStatisticsTab = onOpenStatistics,
        onOpenStatusTab = onOpenStatus
    )
}

@Composable
private fun AdBlockerDestination(viewModel: AdShieldViewModel) {
    val filterSources by viewModel.filterSources.collectAsStateWithLifecycle()
    val customRules by viewModel.customRules.collectAsStateWithLifecycle()
    val ruleConflicts by viewModel.ruleConflicts.collectAsStateWithLifecycle()
    val sandboxResult by viewModel.sandboxTestResult.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val isUpdatingFilters by viewModel.isUpdatingFilters.collectAsStateWithLifecycle()
    AdBlockerHubScreen(
        sources = filterSources,
        rules = customRules,
        conflicts = ruleConflicts,
        sandboxResult = sandboxResult,
        settings = settings,
        isUpdatingFilters = isUpdatingFilters,
        browserContentBlocker = viewModel.browserContentBlocker,
        onToggleSource = viewModel::toggleFilterSource,
        onSyncAllNow = viewModel::triggerManualFilterUpdate,
        onAddCustomSource = viewModel::addCustomFilterSource,
        onDeleteCustomSource = viewModel::deleteCustomFilterSource,
        onUpdateAutoSyncSchedule = viewModel::updateAutoSyncSchedule,
        onAddRule = viewModel::addCustomRule,
        onUpdateRule = viewModel::updateCustomRule,
        onToggleRule = viewModel::toggleCustomRule,
        onDeleteRule = viewModel::deleteCustomRule,
        onDeduplicateRules = viewModel::deduplicateCustomRules,
        onImportRulesText = viewModel::importRulesText,
        onExportRulesText = viewModel::exportRulesText,
        onTestDomainSandbox = viewModel::testDomainInSandbox,
        onToggleSiteException = viewModel::toggleBrowserSiteException,
        onUpdateBrowserPrivacy = viewModel::updateBrowserPrivacySettings,
        onAddCustomCosmeticSelector = viewModel::addCustomCosmeticSelector,
        onShowFeedback = viewModel::showFeedback
    )
}

@Composable
private fun LiveDestination(viewModel: AdShieldViewModel) {
    val liveNetwork by viewModel.liveNetwork.collectAsStateWithLifecycle()
    LiveNetworkScreen(snapshot = liveNetwork)
}

@Composable
private fun SecurityDestination(viewModel: AdShieldViewModel) {
    val securityPosture by viewModel.securityPosture.collectAsStateWithLifecycle()
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val malwareBlocks by viewModel.malwareBlocks.collectAsStateWithLifecycle()
    val appAudits by viewModel.appAudits.collectAsStateWithLifecycle()
    val isAuditingApps by viewModel.isAuditingApps.collectAsStateWithLifecycle()
    val urlScanResult by viewModel.urlScanResult.collectAsStateWithLifecycle()
    val fileScanResult by viewModel.fileScanResult.collectAsStateWithLifecycle()
    val isScanningSecurity by viewModel.isScanningSecurity.collectAsStateWithLifecycle()
    val securityHistory by viewModel.securityHistory.collectAsStateWithLifecycle()
    SecurityScreen(
        posture = securityPosture,
        vpnState = vpnState,
        malwareBlocks = malwareBlocks,
        appAudits = appAudits,
        isAuditingApps = isAuditingApps,
        urlScanResult = urlScanResult,
        fileScanResult = fileScanResult,
        isScanning = isScanningSecurity,
        scanHistory = securityHistory,
        onScanUrl = viewModel::scanUrl,
        onScanUri = viewModel::scanUri,
        onAuditApps = viewModel::auditInstalledApps
    )
}

@Composable
private fun OptimizerDestination(viewModel: AdShieldViewModel) {
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val ramSnapshot by viewModel.ramSnapshot.collectAsStateWithLifecycle()
    val ramUsageTrend by viewModel.ramUsageTrend.collectAsStateWithLifecycle()
    val storageMetrics by viewModel.storageMetrics.collectAsStateWithLifecycle()
    val batterySnapshot by viewModel.batterySnapshot.collectAsStateWithLifecycle()
    val temperatureTrend by viewModel.temperatureTrend.collectAsStateWithLifecycle()
    val healthAssessment by viewModel.healthAssessment.collectAsStateWithLifecycle()
    val smartBoostResult by viewModel.smartBoostResult.collectAsStateWithLifecycle()
    val isRunningSmartBoost by viewModel.isRunningSmartBoost.collectAsStateWithLifecycle()
    val junkScanReport by viewModel.junkScanReport.collectAsStateWithLifecycle()
    val isScanningJunk by viewModel.isScanningJunk.collectAsStateWithLifecycle()
    val ramOptimizationResult by viewModel.ramOptimizationResult.collectAsStateWithLifecycle()
    val installedGames by viewModel.installedGames.collectAsStateWithLifecycle()
    val isDndPolicyGranted by viewModel.isDndPolicyGranted.collectAsStateWithLifecycle()
    OptimizerScreen(
        settings = settings,
        ramSnapshot = ramSnapshot,
        ramUsageTrend = ramUsageTrend,
        storageMetrics = storageMetrics,
        batterySnapshot = batterySnapshot,
        temperatureTrend = temperatureTrend,
        healthAssessment = healthAssessment,
        smartBoostResult = smartBoostResult,
        isRunningSmartBoost = isRunningSmartBoost,
        junkScanReport = junkScanReport,
        isScanningJunk = isScanningJunk,
        ramOptimizationResult = ramOptimizationResult,
        installedGames = installedGames,
        isDndPolicyGranted = isDndPolicyGranted,
        onRunSmartBoost = viewModel::runOneTapSmartBoost,
        onScanJunk = viewModel::scanJunk,
        onToggleJunkCandidate = viewModel::toggleJunkCandidateSelection,
        onCleanSelectedJunk = viewModel::cleanSelectedJunk,
        onAddExcludedJunkPath = viewModel::addExcludedJunkPath,
        onRemoveExcludedJunkPath = viewModel::removeExcludedJunkPath,
        onUpdateSmartAutoSchedule = viewModel::updateSmartAutoOptimizeSchedule,
        onRunSmartRamOptimize = viewModel::runSmartRamOptimize,
        onToggleFavoriteGame = viewModel::toggleFavoriteGame,
        onUpdateGamingSettings = viewModel::updateGamingBoosterSettings,
        onTriggerGameBoost = viewModel::triggerGameBoost,
        onSelectBatteryMode = viewModel::selectAndApplyBatteryMode
    )
}

@Composable
private fun BatteryDestination(viewModel: AdShieldViewModel) {
    val batteryTelemetry by viewModel.batteryTelemetry.collectAsStateWithLifecycle()
    val batteryHistory by viewModel.batteryHistory.collectAsStateWithLifecycle()
    val batterySessions by viewModel.batterySessions.collectAsStateWithLifecycle()
    val batteryDiagnostics by viewModel.batteryDiagnostics.collectAsStateWithLifecycle()
    val batteryLastDiagnosticAtMs by viewModel.batteryLastDiagnosticAtMs.collectAsStateWithLifecycle()
    val isDiagnosingBattery by viewModel.isDiagnosingBattery.collectAsStateWithLifecycle()
    val batteryHealthScore by viewModel.batteryHealthScore.collectAsStateWithLifecycle()
    val batteryMinutesToFull by viewModel.batteryMinutesToFull.collectAsStateWithLifecycle()
    val batteryMinutesToEmpty by viewModel.batteryMinutesToEmpty.collectAsStateWithLifecycle()
    val batteryChargeRate by viewModel.batteryChargeRate.collectAsStateWithLifecycle()
    BatteryScreen(
        telemetry = batteryTelemetry,
        diagnostics = batteryDiagnostics,
        sessions = batterySessions,
        history = batteryHistory,
        healthScore = batteryHealthScore,
        chargeRatePercentPerHour = batteryChargeRate,
        minutesToFull = batteryMinutesToFull,
        minutesToEmpty = batteryMinutesToEmpty,
        isDiagnosing = isDiagnosingBattery,
        lastDiagnosticAtMs = batteryLastDiagnosticAtMs,
        onDetect = viewModel::runBatteryDiagnosis,
        onRefresh = viewModel::refreshBatteryReadings,
        onClearSessions = viewModel::clearBatterySessions
    )
}

@Composable
private fun StatisticsDestination(viewModel: AdShieldViewModel) {
    val recentLogs by viewModel.recentLogs.collectAsStateWithLifecycle()
    val liveTopApps by viewModel.liveTopApps.collectAsStateWithLifecycle()
    val topBlockedDomains by viewModel.topBlockedDomains.collectAsStateWithLifecycle()
    val sourceEffectiveness by viewModel.sourceEffectiveness.collectAsStateWithLifecycle()
    val chartBuckets by viewModel.chartBuckets.collectAsStateWithLifecycle()
    val selectedChartRange by viewModel.selectedChartRange.collectAsStateWithLifecycle()
    val allTimeTotal by viewModel.allTimeTotalQueries.collectAsStateWithLifecycle()
    val allTimeBlocked by viewModel.allTimeBlockedQueries.collectAsStateWithLifecycle()
    val allTimeAllowed by viewModel.allTimeAllowedQueries.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    ActivityScreen(
        logs = recentLogs,
        liveTopApps = liveTopApps,
        topBlockedDomains = topBlockedDomains,
        sourceEffectiveness = sourceEffectiveness,
        chartBuckets = chartBuckets,
        selectedRange = selectedChartRange,
        allTimeTotal = allTimeTotal,
        allTimeBlocked = allTimeBlocked,
        allTimeAllowed = allTimeAllowed,
        settings = settings,
        onSelectRange = viewModel::selectChartRange,
        onToggleDetailedLogging = viewModel::setDetailedLogging,
        onChangeRetentionDays = viewModel::setLogRetentionDays,
        onClearHistory = viewModel::clearAllHistory,
        onQuickRuleFromLog = { domain, ruleType ->
            viewModel.addCustomRule(
                rawPattern = domain,
                ruleType = ruleType,
                matchType = RuleMatchType.SUBDOMAIN,
                comment = "Added from Activity Log"
            )
        }
    )
}

@Composable
private fun SettingsDestination(
    viewModel: AdShieldViewModel,
    showAboutScreen: Boolean,
    onOpenAbout: () -> Unit,
    onCloseAbout: () -> Unit
) {
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()
    SettingsScreen(
        showAboutScreen = showAboutScreen,
        onOpenAbout = onOpenAbout,
        onCloseAbout = onCloseAbout,
        settings = settings,
        installedApps = installedApps,
        onUpdateResolverConfig = viewModel::updateDnsResolverConfig,
        onLoadInstalledApps = viewModel::loadInstalledApps,
        onToggleAppExclusion = viewModel::toggleAppExclusion,
        onToggleAutoStartBoot = viewModel::setAutoStartOnBoot,
        onChangeThemePreference = viewModel::setDarkThemePreference,
        onExportBackupJson = viewModel::exportFullBackupJson,
        onRestoreBackupJson = viewModel::restoreFullBackupJson
    )
}

@Composable
private fun StatusDestination(viewModel: AdShieldViewModel) {
    val configuration = LocalConfiguration.current
    val batteryTelemetry by viewModel.batteryTelemetry.collectAsStateWithLifecycle()
    val deviceProfile = remember(configuration.screenWidthDp, configuration.smallestScreenWidthDp, batteryTelemetry) {
        viewModel.deviceProfile(configuration.screenWidthDp, configuration.smallestScreenWidthDp)
    }
    CapabilitiesScreen(deviceProfile = deviceProfile)
}
