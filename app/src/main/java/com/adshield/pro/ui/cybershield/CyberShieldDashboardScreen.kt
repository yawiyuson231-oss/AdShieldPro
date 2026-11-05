package com.adshield.pro.ui.cybershield

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.cybershield.CyberShieldViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * CyberShield AI — the security-operations dashboard.
 *
 * Every panel is bound to a real data source (Room DNS history, VPN runtime,
 * public Android APIs, AETHER local engine, attributed external feeds). The
 * layout adapts: single column on phones, two columns on wide/landscape screens.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberShieldDashboardScreen(
    onToggleProtection: (Boolean) -> Unit,
    onPauseResume: () -> Unit,
    onOpenClassicHome: () -> Unit,
    onOpenStatistics: () -> Unit,
    onShowFeedback: (String) -> Unit,
    vm: CyberShieldViewModel = hiltViewModel()
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val shield by vm.shieldState.collectAsStateWithLifecycle()
    val vpnState by vm.vpnState.collectAsStateWithLifecycle()
    val stats by vm.threatStats.collectAsStateWithLifecycle()
    val hourly by vm.hourlyBuckets.collectAsStateWithLifecycle()
    val daily by vm.dailyTrend.collectAsStateWithLifecycle()
    val events by vm.threatEvents.collectAsStateWithLifecycle()
    val incidents by vm.incidents.collectAsStateWithLifecycle()
    val filteredIncidents by vm.filteredIncidents.collectAsStateWithLifecycle()
    val query by vm.threatQuery.collectAsStateWithLifecycle()
    val severityFilter by vm.severityFilter.collectAsStateWithLifecycle()
    val anomalies by vm.anomalies.collectAsStateWithLifecycle()
    val verdicts by vm.aiVerdicts.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val device by vm.deviceSnapshot.collectAsStateWithLifecycle()
    val deviceScanning by vm.isDeviceScanning.collectAsStateWithLifecycle()
    val compliance by vm.complianceReport.collectAsStateWithLifecycle()
    val intel by vm.intelState.collectAsStateWithLifecycle()
    val cloud by vm.cloudStatuses.collectAsStateWithLifecycle()
    val cloudRefreshing by vm.cloudRefreshing.collectAsStateWithLifecycle()
    val network by vm.networkSummary.collectAsStateWithLifecycle()
    val vectors by vm.attackVectors.collectAsStateWithLifecycle()
    val topBlocked by vm.topBlockedDomains.collectAsStateWithLifecycle()
    val demoOverlay by vm.demoMapOverlay.collectAsStateWithLifecycle()
    val nowMs by vm.now.collectAsStateWithLifecycle()
    val feedback by vm.feedback.collectAsStateWithLifecycle()

    var showSettings by rememberSaveable { mutableStateOf(false) }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        val content = pendingExport
        pendingExport = null
        if (uri != null && content != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) {
                    runCatching {
                        context.contentResolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
                    }.isSuccess
                }
                onShowFeedback(if (ok) "Compliance report exported." else "Export failed — could not write the file.")
            }
        }
    }

    DisposableEffect(Unit) {
        vm.onDashboardVisible()
        onDispose { vm.onDashboardHidden() }
    }

    LaunchedEffect(feedback) {
        feedback?.let {
            onShowFeedback(it)
            vm.clearFeedback()
        }
    }

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Cs.BackgroundDeep, Cs.Background)))
    ) {
        val wide = maxWidth >= 700.dp
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ---- Header -----------------------------------------------------
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "CYBERSHIELD AI",
                        style = TextStyle(
                            brush = Brush.horizontalGradient(listOf(Cs.Cyan, Cs.NeonBlue)),
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 3.sp,
                            fontFamily = Cs.mono
                        )
                    )
                    Text(
                        "AdShield Pro · on-device security operations",
                        color = Cs.TextDim, fontSize = 10.sp, letterSpacing = 0.6.sp
                    )
                }
                IconButton(onClick = onOpenClassicHome) {
                    Icon(Icons.Default.Home, "Classic home", tint = Cs.TextDim, modifier = Modifier.size(20.dp))
                }
                IconButton(onClick = vm::refreshAll) {
                    Icon(Icons.Default.Refresh, "Refresh all", tint = Cs.Cyan, modifier = Modifier.size(20.dp))
                }
                IconButton(onClick = { showSettings = true }) {
                    Icon(Icons.Default.Tune, "Dashboard settings", tint = Cs.TextDim, modifier = Modifier.size(20.dp))
                }
            }

            if (demoOverlay) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(Cs.Amber.copy(alpha = 0.14f))
                        .padding(horizontal = 10.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "DEMO OVERLAY ACTIVE — the map may show clearly-badged sample markers. Real counters are never affected.",
                        color = Cs.Amber, fontSize = 10.sp, lineHeight = 14.sp
                    )
                }
            }

            // ---- Hero + stats -----------------------------------------------
            ShieldHero(
                shield = shield,
                vpnState = vpnState,
                onActivate = { onToggleProtection(true) },
                onStop = { onToggleProtection(false) },
                onPauseResume = onPauseResume
            )
            StatTilesRow(stats = stats, intelCount = intel.snapshot?.indicators?.size)

            // ---- Cards ------------------------------------------------------
            val cards: List<@Composable () -> Unit> = listOf(
                {
                    ThreatOverviewCard(stats = stats, hourly = hourly, daily = daily)
                },
                {
                    ThreatMapCard(
                        intel = intel,
                        demoOverlay = demoOverlay,
                        nowMs = nowMs,
                        onRefresh = vm::refreshIntel,
                        onEnableIntel = { vm.setIntelEnabled(true) }
                    )
                },
                {
                    AiDetectionCard(
                        verdicts = verdicts,
                        anomalies = anomalies,
                        incidentCount = incidents.size,
                        aetherInfo = vm.aetherInfo,
                        aetherEnabled = settings.aetherEnabled,
                        onAnalyze = vm::reputationCheck
                    )
                },
                {
                    ActiveThreatsCard(
                        incidents = filteredIncidents,
                        query = query,
                        severityFilter = severityFilter,
                        nowMs = nowMs,
                        onQueryChange = { vm.threatQuery.value = it },
                        onSeverityChange = { vm.severityFilter.value = it },
                        onBlock = vm::blockDomain,
                        onAllow = vm::allowTemporary,
                        onFalsePositive = vm::reportFalsePositive
                    )
                },
                {
                    ActivityFeedCard(
                        events = events,
                        live = shield.mode == com.adshield.pro.cybershield.ShieldMode.ACTIVE,
                        nowMs = nowMs,
                        onOpenStatistics = onOpenStatistics
                    )
                },
                {
                    EndpointCard(snapshot = device, scanning = deviceScanning, onRescan = vm::refreshDevice)
                },
                {
                    NetworkCard(
                        summary = network,
                        nowMs = nowMs,
                        onReputationCheck = vm::reputationCheck,
                        onOpenStatistics = onOpenStatistics
                    )
                },
                {
                    CloudCard(
                        statuses = cloud,
                        refreshing = cloudRefreshing,
                        nowMs = nowMs,
                        onRefresh = vm::refreshCloud,
                        onAddEndpoint = vm::addCloudEndpoint,
                        onRemoveEndpoint = vm::removeCloudEndpoint
                    )
                },
                {
                    AttackVectorsCard(vectors = vectors, topBlocked = topBlocked)
                },
                {
                    ComplianceCard(
                        report = compliance,
                        onRerun = vm::refreshDevice,
                        onExport = {
                            val json = vm.exportComplianceJson()
                            if (json == null) {
                                onShowFeedback("Run a device scan first.")
                            } else {
                                pendingExport = json
                                exportLauncher.launch("cybershield-compliance-report.json")
                            }
                        }
                    )
                }
            )

            if (wide) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        cards.forEachIndexed { i, card -> if (i % 2 == 0) card() }
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        cards.forEachIndexed { i, card -> if (i % 2 == 1) card() }
                    }
                }
            } else {
                cards.forEach { it() }
            }

            Text(
                "All detections are computed on this device from real DNS events and public Android APIs. " +
                    "External intelligence is attributed and timestamped. No fabricated counts, no cloud AI, " +
                    "no access to other apps' private data.",
                color = Cs.TextFaint, fontSize = 9.sp, lineHeight = 13.sp,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp)
            )
        }
    }

    if (showSettings) {
        ModalBottomSheet(
            onDismissRequest = { showSettings = false },
            sheetState = sheetState,
            containerColor = Cs.SurfaceAlt
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp).padding(bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text("Dashboard settings", color = Cs.Text, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                SettingToggle(
                    title = "External threat intelligence",
                    subtitle = "Feodo Tracker (abuse.ch) botnet C2 feed · CC0 · refreshed every 6 h in background and on open. Cached for offline use.",
                    checked = intel.enabled,
                    onChange = vm::setIntelEnabled
                )
                SettingToggle(
                    title = "Demo map overlay",
                    subtitle = "Show clearly-badged SAMPLE markers on the map when no real intel is loaded. Never affects real counters. Off by default.",
                    checked = demoOverlay,
                    onChange = vm::setDemoMapOverlay
                )
                Text(
                    "Data sources: on-device DNS events (Room) · AETHER local engine · Android public APIs · " +
                        "Feodo Tracker intel · Statuspage v2 cloud status. World geometry: Natural Earth (public domain).",
                    color = Cs.TextFaint, fontSize = 10.sp, lineHeight = 14.sp
                )
            }
        }
    }
}

@Composable
private fun SettingToggle(
    title: String,
    subtitle: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f)) {
            Text(title, color = Cs.Text, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp)
        }
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Cs.BackgroundDeep,
                checkedTrackColor = Cs.Cyan,
                uncheckedThumbColor = Cs.TextDim,
                uncheckedTrackColor = Cs.Surface
            )
        )
    }
}
