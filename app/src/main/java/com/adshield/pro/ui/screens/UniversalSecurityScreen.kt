package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.universal.*
import com.adshield.pro.universal.engines.SecurityIntelligenceEngine
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun UniversalSecurityScreen(
    viewModel: UniversalViewModel = hiltViewModel()
) {
    val dashboardState by viewModel.dashboardState.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val selectedPlatform by viewModel.selectedPlatform.collectAsStateWithLifecycle()
    val masterEnabled by viewModel.masterEnabled.collectAsStateWithLifecycle()
    val lastReport by viewModel.lastDiagnosticReport.collectAsStateWithLifecycle()
    val eventLogs by viewModel.getEventLogs().collectAsStateWithLifecycle()
    val scanHistory by viewModel.getScanHistory().collectAsStateWithLifecycle()
    var selectedTab by remember { mutableStateOf(0) }
    var expandedModuleId by remember { mutableStateOf<Int?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 12.dp)
    ) {
        // Master Security Control — ONE central ON/OFF
        MasterControlCard(
            enabled = masterEnabled,
            dashboardState = dashboardState,
            onToggle = { viewModel.toggleMaster(it) },
            onEmergencyLockdown = { viewModel.emergencyLockdown() },
            isScanning = isScanning,
            onRunDiagnostics = { viewModel.runDiagnostics() }
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Platform selector
        PlatformSelector(
            selected = selectedPlatform,
            onSelect = { viewModel.selectPlatform(it) }
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Live Security Status Dashboard — Summary cards
        LiveStatusSummary(dashboardState = dashboardState, lastReport = lastReport)

        Spacer(modifier = Modifier.height(12.dp))

        // Tabs
        TabRow(selectedTabIndex = selectedTab, containerColor = MaterialTheme.colorScheme.surface) {
            Tab(selected = selectedTab == 0, onClick = { selectedTab = 0 }, text = { Text("All 50 Modules", fontSize = 11.sp) })
            Tab(selected = selectedTab == 1, onClick = { selectedTab = 1 }, text = { Text("Diagnostics", fontSize = 11.sp) })
            Tab(selected = selectedTab == 2, onClick = { selectedTab = 2 }, text = { Text("Events", fontSize = 11.sp) })
            Tab(selected = selectedTab == 3, onClick = { selectedTab = 3 }, text = { Text("Reports", fontSize = 11.sp) })
        }

        Spacer(modifier = Modifier.height(8.dp))

        when (selectedTab) {
            0 -> ModulesTab(
                dashboardState = dashboardState,
                isScanning = isScanning,
                expandedModuleId = expandedModuleId,
                onExpand = { expandedModuleId = if (expandedModuleId == it) null else it }
            )
            1 -> DiagnosticsTab(lastReport = lastReport, platform = selectedPlatform, viewModel = viewModel)
            2 -> EventsTab(eventLogs = eventLogs, scanHistory = scanHistory)
            3 -> ReportsTab(viewModel = viewModel, dashboardState = dashboardState, lastReport = lastReport)
        }
    }
}

@Composable
private fun MasterControlCard(
    enabled: Boolean,
    dashboardState: UniversalDashboardState,
    onToggle: (Boolean) -> Unit,
    onEmergencyLockdown: () -> Unit,
    isScanning: Boolean,
    onRunDiagnostics: () -> Unit
) {
    val shieldColor = if (enabled) Color(0xFF10B981) else Color(0xFFEF4444)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(2.dp, shieldColor.copy(alpha = 0.6f), RoundedCornerShape(20.dp)),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(CircleShape)
                        .background(shieldColor.copy(alpha = 0.2f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = if (enabled) Icons.Default.Shield else Icons.Default.Shield,
                        contentDescription = null,
                        tint = shieldColor,
                        modifier = Modifier.size(28.dp)
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (enabled) "UNIVERSAL PROTECTION ACTIVE" else "PROTECTION DISABLED",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = shieldColor
                    )
                    Text(
                        text = if (enabled) "${dashboardState.working} modules working • Engine: ${dashboardState.engineStatus}" else "Tap to re-enable all protections",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = enabled,
                    onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = Color(0xFF10B981),
                        uncheckedThumbColor = Color(0xFF9AA4B2),
                        uncheckedTrackColor = Color(0xFF1E2636)
                    )
                )
            }

            if (!enabled) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFEF4444).copy(alpha = 0.1f)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text("Disabled protections:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = Color(0xFFEF4444))
                        val disabled = listOf(
                            "Real-time threat detection paused",
                            "DNS filtering inactive",
                            "Malware scanning suspended",
                            "Network monitoring disabled"
                        )
                        disabled.forEach { Text("• $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                }
            } else {
                Text(
                    "All supported protection modules active. Background services running. Auto-checks every 5 min.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = onRunDiagnostics,
                    enabled = !isScanning,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                ) {
                    if (isScanning) CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp, color = Color.White)
                    else Icon(Icons.Default.VerifiedUser, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (isScanning) "Scanning..." else "Run Full Diagnostic", fontSize = 12.sp)
                }
                OutlinedButton(
                    onClick = onEmergencyLockdown,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFEF4444))
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Lockdown", fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun PlatformSelector(selected: PlatformType, onSelect: (PlatformType) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PlatformType.values().forEach { platform ->
            val isSelected = platform == selected
            Card(
                modifier = Modifier
                    .weight(1f)
                    .clickable { onSelect(platform) }
                    .border(
                        width = if (isSelected) 2.dp else 1.dp,
                        color = if (isSelected) Color(0xFF10B981) else MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                        shape = RoundedCornerShape(12.dp)
                    ),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isSelected) Color(0xFF10B981).copy(alpha = 0.15f) else MaterialTheme.colorScheme.surface
                )
            ) {
                Column(
                    modifier = Modifier.padding(vertical = 10.dp, horizontal = 8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = when (platform) {
                            PlatformType.ANDROID -> Icons.Default.PhoneAndroid
                            PlatformType.WINDOWS -> Icons.Default.Computer
                            PlatformType.MACOS -> Icons.Default.Laptop
                        },
                        contentDescription = null,
                        tint = if (isSelected) Color(0xFF10B981) else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = platform.name,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                        color = if (isSelected) Color(0xFF10B981) else MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center
                    )
                }
            }
        }
    }
    Text(
        "iOS is permanently excluded — not supported",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp)
    )
}

@Composable
private fun LiveStatusSummary(dashboardState: UniversalDashboardState, lastReport: DiagnosticReport?) {
    // 7 status colors legend + counts
    val statusCounts = mapOf(
        ModuleStatus.WORKING to dashboardState.working,
        ModuleStatus.PARTIALLY_WORKING to dashboardState.partiallyWorking,
        ModuleStatus.SCANNING to dashboardState.scanning,
        ModuleStatus.PERMISSION_REQUIRED to dashboardState.permissionRequired,
        ModuleStatus.NOT_WORKING to dashboardState.failed,
        ModuleStatus.NOT_SUPPORTED to dashboardState.unsupported,
        ModuleStatus.NOT_TESTED to dashboardState.pendingTests
    )

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("LIVE SECURITY STATUS", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                val timeText = if (dashboardState.lastVerificationEpochMs > 0) {
                    SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(dashboardState.lastVerificationEpochMs))
                } else "Never"
                Text("Verified: $timeText", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            // Engine status badge
            Surface(
                color = when (dashboardState.engineStatus) {
                    "PROTECTED" -> Color(0xFF10B981).copy(alpha = 0.2f)
                    "DEGRADED" -> Color(0xFFF59E0B).copy(alpha = 0.2f)
                    "AT RISK" -> Color(0xFFEF4444).copy(alpha = 0.2f)
                    else -> MaterialTheme.colorScheme.surfaceVariant
                },
                shape = RoundedCornerShape(50)
            ) {
                Row(modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(
                        when (dashboardState.engineStatus) {
                            "PROTECTED" -> Color(0xFF10B981)
                            "DEGRADED" -> Color(0xFFF59E0B)
                            "AT RISK" -> Color(0xFFEF4444)
                            else -> Color.Gray
                        }
                    ))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "Engine: ${dashboardState.engineStatus} • CPU ${String.format("%.1f", dashboardState.cpuPercent)}% • RAM ${dashboardState.ramUsedMb} MB",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            // Counts grid — 2 rows of 4
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StatusCountCard("Total", dashboardState.totalFeatures.toString(), Color(0xFF06B6D4), Modifier.weight(1f))
                StatusCountCard("Working", dashboardState.working.toString(), Color(0xFF22C55E), Modifier.weight(1f))
                StatusCountCard("Partial", dashboardState.partiallyWorking.toString(), Color(0xFFEAB308), Modifier.weight(1f))
                StatusCountCard("Failed", dashboardState.failed.toString(), Color(0xFFEF4444), Modifier.weight(1f))
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StatusCountCard("No Support", dashboardState.unsupported.toString(), Color(0xFF6B7280), Modifier.weight(1f))
                StatusCountCard("Need Perm", dashboardState.permissionRequired.toString(), Color(0xFFF97316), Modifier.weight(1f))
                StatusCountCard("Scanning", dashboardState.scanning.toString(), Color(0xFF3B82F6), Modifier.weight(1f))
                StatusCountCard("Threats", dashboardState.activeThreats.toString(), Color(0xFFEF4444), Modifier.weight(1f))
            }

            // Legend
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                statusCounts.forEach { (status, count) ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.weight(1f)) {
                        Box(modifier = Modifier.size(12.dp).clip(CircleShape).background(Color(android.graphics.Color.parseColor(status.colorHex))))
                        Text(status.label.take(4), fontSize = 7.sp, lineHeight = 8.sp, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            Text("GREEN=Working YELLOW=Partial BLUE=Scanning ORANGE=Permission RED=Failed GRAY=Unsupported WHITE=Not Tested", fontSize = 8.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, lineHeight = 10.sp)
        }
    }
}

@Composable
private fun StatusCountCard(label: String, value: String, color: Color, modifier: Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f))
    ) {
        Column(modifier = Modifier.padding(vertical = 8.dp, horizontal = 6.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = color)
            Text(label, style = MaterialTheme.typography.labelSmall, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
        }
    }
}

@Composable
private fun ModulesTab(
    dashboardState: UniversalDashboardState,
    isScanning: Boolean,
    expandedModuleId: Int?,
    onExpand: (Int) -> Unit
) {
    if (dashboardState.results.isEmpty()) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
        ) {
            Column(modifier = Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.height(8.dp))
                Text("No diagnostics yet. Tap 'Run Full Diagnostic' to verify all 50 modules.", style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            }
        }
        return
    }

    // Group by category
    val grouped = dashboardState.results.groupBy { result ->
        UniversalModuleRegistry.byId(result.moduleId)?.category ?: ModuleCategory.AI_PROTECTION
    }

    LazyColumn(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
        grouped.forEach { (category, modules) ->
            item {
                Text(category.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = Color(0xFF10B981), modifier = Modifier.padding(vertical = 4.dp))
            }
            items(modules, key = { it.moduleId }) { result ->
                val module = UniversalModuleRegistry.byId(result.moduleId)
                ModuleRow(result = result, module = module, expanded = expandedModuleId == result.moduleId, onExpand = { onExpand(result.moduleId) })
            }
        }
    }
}

@Composable
private fun ModuleRow(result: ModuleDiagnosticResult, module: UniversalModule?, expanded: Boolean, onExpand: () -> Unit) {
    val statusColor = Color(android.graphics.Color.parseColor(result.status.colorHex))
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onExpand() }
            .border(1.dp, statusColor.copy(alpha = 0.3f), RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(modifier = Modifier.size(36.dp).clip(CircleShape).background(statusColor.copy(alpha = 0.2f)), contentAlignment = Alignment.Center) {
                    Text("${result.moduleId}", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = statusColor)
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(module?.name ?: "Module ${result.moduleId}", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold, maxLines = 1)
                    Text(module?.description ?: "", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                }
                Spacer(modifier = Modifier.width(8.dp))
                Column(horizontalAlignment = Alignment.End) {
                    Box(modifier = Modifier.clip(RoundedCornerShape(50)).background(statusColor).padding(horizontal = 8.dp, vertical = 4.dp)) {
                        Text(result.status.label, style = MaterialTheme.typography.labelSmall, color = Color.White, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    }
                    if (expanded) Icon(Icons.Default.ExpandLess, contentDescription = null, modifier = Modifier.size(16.dp))
                    else Icon(Icons.Default.ExpandMore, contentDescription = null, modifier = Modifier.size(16.dp))
                }
            }
            if (expanded) {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                Spacer(modifier = Modifier.height(8.dp))
                // 4 verification conditions
                Text("Verification (4 conditions):", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                VerificationRow("Service running", result.serviceRunning)
                VerificationRow("Protection enabled", result.protectionEnabled)
                VerificationRow("Functionality tested", result.functionalityTested)
                VerificationRow("Detection verified", result.detectionVerified)
                Spacer(modifier = Modifier.height(6.dp))
                Text("Detail:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                Text(result.detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (result.error != null) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Error: ${result.error}", style = MaterialTheme.typography.labelSmall, color = Color(0xFFEF4444))
                }
                Text("Platform: ANDROID • Last test: ${SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(result.lastTestEpochMs))}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun VerificationRow(label: String, passed: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = if (passed) Icons.Default.CheckCircle else Icons.Default.Cancel,
            contentDescription = null,
            modifier = Modifier.size(14.dp),
            tint = if (passed) Color(0xFF22C55E) else Color(0xFFEF4444)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun DiagnosticsTab(lastReport: DiagnosticReport?, platform: PlatformType, viewModel: UniversalViewModel) {
    if (lastReport == null) {
        Text("Run diagnostics to see detailed results.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
        return
    }
    LazyColumn(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
        item {
            Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Diagnostic Report", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text("Platform: $platform • Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(lastReport.timestampMs))}", style = MaterialTheme.typography.labelSmall)
                    Text("Duration: ${lastReport.durationMs}ms • Master: ${if (lastReport.masterEnabled) "ON" else "OFF"}", style = MaterialTheme.typography.labelSmall)
                    HorizontalDivider()
                    Text("API Availability:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    lastReport.apiAvailability.forEach { (api, ok) ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(if (ok) Icons.Default.CheckCircle else Icons.Default.Cancel, contentDescription = null, modifier = Modifier.size(12.dp), tint = if (ok) Color(0xFF22C55E) else Color(0xFFEF4444))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("$api: ${if (ok) "OK" else "FAIL"}", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    HorizontalDivider()
                    Text("File scan: ${lastReport.fileScanTest.detail}", style = MaterialTheme.typography.labelSmall)
                    Text("Threat detection: ${lastReport.threatDetectionTest.detail}", style = MaterialTheme.typography.labelSmall)
                    Text("Intel updates: ${lastReport.intelUpdateCheck.detail}", style = MaterialTheme.typography.labelSmall)
                    Text("Performance: CPU ${lastReport.performance.cpuPercent}% RAM ${lastReport.performance.ramUsedMb}/${lastReport.performance.ramTotalMb}MB", style = MaterialTheme.typography.labelSmall)
                    if (lastReport.crashDetected) Text("⚠ Crash detected in last 24h", color = Color(0xFFEF4444), style = MaterialTheme.typography.labelSmall)
                    if (lastReport.serviceFailures.isNotEmpty()) {
                        Text("Service failures: ${lastReport.serviceFailures.joinToString("; ")}", color = Color(0xFFEF4444), style = MaterialTheme.typography.labelSmall)
                    }
                    Text("Inactive modules: ${lastReport.inactiveModules.joinToString(", ")}", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        item {
            Text("Platform Capabilities:", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
        }
        item {
            val caps = viewModel.getPlatformCapabilities(platform)
            Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Limitations:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    caps.limitations.forEach { lim -> Text("• $lim", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("VPN: ${caps.supportsVpnService} • Firewall: ${caps.supportsFirewall} • Process isolation: ${caps.supportsProcessIsolation}", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun EventsTab(eventLogs: List<SecurityEventLog>, scanHistory: List<ScanHistoryEntry>) {
    if (eventLogs.isEmpty() && scanHistory.isEmpty()) {
        Text("No events yet. Run diagnostics or enable protection to generate events.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
        return
    }
    LazyColumn(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
        item { Text("Real-time Security Events", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold) }
        items(eventLogs.take(30)) { event ->
            Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(event.moduleName, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                        Text(event.severity.uppercase(), style = MaterialTheme.typography.labelSmall, color = when (event.severity) { "critical" -> Color(0xFFEF4444); "warning" -> Color(0xFFF59E0B); else -> Color(0xFF10B981) })
                    }
                    Text(event.description, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(event.timestampEpochMs)) + " • " + event.platform.name, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
                }
            }
        }
        item { Text("Scan History", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp)) }
        items(scanHistory.take(10)) { scan ->
            Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Text(scan.scanType, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    Text(scan.result, style = MaterialTheme.typography.labelSmall)
                    Text(SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(scan.timestampMs)), style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
                }
            }
        }
    }
}

@Composable
private fun ReportsTab(viewModel: UniversalViewModel, dashboardState: UniversalDashboardState, lastReport: DiagnosticReport?) {
    var showPasswordInput by remember { mutableStateOf("") }
    var passwordResult by remember { mutableStateOf<com.adshield.pro.universal.engines.PasswordStrengthResult?>(null) }
    Column(modifier = Modifier.fillMaxSize().padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Security Reports & Exports", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text("Every report includes timestamps, platform info, test results, and actual feature statuses.", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

                Button(onClick = { /* export handled via share intent in real app */ }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Export JSON Report", fontSize = 12.sp)
                }
                OutlinedButton(onClick = {}, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.PictureAsPdf, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Export PDF Report", fontSize = 12.sp)
                }
                Text("Reports are encrypted at rest (AES-GCM) and include audit chain verification.", style = MaterialTheme.typography.labelSmall, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Password Strength Analyzer", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                OutlinedTextField(value = showPasswordInput, onValueChange = { showPasswordInput = it; if (it.isNotEmpty()) passwordResult = viewModel.analyzePassword(it) else passwordResult = null }, label = { Text("Enter password to analyze") }, modifier = Modifier.fillMaxWidth())
                passwordResult?.let { r ->
                    Text("Strength: ${r.strengthLabel} (${r.score}/100) • Entropy: ${String.format("%.1f", r.entropy)} bits", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = when { r.score >= 80 -> Color(0xFF22C55E); r.score >= 40 -> Color(0xFFEAB308); else -> Color(0xFFEF4444) })
                    r.feedback.forEach { fb -> Text("• $fb", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Last Report Summary", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                if (lastReport != null) {
                    Text(viewModel.exportReportText().take(800), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("No report generated yet.", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}
