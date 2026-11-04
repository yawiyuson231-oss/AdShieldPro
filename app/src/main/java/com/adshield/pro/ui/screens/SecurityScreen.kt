package com.adshield.pro.ui.screens

import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccessTime
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.engine.aether.ControlCenterReport
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityLocalStore
import com.adshield.pro.engine.security.SecurityPosture
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import java.text.DateFormat
import java.util.Date

/**
 * OmniShield X Infinity — Security Center (Anti-Virus & Anti-Phishing).
 *
 * Sub-tabs: Protection posture, App audit, File scanner, Link/URL scanner, Scan history.
 */
@Composable
fun SecurityScreen(
    posture: SecurityPosture,
    vpnState: VpnRuntimeState,
    malwareBlocks: Long,
    appAudits: List<AppRiskAuditor.AppRiskAudit>,
    isAuditingApps: Boolean,
    urlScanResult: UrlThreatScanner.UrlVerdict?,
    fileScanResult: SecurityScanRecord?,
    isScanning: Boolean,
    scanHistory: List<SecurityScanRecord>,
    onScanUrl: (String) -> Unit,
    onScanUri: (android.net.Uri, String) -> Unit,
    onAuditApps: () -> Unit,
    settings: AppSettingsState,
    aetherReport: ControlCenterReport,
    onToggleAutonomousResponse: (Boolean) -> Unit,
    onToggleEmergencyProtection: (Boolean) -> Unit,
    onToggleManualOverride: (Boolean) -> Unit,
    onOpenBattery: () -> Unit,
    onOpenNetwork: () -> Unit,
    onOpenAdBlocker: () -> Unit,
    onOpenPrivacySettings: () -> Unit,
    isQuarantining: Boolean,
    quarantineItems: List<SecurityLocalStore.QuarantineItem>,
    onQuarantineUri: (android.net.Uri, String) -> Unit,
    onDeleteQuarantined: (SecurityLocalStore.QuarantineItem) -> Unit
) {
    var selectedSubTab by rememberSaveable { mutableIntStateOf(0) }

    Column(modifier = Modifier.fillMaxSize()) {
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 2.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                SecurityTabChip("Shield", Icons.Default.Security, selectedSubTab == 0, Modifier.weight(1f)) { selectedSubTab = 0 }
                SecurityTabChip("Apps", Icons.Default.GppGood, selectedSubTab == 1, Modifier.weight(1f)) { selectedSubTab = 1 }
                SecurityTabChip("Files", Icons.Default.Description, selectedSubTab == 2, Modifier.weight(1f)) { selectedSubTab = 2 }
                SecurityTabChip("Links", Icons.Default.Link, selectedSubTab == 3, Modifier.weight(1f)) { selectedSubTab = 3 }
                SecurityTabChip("History", Icons.Default.AccessTime, selectedSubTab == 4, Modifier.weight(1f)) { selectedSubTab = 4 }
            }
        }

        when (selectedSubTab) {
            0 -> ProtectionPostureTab(
                posture = posture,
                vpnState = vpnState,
                malwareBlocks = malwareBlocks,
                onAuditApps = onAuditApps,
                settings = settings,
                aetherReport = aetherReport,
                onToggleAutonomousResponse = onToggleAutonomousResponse,
                onToggleEmergencyProtection = onToggleEmergencyProtection,
                onToggleManualOverride = onToggleManualOverride,
                onOpenBattery = onOpenBattery,
                onOpenNetwork = onOpenNetwork,
                onOpenAdBlocker = onOpenAdBlocker,
                onOpenPrivacySettings = onOpenPrivacySettings,
                onOpenReports = { selectedSubTab = 4 }
            )
            1 -> AppAuditTab(appAudits, isAuditingApps, onAuditApps)
            2 -> FileScanTab(
                result = fileScanResult,
                isScanning = isScanning,
                onScanUri = onScanUri,
                isQuarantining = isQuarantining,
                quarantineItems = quarantineItems,
                onQuarantineUri = onQuarantineUri,
                onDeleteQuarantined = onDeleteQuarantined
            )
            3 -> LinkScanTab(urlScanResult, isScanning, onScanUrl)
            else -> HistoryTab(scanHistory)
        }
    }
}

@Composable
private fun SecurityTabChip(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean,
    modifier: Modifier,
    onClick: () -> Unit
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, maxLines = 1, fontSize = 12.sp) },
        leadingIcon = {
            Icon(icon, contentDescription = null, modifier = Modifier.size(15.dp))
        },
        modifier = modifier
    )
}

@Composable
private fun ProtectionPostureTab(
    posture: SecurityPosture,
    vpnState: VpnRuntimeState,
    malwareBlocks: Long,
    onAuditApps: () -> Unit,
    settings: AppSettingsState,
    aetherReport: ControlCenterReport,
    onToggleAutonomousResponse: (Boolean) -> Unit,
    onToggleEmergencyProtection: (Boolean) -> Unit,
    onToggleManualOverride: (Boolean) -> Unit,
    onOpenBattery: () -> Unit,
    onOpenNetwork: () -> Unit,
    onOpenAdBlocker: () -> Unit,
    onOpenPrivacySettings: () -> Unit,
    onOpenReports: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { posture.protectionScore / 100f },
                            modifier = Modifier.size(120.dp),
                            strokeWidth = 10.dp,
                            trackColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                            color = when {
                                posture.protectionScore >= 75 -> ElectricBlue
                                posture.protectionScore >= 45 -> com.adshield.pro.ui.theme.WarningAmber
                                else -> com.adshield.pro.ui.theme.AlertRed
                            }
                        )
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                "${posture.protectionScore}",
                                fontSize = 34.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                "SECURITY SCORE",
                                fontSize = 10.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                letterSpacing = 1.5.sp
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        when {
                            posture.protectionScore >= 90 -> "Maximum protection active"
                            posture.protectionScore >= 75 -> "Strong protection — one more step to max"
                            posture.protectionScore >= 45 -> "Protection has gaps — fix the items below"
                            else -> "Device is exposed — enable protection now"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }

        item {
            SecurityStatusRow(
                icon = Icons.Default.Shield,
                title = "Web & DNS Threat Protection",
                detail = if (vpnState.status == VpnStatus.CONNECTED) {
                    "ACTIVE — ${posture.threatSignatures} malware/phishing signatures blocking sites and apps device-wide"
                } else {
                    "OFFLINE — enable Home protection to block malicious domains in every app"
                },
                isGood = vpnState.status == VpnStatus.CONNECTED
            )
        }
        item {
            SecurityStatusRow(
                icon = Icons.Default.Block,
                title = "Threats Blocked (all time)",
                detail = "$malwareBlocks malware, phishing and scam requests blocked on this device",
                isGood = malwareBlocks > 0
            )
        }
        item {
            SecurityStatusRow(
                icon = Icons.Default.GppGood,
                title = "Installed App Audit",
                detail = if (posture.highRiskApps > 0) {
                    "${posture.highRiskApps} high-risk app(s) detected — review them in the Apps tab"
                } else {
                    "No high-risk apps detected. Run a fresh audit after installing anything new."
                },
                isGood = posture.highRiskApps == 0
            )
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = onAuditApps,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.GppGood, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scan All Installed Apps")
            }
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("AETHER autonomous security", style = MaterialTheme.typography.titleMedium, color = CyberCyan)
                    Text(
                        "Latest evidence: ${aetherReport.lastThreatClassification} · " +
                            "${(aetherReport.lastConfidenceScore * 100).toInt()}% heuristic confidence · ${aetherReport.lastAction}",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(aetherReport.lastExplanation, style = MaterialTheme.typography.bodySmall)
                    AutomationSwitch(
                        "Autonomous response",
                        "Permits user-approved encrypted failover and measured resolver optimization. Existing DNS blocking always follows your policy.",
                        settings.autonomousResponseEnabled,
                        onToggleAutonomousResponse
                    )
                    AutomationSwitch(
                        "Emergency protection",
                        "Switches to Strict and enables heuristic protections; turning this off restores your previous mode.",
                        settings.emergencyProtectionEnabled,
                        onToggleEmergencyProtection
                    )
                    AutomationSwitch(
                        "Manual override",
                        "Stops new autonomous resolver changes without disabling DNS protection or your existing rules.",
                        settings.manualOverrideEnabled,
                        onToggleManualOverride
                    )
                    Text(
                        "${aetherReport.totalAgents} evidence agents · ${aetherReport.autoRecoveries} verified recovery events · audit retains the newest 100 decisions in memory; DNS history follows your retention setting.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Unified protection modules", style = MaterialTheme.typography.titleMedium)
                    ModuleButton("DNS firewall & protection status", vpnState.status.name, onOpenNetwork)
                    ModuleButton("Global adaptive ad blocker", settings.protectionMode.title, onOpenAdBlocker)
                    ModuleButton("Network intelligence & live event feed", "${aetherReport.dnsObserved} observed", onOpenNetwork)
                    ModuleButton("Battery & device intelligence", "Measured Android sensors", onOpenBattery)
                    ModuleButton("Privacy auditor & encrypted DNS", settings.resolverConfig.protocol.name, onOpenPrivacySettings)
                    ModuleButton("Security reports & scan history", "Local records only", onOpenReports)
                    Text(
                        "Antivirus, malware/APK scanning, application auditing, link phishing checks and AETHER explanations are available in the tabs above.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = ElectricBlue.copy(alpha = 0.08f)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "OmniShield checks DNS destinations against your active threat lists and analyzes user-selected links, files and APKs on-device. " +
                        "Allowed DNS queries go to your chosen upstream provider; optional domain-age checks use RDAP. " +
                        "A DNS match is not a full device antivirus verdict, and unknown evidence is never called malware.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(14.dp)
                )
            }
        }
    }
}

@Composable
private fun AutomationSwitch(
    title: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    HorizontalDivider()
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(8.dp))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun ModuleButton(title: String, status: String, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.weight(1f), horizontalAlignment = Alignment.Start) {
            Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(status, style = MaterialTheme.typography.labelSmall, color = EmeraldPrimary)
        }
    }
}

@Composable
private fun SecurityStatusRow(icon: androidx.compose.ui.graphics.vector.ImageVector, title: String, detail: String, isGood: Boolean) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (isGood) ElectricBlue else com.adshield.pro.ui.theme.WarningAmber,
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun AppAuditTab(
    audits: List<AppRiskAuditor.AppRiskAudit>,
    isAuditing: Boolean,
    onAuditApps: () -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(onClick = onAuditApps, enabled = !isAuditing, modifier = Modifier.weight(1f)) {
                if (isAuditing) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text("Full Device Scan")
            }
        }
        if (audits.isEmpty() && !isAuditing) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(Icons.Default.GppGood, contentDescription = null, tint = SkyBlueGlow, modifier = Modifier.size(56.dp))
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    "Tap Full Device Scan to audit every installed app for trojan behavior, spyware stacks, and dropper capabilities.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        LazyColumn(
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(audits, key = { it.profile.packageName }) { audit ->
                AppAuditCard(audit)
            }
        }
    }
}

@Composable
private fun AppAuditCard(audit: AppRiskAuditor.AppRiskAudit) {
    val (tint, label) = when (audit.riskLevel) {
        AppRiskAuditor.RiskLevel.HIGH -> com.adshield.pro.ui.theme.AlertRed to "HIGH RISK"
        AppRiskAuditor.RiskLevel.MEDIUM -> com.adshield.pro.ui.theme.WarningAmber to "ELEVATED"
        AppRiskAuditor.RiskLevel.LOW -> ElectricBlue to "LOW"
        AppRiskAuditor.RiskLevel.TRUSTED -> Color(0xFF34D399) to "TRUSTED"
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    audit.profile.appName,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Surface(color = tint.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
                    Text(
                        label,
                        color = tint,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }
            Text(
                audit.profile.packageName,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (audit.findings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                audit.findings.take(3).forEach { finding ->
                    Text(
                        "• $finding",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun FileScanTab(
    result: SecurityScanRecord?,
    isScanning: Boolean,
    onScanUri: (android.net.Uri, String) -> Unit,
    isQuarantining: Boolean,
    quarantineItems: List<SecurityLocalStore.QuarantineItem>,
    onQuarantineUri: (android.net.Uri, String) -> Unit,
    onDeleteQuarantined: (SecurityLocalStore.QuarantineItem) -> Unit
) {
    val context = LocalContext.current
    var selectedUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var selectedName by rememberSaveable { mutableStateOf("") }
    var confirmQuarantine by remember { mutableStateOf(false) }

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val name = queryDisplayName(context, uri) ?: "selected_file"
            selectedUri = uri
            selectedName = name
            onScanUri(uri, name)
        }
    }

    if (confirmQuarantine) {
        AlertDialog(
            onDismissRequest = { confirmQuarantine = false },
            title = { Text("Quarantine selected file?") },
            text = {
                Text("OmniShield will verify a private copy, then ask Android's document provider to delete the original. Some providers refuse deletion; the app will report that outcome instead of claiming success.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmQuarantine = false
                    selectedUri?.let { onQuarantineUri(it, selectedName) }
                }) { Text("Quarantine") }
            },
            dismissButton = { TextButton(onClick = { confirmQuarantine = false }) { Text("Cancel") } }
        )
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Default.FolderOpen,
                        contentDescription = null,
                        tint = ElectricBlue,
                        modifier = Modifier.size(52.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "Scan Any File",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        "Signature scan + structural analysis: polyglot executables, dropper scripts, macro documents, zip-slip archives, and APK permission/dropper triage. 100% on-device.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    if (isScanning) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp), strokeWidth = 3.dp)
                    } else {
                        Button(onClick = { runCatching { picker.launch(arrayOf("*/*")) } }) {
                            Icon(Icons.Default.Description, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Choose File to Scan")
                        }
                    }
                }
            }
        }

        result?.let { record ->
            item { ScanResultCard(record) }
            if (record.threatLevel != SecurityLevel.CLEAN && selectedUri != null) {
                item {
                    Button(
                        onClick = { confirmQuarantine = true },
                        enabled = !isQuarantining && !isScanning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isQuarantining) {
                            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        } else {
                            Text("Quarantine selected file")
                        }
                    }
                }
            }
        }
        if (quarantineItems.isNotEmpty()) {
            item {
                Text("App-private quarantine", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Copies here are inaccessible to other apps. ‘Original removed’ is shown only when the document provider confirmed deletion.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            items(quarantineItems, key = { it.id }) { item ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(item.originalName, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("${item.sizeBytes} bytes · SHA-256 ${item.sha256.take(16)}…", style = MaterialTheme.typography.bodySmall)
                        Text(
                            if (item.originalRemoved) "Original removed" else "Original unchanged / deletion unavailable",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (item.originalRemoved) EmeraldPrimary else com.adshield.pro.ui.theme.WarningAmber
                        )
                        TextButton(onClick = { onDeleteQuarantined(item) }) { Text("Delete quarantined copy") }
                    }
                }
            }
        }
    }
}

private fun queryDisplayName(context: android.content.Context, uri: android.net.Uri): String? {
    return runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }.getOrNull()
}

@Composable
private fun LinkScanTab(result: UrlThreatScanner.UrlVerdict?, isScanning: Boolean, onScanUrl: (String) -> Unit) {
    var urlInput by rememberSaveable { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Link, contentDescription = null, tint = ElectricBlue, modifier = Modifier.size(26.dp))
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            "Scan Any Link",
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Text(
                        "Checks against live malware/phishing intelligence plus typosquat, punycode, credential-harvest and dropper heuristics.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp, bottom = 12.dp)
                    )
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("https://suspicious-link.example…") },
                        singleLine = true,
                        enabled = !isScanning
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = { onScanUrl(urlInput) },
                        enabled = urlInput.isNotBlank() && !isScanning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isScanning) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text("Analyze Link")
                    }
                }
            }
        }

        result?.let { verdict ->
            item {
                val (tint, label) = when (verdict.threatLevel) {
                    UrlThreatScanner.ThreatLevel.DANGEROUS -> com.adshield.pro.ui.theme.AlertRed to "DANGEROUS LINK"
                    UrlThreatScanner.ThreatLevel.SUSPICIOUS -> com.adshield.pro.ui.theme.WarningAmber to "SUSPICIOUS LINK"
                    UrlThreatScanner.ThreatLevel.CLEAN -> Color(0xFF34D399) to "NO THREATS FOUND"
                }
                Card(
                    colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = 0.10f)),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                if (verdict.threatLevel == UrlThreatScanner.ThreatLevel.CLEAN) Icons.Default.CheckCircle else Icons.Default.Warning,
                                contentDescription = null,
                                tint = tint
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(label, color = tint, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.weight(1f))
                            Text(
                                "Risk ${verdict.riskScore}/100",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Text(
                            verdict.normalizedHost,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (verdict.findings.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            verdict.findings.forEach { finding ->
                                Text("• $finding", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            verdict.recommendation,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanResultCard(record: SecurityScanRecord) {
    val (tint, label) = when (record.threatLevel) {
        SecurityLevel.DANGEROUS -> com.adshield.pro.ui.theme.AlertRed to "THREAT DETECTED"
        SecurityLevel.SUSPICIOUS -> com.adshield.pro.ui.theme.WarningAmber to "SUSPICIOUS"
        SecurityLevel.CLEAN -> Color(0xFF34D399) to "CLEAN"
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = 0.10f)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (record.threatLevel == SecurityLevel.CLEAN) Icons.Default.CheckCircle else Icons.Default.Warning,
                    contentDescription = null,
                    tint = tint
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(label, color = tint, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.weight(1f))
                Text("Risk ${record.riskScore}/100", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                record.target,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            record.threatName?.let {
                Spacer(modifier = Modifier.height(6.dp))
                Text(it, fontWeight = FontWeight.SemiBold, color = tint, fontSize = 14.sp)
            }
            if (record.findings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                record.findings.take(6).forEach { finding ->
                    Text("• $finding", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                record.recommendation,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (record.kind == ScanKind.FILE && record.threatLevel != SecurityLevel.CLEAN) {
                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { /* deletion handled from Deep Cleaner */ }) {
                    Text("Tip: delete it from Optimizer → Junk Cleaner")
                }
            }
        }
    }
}

@Composable
private fun HistoryTab(history: List<SecurityScanRecord>) {
    if (history.isEmpty()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(Icons.Default.MusicNote, contentDescription = null, tint = SkyBlueGlow, modifier = Modifier.size(48.dp))
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                "No scans yet this session. Scan a link, file, or run the app audit.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(history, key = { it.id }) { record ->
            val tint = when (record.threatLevel) {
                SecurityLevel.DANGEROUS -> com.adshield.pro.ui.theme.AlertRed
                SecurityLevel.SUSPICIOUS -> com.adshield.pro.ui.theme.WarningAmber
                SecurityLevel.CLEAN -> ElectricBlue
            }
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(tint, androidx.compose.foundation.shape.CircleShape)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            record.target,
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                                .format(Date(record.timestampEpochMs)) + " • Risk ${record.riskScore}",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        record.threatLevel.name,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = tint
                    )
                }
            }
        }
    }
}
