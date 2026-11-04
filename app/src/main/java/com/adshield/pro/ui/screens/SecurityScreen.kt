package com.adshield.pro.ui.screens

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccessTime
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.optimizer.RuleBasedOptimizationPredictor
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityPosture
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.security.SystemScannerEngine
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.engine.storage.PrivateCloudBoxEngine
import com.adshield.pro.engine.storage.UniversalFileManager
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.theme.currentLocale
import java.io.File
import java.text.DateFormat
import java.util.Date

/**
 * AdShield Pro — Security Center, Complete System Scanner, Universal File/APK Manager & Private Cloud Box.
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
    systemScanProgress: SystemScannerEngine.SystemScanProgress?,
    systemScanReports: List<SystemScannerEngine.SystemScanReport>,
    managedFiles: List<UniversalFileManager.ManagedFileItem>,
    managedFileKindFilter: UniversalFileManager.ManagedMediaKind?,
    vaultItems: List<PrivateCloudBoxEngine.VaultItem>,
    vaultSummary: PrivateCloudBoxEngine.VaultStorageSummary,
    vaultCloudConfig: PrivateCloudBoxEngine.CloudEndpointConfig,
    vaultSelectedFolder: String?,
    vaultSelectedCategory: PrivateCloudBoxEngine.VaultCategory?,
    vaultSearchQuery: String,
    vaultPreview: PrivateCloudBoxEngine.VaultPreview?,
    isVaultBusy: Boolean,
    onRunCompleteSystemScan: () -> Unit,
    onClearScanHistory: () -> Unit,
    onScanUrl: (String) -> Unit,
    onScanUri: (Uri, String) -> Unit,
    onAuditApps: () -> Unit,
    onOpenAppSettings: (String) -> Unit,
    onSetManagedFileKindFilter: (UniversalFileManager.ManagedMediaKind?) -> Unit,
    onImportManagedUri: (Uri) -> Unit,
    onOpenManagedItem: (String) -> Unit,
    onSendManagedToVault: (String) -> Unit,
    onDeleteManagedItem: (String) -> Unit,
    onSelectVaultFolder: (String?) -> Unit,
    onSelectVaultCategory: (PrivateCloudBoxEngine.VaultCategory?) -> Unit,
    onVaultSearchChange: (String) -> Unit,
    onCreateVaultFolder: (String) -> Unit,
    onMoveVaultItem: (String, String) -> Unit,
    onUploadUriToVault: (Uri, String?) -> Unit,
    onExportVaultItemToUri: (String, Uri) -> Unit,
    onPreviewVaultItem: (String) -> Unit,
    onCloseVaultPreview: () -> Unit,
    onOpenFileExternally: (File, String) -> Unit,
    onDeleteVaultItem: (String, Boolean) -> Unit,
    onSetVaultPin: (String) -> Unit,
    onUnlockVault: (String) -> Unit,
    onLockVault: () -> Unit,
    onRemoveVaultPin: (String) -> Unit,
    onConfigureVaultCloud: (PrivateCloudBoxEngine.CloudEndpointConfig) -> Unit,
    onSyncVaultItem: (String) -> Unit,
    onSyncAllVault: () -> Unit
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
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                SecurityTabChip("Shield", Icons.Default.Security, selectedSubTab == 0) { selectedSubTab = 0 }
                SecurityTabChip("Apps", Icons.Default.GppGood, selectedSubTab == 1) { selectedSubTab = 1 }
                SecurityTabChip("Files", Icons.Default.Description, selectedSubTab == 2) { selectedSubTab = 2 }
                SecurityTabChip("Links", Icons.Default.Link, selectedSubTab == 3) { selectedSubTab = 3 }
                SecurityTabChip("Cloud Box", Icons.Default.CloudDone, selectedSubTab == 4) { selectedSubTab = 4 }
                SecurityTabChip("History", Icons.Default.AccessTime, selectedSubTab == 5) { selectedSubTab = 5 }
            }
        }

        when (selectedSubTab) {
            0 -> ProtectionPostureTab(
                posture = posture,
                vpnState = vpnState,
                malwareBlocks = malwareBlocks,
                scanProgress = systemScanProgress,
                latestReport = systemScanReports.firstOrNull(),
                onRunCompleteSystemScan = onRunCompleteSystemScan,
                onAuditApps = onAuditApps
            )
            1 -> AppAuditTab(
                audits = appAudits,
                isAuditing = isAuditingApps,
                onAuditApps = onAuditApps,
                onImportApkUri = onImportManagedUri,
                onOpenAppSettings = onOpenAppSettings
            )
            2 -> FileScanTab(
                result = fileScanResult,
                isScanning = isScanning,
                managedFiles = managedFiles,
                selectedKind = managedFileKindFilter,
                onSelectKind = onSetManagedFileKindFilter,
                onScanUri = onScanUri,
                onImportUri = onImportManagedUri,
                onOpenItem = onOpenManagedItem,
                onSendToVault = onSendManagedToVault,
                onDeleteItem = onDeleteManagedItem
            )
            3 -> LinkScanTab(urlScanResult, isScanning, onScanUrl)
            4 -> VaultScreen(
                items = vaultItems,
                summary = vaultSummary,
                cloudConfig = vaultCloudConfig,
                selectedFolder = vaultSelectedFolder,
                selectedCategory = vaultSelectedCategory,
                searchQuery = vaultSearchQuery,
                preview = vaultPreview,
                isBusy = isVaultBusy,
                onSelectFolder = onSelectVaultFolder,
                onSelectCategory = onSelectVaultCategory,
                onSearchChange = onVaultSearchChange,
                onCreateFolder = onCreateVaultFolder,
                onMoveItem = onMoveVaultItem,
                onUploadUri = onUploadUriToVault,
                onExportItemToUri = onExportVaultItemToUri,
                onPreviewItem = onPreviewVaultItem,
                onClosePreview = onCloseVaultPreview,
                onOpenPreviewExternally = onOpenFileExternally,
                onDeleteItem = onDeleteVaultItem,
                onSetPin = onSetVaultPin,
                onUnlock = onUnlockVault,
                onLock = onLockVault,
                onRemovePin = onRemoveVaultPin,
                onConfigureCloud = onConfigureVaultCloud,
                onSyncItem = onSyncVaultItem,
                onSyncAll = onSyncAllVault
            )
            else -> HistoryTab(
                history = scanHistory,
                systemReports = systemScanReports,
                onClearHistory = onClearScanHistory
            )
        }
    }
}

@Composable
private fun SecurityTabChip(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean,
    onClick: () -> Unit
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, maxLines = 1, fontSize = 12.sp) },
        leadingIcon = {
            Icon(icon, contentDescription = null, modifier = Modifier.size(15.dp))
        }
    )
}

@Composable
private fun ProtectionPostureTab(
    posture: SecurityPosture,
    vpnState: VpnRuntimeState,
    malwareBlocks: Long,
    scanProgress: SystemScannerEngine.SystemScanProgress?,
    latestReport: SystemScannerEngine.SystemScanReport?,
    onRunCompleteSystemScan: () -> Unit,
    onAuditApps: () -> Unit
) {
    var showFullReportDialog by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val isScanRunning = scanProgress?.isRunning == true

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
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
                                posture.protectionScore >= 45 -> WarningAmber
                                else -> AlertRed
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

        // Complete System Scanning Card
        item(key = "complete-system-scan-card") {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Complete System Scan", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        "Scans Security Config, Installed Apps, Accessible Downloads & Files, Storage/Cache, Battery/Thermal Health, and Filter Rule Integrity.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    if (scanProgress != null && isScanRunning) {
                        LinearProgressIndicator(
                            progress = { scanProgress.percent / 100f },
                            modifier = Modifier.fillMaxWidth(),
                            color = ElectricBlue
                        )
                        Text(
                            "${scanProgress.percent}% · ${scanProgress.statusText} (${scanProgress.itemsScannedSoFar} checked)",
                            fontSize = 11.sp,
                            color = CyberCyan
                        )
                    }

                    Button(
                        onClick = onRunCompleteSystemScan,
                        enabled = !isScanRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isScanRunning) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("Scanning System Modules…")
                        } else {
                            Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Run Complete System Scan")
                        }
                    }

                    if (latestReport != null && !isScanRunning) {
                        val reportColor = when (latestReport.overallLevel) {
                            SecurityLevel.DANGEROUS -> AlertRed
                            SecurityLevel.SUSPICIOUS -> WarningAmber
                            SecurityLevel.CLEAN -> EmeraldPrimary
                        }
                        Surface(
                            color = reportColor.copy(alpha = 0.12f),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    "Last System Scan: ${latestReport.overallLevel.name} (Risk ${latestReport.overallRiskScore}/100)",
                                    color = reportColor,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                                Text(latestReport.summary, fontSize = 12.sp)
                                latestReport.modules.forEach { mod ->
                                    Text(
                                        "• ${mod.module.title}: ${mod.level.name} (${mod.itemsChecked} checked, ${mod.issuesFound} finding(s))",
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                TextButton(onClick = { showFullReportDialog = true }) {
                                    Text("View Detailed Report")
                                }
                            }
                        }
                    }
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
            OutlinedButton(
                onClick = onAuditApps,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.GppGood, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scan All Installed Apps")
            }
        }
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = ElectricBlue.copy(alpha = 0.08f)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "How AdShield protects you: every website, link and app connection is checked against " +
                        "191,000+ live malware/phishing domains plus structural analysis of files, APKs and links — " +
                        "all on-device, with zero data leaving your phone.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(14.dp)
                )
            }
        }
    }

    if (showFullReportDialog && latestReport != null) {
        val text = remember(latestReport) { latestReport.toDetailedReportText() }
        AlertDialog(
            onDismissRequest = { showFullReportDialog = false },
            title = { Text("System Scan Detailed Report") },
            text = {
                Column(
                    modifier = Modifier
                        .heightIn(max = 360.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(text, fontSize = 11.sp)
                }
            },
            confirmButton = {
                Button(onClick = {
                    clipboard.setText(AnnotatedString(text))
                    showFullReportDialog = false
                }) {
                    Text("Copy Report")
                }
            },
            dismissButton = {
                TextButton(onClick = { showFullReportDialog = false }) { Text("Close") }
            }
        )
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
                tint = if (isGood) ElectricBlue else WarningAmber,
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
    onAuditApps: () -> Unit,
    onImportApkUri: (Uri) -> Unit,
    onOpenAppSettings: (String) -> Unit
) {
    val apkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) onImportApkUri(uri)
    }

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
                Text("Full Device Scan", maxLines = 1)
            }
            OutlinedButton(
                onClick = { runCatching { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "*/*")) } }
            ) {
                Text("Import APK", maxLines = 1)
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
                    "Tap Full Device Scan to audit installed apps, or Import APK to inspect & verify an APK package before installation.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(audits, key = { it.profile.packageName }, contentType = { "app-audit" }) { audit ->
                AppAuditCard(audit, onOpenAppSettings = { onOpenAppSettings(audit.profile.packageName) })
            }
        }
    }
}

@Composable
private fun AppAuditCard(
    audit: AppRiskAuditor.AppRiskAudit,
    onOpenAppSettings: () -> Unit
) {
    val (tint, label) = when (audit.riskLevel) {
        AppRiskAuditor.RiskLevel.HIGH -> AlertRed to "HIGH RISK"
        AppRiskAuditor.RiskLevel.MEDIUM -> WarningAmber to "ELEVATED"
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
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        audit.profile.appName,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        "${audit.profile.packageName} · targetSdk ${audit.profile.targetSdkVersion}",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Surface(color = tint.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
                    Text(
                        label,
                        color = tint,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
                IconButton(onClick = onOpenAppSettings) {
                    Icon(Icons.Default.Settings, contentDescription = "Open Android App Info", tint = CyberCyan)
                }
            }
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
    managedFiles: List<UniversalFileManager.ManagedFileItem>,
    selectedKind: UniversalFileManager.ManagedMediaKind?,
    onSelectKind: (UniversalFileManager.ManagedMediaKind?) -> Unit,
    onScanUri: (Uri, String) -> Unit,
    onImportUri: (Uri) -> Unit,
    onOpenItem: (String) -> Unit,
    onSendToVault: (String) -> Unit,
    onDeleteItem: (String) -> Unit
) {
    val context = LocalContext.current

    val scanOnlyPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val name = queryDisplayName(context, uri) ?: "selected_file"
            onScanUri(uri, name)
        }
    }

    val importPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        uris.forEach { onImportUri(it) }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
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
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Universal File & APK Scanner + Manager",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        "Supports photos, videos, audio, documents, archives, and APKs via Android's Storage Access Framework. Verifies magic-byte headers, SHA-256, polyglots, zip-slip, macros, and APK permissions.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    if (isScanning) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp), strokeWidth = 3.dp)
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { runCatching { scanOnlyPicker.launch(arrayOf("*/*")) } }) {
                                Icon(Icons.Default.Description, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Quick Scan")
                            }
                            OutlinedButton(onClick = { runCatching { importPicker.launch(arrayOf("*/*")) } }) {
                                Text("Import & Manage")
                            }
                        }
                    }
                }
            }
        }

        result?.let { record ->
            item { ScanResultCard(record) }
        }

        item(key = "managed-files-filter") {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    "Managed Files & APKs (${managedFiles.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = selectedKind == null,
                        onClick = { onSelectKind(null) },
                        label = { Text("All") }
                    )
                    UniversalFileManager.ManagedMediaKind.entries.forEach { kind ->
                        FilterChip(
                            selected = selectedKind == kind,
                            onClick = { onSelectKind(if (selectedKind == kind) null else kind) },
                            label = { Text(kind.label) }
                        )
                    }
                }
            }
        }

        items(managedFiles, key = { it.id }, contentType = { "managed-file" }) { item ->
            val badgeColor = when (item.securityLevel) {
                SecurityLevel.DANGEROUS -> AlertRed
                SecurityLevel.SUSPICIOUS -> WarningAmber
                SecurityLevel.CLEAN -> EmeraldPrimary
            }
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                item.displayName,
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            val apkNote = item.apkPackageName?.let { " · pkg: $it (${item.apkPermissionsCount} perms)" }.orEmpty()
                            Text(
                                "${item.kind.label} · ${RuleBasedOptimizationPredictor.formatBytes(item.sizeBytes)}$apkNote",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Surface(color = badgeColor.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
                            Text(
                                item.securityLevel.name,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = badgeColor,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                    item.mimeMismatchWarning?.let {
                        Text("⚠ $it", fontSize = 11.sp, color = WarningAmber, modifier = Modifier.padding(top = 4.dp))
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        IconButton(onClick = { onOpenItem(item.id) }) {
                            Icon(Icons.Default.OpenInNew, contentDescription = "Open or Install", tint = EmeraldPrimary)
                        }
                        IconButton(onClick = { onSendToVault(item.id) }) {
                            Icon(Icons.Default.CloudUpload, contentDescription = "Encrypt into Cloud Box", tint = ElectricBlue)
                        }
                        IconButton(onClick = { onDeleteItem(item.id) }) {
                            Icon(Icons.Default.Delete, contentDescription = "Delete", tint = AlertRed)
                        }
                    }
                }
            }
        }
    }
}

private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
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
        contentPadding = PaddingValues(16.dp),
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
                    UrlThreatScanner.ThreatLevel.DANGEROUS -> AlertRed to "DANGEROUS LINK"
                    UrlThreatScanner.ThreatLevel.SUSPICIOUS -> WarningAmber to "SUSPICIOUS LINK"
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
        SecurityLevel.DANGEROUS -> AlertRed to "THREAT DETECTED"
        SecurityLevel.SUSPICIOUS -> WarningAmber to "SUSPICIOUS"
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
        }
    }
}

@Composable
private fun HistoryTab(
    history: List<SecurityScanRecord>,
    systemReports: List<SystemScannerEngine.SystemScanReport>,
    onClearHistory: () -> Unit
) {
    val locale = currentLocale()
    val dateTimeFormatter = remember(locale) {
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, locale)
    }
    var selectedRecord by remember { mutableStateOf<SecurityScanRecord?>(null) }

    if (history.isEmpty() && systemReports.isEmpty()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(Icons.Default.AccessTime, contentDescription = null, tint = SkyBlueGlow, modifier = Modifier.size(48.dp))
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                "No scans recorded yet. Run Complete System Scan, scan a file/link, or audit installed apps.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item(key = "history-header") {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Persisted Scan History (${history.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                TextButton(onClick = onClearHistory) {
                    Text("Clear History")
                }
            }
        }
        items(history, key = { it.id }, contentType = { "scan-record" }) { record ->
            val tint = when (record.threatLevel) {
                SecurityLevel.DANGEROUS -> AlertRed
                SecurityLevel.SUSPICIOUS -> WarningAmber
                SecurityLevel.CLEAN -> ElectricBlue
            }
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { selectedRecord = record }
            ) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(tint, CircleShape)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "[${record.kind.name}] ${record.target}",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            dateTimeFormatter.format(Date(record.timestampEpochMs)) + " • Risk ${record.riskScore}/100",
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

    selectedRecord?.let { rec ->
        AlertDialog(
            onDismissRequest = { selectedRecord = null },
            title = { Text("${rec.kind.name} Scan Details") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Target: ${rec.target}", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Text("Verdict: ${rec.threatLevel.name} (Risk ${rec.riskScore}/100)", fontSize = 12.sp)
                    if (rec.findings.isEmpty()) {
                        Text("Findings: None (clean)", fontSize = 12.sp)
                    } else {
                        rec.findings.forEach { Text("• $it", fontSize = 12.sp) }
                    }
                    Text("Recommendation: ${rec.recommendation}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = {
                TextButton(onClick = { selectedRecord = null }) { Text("Close") }
            }
        )
    }
}
