package com.adshield.pro.ui.screens

import android.content.Intent
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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.runtime.rememberCoroutineScope
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
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.engine.aether.SecurityReportExplainer
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.ScanJournalSummary
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.ScanProgress
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityPosture
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.SkyBlueGlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/**
 * AdShield Pro — Security Center (Anti-Virus & Anti-Phishing).
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
    scanSummary: ScanJournalSummary,
    scanProgress: ScanProgress?,
    quarantineItems: List<QuarantinedItem>,
    scheduledScanEnabled: Boolean,
    scheduledScanIntervalHours: Int,
    onScanUrl: (String) -> Unit,
    onScanUri: (android.net.Uri, String) -> Unit,
    onAuditApps: () -> Unit,
    onQuarantineLastScanned: (Boolean) -> Unit,
    onDeleteScannedDocument: (SecurityScanRecord) -> Unit,
    onRestoreQuarantined: (QuarantinedItem, android.net.Uri) -> Unit,
    onDeleteQuarantined: (QuarantinedItem) -> Unit,
    onVerifyQuarantined: (QuarantinedItem) -> Unit,
    onClearScanHistory: () -> Unit,
    onBuildScanReport: suspend () -> String,
    onSetScheduledScan: (Boolean, Int) -> Unit,
    onShowFeedback: (String) -> Unit
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
            0 -> ProtectionPostureTab(posture, vpnState, malwareBlocks, onAuditApps)
            1 -> AppAuditTab(appAudits, isAuditingApps, onAuditApps)
            2 -> FileScanTab(fileScanResult, isScanning, scanProgress, onScanUri, onQuarantineLastScanned, onDeleteScannedDocument)
            3 -> LinkScanTab(urlScanResult, isScanning, onScanUrl)
            else -> HistoryTab(
                history = scanHistory,
                summary = scanSummary,
                quarantineItems = quarantineItems,
                scheduledScanEnabled = scheduledScanEnabled,
                scheduledScanIntervalHours = scheduledScanIntervalHours,
                onRestoreQuarantined = onRestoreQuarantined,
                onDeleteQuarantined = onDeleteQuarantined,
                onVerifyQuarantined = onVerifyQuarantined,
                onClearScanHistory = onClearScanHistory,
                onBuildScanReport = onBuildScanReport,
                onSetScheduledScan = onSetScheduledScan,
                onShowFeedback = onShowFeedback
            )
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
    onAuditApps: () -> Unit
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
            modifier = Modifier.weight(1f),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(audits, key = { it.profile.packageName }, contentType = { "app-audit" }) { audit ->
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
    scanProgress: ScanProgress?,
    onScanUri: (android.net.Uri, String) -> Unit,
    onQuarantineLastScanned: (Boolean) -> Unit,
    onDeleteScannedDocument: (SecurityScanRecord) -> Unit
) {
    val context = LocalContext.current

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            // Persisting the grant lets a later verified delete reach the same document.
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }.recoverCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            val name = queryDisplayName(context, uri) ?: "selected_file"
            onScanUri(uri, name)
        }
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
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            if (scanProgress != null && !scanProgress.isIndeterminate) {
                                LinearProgressIndicator(
                                    progress = { scanProgress.fraction },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            } else {
                                CircularProgressIndicator(modifier = Modifier.size(28.dp), strokeWidth = 3.dp)
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = scanProgress?.let { "${it.percentLabel} · ${it.label}" } ?: "Scanning…",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
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
            item { ScanResultCard(record, onDeleteScannedDocument) }
            if (record.threatLevel != SecurityLevel.CLEAN) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Quarantine this file", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "Moves a neutralised copy into app-private storage. The original is kept unless you " +
                                    "explicitly choose to delete it, and Android may refuse that deletion.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(onClick = { onQuarantineLastScanned(false) }) {
                                    Text("Quarantine copy")
                                }
                                Button(onClick = { onQuarantineLastScanned(true) }) {
                                    Text("Quarantine & delete original")
                                }
                            }
                        }
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
private fun ScanResultCard(
    record: SecurityScanRecord,
    onDeleteScannedDocument: (SecurityScanRecord) -> Unit = {}
    ) {
    var showDeleteConfirmation by remember(record.id) { mutableStateOf(false) }
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
            if (record.kind == ScanKind.FILE && record.sourceUri != null) {
                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = { showDeleteConfirmation = true }) {
                    Text("Delete source document…")
                }
            }
        }
    }
    if (showDeleteConfirmation) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirmation = false },
            title = { Text("Delete ${record.target}?") },
            text = {
                Text(
                    "AdShield will ask the storage provider to permanently delete this user-selected " +
                        "document. This cannot be undone by AdShield. The provider may not support deletion."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteConfirmation = false
                    onDeleteScannedDocument(record)
                }) { Text("Delete permanently", color = com.adshield.pro.ui.theme.AlertRed) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirmation = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun HistoryTab(
    history: List<SecurityScanRecord>,
    summary: ScanJournalSummary,
    quarantineItems: List<QuarantinedItem>,
    scheduledScanEnabled: Boolean,
    scheduledScanIntervalHours: Int,
    onRestoreQuarantined: (QuarantinedItem, android.net.Uri) -> Unit,
    onDeleteQuarantined: (QuarantinedItem) -> Unit,
    onVerifyQuarantined: (QuarantinedItem) -> Unit,
    onClearScanHistory: () -> Unit,
    onBuildScanReport: suspend () -> String,
    onSetScheduledScan: (Boolean, Int) -> Unit,
    onShowFeedback: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val aiSummary = remember(history) { SecurityReportExplainer.summarize(history) }
    var pendingReport by remember { mutableStateOf<String?>(null) }
    var pendingRestore by remember { mutableStateOf<QuarantinedItem?>(null) }
    var showClearConfirm by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        val report = pendingReport
        pendingReport = null
        if (uri != null && report != null) {
            scope.launch {
                val written = withContext(Dispatchers.IO) {
                    runCatching {
                        context.contentResolver.openOutputStream(uri, "wt")?.use { stream ->
                            stream.write(report.toByteArray(Charsets.UTF_8))
                        } != null
                    }.getOrDefault(false)
                }
                onShowFeedback(
                    if (written) "Scan report exported." else "Could not write the report to that location."
                )
            }
        }
    }

    val restoreLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val item = pendingRestore
        pendingRestore = null
        if (uri != null && item != null) onRestoreQuarantined(item, uri)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item(key = "aether-report-summary") {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Column(Modifier.padding(14.dp)) {
                    Text("AETHER evidence summary", style = MaterialTheme.typography.titleMedium, color = CyberCyan)
                    Spacer(Modifier.height(6.dp))
                    Text(aiSummary.headline, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(4.dp))
                    Text(aiSummary.explanation, style = MaterialTheme.typography.bodyMedium)
                    aiSummary.recommendedActions.forEach { action ->
                        Text("• $action", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 5.dp))
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Deterministic on-device explanation only. It cannot delete files, install apps, or change security settings.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item(key = "journal-summary", contentType = "summary") {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Scan journal", style = MaterialTheme.typography.titleMedium)
                    if (summary.total == 0) {
                        Text(
                            "No scan has been performed yet. Nothing here is a statement that the device is clean.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Text(
                            "${summary.total} record(s) kept · ${summary.clean} clean · " +
                                "${summary.suspicious} suspicious · ${summary.dangerous} dangerous",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            "Files/APKs ${summary.fileScans} · Links ${summary.urlScans} · App audits ${summary.appAudits}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        summary.lastScanEpochMs?.let { last ->
                            Text(
                                "Last scan: " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                                    .format(Date(last)),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            scope.launch {
                                pendingReport = onBuildScanReport()
                                runCatching { exportLauncher.launch("adshield-scan-report.txt") }
                                    .onFailure { onShowFeedback("Could not open the file picker.") }
                            }
                        }) { Text("Export report") }
                        OutlinedButton(
                            onClick = { showClearConfirm = true },
                            enabled = summary.total > 0
                        ) { Text("Clear history") }
                    }
                }
            }
        }

        item(key = "scheduled-scan", contentType = "summary") {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Scheduled scan", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "Audits installed apps and re-verifies quarantine hashes. Shared storage is not " +
                                    "scanned unless you grant access to it.",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = scheduledScanEnabled,
                            onCheckedChange = { onSetScheduledScan(it, scheduledScanIntervalHours) }
                        )
                    }
                    if (scheduledScanEnabled) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf(12, 24, 168).forEach { hours ->
                                FilterChip(
                                    selected = scheduledScanIntervalHours == hours,
                                    onClick = { onSetScheduledScan(true, hours) },
                                    label = { Text(if (hours == 168) "Weekly" else "${hours}h", maxLines = 1) }
                                )
                            }
                        }
                    }
                }
            }
        }

        item(key = "quarantine-header", contentType = "summary") {
            Text(
                "Quarantine (${quarantineItems.size})",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 6.dp)
            )
        }

        if (quarantineItems.isEmpty()) {
            item(key = "quarantine-empty", contentType = "summary") {
                Text(
                    "Nothing quarantined. Flagged files can be isolated from the Files tab after a scan.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        items(quarantineItems, key = { it.id }, contentType = { "quarantine-item" }) { item ->
            QuarantineCard(
                item = item,
                onVerify = { onVerifyQuarantined(item) },
                onRestore = {
                    pendingRestore = item
                    runCatching { restoreLauncher.launch(item.displayName) }
                        .onFailure { onShowFeedback("Could not open the file picker.") }
                },
                onDelete = { onDeleteQuarantined(item) }
            )
        }

        item(key = "history-header", contentType = "summary") {
            Text(
                "History",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 6.dp)
            )
        }

        if (history.isEmpty()) {
            item(key = "history-empty", contentType = "summary") {
                Text(
                    "No scans recorded yet. Scan a link or file, or run the app audit.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        items(history, key = { it.id }, contentType = { "scan-record" }) { record ->
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
                                .format(Date(record.timestampEpochMs)) +
                                " • Risk ${record.riskScore} • ${record.scanSource.label}" +
                                if (record.durationMs > 0) " • ${record.durationMs} ms" else "",
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

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text("Clear scan history?") },
            text = { Text("This removes the recorded scan results. Quarantined files are kept.") },
            confirmButton = {
                TextButton(onClick = {
                    showClearConfirm = false
                    onClearScanHistory()
                }) { Text("Clear history") }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun QuarantineCard(
    item: QuarantinedItem,
    onVerify: () -> Unit,
    onRestore: () -> Unit,
    onDelete: () -> Unit
) {
    var confirmDelete by remember { mutableStateOf(false) }
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                item.displayName,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                "${item.threatLevel.name} · ${item.sizeBytes} bytes · " +
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                        .format(Date(item.quarantinedAtEpochMs)),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (item.originalRemoved) "Original deleted." else "Original still in its original location.",
                style = MaterialTheme.typography.labelMedium,
                color = if (item.originalRemoved) ElectricBlue else com.adshield.pro.ui.theme.WarningAmber
            )
            Text(
                "SHA-256 ${item.sha256.take(16)}…",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                TextButton(onClick = onVerify) { Text("Verify") }
                TextButton(onClick = onRestore) { Text("Restore") }
                TextButton(onClick = { confirmDelete = true }) { Text("Delete") }
            }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete quarantined copy?") },
            text = { Text("This permanently removes the isolated copy of ${item.displayName}. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) { Text("Delete permanently") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } }
        )
    }
}
