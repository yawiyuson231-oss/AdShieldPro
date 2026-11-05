package com.adshield.pro.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Https
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.OfflineBolt
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.engine.compliance.ComplianceChecker
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.PrivacyBadge
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.AdShieldViewModel
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Reports console: the exportable device-compliance assessment and the real scan journal
 * report, plus the capability disclosure. Exports are written through the Storage Access
 * Framework so the user picks the destination; nothing is uploaded anywhere.
 */
@Composable
fun ReportsScreen(
    viewModel: AdShieldViewModel,
    cyberViewModel: CyberShieldViewModel,
    onOpenStatusTab: () -> Unit,
    onOpenStatisticsTab: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val compliance by cyberViewModel.complianceReport.collectAsStateWithLifecycle()
    val isEvaluating by cyberViewModel.isEvaluatingCompliance.collectAsStateWithLifecycle()
    val appAudits by viewModel.appAudits.collectAsStateWithLifecycle()
    val scanSummary by viewModel.scanSummary.collectAsStateWithLifecycle()
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    val flaggedApps = appAudits.takeIf { it.isNotEmpty() }?.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }
    var pendingExport by remember { mutableStateOf<Pair<String, String>?>(null) } // filename to content

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        val pending = pendingExport
        pendingExport = null
        if (uri != null && pending != null) {
            scope.launch {
                val written = withContext(Dispatchers.IO) {
                    runCatching {
                        context.contentResolver.openOutputStream(uri, "wt")?.use { stream ->
                            stream.write(pending.second.toByteArray(Charsets.UTF_8))
                        } != null
                    }.getOrDefault(false)
                }
                viewModel.showFeedback(if (written) "Report exported." else "Could not write the report to that location.")
            }
        }
    }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "reports-compliance", contentType = "panel") {
                CyberPanel(
                    title = "Compliance report",
                    subtitle = "Local configuration assessment · not a certification",
                    trailing = {
                        if (isEvaluating) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
                        else StatusPill(
                            compliance?.scorePercent?.let { "$it%" } ?: "Not run",
                            if (compliance != null && (compliance?.scorePercent ?: 0) >= 80) EmeraldPrimary else WarningAmber
                        )
                    }
                ) {
                    Text(
                        "Checks read real Android signals (lock screen, encryption, patch level, ADB) and AdShield settings. " +
                            "UNKNOWN means a signal could not be measured — it is never counted as a pass. This is not ISO 27001, " +
                            "SOC 2, GDPR or HIPAA certification.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = { cyberViewModel.evaluateCompliance(flaggedApps) },
                            enabled = !isEvaluating,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Assessment, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(if (compliance == null) "Evaluate" else "Re-evaluate", maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    val text = cyberViewModel.buildComplianceReportText()
                                    pendingExport = "cybershield-compliance-report.txt" to text
                                    exportLauncher.launch("cybershield-compliance-report.txt")
                                }
                            },
                            enabled = compliance != null,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Export", maxLines = 1)
                        }
                    }
                }
            }

            val report = compliance
            if (report != null) {
                report.categories.forEach { summary ->
                    item(key = "reports-cat-${summary.category.name}", contentType = "category") {
                        Column {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    summary.category.label.uppercase(),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp
                                )
                                Text(
                                    "${summary.passed}/${summary.evaluated} passed" + if (summary.unknown > 0) " · ${summary.unknown} unknown" else "",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                report.checks.filter { it.category == summary.category }.forEach { check ->
                                    ComplianceCheckRow(check)
                                }
                            }
                        }
                    }
                }
            }

            item(key = "reports-scan", contentType = "panel") {
                CyberPanel(title = "Security scan report", subtitle = "Real scan journal · files, URLs, APKs, app audits") {
                    Text(
                        if (scanSummary.total == 0) "No scan has been performed yet. An empty journal is reported as 'no scan performed', never as a clean device."
                        else "${scanSummary.total} record(s): ${scanSummary.clean} clean · ${scanSummary.suspicious} suspicious · ${scanSummary.dangerous} dangerous.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                val text = viewModel.buildScanReport()
                                pendingExport = "adshield-scan-report.txt" to text
                                exportLauncher.launch("adshield-scan-report.txt")
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Export scan report")
                    }
                }
            }

            item(key = "reports-privacy", contentType = "panel") {
                CyberPanel(title = "Privacy & coverage", subtitle = "What this build actually does") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PrivacyBadge("Local only", Icons.Default.Lock, true, Modifier.weight(1f))
                        PrivacyBadge("No root", Icons.Default.Shield, true, Modifier.weight(1f))
                        PrivacyBadge("No MITM", Icons.Default.Https, true, Modifier.weight(1f))
                        PrivacyBadge("Offline rules", Icons.Default.OfflineBolt, vpnState.loadedRuleCount > 0, Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = onOpenStatusTab) { Text("Capability report", fontSize = 12.sp) }
                        TextButton(onClick = onOpenStatisticsTab) { Text("DNS statistics", fontSize = 12.sp) }
                    }
                }
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }
}

@Composable
private fun ComplianceCheckRow(check: ComplianceChecker.ComplianceCheck) {
    val color = when (check.status) {
        ComplianceChecker.CheckStatus.PASS -> EmeraldPrimary
        ComplianceChecker.CheckStatus.FAIL -> AlertRed
        ComplianceChecker.CheckStatus.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF071526))
            .border(1.dp, NavyBorder.copy(alpha = 0.6f), RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(8.dp))
            Text(check.title, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Text(check.status.name, color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(4.dp))
        Text(check.detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
        check.recommendation?.let {
            Spacer(Modifier.height(3.dp))
            Text("→ $it", color = CyberCyan, fontSize = 10.sp)
        }
    }
}
