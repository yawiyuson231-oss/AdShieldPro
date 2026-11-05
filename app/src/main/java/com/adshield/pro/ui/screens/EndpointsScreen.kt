package com.adshield.pro.ui.screens

import android.os.Build
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
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.engine.compliance.ComplianceChecker
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.MetricSpec
import com.adshield.pro.ui.components.ResponsiveMetrics
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.theme.formatInteger
import com.adshield.pro.ui.viewmodel.AdShieldViewModel
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel

/**
 * Endpoint security for the one endpoint this app can actually see: this device.
 * Installed-app inventory and permission audits come from PackageManager; device hardening
 * signals come from the compliance evaluator. Other machines on the network are NOT visible
 * to a non-root Android app and the screen says so instead of inventing an endpoint fleet.
 */
@Composable
fun EndpointsScreen(
    viewModel: AdShieldViewModel,
    cyberViewModel: CyberShieldViewModel,
    onOpenSecurityTab: () -> Unit
) {
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()
    val appAudits by viewModel.appAudits.collectAsStateWithLifecycle()
    val isAuditing by viewModel.isAuditingApps.collectAsStateWithLifecycle()
    val scanProgress by viewModel.scanProgress.collectAsStateWithLifecycle()
    val compliance by cyberViewModel.complianceReport.collectAsStateWithLifecycle()
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    val flagged = appAudits.filter {
        it.riskLevel == AppRiskAuditor.RiskLevel.HIGH || it.riskLevel == AppRiskAuditor.RiskLevel.MEDIUM
    }
    val highRisk = appAudits.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "endpoint-device", contentType = "panel") {
                CyberPanel(
                    title = "This device",
                    subtitle = "${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE}",
                    trailing = {
                        StatusPill(
                            if (vpnState.status == com.adshield.pro.domain.model.VpnStatus.CONNECTED) "Protected" else "Unprotected",
                            if (vpnState.status == com.adshield.pro.domain.model.VpnStatus.CONNECTED) EmeraldPrimary else AlertRed
                        )
                    }
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.PhoneAndroid, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(34.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text("API ${Build.VERSION.SDK_INT} · patch ${Build.VERSION.SECURITY_PATCH ?: "unknown"}", color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text(
                                "The only endpoint AdShield can inspect. Other devices are not visible to a non-root Android app.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                            )
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    val deviceChecks = compliance?.checks?.filter { it.category == ComplianceChecker.Category.DEVICE }
                    if (deviceChecks == null) {
                        Text("Device hardening checks have not been evaluated yet.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            deviceChecks.forEach { check ->
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    val color = when (check.status) {
                                        ComplianceChecker.CheckStatus.PASS -> EmeraldPrimary
                                        ComplianceChecker.CheckStatus.FAIL -> AlertRed
                                        ComplianceChecker.CheckStatus.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
                                    }
                                    Box(Modifier.size(7.dp).clip(CircleShape).background(color))
                                    Spacer(Modifier.width(8.dp))
                                    Text(check.title, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.weight(1f))
                                    Text(check.status.name, color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }

            item(key = "endpoint-apps", contentType = "panel") {
                CyberPanel(
                    title = "Application inventory",
                    subtitle = "PackageManager · permission-stack audit",
                    trailing = {
                        if (isAuditing) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
                        else StatusPill(if (appAudits.isEmpty()) "Not audited" else "$highRisk high-risk", if (appAudits.isEmpty()) WarningAmber else if (highRisk == 0) EmeraldPrimary else AlertRed)
                    }
                ) {
                    ResponsiveMetrics(
                        columns = 3,
                        metrics = listOf(
                            MetricSpec("Installed", if (installedApps.isNotEmpty()) formatInteger(installedApps.size) else "—", "visible apps", Color.White),
                            MetricSpec("Audited", if (appAudits.isNotEmpty()) formatInteger(appAudits.size) else "0", "permission profiles", CyberCyan),
                            MetricSpec("Flagged", if (appAudits.isNotEmpty()) formatInteger(flagged.size) else "—", "medium + high risk", if (flagged.isEmpty()) EmeraldPrimary else AlertRed)
                        )
                    )
                    Spacer(Modifier.height(12.dp))
                    if (isAuditing) {
                        val progress = scanProgress
                        if (progress != null && progress.total > 0) {
                            LinearProgressIndicator(
                                progress = { progress.completed.toFloat() / progress.total },
                                modifier = Modifier.fillMaxWidth(),
                                color = ElectricBlue
                            )
                            Spacer(Modifier.height(6.dp))
                            Text("Auditing ${progress.label} (${progress.completed}/${progress.total})", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        } else {
                            LinearProgressIndicator(Modifier.fillMaxWidth(), color = ElectricBlue)
                        }
                        Spacer(Modifier.height(10.dp))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = viewModel::auditInstalledApps, enabled = !isAuditing, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(if (appAudits.isEmpty()) "Run app audit" else "Re-audit apps", maxLines = 1)
                        }
                        OutlinedButton(onClick = onOpenSecurityTab, modifier = Modifier.weight(1f)) {
                            Text("Full scanner", maxLines = 1)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "The audit reads app metadata and requested permissions only. It cannot read other apps' private files, " +
                            "scan their memory, or guarantee a malware-free device — a risky permission stack is a review signal, not a verdict.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                    )
                }
            }

            if (flagged.isNotEmpty()) {
                item(key = "endpoint-flagged-header", contentType = "header") {
                    Text(
                        "FLAGGED APPLICATIONS (${flagged.size})",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp
                    )
                }
                items(flagged, key = { it.profile.packageName }, contentType = { "app" }) { audit ->
                    val color = if (audit.riskLevel == AppRiskAuditor.RiskLevel.HIGH) AlertRed else WarningAmber
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFF071526))
                            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
                            .padding(12.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(audit.profile.appName, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${audit.riskLevel.name} · ${audit.riskScore}", color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        }
                        Text(audit.profile.packageName, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Spacer(Modifier.height(4.dp))
                        Text(audit.summary, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                        audit.findings.take(3).forEach { finding ->
                            Text("• $finding", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
                        }
                    }
                }
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }
}
