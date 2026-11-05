package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cybershield.CategoryCount
import com.adshield.pro.cybershield.CloudIndicator
import com.adshield.pro.cybershield.CloudProviderStatus
import com.adshield.pro.cybershield.ComplianceCheck
import com.adshield.pro.cybershield.ComplianceReport
import com.adshield.pro.cybershield.ComplianceStatus
import com.adshield.pro.cybershield.CsDataSource
import com.adshield.pro.domain.model.DomainBlockCount

private fun indicatorColor(indicator: CloudIndicator): Color = when (indicator) {
    CloudIndicator.OPERATIONAL -> Cs.Green
    CloudIndicator.DEGRADED -> Cs.Amber
    CloudIndicator.PARTIAL_OUTAGE -> Color(0xFFFF7A45)
    CloudIndicator.MAJOR_OUTAGE -> Cs.Red
    CloudIndicator.MAINTENANCE -> Cs.Cyan
    CloudIndicator.UNKNOWN -> Cs.Steel
}

/** Cloud security: real provider platform status + honest tenant disclosure. */
@Composable
fun CloudCard(
    statuses: List<CloudProviderStatus>,
    refreshing: Boolean,
    nowMs: Long,
    onRefresh: () -> Unit,
    onAddEndpoint: (String, String, String?) -> Unit,
    onRemoveEndpoint: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var addDialog by remember { mutableStateOf(false) }
    var detail by remember { mutableStateOf<CloudProviderStatus?>(null) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.NeonBlue) {
        CardHeader(
            "Cloud Security", accent = Cs.NeonBlue,
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    SourceChip(CsDataSource.EXTERNAL_INTEL)
                    IconButton(onClick = onRefresh, enabled = !refreshing, modifier = Modifier.size(26.dp)) {
                        if (refreshing) CircularProgressIndicator(Modifier.size(14.dp), color = Cs.Cyan, strokeWidth = 2.dp)
                        else Icon(Icons.Default.Refresh, "Refresh cloud status", tint = Cs.Cyan, modifier = Modifier.size(16.dp))
                    }
                }
            }
        )
        statuses.forEach { provider ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(Cs.Surface.copy(alpha = 0.7f))
                    .clickable { detail = provider }
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(provider.name, color = Cs.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        if (provider.isCustom) StatusChip("Custom", Cs.Purple)
                        if (provider.hasToken) StatusChip("Token", Cs.Green)
                    }
                    Text(
                        provider.description.ifBlank {
                            provider.error ?: when (provider.loadState) {
                                com.adshield.pro.cybershield.CsLoadState.NEVER_LOADED -> "Not polled yet"
                                com.adshield.pro.cybershield.CsLoadState.LOADING -> "Fetching real status…"
                                else -> "No status description"
                            }
                        },
                        color = Cs.TextDim, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                    provider.fetchedAtEpochMs?.let {
                        Text(
                            "${if (provider.loadState == com.adshield.pro.cybershield.CsLoadState.CACHED) "cached · " else ""}checked ${relativeTime(it, nowMs)}",
                            color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono
                        )
                    }
                }
                StatusChip(provider.indicator.label, indicatorColor(provider.indicator))
                if (provider.isCustom) {
                    IconButton(onClick = { onRemoveEndpoint(provider.id) }, modifier = Modifier.size(22.dp)) {
                        Icon(Icons.Default.Delete, "Remove endpoint", tint = Cs.TextFaint, modifier = Modifier.size(14.dp))
                    }
                }
            }
        }
        TextButton(onClick = { addDialog = true }) {
            Icon(Icons.Default.Add, null, tint = Cs.Cyan, modifier = Modifier.size(14.dp))
            Text(" Add status endpoint", color = Cs.Cyan, fontSize = 11.sp)
        }
        HonestNote("Real provider PLATFORM status via the public Statuspage v2 API. Your own cloud tenant's security posture requires provider-specific authenticated integration — not connected. Custom endpoint tokens are stored encrypted (Android Keystore).")
    }

    if (addDialog) {
        AddEndpointDialog(
            onDismiss = { addDialog = false },
            onAdd = { name, url, token -> onAddEndpoint(name, url, token); addDialog = false }
        )
    }

    detail?.let { provider ->
        AlertDialog(
            onDismissRequest = { detail = null },
            containerColor = Cs.SurfaceAlt,
            title = {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(provider.name, color = Cs.Text, fontSize = 15.sp, modifier = Modifier.weight(1f))
                    StatusChip(provider.indicator.label, indicatorColor(provider.indicator))
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(provider.description.ifBlank { "No description published." }, color = Cs.TextDim, fontSize = 12.sp, lineHeight = 17.sp)
                    KeyValueLine("Endpoint", provider.statusUrl.removePrefix("https://").take(48))
                    provider.providerUpdatedAt?.let { KeyValueLine("Provider updated", it.take(25)) }
                    provider.fetchedAtEpochMs?.let { KeyValueLine("Last checked", relativeTime(it, nowMs)) }
                    provider.error?.let { Text("Error: $it", color = Cs.Red.copy(alpha = 0.85f), fontSize = 11.sp) }
                    LoadStateChip(provider.loadState)
                }
            },
            confirmButton = { TextButton(onClick = { detail = null }) { Text("Close", color = Cs.Cyan, fontSize = 12.sp) } }
        )
    }
}

@Composable
private fun AddEndpointDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String, String?) -> Unit
) {
    var name by rememberSaveable { mutableStateOf("") }
    var url by rememberSaveable { mutableStateOf("") }
    var token by rememberSaveable { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Cs.SurfaceAlt,
        title = { Text("Add cloud status endpoint", color = Cs.Text, fontSize = 15.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Any Statuspage v2 compatible endpoint (…/api/v2/status.json). Optional bearer token is encrypted with the Android Keystore and never logged.",
                    color = Cs.TextDim, fontSize = 11.sp, lineHeight = 15.sp
                )
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    placeholder = { Text("Name (e.g. My SaaS)", fontSize = 12.sp, color = Cs.TextFaint) },
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 13.sp, color = Cs.Text),
                    colors = cyberTextFieldColors()
                )
                OutlinedTextField(
                    value = url, onValueChange = { url = it },
                    placeholder = { Text("https://status.example.com/api/v2/status.json", fontSize = 11.sp, color = Cs.TextFaint) },
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = Cs.Text),
                    colors = cyberTextFieldColors()
                )
                OutlinedTextField(
                    value = token, onValueChange = { token = it },
                    placeholder = { Text("Bearer token (optional)", fontSize = 12.sp, color = Cs.TextFaint) },
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = Cs.Text),
                    colors = cyberTextFieldColors()
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = name.isNotBlank() && url.isNotBlank(),
                onClick = { onAdd(name, url, token.takeIf { it.isNotBlank() }) }
            ) { Text("ADD", color = Cs.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = Cs.TextDim, fontSize = 12.sp) } }
    )
}

/** Attack vector analytics from real blocked events. */
@Composable
fun AttackVectorsCard(
    vectors: List<CategoryCount>,
    topBlocked: List<DomainBlockCount>,
    modifier: Modifier = Modifier
) {
    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Amber) {
        CardHeader(
            "Attack Vector Analytics", accent = Cs.Amber,
            trailing = { SourceChip(CsDataSource.ON_DEVICE) }
        )
        if (vectors.isEmpty()) {
            EmptyState("No blocked events in the last 24 h to analyze.", icon = "◔")
        } else {
            VectorBars(vectors)
        }
        if (topBlocked.isNotEmpty()) {
            Text("TOP BLOCKED DOMAINS (ALL HISTORY)", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
            topBlocked.take(5).forEach { domain ->
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        domain.domain, color = Cs.Text, fontSize = 10.sp, fontFamily = Cs.mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                    )
                    Text(domain.count.toString(), color = Cs.Amber, fontSize = 10.sp, fontFamily = Cs.mono, fontWeight = FontWeight.Bold)
                }
            }
        }
        HonestNote("Categories reflect which filter layer blocked each DNS request on this device — a local view, not global attack telemetry.")
    }
}

/** Compliance monitoring: real local checks + exportable report. */
@Composable
fun ComplianceCard(
    report: ComplianceReport?,
    onRerun: () -> Unit,
    onExport: () -> Unit,
    modifier: Modifier = Modifier
) {
    var expandedId by rememberSaveable { mutableStateOf<String?>(null) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Green) {
        CardHeader(
            "Compliance Monitor", accent = Cs.Green,
            trailing = { SourceChip(CsDataSource.LOCAL_CHECK) }
        )
        if (report == null) {
            EmptyState("Waiting for the first device configuration scan…", icon = "◌")
            return@NeonCard
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            ScoreRing(report.score)
            Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.weight(1f)) {
                KeyValueLine("Passed", report.passed.toString(), Cs.Green)
                KeyValueLine("Warnings", report.warnings.toString(), Cs.Amber)
                KeyValueLine("Failed", report.failed.toString(), Cs.Red)
                KeyValueLine("Unavailable", report.unavailable.toString(), Cs.Steel)
            }
        }
        report.checks.forEach { check ->
            ComplianceRow(check, expandedId == check.id) {
                expandedId = if (expandedId == check.id) null else check.id
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onRerun, modifier = Modifier.weight(1f)) {
                Text("Re-run checks", color = Cs.Cyan, fontSize = 11.sp)
            }
            TextButton(onClick = onExport, modifier = Modifier.weight(1f)) {
                Text("Export JSON report", color = Cs.Green, fontSize = 11.sp)
            }
        }
        HonestNote("Local configuration checks mapped to public best practices (CIS / NIST CSF) for orientation — not a formal certification audit. Signals Android hides are marked unavailable.")
    }
}

@Composable
private fun ComplianceRow(check: ComplianceCheck, expanded: Boolean, onClick: () -> Unit) {
    val color = when (check.status) {
        ComplianceStatus.PASS -> Cs.Green
        ComplianceStatus.WARN -> Cs.Amber
        ComplianceStatus.FAIL -> Cs.Red
        ComplianceStatus.UNAVAILABLE -> Cs.Steel
    }
    val symbol = when (check.status) {
        ComplianceStatus.PASS -> "✓"
        ComplianceStatus.WARN -> "!"
        ComplianceStatus.FAIL -> "✗"
        ComplianceStatus.UNAVAILABLE -> "?"
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Cs.Surface.copy(alpha = 0.6f))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(symbol, color = color, fontSize = 13.sp, fontWeight = FontWeight.Bold, fontFamily = Cs.mono)
            Column(Modifier.weight(1f)) {
                Text(check.title, color = Cs.Text, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                Text(check.framework, color = Cs.TextFaint, fontSize = 8.sp, fontFamily = Cs.mono)
            }
            StatusChip(check.status.name, color)
        }
        if (expanded) {
            Text(check.detail, color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp)
            check.recommendation?.let {
                Text("→ $it", color = Cs.Cyan.copy(alpha = 0.85f), fontSize = 10.sp, lineHeight = 14.sp)
            }
        }
    }
}
