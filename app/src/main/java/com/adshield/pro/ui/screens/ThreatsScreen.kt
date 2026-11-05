package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.engine.detection.LocalDetectionEngine
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.cybershield.severityColor
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Active-threat console: real logged events with search, severity filtering and per-domain
 * history, plus the local detection engine's findings. Nothing here is simulated — an empty
 * result says why (no traffic, logging off, or filters matched nothing).
 */
@Composable
fun ThreatsScreen(
    cyberViewModel: CyberShieldViewModel,
    onShowFeedback: (String) -> Unit
) {
    val query by cyberViewModel.threatQuery.collectAsStateWithLifecycle()
    val severityFilter by cyberViewModel.severityFilter.collectAsStateWithLifecycle()
    val includeAllowed by cyberViewModel.includeAllowed.collectAsStateWithLifecycle()
    val threats by cyberViewModel.filteredThreats.collectAsStateWithLifecycle()
    val detection by cyberViewModel.detectionReport.collectAsStateWithLifecycle()
    var detailRecord by remember { mutableStateOf<DnsActivityRecord?>(null) }
    val listState = rememberLazyListState()
    val timeFormat = remember { SimpleDateFormat("MMM d, HH:mm:ss", Locale.US) }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "threats-controls", contentType = "controls") {
                CyberPanel(title = "Active threats", subtitle = "Search and filter the real event log") {
                    OutlinedTextField(
                        value = query,
                        onValueChange = cyberViewModel::setThreatQuery,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = SkyBlueGlow) },
                        placeholder = { Text("Domain, list or rule…", fontSize = 13.sp) },
                        label = { Text("Search events") }
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                        FilterChip(
                            selected = severityFilter == null,
                            onClick = { cyberViewModel.setSeverityFilter(null) },
                            label = { Text("All", fontSize = 11.sp) },
                            colors = FilterChipDefaults.filterChipColors(selectedContainerColor = ElectricBlue.copy(alpha = 0.25f), selectedLabelColor = SkyBlueGlow)
                        )
                        ThreatSeverity.entries.forEach { severity ->
                            FilterChip(
                                selected = severityFilter == severity,
                                onClick = { cyberViewModel.setSeverityFilter(if (severityFilter == severity) null else severity) },
                                label = { Text(severity.label, fontSize = 11.sp) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = severityColor(severity).copy(alpha = 0.22f),
                                    selectedLabelColor = severityColor(severity)
                                )
                            )
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    FilterChip(
                        selected = includeAllowed,
                        onClick = { cyberViewModel.setIncludeAllowed(!includeAllowed) },
                        label = { Text("Include allowed queries", fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = ElectricBlue.copy(alpha = 0.25f), selectedLabelColor = SkyBlueGlow)
                    )
                }
            }

            if (detection.findings.isNotEmpty()) {
                item(key = "threats-findings-header", contentType = "header") {
                    Text(
                        "DETECTION FINDINGS (${detection.findings.size})",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.8.sp
                    )
                }
                items(detection.findings, key = { it.id }, contentType = { "finding" }) { finding ->
                    FindingRow(finding)
                }
            }

            item(key = "threats-events-header", contentType = "header") {
                Text(
                    "EVENT LOG (${threats.size})",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp
                )
            }

            if (threats.isEmpty()) {
                item(key = "threats-empty", contentType = "empty") {
                    CyberPanel(title = "No matching events", subtitle = "Real data only") {
                        Text(
                            "No logged events match the current filters. Turn on protection and generate traffic, " +
                                "clear the filters, or enable detailed DNS logging in Settings. Nothing is fabricated to fill this list.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 12.sp
                        )
                    }
                }
            } else {
                items(threats, key = { it.id }, contentType = { "event" }) { record ->
                    ThreatEventRow(
                        record = record,
                        timeLabel = timeFormat.format(Date(record.timestampEpochMs)),
                        onClick = { detailRecord = record }
                    )
                }
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }

    detailRecord?.let { record ->
        val history = remember(record.domain, threats) {
            threats.filter { it.domain == record.domain }.take(20)
        }
        AlertDialog(
            onDismissRequest = { detailRecord = null },
            title = { Text(record.domain, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    val severity = ThreatSeverity.of(record)
                    DetailLine("Verdict", if (record.isBlocked) "Blocked" else "Allowed")
                    DetailLine("Severity", severity?.label ?: "Not a threat (allowed)")
                    DetailLine("Category", record.category?.displayName ?: "—")
                    DetailLine("Source list", record.sourceList.ifBlank { "—" })
                    DetailLine("Matched rule", record.matchedRule ?: "—")
                    DetailLine("Query type", record.queryType)
                    DetailLine("Protocol", record.protocolUsed)
                    DetailLine("Latency", if (record.latencyMs > 0) "${record.latencyMs} ms" else "—")
                    DetailLine("Time", timeFormat.format(Date(record.timestampEpochMs)))
                    Spacer(Modifier.height(6.dp))
                    Text("EVENT HISTORY (${history.size})", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.6.sp)
                    history.forEach { item ->
                        Text(
                            "${timeFormat.format(Date(item.timestampEpochMs))} · ${if (item.isBlocked) "blocked" else "allowed"}",
                            color = if (item.isBlocked) AlertRed else MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 11.sp
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    cyberViewModel.setThreatQuery(record.domain)
                    detailRecord = null
                    onShowFeedback("Filtering events for ${record.domain}")
                }) { Text("Filter this domain") }
            },
            dismissButton = { TextButton(onClick = { detailRecord = null }) { Text("Close") } }
        )
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.width(96.dp))
        Text(value, color = Color.White, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun FindingRow(finding: LocalDetectionEngine.Finding) {
    val color = severityColor(finding.severity)
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF071526))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(8.dp))
            Text(finding.title, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(finding.severity.label.uppercase(), color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(4.dp))
        Text(finding.detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
        Spacer(Modifier.height(4.dp))
        Text(
            "${finding.stage.label} · evidence: ${finding.evidence.take(2).joinToString("; ")}",
            color = CyberCyan.copy(alpha = 0.8f),
            fontSize = 10.sp
        )
    }
}

@Composable
private fun ThreatEventRow(record: DnsActivityRecord, timeLabel: String, onClick: () -> Unit) {
    val severity = ThreatSeverity.of(record)
    val color = severity?.let { severityColor(it) } ?: MaterialTheme.colorScheme.onSurfaceVariant
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF071526))
            .border(1.dp, NavyBorder.copy(alpha = 0.6f), RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(record.domain, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                "${if (record.isBlocked) "Blocked" else "Allowed"} · ${record.category?.displayName ?: "no category"} · ${record.sourceList.ifBlank { "policy" }}",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(severity?.label?.uppercase() ?: "ALLOWED", color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Text(timeLabel, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp)
        }
    }
}
