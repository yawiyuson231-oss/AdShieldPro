package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import com.adshield.pro.cybershield.CsDataSource
import com.adshield.pro.cybershield.CsEventAction
import com.adshield.pro.cybershield.CsSeverity
import com.adshield.pro.cybershield.HourBucket
import com.adshield.pro.cybershield.ThreatEvent
import com.adshield.pro.cybershield.ThreatIncident
import com.adshield.pro.cybershield.ThreatStats
import com.adshield.pro.domain.model.TimeBucketStat

/** Threat overview: severity distribution + real hourly activity + 7-day trend. */
@Composable
fun ThreatOverviewCard(
    stats: ThreatStats,
    hourly: List<HourBucket>,
    daily: List<TimeBucketStat>,
    modifier: Modifier = Modifier
) {
    NeonCard(modifier = modifier.fillMaxWidth()) {
        CardHeader(
            "Threat Overview",
            trailing = {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SourceChip(CsDataSource.ON_DEVICE)
                    StatusChip(stats.windowLabel, Cs.Steel)
                }
            }
        )
        if (stats.totalEvents == 0L) {
            EmptyState(
                "No DNS events recorded in this window yet. Activate protection and events will appear here as they are really observed.",
                icon = "◎"
            )
        } else {
            SeverityDonut(stats)
            Text("HOURLY ACTIVITY · LAST 24 H", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
            HourlyActivityBars(hourly)
        }
        if (daily.isNotEmpty() && daily.any { it.totalQueries > 0 }) {
            Text("7-DAY BLOCKED TREND", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
            TrendSparkline(daily)
        }
        HonestNote("Counts are computed from DNS events actually recorded on this device. Detailed logging can be disabled in Statistics → privacy.")
    }
}

/** Compact real-number stat tiles row. */
@Composable
fun StatTilesRow(
    stats: ThreatStats,
    intelCount: Int?,
    modifier: Modifier = Modifier
) {
    Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        StatTile("BLOCKED · 24H", stats.blocked.toString(), Cs.Red, Modifier.weight(1f))
        StatTile("ACTIVE THREATS", stats.activeThreatDomains.toString(), if (stats.activeThreatDomains > 0) Cs.Amber else Cs.Green, Modifier.weight(1f))
        StatTile("EVENTS · 24H", stats.totalEvents.toString(), Cs.Cyan, Modifier.weight(1f))
        StatTile("INTEL IOCS", intelCount?.toString() ?: "—", Cs.Purple, Modifier.weight(1f))
    }
}

@Composable
private fun StatTile(label: String, value: String, accent: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(Cs.Surface)
            .padding(vertical = 10.dp, horizontal = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        Text(value, color = accent, fontSize = 17.sp, fontWeight = FontWeight.Bold, fontFamily = Cs.mono, maxLines = 1)
        Text(label, color = Cs.TextFaint, fontSize = 7.sp, letterSpacing = 0.8.sp, fontFamily = Cs.mono, maxLines = 1)
    }
}

/** Active threats: search, severity filters, correlated incidents, details + history. */
@Composable
fun ActiveThreatsCard(
    incidents: List<ThreatIncident>,
    query: String,
    severityFilter: CsSeverity?,
    nowMs: Long,
    onQueryChange: (String) -> Unit,
    onSeverityChange: (CsSeverity?) -> Unit,
    onBlock: (String) -> Unit,
    onAllow: (String, Int, String) -> Boolean,
    onFalsePositive: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var detail by remember { mutableStateOf<ThreatIncident?>(null) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Red) {
        CardHeader(
            "Active Threats", accent = Cs.Red,
            trailing = { StatusChip("${incidents.size} shown", Cs.Steel) }
        )
        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            placeholder = { Text("Search domain or app…", fontSize = 12.sp, color = Cs.TextFaint) },
            leadingIcon = { Icon(Icons.Default.Search, null, tint = Cs.TextDim, modifier = Modifier.size(16.dp)) },
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 13.sp, color = Cs.Text),
            colors = cyberTextFieldColors(),
            shape = RoundedCornerShape(8.dp)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            SeverityFilterChip("All", severityFilter == null) { onSeverityChange(null) }
            listOf(CsSeverity.CRITICAL, CsSeverity.HIGH, CsSeverity.MEDIUM, CsSeverity.LOW).forEach { sev ->
                SeverityFilterChip(sev.name.take(4), severityFilter == sev, Cs.severityColor(sev)) {
                    onSeverityChange(if (severityFilter == sev) null else sev)
                }
            }
        }
        if (incidents.isEmpty()) {
            EmptyState(
                if (query.isNotBlank() || severityFilter != null) "No threats match the current filters."
                else "No active threats in the last 24 hours. Blocked malware, phishing and flagged patterns will appear here.",
                icon = "✓"
            )
        } else {
            incidents.take(20).forEach { incident ->
                IncidentRow(incident, nowMs) { detail = incident }
            }
            if (incidents.size > 20) {
                Text("+ ${incidents.size - 20} more — refine the search", color = Cs.TextFaint, fontSize = 10.sp)
            }
        }
        HonestNote("Grouped by domain from real blocked/flagged events (24 h window). Ads-only blocks are excluded from this list.")
    }

    detail?.let { incident ->
        IncidentDetailDialog(
            incident = incident,
            nowMs = nowMs,
            onDismiss = { detail = null },
            onBlock = { onBlock(incident.domain); detail = null },
            onAllow = { minutes, reason -> onAllow(incident.domain, minutes, reason) },
            onFalsePositive = { onFalsePositive(incident.domain); detail = null }
        )
    }
}

@Composable
private fun SeverityFilterChip(label: String, selected: Boolean, color: Color = Cs.Cyan, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 9.sp, fontFamily = Cs.mono) },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = Cs.Surface, labelColor = Cs.TextDim,
            selectedContainerColor = color.copy(alpha = 0.2f), selectedLabelColor = color
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true, selected = selected,
            borderColor = Cs.Border, selectedBorderColor = color.copy(alpha = 0.6f)
        ),
        modifier = Modifier.height(28.dp)
    )
}

@Composable
private fun IncidentRow(incident: ThreatIncident, nowMs: Long, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Cs.Surface.copy(alpha = 0.7f))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Canvas(Modifier.size(8.dp)) { drawCircle(Cs.severityColor(incident.severity)) }
        Column(Modifier.weight(1f)) {
            Text(
                incident.domain, color = Cs.Text, fontSize = 12.sp, fontFamily = Cs.mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                incident.summary, color = Cs.TextDim, fontSize = 10.sp,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            SeverityChip(incident.severity)
            Text(relativeTime(incident.lastSeenEpochMs, nowMs), color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
        }
    }
}

@Composable
private fun IncidentDetailDialog(
    incident: ThreatIncident,
    nowMs: Long,
    onDismiss: () -> Unit,
    onBlock: () -> Unit,
    onAllow: (Int, String) -> Boolean,
    onFalsePositive: () -> Unit
) {
    var allowMode by rememberSaveable { mutableStateOf(false) }
    var allowReason by rememberSaveable { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Cs.SurfaceAlt,
        title = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SeverityChip(incident.severity)
                    SourceChip(CsDataSource.ON_DEVICE)
                }
                Text(incident.domain, color = Cs.Text, fontSize = 15.sp, fontFamily = Cs.mono)
            }
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState())
            ) {
                KeyValueLine("Events (24 h)", incident.eventCount.toString())
                KeyValueLine("Blocked", incident.blockedCount.toString())
                KeyValueLine("First seen", clockTime(incident.firstSeenEpochMs))
                KeyValueLine("Last seen", "${clockTime(incident.lastSeenEpochMs)} (${relativeTime(incident.lastSeenEpochMs, nowMs)})")
                if (incident.apps.isNotEmpty()) KeyValueLine("Apps", incident.apps.joinToString(", "))
                if (incident.sources.isNotEmpty()) KeyValueLine("Sources", incident.sources.joinToString(", "))

                Text("EVENT HISTORY", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
                incident.events.take(12).forEach { event ->
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(clockTime(event.timestampEpochMs), color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
                        StatusChip(
                            event.action.name,
                            if (event.action == CsEventAction.BLOCKED) Cs.Red else Cs.Steel
                        )
                        Text(
                            event.domain, color = Cs.TextDim, fontSize = 10.sp, fontFamily = Cs.mono,
                            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                        )
                    }
                }
                val evidence = incident.events.firstOrNull()?.evidence ?: emptyList()
                if (evidence.isNotEmpty()) {
                    Text("EVIDENCE (LATEST EVENT)", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
                    evidence.forEach { Text("· $it", color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp) }
                }

                if (allowMode) {
                    Text(
                        "Temporary allowlisting is audited and auto-expires. It overrides AETHER auto-blocking only — filter-list rules are managed in Ad Blocker.",
                        color = Cs.Amber, fontSize = 10.sp, lineHeight = 14.sp
                    )
                    OutlinedTextField(
                        value = allowReason,
                        onValueChange = { allowReason = it },
                        placeholder = { Text("Reason (required for audit)", fontSize = 11.sp, color = Cs.TextFaint) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = Cs.Text),
                        colors = cyberTextFieldColors()
                    )
                }
            }
        },
        confirmButton = {
            if (allowMode) {
                TextButton(
                    onClick = { if (onAllow(15, allowReason)) onDismiss() },
                    enabled = allowReason.isNotBlank()
                ) { Text("I APPROVE · 15 MIN", color = Cs.Amber, fontSize = 11.sp, fontWeight = FontWeight.Bold) }
            } else {
                TextButton(onClick = onBlock) { Text("BLOCK DOMAIN", color = Cs.Red, fontSize = 11.sp, fontWeight = FontWeight.Bold) }
            }
        },
        dismissButton = {
            Row {
                if (allowMode) {
                    TextButton(onClick = { allowMode = false }) { Text("Back", color = Cs.TextDim, fontSize = 11.sp) }
                } else {
                    TextButton(onClick = { allowMode = true }) { Text("Allow 15 min", color = Cs.Amber, fontSize = 11.sp) }
                    TextButton(onClick = onFalsePositive) { Text("False positive", color = Cs.TextDim, fontSize = 11.sp) }
                }
            }
        }
    )
}

/** Live security activity feed with accurate timestamps and severity. */
@Composable
fun ActivityFeedCard(
    events: List<ThreatEvent>,
    live: Boolean,
    nowMs: Long,
    onOpenStatistics: () -> Unit,
    modifier: Modifier = Modifier
) {
    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Cyan) {
        CardHeader(
            "Security Activity",
            trailing = {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (live) StatusChip("● Live", Cs.Green, filled = false)
                    SourceChip(CsDataSource.ON_DEVICE)
                }
            }
        )
        if (events.isEmpty()) {
            EmptyState("No security events yet. The feed updates automatically as real DNS events are recorded.", icon = "≋")
        } else {
            events.take(25).forEach { event ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(7.dp)
                ) {
                    Text(clockTime(event.timestampEpochMs), color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
                    Canvas(Modifier.size(7.dp)) { drawCircle(Cs.severityColor(event.severity)) }
                    Column(Modifier.weight(1f)) {
                        Text(
                            event.domain, color = Cs.Text, fontSize = 11.sp, fontFamily = Cs.mono,
                            maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            buildString {
                                append(event.description)
                                event.appName?.let { append(" · $it") }
                            },
                            color = Cs.TextDim, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                    StatusChip(
                        if (event.action == CsEventAction.BLOCKED) "BLOCK" else "ALLOW",
                        if (event.action == CsEventAction.BLOCKED) Cs.Red else Cs.CyanDim
                    )
                }
            }
            TextButton(onClick = onOpenStatistics) {
                Text("Open full statistics →", color = Cs.Cyan, fontSize = 11.sp)
            }
        }
    }
}

@Composable
fun cyberTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = Cs.Cyan.copy(alpha = 0.6f),
    unfocusedBorderColor = Cs.Border,
    cursorColor = Cs.Cyan,
    focusedContainerColor = Cs.BackgroundDeep.copy(alpha = 0.4f),
    unfocusedContainerColor = Cs.BackgroundDeep.copy(alpha = 0.4f),
    focusedTextColor = Cs.Text,
    unfocusedTextColor = Cs.Text
)
