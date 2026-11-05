package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CarCrash
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Construction
import androidx.compose.material.icons.filled.Engineering
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material.icons.filled.LocalPolice
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Thunderstorm
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.traffic.IncidentKind
import com.adshield.pro.gps.traffic.SegmentTrafficState
import com.adshield.pro.gps.traffic.TrafficIncident
import com.adshield.pro.gps.traffic.formatAge
import com.adshield.pro.gps.traffic.formatConfidence
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsEmptyState
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsGrey
import com.adshield.pro.gps.ui.GpsInlineNotice
import com.adshield.pro.gps.ui.GpsKeyValue
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.traffic.TrafficRepository.TrafficStatus
import com.adshield.pro.gps.ui.TrafficLegend
import com.adshield.pro.gps.ui.congestionColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * LIVE TRAFFIC — the community traffic surface.
 *
 * The screen is built around one rule: **never show a colour you cannot justify.** A segment without
 * observations renders grey with the reason, and the whole tab renders an explicit UNKNOWN state
 * when there is nothing measured yet. Every measurement shows its sample count, age and confidence.
 */
@Composable
fun TrafficScreen(
    state: GpsUiState,
    frame: GpsFrame,
    segments: List<SegmentTrafficState>,
    status: TrafficStatus,
    incidents: List<TrafficIncident>,
    gateLog: List<String>,
    online: Boolean,
    onSync: () -> Unit,
    onToggleContribution: (Boolean) -> Unit,
    onReport: (IncidentKind, String?) -> Unit,
    onDismissIncident: (String) -> Unit,
    onSetBackend: (String) -> Unit,
    onClearReportMessage: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showReportSheet by remember { mutableStateOf(false) }
    var backendUrl by remember { mutableStateOf(state.trafficBackendUrl) }
    val measured = segments.filter { it.isMeasured }
    val unknown = segments.filterNot { it.isMeasured }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "traffic-status") {
            Spacer(Modifier.height(10.dp))
            GpsPanel(accent = if (measured.isEmpty()) GpsGrey else GpsGreen) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Live traffic", accent = GpsCyan, modifier = Modifier.weight(1f))
                        GpsChip(
                            text = if (online) "ONLINE" else "OFFLINE",
                            color = if (online) GpsGreen else GpsAmber
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(8.dp)
                                .clip(RoundedCornerShape(50))
                                .background(if (measured.isEmpty()) GpsGrey else GpsGreen)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            status.message,
                            color = GpsTextPrimary,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            lineHeight = 16.sp
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    TrafficLegend()
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatBlock("Measured", "${measured.size}", GpsGreen)
                        StatBlock("Unknown", "${unknown.size}", GpsGrey)
                        StatBlock("Own samples", "${status.ownSamples}", GpsCyan)
                        StatBlock("Queued", "${status.queuedSamples}", GpsAmber)
                    }
                    Spacer(Modifier.height(8.dp))
                    GpsKeyValue("Last sync", status.lastSyncAtMs.takeIf { it > 0 }?.let { formatClock(it) } ?: "never")
                    GpsKeyValue(
                        "Community backend",
                        when {
                            !status.backendConfigured -> "not configured"
                            !status.backendEnabled -> "configured, disabled"
                            else -> "connected"
                        }
                    )
                    if (status.lastError != null) {
                        Spacer(Modifier.height(6.dp))
                        GpsInlineNotice(status.lastError, GpsAmber)
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = onSync,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsCyan.copy(alpha = 0.16f),
                                contentColor = GpsCyan
                            ),
                            shape = RoundedCornerShape(8.dp),
                            enabled = online
                        ) {
                            Icon(Icons.Default.Sync, null, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Sync", fontSize = 11.sp)
                        }
                        Button(
                            onClick = { showReportSheet = !showReportSheet },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsBackground,
                                contentColor = if (state.policy.allowIncidentReporting) GpsCyan else GpsTextDim
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.Default.Report, null, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Report", fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        if (state.reportMessage != null) {
            item(key = "traffic-report-message") {
                Column {
                    GpsInlineNotice(
                        state.reportMessage,
                        if (state.reportAccepted) GpsGreen else GpsAmber
                    )
                    Text(
                        "Dismiss",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        modifier = Modifier
                            .clickable { onClearReportMessage() }
                            .padding(top = 4.dp)
                    )
                }
            }
        }

        if (showReportSheet) {
            item(key = "traffic-report-kinds") {
                GpsPanel {
                    Column(Modifier.padding(12.dp)) {
                        GpsSectionTitle("Report an incident", accent = GpsCyan)
                        Spacer(Modifier.height(4.dp))
                        if (!state.policy.allowIncidentReporting) {
                            GpsInlineNotice(
                                "Incident reporting is switched off. Enable it in Location security to contribute reports.",
                                GpsAmber
                            )
                            Spacer(Modifier.height(6.dp))
                        }
                        IncidentKind.entries.forEach { kind ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = state.policy.allowIncidentReporting && frame.fix != null) {
                                        onReport(kind, null)
                                        showReportSheet = false
                                    }
                                    .padding(vertical = 7.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    kindIcon(kind),
                                    contentDescription = null,
                                    tint = when (kind) {
                                        IncidentKind.ACCIDENT -> GpsRed
                                        IncidentKind.ROAD_CLOSED -> GpsRed
                                        IncidentKind.POLICE -> GpsCyan
                                        else -> GpsAmber
                                    },
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(Modifier.width(10.dp))
                                Text(
                                    kind.label,
                                    color = GpsTextPrimary,
                                    fontSize = 12.sp,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    "expires ${kind.defaultLifetimeMinutes / 60}h",
                                    color = GpsTextDim,
                                    fontSize = 9.sp
                                )
                            }
                        }
                        if (frame.fix == null) {
                            Spacer(Modifier.height(6.dp))
                            GpsInlineNotice("A GPS fix is required before reporting a position.", GpsAmber)
                        }
                    }
                }
            }
        }

        if (segments.isEmpty()) {
            item(key = "traffic-empty") {
                GpsEmptyState(
                    title = "UNKNOWN — no roads loaded",
                    detail = "Traffic colours need road segments. Calculate a route, or load an offline " +
                        "graph, and the segments around you become visible. Green means measured " +
                        "free-flow, never 'we assume it is fine'.",
                    icon = Icons.Default.CloudOff,
                    accent = GpsGrey
                )
            }
        } else {
            item(key = "traffic-segments-header") {
                GpsSectionTitle("Road segments (${segments.size})", accent = GpsCyan)
            }
            items(segments, key = { it.segmentId }, contentType = { "traffic-segment" }) { segment ->
                SegmentRow(segment)
            }
        }

        if (incidents.isNotEmpty()) {
            item(key = "traffic-incidents-header") {
                GpsSectionTitle("Active reports (${incidents.size})", accent = GpsCyan)
            }
            items(incidents, key = { it.id }, contentType = { "incident" }) { incident ->
                IncidentRow(incident = incident, onDismiss = { onDismissIncident(incident.id) })
            }
        }

        item(key = "traffic-contribution") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Contribution", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    val contribute = state.policy.contributeTraffic
                    Button(
                        onClick = { onToggleContribution(!contribute) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (contribute) GpsRed.copy(alpha = 0.15f) else GpsCyan.copy(alpha = 0.15f),
                            contentColor = if (contribute) GpsRed else GpsCyan
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            if (contribute) "Stop sharing anonymous speed" else "Opt in: share anonymous speed",
                            fontSize = 11.sp
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "What is shared: one average speed per road segment, rounded, with a random " +
                            "per-install token and no coordinates. What is never shared: your route, " +
                            "your device id, your account.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    GpsSectionTitle("Community backend", accent = GpsCyan)
                    Spacer(Modifier.height(4.dp))
                    androidx.compose.material3.OutlinedTextField(
                        value = backendUrl,
                        onValueChange = { backendUrl = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("https://your-worker.example.workers.dev", color = GpsTextDim, fontSize = 11.sp) },
                        singleLine = true,
                        colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                            focusedTextColor = GpsTextPrimary,
                            unfocusedTextColor = GpsTextPrimary,
                            focusedBorderColor = GpsCyan,
                            unfocusedBorderColor = GpsBorder
                        )
                    )
                    Spacer(Modifier.height(6.dp))
                    Button(
                        onClick = { onSetBackend(backendUrl) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GpsBackground,
                            contentColor = GpsCyan
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Save endpoint", fontSize = 11.sp)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "The backend is optional and runs on a free Cloudflare Worker + D1 + PostGIS-ready " +
                            "schema (see traffic/ in the repository). Without it the app uses only what " +
                            "this device and other opted-in installs recorded locally.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                }
            }
        }

        if (gateLog.isNotEmpty()) {
            item(key = "traffic-gate-log") {
                GpsPanel {
                    Column(Modifier.padding(12.dp)) {
                        GpsSectionTitle("Observation log", accent = GpsCyan)
                        Spacer(Modifier.height(6.dp))
                        gateLog.take(8).forEach { line ->
                            Text(
                                line,
                                color = GpsTextSecondary,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                lineHeight = 13.sp
                            )
                        }
                    }
                }
            }
        }

        item(key = "traffic-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text(
                    "Traffic is community-sourced from opted-in devices only. No commercial traffic " +
                        "provider is used, and no value is interpolated: a grey road has no recent " +
                        "observations.",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}

@Composable
private fun SegmentRow(segment: SegmentTrafficState) {
    val color = congestionColor(segment.level)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(9.dp))
            .background(GpsPanel.copy(alpha = 0.65f))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(9.dp))
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(width = 4.dp, height = 34.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(color)
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                segment.segmentName ?: "Unnamed road",
                color = GpsTextPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                maxLines = 1
            )
            Text(
                buildString {
                    append("${segment.level.label} · ")
                    append(segment.averageSpeedKmh?.let { "%.0f km/h".format(it) } ?: "no measured speed")
                    if (segment.freeFlowSpeedKmh != null) append(" · free flow %.0f".format(segment.freeFlowSpeedKmh))
                },
                color = GpsTextSecondary,
                fontSize = 9.sp
            )
            Text(
                "${formatAge(segment.ageMinutes)} · ${segment.sampleCount} samples · " +
                    "${segment.reporterCount} reporter(s) · confidence ${formatConfidence(segment.confidence)}",
                color = GpsTextDim,
                fontSize = 8.sp
            )
            if (segment.incidents.isNotEmpty()) {
                Text(
                    "${segment.incidents.size} active report(s): " +
                        segment.incidents.joinToString(", ") { it.kind.label },
                    color = GpsRed,
                    fontSize = 9.sp
                )
            }
        }
        GpsChip(text = segment.source.label, color = color)
    }
}

@Composable
private fun IncidentRow(incident: TrafficIncident, onDismiss: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(9.dp))
            .background(GpsPanel.copy(alpha = 0.6f))
            .border(1.dp, GpsRed.copy(alpha = 0.25f), RoundedCornerShape(9.dp))
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(kindIcon(incident.kind), null, tint = GpsRed, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                "${incident.kind.label} · ${incident.roadName ?: "unattributed road"}",
                color = GpsTextPrimary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium
            )
            Text(
                "${formatAge(incident.ageMinutes)} · ${incident.confirmations} confirmation(s)" +
                    (incident.notes?.let { " · $it" } ?: ""),
                color = GpsTextDim,
                fontSize = 9.sp
            )
        }
        Text(
            "Dismiss",
            color = GpsTextSecondary,
            fontSize = 9.sp,
            modifier = Modifier
                .clickable(onClick = onDismiss)
                .padding(6.dp)
        )
    }
}

@Composable
private fun StatBlock(label: String, value: String, color: androidx.compose.ui.graphics.Color) {
    Column {
        Text(label.uppercase(), color = GpsTextDim, fontSize = 8.sp, letterSpacing = 0.8.sp)
        Text(value, color = color, fontSize = 16.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
    }
}

private fun kindIcon(kind: IncidentKind): ImageVector = when (kind) {
    IncidentKind.ACCIDENT -> Icons.Default.CarCrash
    IncidentKind.HAZARD -> Icons.Default.WarningAmber
    IncidentKind.CONSTRUCTION -> Icons.Default.Construction
    IncidentKind.ROAD_CLOSED -> Icons.Default.Engineering
    IncidentKind.POLICE -> Icons.Default.LocalPolice
    IncidentKind.WEATHER -> Icons.Default.Thunderstorm
    IncidentKind.BROKEN_DOWN -> Icons.Default.CarCrash
}

private fun formatClock(epochMs: Long): String =
    SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(epochMs))
