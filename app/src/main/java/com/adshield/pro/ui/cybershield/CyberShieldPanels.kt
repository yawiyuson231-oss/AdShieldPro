package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.PrivacyTip
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.SeverityCounts
import com.adshield.pro.domain.model.ThreatSeverity
import com.adshield.pro.domain.model.TimeBucketStat
import com.adshield.pro.engine.cloud.CloudStatusState
import com.adshield.pro.engine.compliance.ComplianceChecker
import com.adshield.pro.engine.detection.LocalDetectionEngine
import com.adshield.pro.engine.intel.CountryThreat
import com.adshield.pro.engine.intel.IntelSource
import com.adshield.pro.engine.intel.ThreatIntelAggregation
import com.adshield.pro.engine.intel.ThreatIntelState
import com.adshield.pro.ui.components.BarRow
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.DonutChart
import com.adshield.pro.ui.components.DonutSegment
import com.adshield.pro.ui.components.MetricSpec
import com.adshield.pro.ui.components.ResponsiveMetrics
import com.adshield.pro.ui.components.Sparkline
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.model.DashboardPresentation
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.theme.formatInteger
import com.adshield.pro.ui.viewmodel.IntelMapFilter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Severity palette shared by every severity surface so the console reads consistently. */
fun severityColor(severity: ThreatSeverity): Color = when (severity) {
    ThreatSeverity.CRITICAL -> AlertRed
    ThreatSeverity.HIGH -> Color(0xFFFF7A45)
    ThreatSeverity.MEDIUM -> WarningAmber
    ThreatSeverity.LOW -> EmeraldPrimary
}

// --------------------------------------------------------------------- Threat overview

@Composable
fun ThreatOverviewPanel(
    totalThreats: Long,
    severity: SeverityCounts,
    chartBuckets: List<TimeBucketStat>,
    recentLogs: List<DnsActivityRecord>,
    modifier: Modifier = Modifier
) {
    val trends = rememberSeverityTrends(recentLogs)
    val unclassified = (totalThreats - severity.total).coerceAtLeast(0L)
    CyberPanel(
        title = "Threat overview",
        subtitle = "Real-time summary · blocked queries on this device",
        modifier = modifier
    ) {
        Sparkline(
            values = chartBuckets.map { it.blockedQueries },
            secondaryValues = chartBuckets.map { it.totalQueries },
            lineColor = AlertRed,
            secondaryColor = ElectricBlue.copy(alpha = 0.5f),
            modifier = Modifier.fillMaxWidth().height(72.dp)
        )
        Spacer(Modifier.height(12.dp))
        ResponsiveMetrics(
            columns = 4,
            metrics = listOf(
                MetricSpec("Total threats", formatInteger(totalThreats), "All recorded blocks", Color.White),
                MetricSpec("High", formatInteger(severity.high), trendLabel(trends[ThreatSeverity.HIGH]), severityColor(ThreatSeverity.HIGH)),
                MetricSpec("Medium", formatInteger(severity.medium), trendLabel(trends[ThreatSeverity.MEDIUM]), severityColor(ThreatSeverity.MEDIUM)),
                MetricSpec("Low", formatInteger(severity.low), trendLabel(trends[ThreatSeverity.LOW]), severityColor(ThreatSeverity.LOW))
            )
        )
        if (severity.critical > 0L) {
            Spacer(Modifier.height(8.dp))
            Text(
                "${formatInteger(severity.critical)} critical (malware/phishing) blocks included in the total.",
                color = AlertRed,
                fontSize = 11.sp
            )
        }
        if (unclassified > 0L) {
            Spacer(Modifier.height(6.dp))
            Text(
                "${formatInteger(unclassified)} earlier block(s) predate severity tracking and are counted in the total only.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }
    }
}

/** Percent change of the last 24h vs the previous 24h, per severity. Null = no baseline. */
@Composable
private fun rememberSeverityTrends(logs: List<DnsActivityRecord>): Map<ThreatSeverity, Float?> {
    return androidx.compose.runtime.remember(logs) {
        val now = System.currentTimeMillis()
        val dayMs = 24 * 60 * 60 * 1000L
        val current = SeverityCounts.from(logs.filter { now - it.timestampEpochMs <= dayMs })
        val previous = SeverityCounts.from(
            logs.filter { now - it.timestampEpochMs in (dayMs + 1)..(2 * dayMs) }
        )
        ThreatSeverity.entries.associateWith { severity ->
            val prev = previous.countFor(severity)
            val cur = current.countFor(severity)
            if (prev == 0L) null else (cur - prev) * 100f / prev
        }
    }
}

private fun trendLabel(trend: Float?): String = when {
    trend == null -> "24h trend: no baseline"
    trend > 0f -> "▲ ${kotlin.math.abs(trend).toInt()}% vs prior 24h"
    trend < 0f -> "▼ ${kotlin.math.abs(trend).toInt()}% vs prior 24h"
    else -> "level vs prior 24h"
}

// --------------------------------------------------------------------- Global threat map

@Composable
fun GlobalThreatMapPanel(
    intelState: ThreatIntelState,
    countryThreats: List<CountryThreat>,
    mapFilter: IntelMapFilter,
    selectedCountry: String?,
    filteredIndicatorCount: Int,
    onFilterChange: (IntelMapFilter) -> Unit,
    onSelectCountry: (String?) -> Unit,
    onSync: () -> Unit,
    modifier: Modifier = Modifier
) {
    val selected = countryThreats.firstOrNull { it.countryCode == selectedCountry }
    val unmapped = ThreatIntelAggregation.unmappedCount(
        when (mapFilter) {
            IntelMapFilter.ALL -> intelState.indicators
            IntelMapFilter.BOTNET_C2 -> intelState.indicators.filter { it.kind == com.adshield.pro.engine.intel.IndicatorKind.BOTNET_C2 }
            IntelMapFilter.MALWARE_URLS -> intelState.indicators.filter { it.kind == com.adshield.pro.engine.intel.IndicatorKind.MALWARE_URL }
        }
    )
    CyberPanel(
        title = "Global threat map",
        subtitle = "Verified intelligence · abuse.ch feeds",
        modifier = modifier,
        trailing = {
            if (intelState.isRefreshing) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
            } else {
                IconButton(onClick = onSync, modifier = Modifier.size(28.dp)) {
                    Icon(Icons.Default.Refresh, contentDescription = "Sync threat intelligence", tint = SkyBlueGlow, modifier = Modifier.size(18.dp))
                }
            }
        }
    ) {
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(IntelMapFilter.entries.toList(), key = { it.name }) { filter ->
                FilterChip(
                    selected = mapFilter == filter,
                    onClick = { onFilterChange(filter) },
                    label = { Text(filter.label, fontSize = 11.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = ElectricBlue.copy(alpha = 0.25f),
                        selectedLabelColor = SkyBlueGlow
                    )
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        WorldThreatMap(
            countryThreats = countryThreats,
            selectedCountry = selectedCountry,
            onSelectCountry = onSelectCountry
        )
        Spacer(Modifier.height(10.dp))
        when {
            selected != null -> {
                Text(
                    "${WorldMapData.displayName(selected.countryCode)} — ${selected.count} indicator(s)",
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp
                )
                Text(
                    buildString {
                        append("${selected.onlineCount} reported online")
                        if (selected.malwareFamilies.isNotEmpty()) {
                            append(" · families: ${selected.malwareFamilies.take(4).joinToString()}")
                        }
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp
                )
            }
            countryThreats.isEmpty() -> {
                Text(
                    if (intelState.hasAnyData) {
                        "The active filter has no geolocated indicators. URLhaus publishes no country data, so its URLs appear in the Intelligence list, not on the map."
                    } else if (intelState.feeds.all { it.status == com.adshield.pro.engine.intel.FeedFetchStatus.NOT_FETCHED }) {
                        "No threat intelligence loaded yet. Tap sync to fetch the public abuse.ch feeds. No markers are shown until real data arrives."
                    } else {
                        "No geolocated indicators in the cached feeds. Check the feed status in the Intelligence tab."
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp
                )
            }
            else -> {
                Text(
                    "${countryThreats.size} countries · ${countryThreats.sumOf { it.count }} geolocated indicators. Tap a marker for details.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp
                )
            }
        }
        if (unmapped > 0) {
            Spacer(Modifier.height(4.dp))
            Text(
                "$unmapped indicator(s) without location data are listed in Intelligence, never placed on the map.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }
        Spacer(Modifier.height(6.dp))
        val syncLabel = if (intelState.lastSyncEpochMs > 0L) {
            "Last sync ${SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(intelState.lastSyncEpochMs))}"
        } else {
            "Never synced"
        }
        val stale = intelState.feeds.any { it.isStale || it.status == com.adshield.pro.engine.intel.FeedFetchStatus.ERROR }
        Text(
            if (stale) "$syncLabel · cached data may be stale" else syncLabel,
            color = if (stale) WarningAmber else MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 10.sp
        )
    }
}

// --------------------------------------------------------------------- Detection engine

@Composable
fun DetectionEnginePanel(
    report: LocalDetectionEngine.DetectionReport,
    modifier: Modifier = Modifier,
    onOpenFindings: () -> Unit = {}
) {
    CyberPanel(
        title = "Threat detection engine",
        subtitle = "Local rule-based analysis · no cloud AI",
        modifier = modifier
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(64.dp).clip(CircleShape)
                    .background(ElectricBlue.copy(alpha = 0.10f))
                    .border(1.dp, ElectricBlue.copy(alpha = 0.5f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Default.Psychology, contentDescription = null, tint = SkyBlueGlow, modifier = Modifier.size(34.dp))
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                report.stages.forEach { stage ->
                    DetectionStageRow(stage)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                if (report.hasEnoughData) "Analysis coverage · ${report.analyzedEvents} real events"
                else "Waiting for logged events — nothing is simulated",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
            Text("${(report.coverage * 100).toInt()}%", color = SkyBlueGlow, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(5.dp))
        LinearProgressIndicator(
            progress = { report.coverage.coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp),
            color = ElectricBlue,
            trackColor = NavyBorder.copy(alpha = 0.5f)
        )
        if (report.findings.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "${report.findings.size} finding(s) · highest: ${report.findings.first().severity.label}",
                    color = severityColor(report.findings.first().severity),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
                TextButton(onClick = onOpenFindings) { Text("Review", fontSize = 11.sp) }
            }
        }
    }
}

@Composable
private fun DetectionStageRow(stage: LocalDetectionEngine.StageResult) {
    val complete = stage.status == LocalDetectionEngine.StageStatus.COMPLETE
    val color = if (complete) EmeraldPrimary else MaterialTheme.colorScheme.onSurfaceVariant
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(8.dp))
        Text(stage.stage.label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(
            if (complete) "${stage.findingCount} finding(s)" else "Needs data",
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1
        )
    }
}

// --------------------------------------------------------------------- Active threats

@Composable
fun ActiveThreatsPanel(
    severity: SeverityCounts,
    onOpenSeverity: (ThreatSeverity) -> Unit,
    modifier: Modifier = Modifier
) {
    val segments = ThreatSeverity.entries.map { s ->
        DonutSegment(s.label, severity.countFor(s), severityColor(s))
    }
    CyberPanel(title = "Active threats", subtitle = "By severity · persisted block history", modifier = modifier) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            DonutChart(
                segments = segments,
                centerValue = formatInteger(severity.total),
                centerLabel = "TOTAL",
                modifier = Modifier.size(124.dp)
            )
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                ThreatSeverity.entries.forEach { s ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(6.dp))
                            .clickable { onOpenSeverity(s) }
                            .padding(vertical = 2.dp, horizontal = 4.dp)
                    ) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(severityColor(s)))
                        Spacer(Modifier.width(8.dp))
                        Text(s.label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.weight(1f))
                        Text(formatInteger(severity.countFor(s)), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
                if (severity.total == 0L) {
                    Text("No blocked threats recorded yet.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                }
            }
        }
    }
}

// --------------------------------------------------------------------- Attack vectors

@Composable
fun AttackVectorsPanel(
    categories: List<com.adshield.pro.engine.aether.LiveNetworkModel.CategorySlice>,
    modifier: Modifier = Modifier
) {
    val blocked = categories.filter { it.lane != com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.ALLOWED }
    val total = blocked.sumOf { it.count }
    CyberPanel(title = "Top attack vectors", subtitle = "Share of recent blocked queries", modifier = modifier) {
        if (blocked.isEmpty() || total == 0L) {
            Text(
                "Nothing blocked in the recent log window yet. Vector shares appear here after real DNS traffic is filtered.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp
            )
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                blocked.sortedByDescending { it.count }.take(5).forEach { slice ->
                    val percent = slice.count * 100f / total
                    BarRow(slice.lane.label, "${percent.toInt()}%", percent, laneColor(slice.lane))
                }
            }
        }
    }
}

private fun laneColor(lane: com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane): Color = when (lane) {
    com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.ADS -> Color(0xFFFF6B6B)
    com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.TRACKERS -> WarningAmber
    com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.THREATS -> AlertRed
    com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.CUSTOM -> CyberCyan
    com.adshield.pro.engine.aether.LiveNetworkModel.TrafficLane.ALLOWED -> EmeraldPrimary
}

// --------------------------------------------------------------------- Activity feed

@Composable
fun ActivityFeedPanel(
    logs: List<DnsActivityRecord>,
    detailedLoggingEnabled: Boolean,
    onViewAll: () -> Unit,
    modifier: Modifier = Modifier
) {
    val timeFormat = androidx.compose.runtime.remember { SimpleDateFormat("HH:mm:ss", Locale.US) }
    CyberPanel(
        title = "Threat activity feed",
        subtitle = if (detailedLoggingEnabled) "Live updates from this device" else "Detailed DNS logging is off",
        modifier = modifier,
        trailing = { TextButton(onClick = onViewAll) { Text("View all", fontSize = 12.sp) } }
    ) {
        val events = logs.take(6)
        if (events.isEmpty()) {
            Text(
                if (detailedLoggingEnabled) "No DNS events logged yet. Turn on protection and open an app to populate this feed."
                else "Enable detailed logging in Settings to see per-domain events. Aggregate counters still work.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp
            )
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                events.forEach { record ->
                    FeedEventRow(record, timeFormat.format(Date(record.timestampEpochMs)))
                }
            }
        }
    }
}

@Composable
private fun FeedEventRow(record: DnsActivityRecord, time: String) {
    val severity = DashboardPresentation.eventSeverity(record)
    val color = when (severity) {
        "CRITICAL" -> AlertRed
        "HIGH" -> Color(0xFFFF7A45)
        "MEDIUM" -> WarningAmber
        "CUSTOM" -> CyberCyan
        else -> EmeraldPrimary
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.Surface(color = color.copy(alpha = 0.16f), shape = RoundedCornerShape(5.dp)) {
            Text(severity, color = color, fontSize = 8.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp))
        }
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(DashboardPresentation.eventTitle(record), color = Color.White, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(record.domain, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Text(time, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
    }
}

// --------------------------------------------------------------------- Status cards

@Composable
fun StatusCardsRow(
    endpointCount: Int,
    endpointFlagged: Int?,
    cloud: CloudStatusState,
    networkTotalToday: Long,
    networkBlockedToday: Long,
    networkActive: Boolean,
    chartBuckets: List<TimeBucketStat>,
    onOpenEndpoints: () -> Unit,
    onOpenCloud: () -> Unit,
    onOpenNetwork: () -> Unit,
    modifier: Modifier = Modifier
) {
    Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        StatusCard(
            title = "Endpoints",
            subtitle = "This device",
            icon = Icons.Default.Devices,
            statusText = when {
                !networkActive -> "Unprotected"
                endpointFlagged == null -> "Not audited"
                endpointFlagged == 0 -> "Protected"
                else -> "Attention"
            },
            statusColor = when {
                !networkActive -> AlertRed
                endpointFlagged == null -> WarningAmber
                endpointFlagged == 0 -> EmeraldPrimary
                else -> AlertRed
            },
            value = if (endpointCount > 0) formatInteger(endpointCount) else "—",
            valueLabel = "apps installed",
            riskText = when (endpointFlagged) {
                null -> "Audit not run"
                0 -> "0 flagged"
                else -> "$endpointFlagged flagged"
            },
            sparkValues = chartBuckets.map { it.totalQueries },
            onClick = onOpenEndpoints,
            modifier = Modifier.weight(1f)
        )
        StatusCard(
            title = "Cloud systems",
            subtitle = "Service status",
            icon = Icons.Default.Cloud,
            statusText = when {
                cloud.connectedCount == 0 -> "Not connected"
                cloud.incidentCount > 0 -> "Incidents"
                else -> "Operational"
            },
            statusColor = when {
                cloud.connectedCount == 0 -> MaterialTheme.colorScheme.onSurfaceVariant
                cloud.incidentCount > 0 -> WarningAmber
                else -> EmeraldPrimary
            },
            value = "${cloud.connectedCount}/${cloud.services.size}",
            valueLabel = "feeds connected",
            riskText = if (cloud.connectedCount == 0) "No account access" else "${cloud.incidentCount} incident(s)",
            sparkValues = emptyList(),
            onClick = onOpenCloud,
            modifier = Modifier.weight(1f)
        )
        StatusCard(
            title = "Network",
            subtitle = "DNS monitoring",
            icon = Icons.Default.Hub,
            statusText = if (networkActive) "Protected" else "Off",
            statusColor = if (networkActive) EmeraldPrimary else AlertRed,
            value = formatInteger(networkTotalToday),
            valueLabel = "queries today",
            riskText = "${formatInteger(networkBlockedToday)} blocked",
            sparkValues = chartBuckets.map { it.blockedQueries },
            onClick = onOpenNetwork,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun StatusCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    statusText: String,
    statusColor: Color,
    value: String,
    valueLabel: String,
    riskText: String,
    sparkValues: List<Long>,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFF071526))
            .border(1.dp, NavyBorder.copy(alpha = 0.85f), RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(12.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(title.uppercase(), color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.6.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            Box(Modifier.size(8.dp).clip(CircleShape).background(statusColor))
        }
        Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, maxLines = 1)
        Spacer(Modifier.height(10.dp))
        Icon(icon, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(26.dp))
        Spacer(Modifier.height(8.dp))
        Text(statusText, color = statusColor, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
        Text(value, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, maxLines = 1)
        Text(valueLabel, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, maxLines = 1)
        Text(riskText, color = if (riskText.startsWith("0")) EmeraldPrimary else AlertRed, fontSize = 10.sp, maxLines = 1)
        Spacer(Modifier.height(8.dp))
        if (sparkValues.isNotEmpty()) {
            Sparkline(values = sparkValues, lineColor = ElectricBlue, modifier = Modifier.fillMaxWidth().height(26.dp))
        } else {
            Box(Modifier.fillMaxWidth().height(26.dp))
        }
    }
}

// --------------------------------------------------------------------- Compliance

@Composable
fun CompliancePanel(
    report: ComplianceChecker.ComplianceReport?,
    isEvaluating: Boolean,
    onEvaluate: () -> Unit,
    onViewReport: () -> Unit,
    modifier: Modifier = Modifier
) {
    CyberPanel(
        title = "Compliance status",
        subtitle = "Local configuration checks · not a certification",
        modifier = modifier,
        trailing = {
            if (isEvaluating) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
            } else {
                StatusPill(
                    report?.scorePercent?.let { "$it%" } ?: "Not run",
                    if (report != null && (report.scorePercent ?: 0) >= 80) EmeraldPrimary else WarningAmber
                )
            }
        }
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            ComplianceChecker.Category.entries.forEach { category ->
                val summary = report?.categories?.firstOrNull { it.category == category }
                ComplianceRing(
                    label = category.label,
                    icon = when (category) {
                        ComplianceChecker.Category.DEVICE -> Icons.Default.Devices
                        ComplianceChecker.Category.DATA -> Icons.Default.Storage
                        ComplianceChecker.Category.NETWORK -> Icons.Default.Hub
                        ComplianceChecker.Category.PRIVACY -> Icons.Default.PrivacyTip
                    },
                    passRatio = summary?.passRatio,
                    evaluated = summary?.evaluated ?: 0
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        if (report == null) {
            Text(
                "No evaluation yet. Checks read real Android signals (lock screen, encryption, patch level, filtering) and AdShield settings.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onEvaluate) { Text("Evaluate device", fontSize = 12.sp) }
        } else {
            Text(
                "${report.checks.count { it.status == ComplianceChecker.CheckStatus.PASS }} passed · " +
                    "${report.checks.count { it.status == ComplianceChecker.CheckStatus.FAIL }} failed · " +
                    "${report.unknownCount} unknown",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onEvaluate) { Text("Re-evaluate", fontSize = 12.sp) }
                TextButton(onClick = onViewReport) { Text("View compliance report", fontSize = 12.sp) }
            }
        }
    }
}

@Composable
private fun ComplianceRing(
    label: String,
    icon: ImageVector,
    passRatio: Float?,
    evaluated: Int
) {
    val color = when {
        passRatio == null -> MaterialTheme.colorScheme.onSurfaceVariant
        passRatio >= 0.999f -> EmeraldPrimary
        passRatio >= 0.6f -> WarningAmber
        else -> AlertRed
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.size(52.dp), contentAlignment = Alignment.Center) {
            Canvas(Modifier.size(52.dp)) {
                val stroke = 3.5.dp.toPx()
                val diameter = size.minDimension - stroke
                val topLeft = Offset((size.width - diameter) / 2f, (size.height - diameter) / 2f)
                drawArc(
                    color = NavyBorder.copy(alpha = 0.5f),
                    startAngle = -90f, sweepAngle = 360f, useCenter = false,
                    topLeft = topLeft, size = Size(diameter, diameter),
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )
                if (passRatio != null && passRatio > 0f) {
                    drawArc(
                        color = color,
                        startAngle = -90f, sweepAngle = 360f * passRatio, useCenter = false,
                        topLeft = topLeft, size = Size(diameter, diameter),
                        style = Stroke(stroke, cap = StrokeCap.Round)
                    )
                }
            }
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.height(4.dp))
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, maxLines = 1)
        Text(
            if (passRatio == null) "Unknown" else "${(passRatio * 100).toInt()}%",
            color = color,
            fontSize = 9.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}
