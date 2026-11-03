package com.adshield.pro.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PauseCircle
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.SportsEsports
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Newspaper
import androidx.compose.material.icons.filled.Warning
import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.AetherVerdict
import com.adshield.pro.engine.aether.ControlCenterReport
import com.adshield.pro.engine.aether.LiveFeedMapper
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber

/**
 * OmniShield X — LIVE MONITOR (Part 12).
 *
 * Shows what the VPN is REALLY doing right now: every row is a real DNS event
 * recorded by the tunnel (domain, app, verdict, list, latency). The pulse and
 * lane highlights react to real event arrival. Nothing here is simulated —
 * when the VPN is off, the monitor says so instead of inventing traffic.
 */
@Composable
fun LiveMonitorScreen(
    vpnState: VpnRuntimeState,
    recentLogs: List<DnsActivityRecord>,
    allTimeTotal: Long,
    allTimeBlocked: Long,
    allTimeAllowed: Long,
    aetherReport: ControlCenterReport,
    dnsBypassWarning: String?,
    onOpenPrivateDnsSettings: () -> Unit,
    onSelectProtectionMode: (ProtectionMode) -> Unit
) {
    val now = System.currentTimeMillis()
    val sessionBlocked = remember(recentLogs) { recentLogs.count { it.isBlocked } }
    val sessionAllowed = remember(recentLogs) { recentLogs.size - sessionBlocked }
    val perMinute = remember(recentLogs) {
        recentLogs.count { now - it.timestampEpochMs < 60_000L }
    }
    val latest = recentLogs.firstOrNull()

    val laneEvents = remember(recentLogs) {
        LiveFeedMapper.Lane.entries.map { lane ->
            lane to recentLogs.firstOrNull { LiveFeedMapper.laneFor(it.domain) == lane }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // --- Private DNS bypass warning (REAL system state — the #1 "blocker not working" cause) ---
        if (dnsBypassWarning != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = AlertRed.copy(alpha = 0.12f))
            ) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text("DNS BYPASS DETECTED", style = MaterialTheme.typography.labelMedium, color = AlertRed, fontWeight = FontWeight.Bold)
                        Text(dnsBypassWarning, style = MaterialTheme.typography.bodySmall, maxLines = 4, overflow = TextOverflow.Ellipsis)
                    }
                    androidx.compose.material3.TextButton(onClick = onOpenPrivateDnsSettings) { Text("Open") }
                }
            }
        }

        // --- Mode chips + live status ---
        Row(verticalAlignment = Alignment.CenterVertically) {
            ModeChip("Balanced", vpnState.activeMode == ProtectionMode.STANDARD) { onSelectProtectionMode(ProtectionMode.STANDARD) }
            Spacer(Modifier.width(6.dp))
            ModeChip("Strict", vpnState.activeMode == ProtectionMode.STRICT) { onSelectProtectionMode(ProtectionMode.STRICT) }
            Spacer(Modifier.width(6.dp))
            ModeChip("Privacy", vpnState.activeMode == ProtectionMode.PRIVACY) { onSelectProtectionMode(ProtectionMode.PRIVACY) }
            Spacer(Modifier.width(6.dp))
            ModeChip("Custom", vpnState.activeMode == ProtectionMode.CUSTOM) { onSelectProtectionMode(ProtectionMode.CUSTOM) }
            Spacer(Modifier.weight(1f))
            LiveBadge(vpnState.status)
        }

        // --- Counters (real: all-time + this session window) ---
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            CounterCard("BLOCKED", allTimeBlocked, AlertRed, Modifier.weight(1f))
            CounterCard("ALLOWED", allTimeAllowed, Color(0xFF34D399), Modifier.weight(1f))
        }
        Text(
            "This session window: $sessionBlocked blocked • $sessionAllowed allowed • ~$perMinute queries/min" +
                (latest?.let { " • last ${it.latencyMs}ms ${it.protocolUsed}" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // --- Live hub: lanes pulse on real events ---
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PulseShield(vpnState.status == VpnStatus.CONNECTED)
                    Spacer(Modifier.width(14.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        laneEvents.forEach { (lane, event) -> LaneRow(lane, event, now) }
                    }
                }
                if (vpnState.status == VpnStatus.DISCONNECTED) {
                    Text(
                        "VPN is off — no traffic is flowing through OmniShield. Turn protection on to see live events.",
                        style = MaterialTheme.typography.bodySmall,
                        color = WarningAmber
                    )
                }
            }
        }

        // --- AETHER anomaly strip (real counters) ---
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MiniStat("Anomalies observed", aetherReport.anomaliesObserved, Modifier.weight(1f))
            MiniStat("Rebinding stopped", aetherReport.rebindingBlocked, Modifier.weight(1f))
            MiniStat("Agents online", "${aetherReport.agentsOnline}/${aetherReport.totalAgents}", Modifier.weight(1f))
            MiniStat("Auto-recoveries", aetherReport.autoRecoveries, Modifier.weight(1f))
        }
        if (aetherReport.safeModeActive) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Zero-Breakage SAFE MODE active — filter lists temporarily suspended, connectivity guarded.",
                    style = MaterialTheme.typography.bodySmall, color = WarningAmber)
            }
        }

        // --- Live event feed (real DB records, newest first) ---
        Text("LIVE EVENTS — real VPN traffic", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(recentLogs.take(80), key = { it.id }) { record ->
                FeedRow(record)
            }
            item {
                Text(
                    "Categories:  • Ad (red)  • Tracker (amber)  • Malicious (deep red)  • Analytics (purple)  • Not listed (green)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(12.dp))
            }
        }
    }
}

@Composable
private fun ModeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(selected = selected, onClick = onClick, label = { Text(label, style = MaterialTheme.typography.labelSmall) })
}

@Composable
private fun LiveBadge(status: VpnStatus) {
    val color = when (status) {
        VpnStatus.CONNECTED -> Color(0xFF34D399)
        VpnStatus.PAUSED -> WarningAmber
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val label = when (status) {
        VpnStatus.CONNECTED -> "LIVE"
        VpnStatus.PAUSED -> "PAUSED (passthrough)"
        VpnStatus.STARTING -> "STARTING"
        VpnStatus.RECONNECTING -> "RECONNECTING"
        VpnStatus.ERROR -> "ERROR"
        else -> "OFF"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(color, RoundedCornerShape(4.dp))
        )
        Spacer(Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.labelSmall, color = color, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun CounterCard(label: String, value: Long, color: Color, modifier: Modifier = Modifier) {
    Card(modifier = modifier, colors = CardDefaults.cardColors()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
            Text(
                value.toString(),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Black,
                color = color,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

@Composable
private fun MiniStat(label: String, value: Any, modifier: Modifier = Modifier) {
    Card(modifier = modifier, colors = CardDefaults.cardColors()) {
        Column(modifier = Modifier.padding(8.dp)) {
            Text(value.toString(), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = ElectricBlue)
            Text(label, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun PulseShield(active: Boolean) {
    val transition = rememberInfiniteTransition(label = "shield_pulse")
    val scale by transition.animateFloat(
        initialValue = 0.92f,
        targetValue = if (active) 1.06f else 0.96f,
        animationSpec = infiniteRepeatable(tween(1100), RepeatMode.Reverse),
        label = "shield_scale"
    )
    val color = if (active) ElectricBlue else MaterialTheme.colorScheme.onSurfaceVariant
    Box(
        modifier = Modifier
            .size(84.dp)
            .scale(scale)
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(42.dp)),
        contentAlignment = Alignment.Center
    ) {
        Icon(Icons.Default.Shield, contentDescription = null, tint = color, modifier = Modifier.size(40.dp))
    }
}

@Composable
private fun LaneRow(lane: LiveFeedMapper.Lane, event: DnsActivityRecord?, now: Long) {
    val icon = when (lane) {
        LiveFeedMapper.Lane.VIDEO -> Icons.Default.Videocam
        LiveFeedMapper.Lane.GAME -> Icons.Default.SportsEsports
        LiveFeedMapper.Lane.SOCIAL -> Icons.Default.Public
        LiveFeedMapper.Lane.SYSTEM -> Icons.Default.Dns
        LiveFeedMapper.Lane.WEB -> Icons.Default.Newspaper
    }
    val isFresh = event != null && now - event.timestampEpochMs < 2_500L
    val flash by animateColorAsState(
        targetValue = when {
            isFresh && event!!.isBlocked -> AlertRed.copy(alpha = 0.22f)
            isFresh -> SkyBlueGlow.copy(alpha = 0.20f)
            else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        },
        label = "lane_flash"
    )
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(flash, RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Icon(icon, contentDescription = lane.label, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(8.dp))
        Text(lane.label, style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(52.dp))
        Text(
            event?.domain?.take(34) ?: "waiting for events…",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        if (event != null) {
            val tag = LiveFeedMapper.tagFor(event.category)
            Box(modifier = Modifier.size(8.dp).background(Color(tag.colorHex), RoundedCornerShape(4.dp)))
        }
    }
}

@Composable
private fun FeedRow(record: DnsActivityRecord) {
    val tag = LiveFeedMapper.tagFor(record.category)
    val verdictColor = if (record.isBlocked) AlertRed else Color(0xFF34D399)
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (record.isBlocked) "BLOCKED" else "ALLOWED",
                    style = MaterialTheme.typography.labelSmall,
                    color = verdictColor,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.width(8.dp))
                Box(modifier = Modifier.size(7.dp).background(Color(tag.colorHex), RoundedCornerShape(3.5.dp)))
                Spacer(Modifier.width(4.dp))
                Text(tag.label, style = MaterialTheme.typography.labelSmall, color = Color(tag.colorHex))
                Spacer(Modifier.weight(1f))
                Text("${record.latencyMs}ms", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
            }
            Text(record.domain, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row {
                Text(
                    listOfNotNull(record.sourceList.takeIf { it.isNotBlank() }, record.protocolUsed.takeIf { it.isNotBlank() })
                        .joinToString("  •  "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}
