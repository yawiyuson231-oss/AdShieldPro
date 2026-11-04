package com.adshield.pro.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.AutonomousAction
import com.adshield.pro.engine.aether.ControlCenterReport
import com.adshield.pro.engine.aether.ThreatClassification
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber

/**
 * Mobile command deck inspired by security operations consoles. Every value is sourced from the
 * current VPN/AETHER/settings state. There are intentionally no geo attacks, endpoint counts,
 * compliance certifications or synthetic "AI scan" percentages.
 */
@Composable
fun AetherCommandDeck(
    vpnState: VpnRuntimeState,
    settings: AppSettingsState,
    allTimeTotal: Long,
    allTimeBlocked: Long,
    allTimeAllowed: Long,
    aetherReport: ControlCenterReport
) {
    val total = maxOf(vpnState.sessionTotalQueries, allTimeTotal)
    val blocked = maxOf(vpnState.sessionBlockedQueries, allTimeBlocked)
    val allowed = maxOf(vpnState.sessionAllowedQueries, allTimeAllowed)
    val protected = vpnState.status == VpnStatus.CONNECTED
    val statusColor = when (vpnState.status) {
        VpnStatus.CONNECTED -> EmeraldPrimary
        VpnStatus.PAUSED, VpnStatus.STARTING, VpnStatus.RECONNECTING -> WarningAmber
        VpnStatus.ERROR -> AlertRed
        VpnStatus.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Card(
        modifier = Modifier.fillMaxWidth().border(1.dp, NavyBorder, RoundedCornerShape(20.dp)),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent)
    ) {
        Box(
            Modifier.background(
                Brush.verticalGradient(
                    listOf(CyberCyan.copy(alpha = 0.075f), MaterialTheme.colorScheme.surface)
                )
            )
        ) {
            // Subtle console grid is decorative geometry only, not a traffic map or dataset.
            Canvas(Modifier.matchParentSize()) {
                val step = 36.dp.toPx()
                var x = 0f
                while (x < size.width) {
                    drawLine(CyberCyan.copy(alpha = 0.025f), Offset(x, 0f), Offset(x, size.height))
                    x += step
                }
                var y = 0f
                while (y < size.height) {
                    drawLine(CyberCyan.copy(alpha = 0.025f), Offset(0f, y), Offset(size.width, y))
                    y += step
                }
            }
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, null, tint = CyberCyan, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text("AETHER SECURITY OPERATIONS", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        Text(
                            "REAL-TIME LOCAL TELEMETRY • NO CLOUD ANALYTICS",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Surface(color = statusColor.copy(alpha = 0.13f), shape = CircleShape) {
                        Text(
                            if (protected) "PROTECTED" else vpnState.status.name,
                            color = statusColor,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp)
                        )
                    }
                }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CommandMetric("TOTAL DNS", total.toString(), CyberCyan, Modifier.weight(1f))
                    CommandMetric("BLOCKED", blocked.toString(), EmeraldPrimary, Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CommandMetric("ALLOWED", allowed.toString(), SkyBlueGlow, Modifier.weight(1f))
                    CommandMetric("ACTIVE RULES", vpnState.loadedRuleCount.toString(), WarningAmber, Modifier.weight(1f))
                }

                ConsoleSection(
                    title = "AETHER DECISION ENGINE",
                    icon = { Icon(Icons.Default.AutoAwesome, null, tint = CyberCyan, modifier = Modifier.size(17.dp)) }
                ) {
                    val classificationColor = when (aetherReport.lastThreatClassification) {
                        ThreatClassification.VERIFIED -> CyberCyan
                        ThreatClassification.SUSPECTED -> WarningAmber
                        ThreatClassification.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            aetherReport.lastThreatClassification.name,
                            color = classificationColor,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            if (aetherReport.lastThreatClassification == ThreatClassification.UNKNOWN) "NO SUFFICIENT EVIDENCE"
                            else "${(aetherReport.lastConfidenceScore * 100).toInt()}% HEURISTIC CONFIDENCE",
                            color = classificationColor,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    if (aetherReport.lastThreatClassification != ThreatClassification.UNKNOWN) {
                        LinearProgressIndicator(
                            progress = { aetherReport.lastConfidenceScore.toFloat().coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                            color = classificationColor,
                            trackColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    }
                    Text(
                        aetherReport.lastExplanation,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        "${aetherReport.agentsOnline}/${aetherReport.totalAgents} agents active • " +
                            "${aetherReport.dnsObserved} DNS observations • action ${aetherReport.lastAction.displayLabel()}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                ConsoleSection(
                    title = "LIVE SECURITY AUDIT",
                    icon = { Icon(Icons.Default.History, null, tint = EmeraldPrimary, modifier = Modifier.size(17.dp)) }
                ) {
                    if (aetherReport.recentAudit.isEmpty()) {
                        Text(
                            "No DNS decision has been recorded in this process. Open an app with protection enabled to populate this feed.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        aetherReport.recentAudit.takeLast(4).asReversed().forEach { line ->
                            Text(
                                line,
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    if (aetherReport.possibleFalsePositives.isNotEmpty()) {
                        Text(
                            "Review possible over-blocking: ${aetherReport.possibleFalsePositives.joinToString()}",
                            color = WarningAmber,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                ConsoleSection(
                    title = "PROTECTION & EVOLUTION",
                    icon = { Icon(Icons.Default.Dns, null, tint = SkyBlueGlow, modifier = Modifier.size(17.dp)) }
                ) {
                    ConsoleStatus("Resolver", "${settings.resolverConfig.preset.displayName} • ${settings.resolverConfig.protocol.name}")
                    ConsoleStatus(
                        "DNSSEC",
                        if (settings.resolverConfig.requestDnsSecValidation) "Upstream AD requested; AD shown per answer" else "Disabled by user"
                    )
                    ConsoleStatus("IPv6", if (settings.resolverConfig.enableIpv6) "Enabled" else "Disabled")
                    ConsoleStatus("Evolution", settings.lastEvolutionStatus.replace('_', ' '))
                    ConsoleStatus("Autonomous action", if (settings.manualOverrideEnabled) "Manual override" else if (settings.autonomousResponseEnabled) "User policy enabled" else "Monitor only")
                }
            }
        }
    }
}

@Composable
private fun CommandMetric(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.background.copy(alpha = 0.64f),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, color.copy(alpha = 0.18f))
    ) {
        Column(Modifier.padding(horizontal = 11.dp, vertical = 9.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, color = color, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun ConsoleSection(
    title: String,
    icon: @Composable () -> Unit,
    content: @Composable () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.background.copy(alpha = 0.58f),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, NavyBorder.copy(alpha = 0.65f))
    ) {
        Column(Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                icon()
                Spacer(Modifier.width(7.dp))
                Text(title, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            }
            content()
        }
    }
}

@Composable
private fun ConsoleStatus(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.34f))
        Text(value, style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(0.66f), maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

private fun AutonomousAction.displayLabel(): String = when (this) {
    AutonomousAction.ENFORCE_EXISTING_BLOCK -> "enforce existing rule"
    AutonomousAction.RECOMMEND_REVIEW -> "recommend review"
    AutonomousAction.MONITOR -> "monitor"
    AutonomousAction.MANUAL_OVERRIDE -> "manual override"
}
