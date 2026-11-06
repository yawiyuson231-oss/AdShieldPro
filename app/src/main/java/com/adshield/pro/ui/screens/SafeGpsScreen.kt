package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LocationOff
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.engine.location.FactState
import com.adshield.pro.engine.location.LocationAnalyzer
import com.adshield.pro.engine.location.LocationQuality
import com.adshield.pro.engine.location.LocationSafetyAdvisor
import com.adshield.pro.engine.location.SafetyFact
import com.adshield.pro.engine.location.ShareMode
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.NavySurface
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.SafeGpsUiState

/**
 * AdShield Pro — Safe GPS screen.
 *
 * Three jobs, in this order: get the tightest fix the device can produce, judge whether that fix is
 * trustworthy, and only then let the user copy a message that discloses what it does and does not
 * reveal. Nothing here uploads a coordinate, and the screen states the two things it cannot do:
 * track in the background, and call for help.
 */
@Composable
fun SafeGpsScreen(
    state: SafeGpsUiState,
    onLocate: () -> Unit,
    onStop: () -> Unit,
    onRequestPermission: () -> Unit,
    onTargetChange: (Double) -> Unit,
    onTimeoutChange: (Long) -> Unit,
    onGridChange: (Int) -> Unit,
    onSetShareMode: (ShareMode) -> Unit,
    onCopyShare: () -> Unit,
    onOpenSms: () -> Unit,
    onOpenSetting: (SafetyFact) -> Unit,
    onOpenMap: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 14.dp, end = 14.dp, top = 12.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "header", contentType = "header") {
            GpsHeader(state = state, onLocate = onLocate, onStop = onStop, onRequestPermission = onRequestPermission)
        }
        item(key = "keys", contentType = "keys") {
            GpsKeyMetrics(state)
        }
        if (state.hasFix) {
            item(key = "fix", contentType = "panel") {
                FixPanel(state)
            }
            item(key = "quality", contentType = "panel") {
                QualityPanel(state)
            }
            item(key = "share", contentType = "panel") {
                SharePanel(
                    state = state,
                    onGridChange = onGridChange,
                    onSetShareMode = onSetShareMode,
                    onCopyShare = onCopyShare,
                    onOpenSms = onOpenSms,
                    onOpenMap = onOpenMap
                )
            }
        } else {
            item(key = "empty", contentType = "panel") {
                CyberPanel(
                    title = "No pin yet",
                    subtitle = "Nothing is located until you press Locate, and no coordinates are invented."
                ) {
                    Text(
                        state.message ?: "Press “Get my location”. The first fix is usually the worst one; " +
                            "this screen keeps sampling until the device reports a tighter radius.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 12.5.sp
                    )
                }
            }
        }
        item(key = "device", contentType = "panel") {
            DevicePanel(state, onRequestPermission = onRequestPermission, onOpenSetting = onOpenSetting)
        }
        item(key = "limits", contentType = "panel") {
            LimitsPanel()
        }
        items(items = LIMIT_ROWS, key = { row -> row.first }, contentType = { "limits-row" }) { row ->
            LimitRow(row.first, row.second)
        }
    }
}

private val LIMIT_ROWS = listOf(
    "Live tracking" to "Not implemented. A pin is fixed text: it does not update after you send it, and there is nothing to revoke.",
    "Spoof detection" to "Not possible to prove. The screen flags a fix Android reports as simulated and refuses to call an implausible jump verified — a good spoofer defeats both.",
    "Background location" to "Never requested. No foreground service, no periodic capture: the app cannot follow you when this screen is closed.",
    "Indoor accuracy" to "GNSS degrades indoors. The reported radius is shown as-is instead of promising a room.",
    "Emergency calls" to "The app cannot dial 911 or alert a contact for you. It writes a message you send yourself — call, or ask a bystander to call.",
    "Map tiles" to "No map SDK and no tile provider are bundled. Only a geo: link or OpenStreetMap URL you choose to open."
)

@Composable
private fun GpsHeader(
    state: SafeGpsUiState,
    onLocate: () -> Unit,
    onStop: () -> Unit,
    onRequestPermission: () -> Unit
) {
    val permissionGranted = state.permission == com.adshield.pro.engine.location.LocationPermission.GRANTED
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = NavySurface),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.MyLocation, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text("Safe GPS", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    Text(
                        "High-accuracy fix, then a pin you decide how to share",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SharedQualityPill(state.analysis.quality)
            }
            Spacer(Modifier.height(10.dp))
            Text(
                "One getCurrentLocation() call usually returns a cached cell-tower position. " +
                    "This screen keeps asking until the device's own accuracy figure stops improving — " +
                    "that is the only honest way to get a better fix.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(12.dp))
            if (!permissionGranted) {
                Button(
                    onClick = onRequestPermission,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue)
                ) {
                    Icon(Icons.Filled.LocationOn, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Allow location access")
                }
            } else if (state.running) {
                OutlinedButton(onClick = onStop, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Stop sampling")
                }
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = CyberCyan)
            } else {
                Button(
                    onClick = onLocate,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue)
                ) {
                    Icon(Icons.Filled.MyLocation, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(if (state.hasFix) "Locate again" else "Get my location")
                }
            }
            if (state.message != null) {
                Spacer(Modifier.height(10.dp))
                Text(state.message, fontSize = 11.5.sp, color = SkyBlueGlow)
            }
            Spacer(Modifier.height(12.dp))
            Text("Target accuracy", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TARGETS.forEach { (meters, label) ->
                    FilterChip(
                        selected = state.targetAccuracyMeters == meters,
                        onClick = { onTargetChange(meters) },
                        label = { Text(label, fontSize = 11.5.sp) }
                    )
                }
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TIMEOUTS.forEach { (seconds, label) ->
                    FilterChip(
                        selected = state.timeoutMs == seconds * 1_000L,
                        onClick = { onTimeoutChange(seconds) },
                        label = { Text("Deadline $label", fontSize = 11.5.sp) }
                    )
                }
            }
        }
    }
}

private val TARGETS = listOf(
    10.0 to "±10 m best effort",
    25.0 to "±25 m balanced",
    50.0 to "±50 m fast",
    200.0 to "±200 m any fix"
)
private val TIMEOUTS = listOf(15L to "15 s", 30L to "30 s", 60L to "60 s")

@Composable
private fun SharedQualityPill(quality: LocationQuality) {
    val (label, color) = when (quality) {
        LocationQuality.HIGH -> "converged" to EmeraldPrimary
        LocationQuality.MEDIUM -> "usable" to CyberCyan
        LocationQuality.LOW -> "low trust" to WarningAmber
        LocationQuality.COARSE -> "coarse" to WarningAmber
        LocationQuality.NONE -> "no fix" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    StatusPill(text = label, color = color)
}

@Composable
private fun GpsKeyMetrics(state: SafeGpsUiState) {
    val analysis = state.analysis
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        MetricTile(
            modifier = Modifier.weight(1f),
            label = "Best accuracy",
            value = LocationAnalyzer.formatMeters(analysis.bestAccuracyMeters),
            accent = if (analysis.targetMet) EmeraldPrimary else WarningAmber
        )
        MetricTile(
            modifier = Modifier.weight(1f),
            label = "Fixes kept",
            value = analysis.count.toString(),
            accent = SkyBlueGlow
        )
        MetricTile(
            modifier = Modifier.weight(1f),
            label = "Spread",
            value = LocationAnalyzer.formatMeters(analysis.spreadMeters),
            accent = if (analysis.consistent) EmeraldPrimary else AlertRed
        )
    }
}

@Composable
private fun MetricTile(label: String, value: String, accent: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(NavySurface)
            .border(1.dp, NavyBorder.copy(alpha = 0.7f), RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Text(value, fontSize = 19.sp, fontWeight = FontWeight.Bold, color = accent, maxLines = 1)
        Text(label, fontSize = 10.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
    }
}

@Composable
private fun FixPanel(state: SafeGpsUiState) {
    val analysis = state.analysis
    val best = analysis.best ?: return
    CyberPanel(
        title = "The fix",
        subtitle = "Reported by the device, re-checked against every other fix in this window"
    ) {
        InfoRow(
            "Coordinates",
            LocationAnalyzer.formatCoordinates(best.point.latitude, best.point.longitude),
            mono = true
        )
        InfoRow("Reported accuracy", LocationAnalyzer.formatMeters(best.accuracyMeters))
        InfoRow("Latest fix", LocationAnalyzer.formatMeters(analysis.latestAccuracyMeters))
        InfoRow("First fix", LocationAnalyzer.formatMeters(analysis.firstAccuracyMeters))
        InfoRow(
            "Convergence",
            analysis.improvementMeters?.let { improvement ->
                if (improvement > 0) {
                    "${LocationAnalyzer.formatMeters(improvement)} tighter (" +
                        "${(analysis.improvementPercent ?: 0.0).toInt()}%) over ${analysis.count} fix(es)"
                } else {
                    "No further improvement — a longer wait would not help on this device"
                }
            } ?: "—"
        )
        InfoRow("Altitude", best.altitudeMeters?.let { meters ->
            "${meters.toInt()} m" + (best.verticalAccuracyMeters?.let { " (±${it.toInt()} m)" } ?: "")
        } ?: "not reported")
        InfoRow("Source", best.source.name.lowercase() + if (best.mock) " · flagged as simulated" else "")
        InfoRow("Spoken reference", LocationAnalyzer.spokenReference(best))
    }
}

@Composable
private fun QualityPanel(state: SafeGpsUiState) {
    val analysis = state.analysis
    CyberPanel(
        title = "What the number means",
        subtitle = "Accuracy is the device's estimate — it is not verified here"
    ) {
        StatusPill(
            text = analysis.headline,
            color = if (analysis.consistent) EmeraldPrimary else AlertRed
        )
        Spacer(Modifier.height(8.dp))
        Text(analysis.detail, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(10.dp))
        InfoRow(
            "Consistency",
            if (analysis.consistent) {
                "Fixes agree within ${LocationAnalyzer.formatMeters(analysis.spreadMeters)}"
            } else {
                "Fixes disagree by ${LocationAnalyzer.formatMeters(analysis.spreadMeters)} — nothing is trusted"
            }
        )
        InfoRow(
            "Movement plausibility",
            analysis.impliedSpeedMetersPerSecond?.let { speed ->
                if (analysis.implausibleMovement) {
                    "Implausible (${speed.toInt()} m/s implied) — treat as unverified"
                } else {
                    "Plausible (max ${if (speed < 1) "<1" else speed.toInt().toString()} m/s)"
                }
            } ?: "Not enough fixes to compare"
        )
        InfoRow(
            "Target",
            "±${state.targetAccuracyMeters.toInt()} m · " +
                if (analysis.targetMet) "reached" else "not reached in this window"
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "A tight circle can still be wrong: urban multipath, a cached fix or a spoofer all produce " +
                "confident numbers. The plausibility check above compares implied speed between fixes — " +
                "it is a hint, not tamper detection.",
            fontSize = 11.sp,
            color = WarningAmber
        )
    }
}

@Composable
private fun SharePanel(
    state: SafeGpsUiState,
    onGridChange: (Int) -> Unit,
    onSetShareMode: (ShareMode) -> Unit,
    onCopyShare: () -> Unit,
    onOpenSms: () -> Unit,
    onOpenMap: () -> Unit
) {
    val plan = state.sharePlan
    CyberPanel(
        title = "Share it safely",
        subtitle = "Nothing leaves the phone until you copy or send this text yourself",
        trailing = {
            StatusPill(
                text = if (plan?.blocked == false) "shareable" else "withheld",
                color = if (plan?.blocked == false) EmeraldPrimary else AlertRed
            )
        }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            LocationSafetyAdvisor.gridChoices.forEachIndexed { index, meters ->
                FilterChip(
                    selected = state.gridMeters == meters,
                    onClick = { onGridChange(meters) },
                    label = { Text(LocationSafetyAdvisor.gridChoiceLabels[index], fontSize = 11.5.sp) }
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = state.shareMode == ShareMode.EVERYDAY,
                onClick = { onSetShareMode(ShareMode.EVERYDAY) },
                label = { Text("Everyday", fontSize = 11.5.sp) }
            )
            FilterChip(
                selected = state.shareMode == ShareMode.EMERGENCY,
                onClick = { onSetShareMode(ShareMode.EMERGENCY) },
                label = { Text("Emergency", fontSize = 11.5.sp) }
            )
        }
        Spacer(Modifier.height(10.dp))
        Text(
            LocationSafetyAdvisor.describePrecision(state.analysis, plan?.rounded),
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (plan != null) {
            plan.rounded?.let { rounded ->
                Spacer(Modifier.height(6.dp))
                Text(
                    "Rounded to a ${rounded.gridMeters} m grid — the pin moved " +
                        "${LocationAnalyzer.formatMeters(rounded.displacementMeters)}, worst case " +
                        "${LocationAnalyzer.formatMeters(rounded.worstCaseMeters)}. The exact fix stays on this phone.",
                    fontSize = 11.sp,
                    color = EmeraldPrimary
                )
            }
            Spacer(Modifier.height(10.dp))
            if (plan.blocked) {
                Text(
                    plan.blockReason ?: "This pin cannot be shared.",
                    fontSize = 12.sp,
                    color = AlertRed,
                    fontWeight = FontWeight.SemiBold
                )
            } else {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFF07131F))
                        .border(1.dp, NavyBorder.copy(alpha = 0.7f), RoundedCornerShape(10.dp))
                        .padding(10.dp)
                ) {
                    Text(plan.text, fontSize = 11.5.sp, color = MaterialTheme.colorScheme.onSurface, lineHeight = 16.sp)
                }
                if (plan.warnings.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    plan.warnings.forEach { warning ->
                        Row(verticalAlignment = Alignment.Top) {
                            Icon(
                                Icons.Filled.WarningAmber,
                                contentDescription = null,
                                tint = WarningAmber,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(warning, fontSize = 11.sp, color = WarningAmber)
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onCopyShare,
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Copy message", fontSize = 12.sp)
                    }
                    OutlinedButton(
                        onClick = onOpenSms,
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                    ) {
                        Text("Send in SMS", fontSize = 12.sp)
                    }
                    OutlinedButton(
                        onClick = onOpenMap,
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                    ) {
                        Text("Open map", fontSize = 12.sp)
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "“Send in SMS” opens your messaging app with the text filled in — you still choose the " +
                        "recipient and press send. A map link hands the coordinates to that map provider.",
                    fontSize = 10.5.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun DevicePanel(
    state: SafeGpsUiState,
    onRequestPermission: () -> Unit,
    onOpenSetting: (SafetyFact) -> Unit
) {
    CyberPanel(
        title = "Is this phone in a fit state to share?",
        subtitle = "“Cannot read” is a real answer, not a pass"
    ) {
        state.checklist.forEach { fact ->
            DeviceFactRow(fact, onOpenSetting)
            Spacer(Modifier.height(8.dp))
        }
        if (state.permission != com.adshield.pro.engine.location.LocationPermission.GRANTED) {
            TextButton(onClick = onRequestPermission) { Text("Ask for location permission again") }
        }
        if (!state.hasProvider) {
            Text(
                "This device reports no location provider at all. A fix is impossible here, and the screen " +
                    "will not simulate one.",
                fontSize = 11.5.sp,
                color = AlertRed
            )
        }
    }
}

@Composable
private fun DeviceFactRow(fact: SafetyFact, onOpenSetting: (SafetyFact) -> Unit) {
    val (icon, color) = when (fact.state) {
        FactState.OK -> Icons.Filled.CheckCircle to EmeraldPrimary
        FactState.WARN -> Icons.Filled.WarningAmber to WarningAmber
        FactState.BAD -> Icons.Filled.ErrorOutline to AlertRed
        FactState.UNKNOWN -> Icons.Filled.Info to SkyBlueGlow
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF081522))
            .padding(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(8.dp))
            Text(fact.label, fontSize = 12.5.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Text(
                when (fact.state) {
                    FactState.OK -> "ok"
                    FactState.WARN -> "check"
                    FactState.BAD -> "blocking"
                    FactState.UNKNOWN -> "cannot read"
                },
                fontSize = 10.5.sp,
                color = color
            )
        }
        Spacer(Modifier.height(3.dp))
        Text(fact.detail, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (fact.setting != null) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Open the setting that fixes this →",
                fontSize = 11.sp,
                color = CyberCyan,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.clickable { onOpenSetting(fact) }
            )
        }
    }
}

@Composable
private fun LimitsPanel() {
    CyberPanel(
        title = "What this screen cannot do",
        subtitle = "Stated here so no part of the app can imply otherwise"
    ) {
        Text(
            "A pin is a fixed text message, not a tracker, and the app has no way to call for help. " +
                "In the Philippines dial 911; elsewhere use the local number. Tell a person, not an app.",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun LimitRow(title: String, detail: String) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(NavySurface)
            .border(1.dp, NavyBorder.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
            .padding(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.LocationOff, contentDescription = null, tint = SkyBlueGlow, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(8.dp))
            Text(title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(3.dp))
        Text(detail, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(
            label,
            fontSize = 11.5.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(130.dp)
        )
        Text(
            value,
            fontSize = 11.5.sp,
            color = if (mono) CyberCyan else MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
    }
}
