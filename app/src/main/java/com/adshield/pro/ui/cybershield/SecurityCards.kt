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
import androidx.compose.runtime.rememberCoroutineScope
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
import com.adshield.pro.aether.AetherSeverity
import com.adshield.pro.aether.AetherVerdict
import com.adshield.pro.cybershield.AnomalyFinding
import com.adshield.pro.cybershield.CsDataSource
import com.adshield.pro.cybershield.CsSeverity
import com.adshield.pro.cybershield.DeviceSecuritySnapshot
import com.adshield.pro.cybershield.NetworkSummary
import kotlinx.coroutines.launch

internal fun aetherToCs(severity: AetherSeverity): CsSeverity = when (severity) {
    AetherSeverity.NONE -> CsSeverity.INFO
    AetherSeverity.LOW -> CsSeverity.LOW
    AetherSeverity.MEDIUM -> CsSeverity.MEDIUM
    AetherSeverity.HIGH -> CsSeverity.HIGH
    AetherSeverity.CRITICAL -> CsSeverity.CRITICAL
}

/**
 * AI Threat Detection panel — real local analysis: AETHER verdicts on recent
 * domains, statistical anomaly findings and correlated incidents. Clearly
 * labeled as on-device rule-based analysis (no cloud AI).
 */
@Composable
fun AiDetectionCard(
    verdicts: List<AetherVerdict>,
    anomalies: List<AnomalyFinding>,
    incidentCount: Int,
    aetherInfo: Map<String, String>,
    aetherEnabled: Boolean,
    onAnalyze: suspend (String) -> AetherVerdict,
    modifier: Modifier = Modifier
) {
    var expandedId by rememberSaveable { mutableStateOf<String?>(null) }
    var analyzeDialog by remember { mutableStateOf(false) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.NeonBlue) {
        CardHeader(
            "AI Threat Detection", accent = Cs.NeonBlue,
            trailing = {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusChip(if (aetherEnabled) "Engine on" else "Engine off", if (aetherEnabled) Cs.Green else Cs.Steel)
                    StatusChip("Local", Cs.Cyan)
                }
            }
        )
        Text(
            "AETHER ${aetherInfo["ruleset_version"] ?: ""} · ${aetherInfo["threat_indicators"] ?: "0"} verified threat indicators + " +
                "${aetherInfo["privacy_indicators"] ?: "0"} privacy indicators bundled (signed feed ${aetherInfo["feed_version"] ?: ""})",
            color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp
        )

        Text("RECENT DOMAIN VERDICTS", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
        if (verdicts.isEmpty()) {
            EmptyState("No recent domains to analyze yet.", icon = "∅")
        } else {
            verdicts.forEach { verdict ->
                VerdictRow(verdict, expandedId == verdict.domain, {
                    expandedId = if (expandedId == verdict.domain) null else verdict.domain
                })
            }
        }

        Text("BEHAVIORAL ANOMALIES", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
        if (anomalies.isEmpty()) {
            Text(
                "No statistical anomalies in the current event window. Bursts, beaconing, subdomain floods and DGA-like hostnames are checked continuously.",
                color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp
            )
        } else {
            anomalies.take(5).forEach { finding ->
                AnomalyRow(finding, expandedId == finding.id) {
                    expandedId = if (expandedId == finding.id) null else finding.id
                }
            }
        }

        KeyValueLine("Correlated incidents (24 h)", incidentCount.toString(), if (incidentCount > 0) Cs.Amber else Cs.Green)

        TextButton(onClick = { analyzeDialog = true }) {
            Text("Analyze a domain…", color = Cs.Cyan, fontSize = 11.sp)
        }
        HonestNote("Explainable on-device rules + statistics (AETHER engine). No cloud AI, no traffic-payload inspection. Heuristic findings are flagged for review, never auto-blocked.")
    }

    if (analyzeDialog) {
        AnalyzeDomainDialog(onDismiss = { analyzeDialog = false }, onAnalyze = onAnalyze)
    }
}

@Composable
private fun VerdictRow(verdict: AetherVerdict, expanded: Boolean, onClick: () -> Unit) {
    val severity = aetherToCs(verdict.severity)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Cs.Surface.copy(alpha = 0.7f))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.weight(1f)) {
                Text(verdict.domain, color = Cs.Text, fontSize = 11.sp, fontFamily = Cs.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${verdict.classification} · risk ${verdict.risk}/100 · confidence ${String.format(java.util.Locale.US, "%.0f", verdict.confidence * 100)}%",
                    color = Cs.TextDim, fontSize = 9.sp, fontFamily = Cs.mono
                )
            }
            SeverityChip(severity)
            if (verdict.confirmed) StatusChip("Verified", Cs.Red)
        }
        if (expanded) {
            Text("Reason: ${verdict.reasonCode}", color = Cs.TextDim, fontSize = 10.sp)
            verdict.signals.forEach { signal ->
                Text(
                    "· ${signal.id} (w=${signal.weight}) — ${signal.detail}",
                    color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp
                )
                Text(
                    "  source: ${signal.source} · ${signal.observedAt}${if (signal.verifiedIntel) " · verified intel" else ""}",
                    color = Cs.TextFaint, fontSize = 9.sp, lineHeight = 12.sp
                )
            }
            verdict.recommendations.take(2).forEach {
                Text("→ $it", color = Cs.Cyan.copy(alpha = 0.8f), fontSize = 10.sp, lineHeight = 14.sp)
            }
            if (verdict.signals.isEmpty()) {
                Text("No risk signals matched. Allowlisted or clean reputation.", color = Cs.TextDim, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun AnomalyRow(finding: AnomalyFinding, expanded: Boolean, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Cs.Surface.copy(alpha = 0.7f))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.weight(1f)) {
                Text(finding.title, color = Cs.Text, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                Text(finding.domain ?: "", color = Cs.TextDim, fontSize = 10.sp, fontFamily = Cs.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            SeverityChip(finding.severity)
            StatusChip("Flag", Cs.Amber)
        }
        if (expanded) {
            Text(finding.detail, color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp)
            finding.evidence.forEach {
                Text("· $it", color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono, lineHeight = 13.sp)
            }
        }
    }
}

@Composable
private fun AnalyzeDomainDialog(
    onDismiss: () -> Unit,
    onAnalyze: suspend (String) -> AetherVerdict
) {
    var input by rememberSaveable { mutableStateOf("") }
    var verdict by remember { mutableStateOf<AetherVerdict?>(null) }
    var running by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Cs.SurfaceAlt,
        title = { Text("Domain reputation check", color = Cs.Text, fontSize = 15.sp) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = { Text("example.com or https://…", fontSize = 12.sp, color = Cs.TextFaint) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 13.sp, color = Cs.Text),
                    colors = cyberTextFieldColors()
                )
                if (running) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(16.dp), color = Cs.Cyan, strokeWidth = 2.dp)
                        Text("Analyzing locally…", color = Cs.TextDim, fontSize = 11.sp)
                    }
                }
                verdict?.let { v ->
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        SeverityChip(aetherToCs(v.severity))
                        if (v.confirmed) StatusChip("Verified intel", Cs.Red)
                        if (v.shouldBlock) StatusChip("Would block", Cs.Red)
                    }
                    KeyValueLine("Classification", v.classification)
                    KeyValueLine("Risk", "${v.risk}/100")
                    KeyValueLine("Confidence", "${String.format(java.util.Locale.US, "%.0f", v.confidence * 100)}%")
                    KeyValueLine("Reason", v.reasonCode)
                    v.signals.forEach { s ->
                        Text("· ${s.id}: ${s.detail}", color = Cs.TextDim, fontSize = 10.sp, lineHeight = 14.sp)
                        Text("  ${s.source} · ${s.observedAt}", color = Cs.TextFaint, fontSize = 9.sp)
                    }
                    v.recommendations.forEach {
                        Text("→ $it", color = Cs.Cyan.copy(alpha = 0.85f), fontSize = 10.sp, lineHeight = 14.sp)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = input.isNotBlank() && !running,
                onClick = {
                    running = true
                    scope.launch {
                        verdict = onAnalyze(input)
                        running = false
                    }
                }
            ) { Text("ANALYZE", color = Cs.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close", color = Cs.TextDim, fontSize = 12.sp) } }
    )
}

/** Endpoint protection: real Android device security signals. */
@Composable
fun EndpointCard(
    snapshot: DeviceSecuritySnapshot,
    scanning: Boolean,
    onRescan: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showSideloaded by rememberSaveable { mutableStateOf(false) }
    var showLimits by rememberSaveable { mutableStateOf(false) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Green) {
        CardHeader(
            "Endpoint Protection", accent = Cs.Green,
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    SourceChip(CsDataSource.LOCAL_CHECK)
                    IconButton(onClick = onRescan, enabled = !scanning, modifier = Modifier.size(26.dp)) {
                        if (scanning) CircularProgressIndicator(Modifier.size(14.dp), color = Cs.Cyan, strokeWidth = 2.dp)
                        else Icon(Icons.Default.Refresh, "Rescan device", tint = Cs.Cyan, modifier = Modifier.size(16.dp))
                    }
                }
            }
        )
        if (snapshot.collectedAtEpochMs == 0L) {
            EmptyState("Collecting real device security signals…", icon = "◌")
            return@NeonCard
        }
        Text(
            "${snapshot.deviceModel} · Android ${snapshot.androidVersion} (API ${snapshot.sdkInt})",
            color = Cs.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold
        )
        snapshot.securityPatch?.let {
            val color = when {
                (snapshot.patchAgeDays ?: 999) <= 90 -> Cs.Green
                (snapshot.patchAgeDays ?: 999) <= 180 -> Cs.Amber
                else -> Cs.Red
            }
            KeyValueLine("Security patch", "$it (${snapshot.patchAgeDays}d old)", color)
        }

        CheckRow("Screen lock", snapshot.screenLockSecure, invert = false)
        CheckRow("Storage encryption", snapshot.storageEncrypted, invert = false)
        CheckRow("USB debugging off", snapshot.adbEnabled, invert = true)
        CheckRow("Developer options off", snapshot.developerOptionsEnabled, invert = true)

        if (snapshot.totalApps != null) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.clickable { showSideloaded = !showSideloaded }
            ) {
                Text("Installed apps", color = Cs.TextDim, fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(
                    "${snapshot.totalApps} total · ${snapshot.userApps} user · ${snapshot.sideloadedApps} sideloaded",
                    color = if ((snapshot.sideloadedApps ?: 0) > 0) Cs.Amber else Cs.Text,
                    fontSize = 11.sp, fontFamily = Cs.mono
                )
            }
            if (showSideloaded) {
                if (snapshot.sideloadedPackages.isEmpty()) {
                    Text("No sideloaded user apps detected.", color = Cs.TextDim, fontSize = 10.sp)
                } else {
                    Text("No recognized installer (review these):", color = Cs.Amber, fontSize = 10.sp)
                    snapshot.sideloadedPackages.forEach {
                        Text("· $it", color = Cs.TextDim, fontSize = 10.sp, fontFamily = Cs.mono)
                    }
                }
            }
        }

        snapshot.networkTransport?.let { transport ->
            KeyValueLine(
                "Active network",
                buildString {
                    append(transport)
                    if (snapshot.networkValidated == true) append(" · validated")
                    if (snapshot.networkMetered == true) append(" · metered")
                },
                if (snapshot.networkValidated == true) Cs.Text else Cs.Amber
            )
        }
        if (snapshot.dnsServers.isNotEmpty()) {
            KeyValueLine("System DNS", snapshot.dnsServers.take(3).joinToString(", "))
        }

        TextButton(onClick = { showLimits = !showLimits }) {
            Text(
                if (showLimits) "Hide Android limitations ▴" else "What this app cannot access ▾",
                color = Cs.TextFaint, fontSize = 10.sp
            )
        }
        if (showLimits) {
            snapshot.unavailable.forEach {
                Text("· $it", color = Cs.TextFaint, fontSize = 10.sp, lineHeight = 14.sp)
            }
        }
        HonestNote("Configuration signals only — Android does not permit full antivirus scanning of other apps. Sideloaded ≠ malicious; review the list manually.")
    }
}

@Composable
private fun CheckRow(label: String, value: Boolean?, invert: Boolean) {
    val good = if (value == null) null else if (invert) !value else value
    val color = when (good) {
        true -> Cs.Green
        false -> Cs.Red
        null -> Cs.Steel
    }
    val symbol = when (good) {
        true -> "✓"
        false -> "✗"
        null -> "?"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Cs.TextDim, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(
            when (good) {
                true -> "OK"
                false -> "ATTENTION"
                null -> "UNAVAILABLE"
            },
            color = color, fontSize = 10.sp, fontFamily = Cs.mono, fontWeight = FontWeight.Bold
        )
        Text(" $symbol", color = color, fontSize = 12.sp, fontFamily = Cs.mono)
    }
}

/** Network security: DNS monitoring, protocol split, reputation, block history. */
@Composable
fun NetworkCard(
    summary: NetworkSummary,
    nowMs: Long,
    onReputationCheck: suspend (String) -> AetherVerdict,
    onOpenStatistics: () -> Unit,
    modifier: Modifier = Modifier
) {
    var checkDialog by remember { mutableStateOf(false) }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Cyan) {
        CardHeader(
            "Network Security",
            trailing = {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusChip(
                        if (summary.protectionActive) "DNS protected" else "Unprotected",
                        if (summary.protectionActive) Cs.Green else Cs.Red
                    )
                    SourceChip(CsDataSource.ON_DEVICE)
                }
            }
        )
        KeyValueLine("Upstream resolver", summary.upstreamLabel)
        KeyValueLine(
            "Upstream encryption",
            if (summary.encryptedUpstream) "DoH / DoT encrypted" else "Plain UDP/TCP",
            if (summary.encryptedUpstream) Cs.Green else Cs.Amber
        )
        KeyValueLine("DNS events (24 h)", summary.windowEvents.toString())
        KeyValueLine("Blocked (24 h)", summary.windowBlocked.toString(), if (summary.windowBlocked > 0) Cs.Red else Cs.Text)
        KeyValueLine("Avg upstream latency", "${summary.averageLatencyMs} ms")

        if (summary.protocols.isNotEmpty()) {
            Text("RESPONSE PROTOCOLS", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
            summary.protocols.forEach { p ->
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(p.protocol, color = Cs.TextDim, fontSize = 10.sp, fontFamily = Cs.mono, modifier = Modifier.weight(1f))
                    Text("${p.count} · ${String.format(java.util.Locale.US, "%.0f", p.share * 100)}%", color = Cs.Text, fontSize = 10.sp, fontFamily = Cs.mono)
                }
            }
        }

        TextButton(onClick = { checkDialog = true }) {
            Text("Domain reputation check…", color = Cs.Cyan, fontSize = 11.sp)
        }

        Text("BLOCKED CONNECTION HISTORY (DNS)", color = Cs.TextFaint, fontSize = 9.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
        if (summary.blockedHistory.isEmpty()) {
            Text("No blocked DNS resolutions in the last 24 h.", color = Cs.TextDim, fontSize = 10.sp)
        } else {
            summary.blockedHistory.forEach { event ->
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(relativeTime(event.timestampEpochMs, nowMs), color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
                    Text(
                        event.domain, color = Cs.Text, fontSize = 10.sp, fontFamily = Cs.mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                    )
                    Text(Cs.categoryLabel(event.category), color = Cs.categoryColor(event.category), fontSize = 8.sp, fontFamily = Cs.mono)
                }
            }
            TextButton(onClick = onOpenStatistics) { Text("Full history →", color = Cs.Cyan, fontSize = 10.sp) }
        }
        HonestNote("Visibility is DNS-level: blocked resolutions, not packet payloads. Android does not expose other apps' encrypted traffic contents.")
    }

    if (checkDialog) {
        AnalyzeDomainDialog(onDismiss = { checkDialog = false }, onAnalyze = onReputationCheck)
    }
}
