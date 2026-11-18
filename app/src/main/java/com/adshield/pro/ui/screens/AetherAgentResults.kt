package com.adshield.pro.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherPhoneAgent as Agent
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.UrlThreatScanner
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

@Composable
internal fun AgentTaskResult(result: AetherTaskResult, onTool: (Agent.Tool) -> Unit) {
    when (result) {
        is AetherTaskResult.Phone -> Unit // The full report is displayed below the request form.
        is AetherTaskResult.Apps -> AgentAppAudit(result.review)
        is AetherTaskResult.Review -> {
            val report = result.report
            AgentCard("Security review results") {
                val finished = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(report.finishedAtMs))
                Text(if (report.hasGaps) "Finished with gaps · $finished" else "Both checks ran · $finished")
                val phone = report.phone.value
                Text(if (phone != null) "Phone and protection: ${phone.findings.size} findings in the available readings"
                    else "Phone and protection: ${report.phone.missingLabel()}")
                val apps = report.apps.value
                Text(if (apps != null && apps.inspected > 0) "App audit: ${apps.inspected}/${apps.visible} visible apps inspected"
                    else "App audit: ${report.apps.missingLabel()}")
                Text("The review didn't make changes. Check the details before acting on any finding.")
            }
            report.apps.value?.let { AgentAppAudit(it) }
        }
        is AetherTaskResult.ScannedFile -> AgentCard("File scan results") {
            val record = result.record
            Text(record.target, maxLines = 2, overflow = TextOverflow.Ellipsis)
            val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(record.timestampEpochMs))
            Text("$checkedAt · ${NumberFormat.getIntegerInstance().format(result.bytes)} bytes in the local copy",
                style = MaterialTheme.typography.bodySmall)
            Text(when (record.threatLevel) {
                SecurityLevel.DANGEROUS -> "High-risk indicators found. Don't open or install this file."
                SecurityLevel.SUSPICIOUS -> "Suspicious indicators found. Verify the sender before using this file."
                SecurityLevel.CLEAN -> when {
                    record.findings.isNotEmpty() -> "Low-scoring indicators found. Verify the source."
                    else -> "No threat indicators matched in the checks that ran."
                }
            }, style = MaterialTheme.typography.titleSmall)
            record.findings.take(6).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (result.limitations.isNotEmpty()) {
                Text("Scan limits", style = MaterialTheme.typography.titleSmall)
                result.limitations.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            Text("Static checks only. AdShield did not launch, upload, or change the original. This is not a safety guarantee.")
        }
        AetherTaskResult.FileTooLarge -> AgentCard("File wasn't scanned") {
            Text("The file exceeds ${AetherFileInput.MAX_MIB} MiB. Choose a smaller file. AdShield didn't scan a partial copy.")
        }
        AetherTaskResult.FileUnavailable -> AgentCard("File wasn't scanned") {
            Text("Android couldn't give AdShield a readable file. Choose it again, or try a locally stored copy.")
        }
        is AetherTaskResult.Link -> AgentCard("Link check results") {
            val heading = when (result.level) {
                UrlThreatScanner.ThreatLevel.DANGEROUS -> "High-risk link"
                UrlThreatScanner.ThreatLevel.SUSPICIOUS -> "Suspicious indicators found"
                UrlThreatScanner.ThreatLevel.CLEAN -> "No threat indicators matched"
            }
            Text("$heading · ${result.host}", style = MaterialTheme.typography.titleSmall)
            result.findings.take(6).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            Text("AdShield did not visit this link. A local check cannot guarantee a site is safe.")
        }
        is AetherTaskResult.Dns -> AgentCard("DNS benchmark results") {
            val report = result.report
            val testedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(report.testedAtEpochMs))
            Text("$testedAt · ${report.protocol.label} · ${report.reachableCount}/${report.entries.size} responded")
            val fastest = report.fastestReachable
            Text(if (fastest == null) "No tested resolver answered." else "Fastest in this test: ${fastest.providerName} (${fastest.latencyMs} ms).")
            report.entries.forEach { entry ->
                Text("${entry.providerName}: ${entry.latencyMs?.let { "$it ms" } ?: "No usable response"}", style = MaterialTheme.typography.bodySmall)
            }
            Text("Lookup timing only. Your DNS provider did not change.")
            TextButton(onClick = { onTool(Agent.Tool.DNS_SETTINGS) }) { Text("Review DNS settings") }
        }
        AetherTaskResult.AliasShieldOn -> AgentCard("DNS Alias Shield enabled") {
            Text("The setting is enabled in AdShield. It applies to DNS replies that AdShield filters when protection is active.")
            TextButton(onClick = { onTool(Agent.Tool.DNS_SETTINGS) }) { Text("Review or turn off in DNS settings") }
        }
    }
}

private fun AetherSecurityReview.Reading<*>.missingLabel(): String =
    (this as? AetherSecurityReview.Reading.Missing)?.reason?.label ?: "No app metadata available"

@Composable
private fun AgentAppAudit(apps: AetherAppReview) {
    val context = LocalContext.current
    var openError by remember(apps) { mutableStateOf(false) }
    AgentCard("App audit results") {
        if (apps.inspected == 0) {
            Text("No app metadata was inspected. This isn't a safety verdict.")
        } else {
            Text("${apps.inspected}/${apps.visible} visible apps inspected · ${apps.highRisk} with high-risk indicators")
            if (apps.needsReview == 0) Text("No medium- or high-risk indicators matched the inspected apps.")
        }
        if (apps.unavailable > 0) Text("${apps.unavailable} visible apps could not be inspected.")
        for (audit in apps.topFindings) {
            Spacer(Modifier.height(4.dp))
            val profile = audit.profile
            val label = profile.appName.filterNot { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }.take(96)
            Text(label.ifBlank { profile.packageName }, style = MaterialTheme.typography.titleSmall,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text("${profile.packageName} · ${audit.riskLevel.name.lowercase()}-risk indicators", style = MaterialTheme.typography.bodySmall)
            audit.findings.take(3).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = {
                val appInfo = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", profile.packageName, null))
                openError = runCatching { context.startActivity(appInfo) }.isFailure
            }) { Text("Review in Android Settings") }
        }
        if (openError) Text("Couldn't open app details. Find the app in Android Settings → Apps.")
        if (apps.needsReview > apps.topFindings.size) {
            Text("Showing ${apps.topFindings.size} of ${apps.needsReview} flagged apps. Run a separate audit in Security → Apps to see the rest of its findings.")
        }
        Text("These are app declarations and install-source indicators. They don’t prove permissions are granted or an app is malicious.")
    }
}
