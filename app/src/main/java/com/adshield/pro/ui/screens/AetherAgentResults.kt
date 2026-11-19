package com.adshield.pro.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyListScope
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
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherDnsPolicyReview
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherPhoneAgent as Agent
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.UrlThreatScanner
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

@Composable
internal fun AgentTaskResult(result: AetherTaskResult, onTool: (Agent.Tool) -> Unit, actionsEnabled: Boolean) {
    when (result) {
        // The screen renders these reports as separate lazy items.
        is AetherTaskResult.Phone, is AetherTaskResult.Review -> Unit
        is AetherTaskResult.Apps -> AgentAppAudit(result.review, actionsEnabled)
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
            TextButton(onClick = { onTool(Agent.Tool.DNS_SETTINGS) }, enabled = actionsEnabled) { Text("Review DNS settings") }
        }
        AetherTaskResult.AliasShieldOn -> AgentCard("DNS Alias Shield enabled") {
            Text("The setting is enabled in AdShield. It applies to DNS replies that AdShield filters when protection is active.")
            TextButton(onClick = { onTool(Agent.Tool.DNS_SETTINGS) }, enabled = actionsEnabled) { Text("Review or turn off in DNS settings") }
        }
    }
}

internal fun LazyListScope.agentSecurityReviewItems(
    report: AetherSecurityReview.Report,
    onTool: (Agent.Tool) -> Unit,
    actionsEnabled: Boolean
) {
    item(key = "review-coverage") {
        AgentCard("Security review results") {
            val finished = agentDateTime(report.finishedAtMs)
            Text(if (report.hasGaps) "Finished with gaps · $finished" else "Three checks completed · $finished")
            val phone = report.phone.value
            val phoneStatus = when {
                phone == null -> report.phone.missingLabel()
                phone.hasUnavailableReadings -> "Some readings unavailable"
                else -> "Available"
            }
            val apps = report.apps.value
            val appStatus = when {
                apps == null -> report.apps.missingLabel()
                apps.inspected == 0 -> "No app metadata inspected"
                else -> "${apps.inspected}/${apps.visible} visible apps inspected"
            }
            Text("Phone protection: $phoneStatus")
            Text("Saved DNS policy: ${if (report.dns.value != null) "Read" else report.dns.missingLabel()}")
            Text("App metadata: $appStatus")
            Text("No data was sent and no settings were changed by this review. These readings are not a safety verdict.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
    if (report.priorities.isNotEmpty()) {
        item(key = "review-priorities") {
            AgentCard("What to review first") {
                for (finding in report.priorities) {
                    Text(finding.source.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    Text(finding.title, style = MaterialTheme.typography.titleSmall)
                    Text(finding.detail, style = MaterialTheme.typography.bodyMedium)
                    finding.nextTool?.let { tool ->
                        TextButton(onClick = { onTool(tool) }, enabled = actionsEnabled) { Text(tool.label) }
                    }
                }
            }
        }
    }
    report.dns.value?.let { dns ->
        item(key = "review-tunnel") { AgentTunnelEvidence(dns, report.finishedAtMs) }
        item(key = "review-dns") { AgentSavedDnsPolicy(dns, report.dns.checkedAtMs) }
    }
    item(key = "review-cross-check") {
        AgentCard("App indicators and DNS exceptions") {
            val count = report.appPolicyMatchCount
            Text(when {
                count == null -> "Couldn't compare. Both saved DNS policy and inspected app metadata are needed."
                count == 0 -> "No inspected app with medium- or high-risk indicators matched the available exception evidence."
                else -> "$count inspected app(s) with medium- or high-risk indicators matched a saved rule or a VPN exclusion in the setup receipt."
            })
            for (match in report.appPolicyMatches) {
                Spacer(Modifier.height(4.dp))
                Text(agentAppLabel(match.appName, match.packageName), style = MaterialTheme.typography.titleSmall,
                    maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text("${match.packageName} · ${match.level.name.lowercase()}-risk indicators", style = MaterialTheme.typography.bodySmall)
                Text(match.exception.label, style = MaterialTheme.typography.labelMedium)
                match.exclusionEvidence?.let { Text(it.label, style = MaterialTheme.typography.bodySmall) }
                match.indicators.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            if (count != null && count > report.appPolicyMatches.size) {
                Text("Showing ${report.appPolicyMatches.size} of $count matches, ranked by app metadata risk.")
            }
            if ((report.apps.value?.unavailable ?: 0) > 0) {
                Text("Apps without readable metadata could not be compared.", style = MaterialTheme.typography.bodySmall)
            }
            Text("The setup receipt does not show traffic. Allow all DNS stays a saved rule, not proof of a DNS decision. Metadata does not prove an app is malicious.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
    report.apps.value?.let { apps ->
        item(key = "review-apps") { AgentAppAudit(apps, actionsEnabled) }
    }
}

@Composable
private fun AgentTunnelEvidence(dns: AetherDnsPolicyReview.Summary, reviewedAtMs: Long) {
    AgentCard("VPN exclusion evidence") {
        val tunnel = dns.tunnel
        Text("${dns.vpnExcludedApps} saved VPN exclusions")
        if (tunnel == null) {
            Text("Applied state unknown: no current tunnel setup receipt.")
        } else {
            Text("Saved VPN exclusions accepted: ${tunnel.appliedSaved}/${dns.vpnExcludedApps}")
            Text("Saved exclusions rejected: ${tunnel.rejectedSaved}")
            Text("Saved exclusions not recorded at setup: ${tunnel.unrecordedSaved}")
            Text("Accepted at setup but no longer saved: ${tunnel.appliedButNoLongerSaved}")
            Text("DNS routes set up: ${if (tunnel.hasIpv6DnsRoute) "IPv4 and IPv6" else "IPv4"}")
            if (tunnel.filteringPaused) Text("DNS filtering was paused; the Android tunnel was still installed.")
            Text("Tunnel #${tunnel.generation} established ${agentDateTime(tunnel.establishedAtEpochMs)}.",
                style = MaterialTheme.typography.bodySmall)
        }
        Text("Snapshot at ${agentDateTime(reviewedAtMs)}. Run another review after changes. " +
            "This checks tunnel setup, not DNS traffic or which resolver answered.", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun AgentSavedDnsPolicy(dns: AetherDnsPolicyReview.Summary, checkedAtMs: Long?) {
    AgentCard("Saved DNS policy") {
        checkedAtMs?.let { Text("Read ${agentDateTime(it)} · Configuration, not a live test", style = MaterialTheme.typography.bodySmall) }
        Text("Saved primary: ${dns.primaryProvider} · ${dns.protocol.label}")
        Text("Encrypted failover: ${dns.failover.label}")
        if (dns.backups.isNotEmpty()) Text("Saved backups: ${dns.backups.joinToString()}")
        Text("DNS Alias Shield: ${if (dns.aliasShieldOn) "On" else "Off"}")
        Text("DNSSEC: ${dns.dnssecMode.label}. No local signature-chain validation.")
        if (dns.dnssecMode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS) {
            Text("Strict mode rejects positive upstream answers without the AD flag, including unsigned answers.",
                style = MaterialTheme.typography.bodySmall)
        }
        Text("${dns.vpnExcludedApps} saved VPN exclusions · ${dns.allowDnsOverrides} saved Allow all DNS rules")
        if (dns.excludedAppsWithBlockRules > 0) {
            Text("${dns.excludedAppsWithBlockRules} saved VPN exclusions overlap with Block all DNS rules.")
        }
        val transports = dns.networksWithoutDomainFiltering
        Text(if (transports.isEmpty()) "Domain filters selected for all network types."
            else "Network types set to skip domain filters: ${transports.joinToString { it.label }}.")
        Text(if (dns.allowlistOnly) "Allowlist-only DNS is on. For requests reaching the tunnel, it can block names before per-app Allow all DNS or network exceptions are evaluated."
            else "Allowlist-only DNS is off.", style = MaterialTheme.typography.bodySmall)
        if (dns.subnetForwardingProviders.isNotEmpty()) {
            Text("Preset disclosures list these providers in the plan as forwarding a client subnet: ${dns.subnetForwardingProviders.joinToString()}.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun agentDateTime(timeMs: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(timeMs))

private fun AetherSecurityReview.Reading<*>.missingLabel(): String =
    (this as? AetherSecurityReview.Reading.Missing)?.reason?.label ?: "Not available"

private fun agentAppLabel(name: String, packageName: String): String =
    name.filterNot { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }.take(96).ifBlank { packageName }

@Composable
private fun AgentAppAudit(apps: AetherAppReview, actionsEnabled: Boolean) {
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
            Text(agentAppLabel(profile.appName, profile.packageName), style = MaterialTheme.typography.titleSmall,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text("${profile.packageName} · ${audit.riskLevel.name.lowercase()}-risk indicators", style = MaterialTheme.typography.bodySmall)
            audit.findings.take(3).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = {
                val appInfo = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", profile.packageName, null))
                openError = runCatching { context.startActivity(appInfo) }.isFailure
            }, enabled = actionsEnabled) { Text("Review in Android Settings") }
        }
        if (openError) Text("Couldn't open app details. Find the app in Android Settings → Apps.")
        if (apps.needsReview > apps.topFindings.size) {
            Text("Showing ${apps.topFindings.size} of ${apps.needsReview} flagged apps. Run a separate audit in Security → Apps to see the rest of its findings.")
        }
        Text("These are app declarations and install-source indicators. They don’t prove permissions are granted or an app is malicious.")
    }
}
