package com.adshield.pro.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.adshield.pro.data.repository.AetherVpnExclusionPreviewReader.Target
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.engine.aether.AetherVpnExclusionPreview.Report
import com.adshield.pro.engine.dns.DnsPolicyDecision
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout

/** Selection and results are scoped to this dialog, not saved or dispatched as Agent tasks. */
@Composable
internal fun AetherVpnExclusionPreviewDialog(
    loadTargets: suspend () -> List<Target>,
    loadPreview: suspend (String) -> Report?,
    onClose: () -> Unit
) {
    var selected by remember { mutableStateOf<Target?>(null) }
    val target = selected
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(if (target == null) "Choose a VPN-excluded app" else "Filtered mode preview") },
        text = {
            key(target?.packageName) {
                if (target == null) PreviewTargetList(loadTargets) { selected = it }
                else PreviewResult(target) { loadPreview(target.packageName) }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
        dismissButton = {
            if (target != null) TextButton(onClick = { selected = null }) { Text("Choose another app") }
        }
    )
}

@Composable
private fun PreviewTargetList(load: suspend () -> List<Target>, onSelect: (Target) -> Unit) {
    val read = readPreviewData(load)
    val targets = read?.getOrNull()
    PreviewList {
        item(key = "preview-picker-info") {
            Text("Choose one saved exclusion to preview switching that app to Filtered. No settings will change.")
        }
        when {
            read == null -> item { Text("Reading saved VPN exclusions…") }
            targets == null -> item { Text("Couldn't read saved VPN exclusions. Close and try again.") }
            targets.isEmpty() -> item { Text("No saved app exclusions are available to preview.") }
            else -> items(targets, key = { "preview-choice:${it.packageName}" }, contentType = { "preview-app" }) { target ->
                ListItem(
                    headlineContent = { Text(target.appLabel ?: target.packageName) },
                    supportingContent = if (target.appLabel == null) null else { { Text(target.packageName) } },
                    modifier = Modifier
                        .clickable(role = Role.Button, onClickLabel = "Preview Filtered mode") { onSelect(target) }
                        .testTag("preview-choice:${target.packageName}")
                )
            }
        }
    }
}

@Composable
private fun PreviewResult(target: Target, load: suspend () -> Report?) {
    val read = readPreviewData(load)
    val report = read?.getOrNull()
    PreviewList {
        when {
            read == null -> item { Text("Comparing saved settings…") }
            read.isFailure -> item { Text("Couldn't read the preview. Choose the app again to retry.") }
            report == null -> item {
                Text("${target.packageName} no longer has a saved VPN exclusion. Choose another app. Nothing was changed.")
            }
            else -> previewItems(target, report)
        }
    }
}

private fun LazyListScope.previewItems(target: Target, report: Report) {
    item(key = "preview-saved") {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            target.appLabel?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
            Text(report.packageName, style = MaterialTheme.typography.bodySmall)
            Text("If you choose Filtered", style = MaterialTheme.typography.titleSmall)
            Text("VPN exclusion: Saved → Removed")
            if (report.savedAppPolicy == AppDnsPolicy.DEFAULT) {
                Text("Per-app DNS rule: Uses global protection (unchanged)")
            } else {
                Text("Per-app DNS rule: ${report.savedAppPolicy.label} → ${AppDnsPolicy.DEFAULT.label}")
            }
            Text("Other app rules and global DNS settings would stay the same. Nothing was changed by this preview.")
        }
    }
    item(key = "preview-tunnel") {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("VPN setup evidence", style = MaterialTheme.typography.titleSmall)
            Text(report.exclusionEvidence.label)
            val tunnel = report.tunnelGeneration?.let { "Tunnel #$it · " }.orEmpty()
            Text("${tunnel}Snapshot at ${agentDateTime(report.sampledAtMs)}", style = MaterialTheme.typography.bodySmall)
            if (report.filteringPaused) Text("DNS filtering was paused when checked.")
            Text("Removing the saved exclusion alone won't change an existing tunnel. The new exclusion list needs a successful VPN rebuild, or a successful start if protection is off.")
        }
    }
    item(key = "preview-examples") {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Example DNS decisions", style = MaterialTheme.typography.titleSmall)
            Text("These examples compare saved vs. Filtered rules only if a DNS request reaches active filtering and Android identifies it as coming from this app. DNS requests outside the tunnel skip these rules.")
            Text("No DNS was sent or observed. This can't predict which domains the app uses, whether its requests reach the tunnel, upstream answers, or whether the app will work. Another exclusion for a shared app UID can still affect routing.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
    items(report.examples, key = { "preview-network:${it.transport.name}" }, contentType = { "preview-network" }) { network ->
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(network.transport.label, style = MaterialTheme.typography.titleSmall)
            for (example in network.comparisons) {
                Text(example.example.label, style = MaterialTheme.typography.labelMedium)
                Text(
                    "Saved: ${example.saved.previewLabel()}\nFiltered: ${example.filtered.previewLabel()}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

private fun DnsPolicyDecision.previewLabel(): String = when {
    isBlocked -> "Blocked · $sourceName"
    bypassDomainFilters -> "Skips domain filters · $sourceName"
    sourceName == "Allowed" -> "Passes local checks"
    else -> "Passes local checks · $sourceName"
}

@Composable
private fun PreviewList(content: LazyListScope.() -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxWidth().heightIn(max = 420.dp).testTag("aether-vpn-preview-list"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = content
    )
}

@Composable
private fun <T> readPreviewData(load: suspend () -> T): Result<T>? = produceState<Result<T>?>(null) {
    val result = try {
        Result.success(withTimeout(5_000) { load() })
    } catch (timeout: TimeoutCancellationException) {
        Result.failure(timeout)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (failure: Exception) {
        Result.failure(failure)
    }
    currentCoroutineContext().ensureActive()
    value = result
}.value
