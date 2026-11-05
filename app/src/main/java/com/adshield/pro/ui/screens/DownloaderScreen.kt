package com.adshield.pro.ui.screens

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adshield.pro.domain.model.DirectDownload
import com.adshield.pro.domain.model.DirectDownloadStatus
import com.adshield.pro.domain.model.InspectedMedia
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber

@Composable
fun DownloaderScreen(
    inspection: InspectedMedia?,
    downloads: List<DirectDownload>,
    busy: Boolean,
    message: String?,
    error: String?,
    allowMetered: Boolean,
    onInspect: (String) -> Unit,
    onEnqueue: (Uri) -> Unit,
    onAllowMetered: (Boolean) -> Unit,
    onCancel: (DirectDownload) -> Unit,
    onDeleteHistory: (DirectDownload) -> Unit,
    onVerify: (DirectDownload, String?) -> Unit,
    onStartUpdates: () -> Unit,
    onStopUpdates: () -> Unit,
    onClearMessages: () -> Unit
) {
    var url by rememberSaveable { mutableStateOf("") }
    var verifyTarget by remember { mutableStateOf<DirectDownload?>(null) }
    val context = LocalContext.current
    val destinationPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        if (uri != null) onEnqueue(uri)
    }
    DisposableEffect(Unit) {
        onStartUpdates()
        onDispose { onStopUpdates() }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "direct-media-input") {
            CyberPanel("DIRECT MEDIA DOWNLOADER", "MP4 / WebM / supported audio • direct permitted HTTPS files only") {
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Direct HTTPS media URL") },
                    placeholder = { Text("https://server.example/video.mp4") }
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = { onInspect(url) }, enabled = url.isNotBlank() && !busy, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.CloudDownload, contentDescription = null)
                    Spacer(Modifier.width(8.dp)); Text("Inspect actual media response")
                }
                Text(
                    "No universal site extractor is included. HTML pages, DRM, private/authenticated streams, and unsupported formats are refused. Resolution/quality is whatever the supplied file represents; no invented format list is shown.",
                    style = MaterialTheme.typography.bodySmall
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Allow metered connections")
                        Text("Roaming remains disabled; Android may still defer work for data/battery policy", style = MaterialTheme.typography.labelSmall)
                    }
                    Switch(checked = allowMetered, onCheckedChange = onAllowMetered)
                }
            }
        }
        if (busy) item(key = "downloader-busy") { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
        val statusText = error ?: message
        if (statusText != null) {
            item(key = "downloader-message") {
                Card(colors = CardDefaults.cardColors(containerColor = if (error != null) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant)) {
                    Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(statusText, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                        TextButton(onClick = onClearMessages) { Text("Dismiss") }
                    }
                }
            }
        }
        inspection?.let { media ->
            item(key = "inspected-media") {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text("Verified response metadata", fontWeight = FontWeight.Bold, color = EmeraldPrimary)
                        Text(media.fileName, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Text("MIME: ${media.mimeType}")
                        Text("Server size: ${media.sizeBytes?.let(::formatBytes) ?: "not reported"}")
                        Text(media.finalUrl, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Button(onClick = { runCatching { destinationPicker.launch(media.fileName) } }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Download, contentDescription = null); Spacer(Modifier.width(8.dp)); Text("Choose destination & download")
                        }
                    }
                }
            }
        }
        item(key = "download-history-heading") {
            Text("System queue & history", style = MaterialTheme.typography.titleMedium)
        }
        if (downloads.isEmpty()) {
            item(key = "empty-download-history") { Text("No direct-media downloads recorded.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        items(downloads, key = { it.id }, contentType = { "direct-download" }) { record ->
            DownloadCard(
                record = record,
                onCancel = { onCancel(record) },
                onDelete = { onDeleteHistory(record) },
                onVerify = { verifyTarget = record },
                onOpen = {
                    record.destinationUri?.let { destination ->
                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(Uri.parse(destination), record.mimeType)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        runCatching { context.startActivity(intent) }
                            .onFailure { Toast.makeText(context, "No media player can open this file", Toast.LENGTH_LONG).show() }
                    }
                }
            )
        }
    }

    verifyTarget?.let { record ->
        var expected by remember(record.id) { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { verifyTarget = null },
            title = { Text("Verify ${record.fileName}") },
            text = {
                Column {
                    Text("Optional: paste a publisher-supplied SHA-256. Without one, AdShield verifies declared size when available and computes a local digest, which is not a publisher authenticity check.")
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(expected, { expected = it }, singleLine = true, label = { Text("Expected SHA-256 (64 hex characters)") })
                }
            },
            confirmButton = {
                Button(onClick = { onVerify(record, expected.ifBlank { null }); verifyTarget = null }) { Text("Check integrity") }
            },
            dismissButton = { TextButton(onClick = { verifyTarget = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun DownloadCard(
    record: DirectDownload,
    onCancel: () -> Unit,
    onDelete: () -> Unit,
    onVerify: () -> Unit,
    onOpen: () -> Unit
) {
    val active = record.status in setOf(DirectDownloadStatus.QUEUED, DirectDownloadStatus.RUNNING, DirectDownloadStatus.PAUSED_BY_SYSTEM)
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(record.fileName, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text(record.mimeType, style = MaterialTheme.typography.labelSmall)
                }
                StatusPill(record.status.name, if (record.status == DirectDownloadStatus.COMPLETED) EmeraldPrimary else if (record.status == DirectDownloadStatus.FAILED) MaterialTheme.colorScheme.error else WarningAmber)
            }
            val total = record.totalBytes
            if (total != null && total > 0L) {
                LinearProgressIndicator(progress = { (record.downloadedBytes.toFloat() / total).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                Text("${formatBytes(record.downloadedBytes)} / ${formatBytes(total)}", style = MaterialTheme.typography.bodySmall)
            } else if (active) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text("${formatBytes(record.downloadedBytes)} downloaded • total not reported", style = MaterialTheme.typography.bodySmall)
            }
            record.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            record.integrityStatus?.let { Text(it, color = if (it.startsWith("FAILED")) MaterialTheme.colorScheme.error else ElectricBlue, style = MaterialTheme.typography.bodySmall) }
            Text("Pause/resume and background scheduling are controlled by Android DownloadManager; manual pause/resume is not claimed.", style = MaterialTheme.typography.labelSmall)
            Row {
                if (active) TextButton(onClick = onCancel) { Icon(Icons.Default.Cancel, contentDescription = null); Spacer(Modifier.width(4.dp)); Text("Cancel") }
                if (record.status == DirectDownloadStatus.COMPLETED) {
                    TextButton(onClick = onOpen) { Icon(Icons.Default.FileOpen, contentDescription = null); Spacer(Modifier.width(4.dp)); Text("Open") }
                    TextButton(onClick = onVerify) { Icon(Icons.Default.Verified, contentDescription = null); Spacer(Modifier.width(4.dp)); Text("Verify") }
                }
                TextButton(onClick = onDelete) { Text("Remove history") }
            }
        }
    }
}
