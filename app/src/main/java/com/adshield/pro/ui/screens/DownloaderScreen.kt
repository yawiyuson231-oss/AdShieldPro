package com.adshield.pro.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.engine.downloader.MediaDownloaderEngine
import com.adshield.pro.engine.optimizer.RuleBasedOptimizationPredictor
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber
import java.io.File

@Composable
fun DownloaderScreen(
    prefilledUrl: String = "",
    probeResult: MediaDownloaderEngine.MediaProbeResult?,
    probeError: String?,
    isProbing: Boolean,
    tasks: List<MediaDownloaderEngine.MediaDownloadTask>,
    onProbeUrl: (String) -> Unit,
    onStartDownload: (
        MediaDownloaderEngine.MediaProbeResult,
        MediaDownloaderEngine.MediaFormatOption,
        MediaDownloaderEngine.DownloadDestinationKind,
        Uri?
    ) -> Unit,
    onPause: (String) -> Unit,
    onResume: (String) -> Unit,
    onCancel: (String) -> Unit,
    onRemove: (String, Boolean) -> Unit,
    onClearFinished: () -> Unit,
    onOpenCompletedFile: (File, String) -> Unit,
    onSaveCompletedToVault: (String) -> Unit
) {
    var urlInput by rememberSaveable { mutableStateOf(prefilledUrl) }
    LaunchedEffect(prefilledUrl) {
        if (prefilledUrl.isNotBlank() && prefilledUrl != urlInput) {
            urlInput = prefilledUrl
        }
    }

    var selectedFormatId by remember(probeResult) {
        mutableStateOf(probeResult?.formats?.firstOrNull()?.id)
    }
    var destinationKind by rememberSaveable {
        mutableStateOf(MediaDownloaderEngine.DownloadDestinationKind.SYSTEM_MEDIASTORE)
    }
    var customFolderUri by remember { mutableStateOf<Uri?>(null) }

    val folderPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            customFolderUri = uri
            destinationKind = MediaDownloaderEngine.DownloadDestinationKind.CUSTOM_DIRECTORY
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "downloader-input") {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Download, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(26.dp))
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text("Universal Video & Music Downloader", style = MaterialTheme.typography.titleLarge)
                            Text(
                                "Supports legitimate direct video/audio links, open HTML5 media pages, and unencrypted HLS streams. Respects DRM and copyright restrictions.",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        placeholder = { Text("https://example.org/video.mp4 or open media page URL…") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Button(
                        onClick = { onProbeUrl(urlInput) },
                        enabled = urlInput.isNotBlank() && !isProbing,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isProbing) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("Detecting Formats & Resolutions…")
                        } else {
                            Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Detect Available Formats")
                        }
                    }

                    if (!probeError.isNullOrBlank()) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = AlertRed.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                probeError,
                                color = AlertRed,
                                fontSize = 12.sp,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                }
            }
        }

        probeResult?.let { probe ->
            item(key = "downloader-formats") {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(probe.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(
                            "Source: ${probe.sourceHost} · ${probe.formats.size} format(s) available",
                            fontSize = 11.sp,
                            color = CyberCyan
                        )

                        probe.formats.forEach { fmt ->
                            val isSelected = selectedFormatId == fmt.id
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = isSelected,
                                    onClick = { selectedFormatId = fmt.id }
                                )
                                Icon(
                                    if (fmt.mediaKind == MediaDownloaderEngine.MediaKind.AUDIO) Icons.Default.MusicNote else Icons.Default.VideoFile,
                                    contentDescription = null,
                                    tint = if (fmt.mediaKind == MediaDownloaderEngine.MediaKind.AUDIO) CyberCyan else EmeraldPrimary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        "${fmt.containerFormat} · ${fmt.qualityLabel}",
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 13.sp
                                    )
                                    val sizeLabel = fmt.contentLengthBytes?.takeIf { it > 0L }
                                        ?.let { RuleBasedOptimizationPredictor.formatBytes(it) }
                                        ?: if (fmt.isHlsPlaylist) "Segmented HLS" else "Stream"
                                    val resumeNote = if (fmt.supportsRangeResume) " · Pause/Resume supported" else ""
                                    Text(
                                        "$sizeLabel$resumeNote",
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }

                        Spacer(Modifier.height(4.dp))
                        Text("Download Location:", style = MaterialTheme.typography.labelMedium)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilterChip(
                                selected = destinationKind == MediaDownloaderEngine.DownloadDestinationKind.SYSTEM_MEDIASTORE,
                                onClick = { destinationKind = MediaDownloaderEngine.DownloadDestinationKind.SYSTEM_MEDIASTORE },
                                label = { Text("Device Downloads / Music") }
                            )
                            FilterChip(
                                selected = destinationKind == MediaDownloaderEngine.DownloadDestinationKind.APP_MEDIA_FOLDER,
                                onClick = { destinationKind = MediaDownloaderEngine.DownloadDestinationKind.APP_MEDIA_FOLDER },
                                label = { Text("App Media Folder") }
                            )
                            FilterChip(
                                selected = destinationKind == MediaDownloaderEngine.DownloadDestinationKind.CUSTOM_DIRECTORY,
                                onClick = { runCatching { folderPicker.launch(null) } },
                                label = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(14.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text(if (customFolderUri != null) "Custom Folder ✓" else "Choose Folder…")
                                    }
                                }
                            )
                        }

                        val chosenFormat = probe.formats.firstOrNull { it.id == selectedFormatId } ?: probe.formats.firstOrNull()
                        Button(
                            onClick = {
                                if (chosenFormat != null) {
                                    onStartDownload(probe, chosenFormat, destinationKind, customFolderUri)
                                }
                            },
                            enabled = chosenFormat != null,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Download Selected Format")
                        }
                    }
                }
            }
        }

        item(key = "downloader-history-header") {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Active & Download History (${tasks.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                if (tasks.any {
                        it.status == MediaDownloaderEngine.DownloadStatus.COMPLETED ||
                            it.status == MediaDownloaderEngine.DownloadStatus.CANCELLED ||
                            it.status == MediaDownloaderEngine.DownloadStatus.FAILED
                    }
                ) {
                    TextButton(onClick = onClearFinished) {
                        Text("Clear Finished")
                    }
                }
            }
        }

        if (tasks.isEmpty()) {
            item(key = "downloader-empty") {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        "No downloads yet. Paste a direct MP4/WebM/MP3/M4A link or an open media page URL above.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        } else {
            items(tasks, key = { it.id }, contentType = { "media-download" }) { task ->
                val statusColor = when (task.status) {
                    MediaDownloaderEngine.DownloadStatus.COMPLETED -> EmeraldPrimary
                    MediaDownloaderEngine.DownloadStatus.DOWNLOADING -> ElectricBlue
                    MediaDownloaderEngine.DownloadStatus.PAUSED, MediaDownloaderEngine.DownloadStatus.QUEUED -> WarningAmber
                    MediaDownloaderEngine.DownloadStatus.FAILED, MediaDownloaderEngine.DownloadStatus.CANCELLED -> AlertRed
                }
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    task.fileName,
                                    style = MaterialTheme.typography.titleMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "${task.containerFormat} · ${task.qualityLabel} · ${task.destinationKind.label}",
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Surface(color = statusColor.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
                                Text(
                                    task.status.name,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = statusColor,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }

                        if (task.status == MediaDownloaderEngine.DownloadStatus.DOWNLOADING ||
                            task.status == MediaDownloaderEngine.DownloadStatus.PAUSED
                        ) {
                            if (task.totalBytes > 0L || task.totalHlsSegments > 0) {
                                LinearProgressIndicator(
                                    progress = { task.progressFraction },
                                    modifier = Modifier.fillMaxWidth(),
                                    color = statusColor
                                )
                            } else {
                                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = statusColor)
                            }
                        }

                        val progressDetail = buildString {
                            append(RuleBasedOptimizationPredictor.formatBytes(task.downloadedBytes))
                            if (task.totalBytes > 0L) {
                                append(" / ")
                                append(RuleBasedOptimizationPredictor.formatBytes(task.totalBytes))
                                append(" (${(task.progressFraction * 100).toInt()}%)")
                            }
                            if (task.speedBytesPerSec > 0L && task.status == MediaDownloaderEngine.DownloadStatus.DOWNLOADING) {
                                append(" · ${RuleBasedOptimizationPredictor.formatBytes(task.speedBytesPerSec)}/s")
                            }
                            task.errorMessage?.let { append(" · $it") }
                        }
                        Text(progressDetail, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            if (task.status == MediaDownloaderEngine.DownloadStatus.DOWNLOADING ||
                                task.status == MediaDownloaderEngine.DownloadStatus.QUEUED
                            ) {
                                IconButton(onClick = { onPause(task.id) }) {
                                    Icon(Icons.Default.Pause, contentDescription = "Pause", tint = WarningAmber)
                                }
                                IconButton(onClick = { onCancel(task.id) }) {
                                    Icon(Icons.Default.Cancel, contentDescription = "Cancel", tint = AlertRed)
                                }
                            }
                            if (task.status == MediaDownloaderEngine.DownloadStatus.PAUSED ||
                                task.status == MediaDownloaderEngine.DownloadStatus.FAILED
                            ) {
                                IconButton(onClick = { onResume(task.id) }) {
                                    Icon(Icons.Default.PlayArrow, contentDescription = "Resume", tint = EmeraldPrimary)
                                }
                                IconButton(onClick = { onCancel(task.id) }) {
                                    Icon(Icons.Default.Cancel, contentDescription = "Cancel", tint = AlertRed)
                                }
                            }
                            if (task.status == MediaDownloaderEngine.DownloadStatus.COMPLETED) {
                                IconButton(onClick = { onOpenCompletedFile(File(task.outputFilePath), task.mimeType) }) {
                                    Icon(Icons.Default.OpenInNew, contentDescription = "Play / Open", tint = EmeraldPrimary)
                                }
                                IconButton(onClick = { onSaveCompletedToVault(task.id) }) {
                                    Icon(Icons.Default.CloudUpload, contentDescription = "Encrypt to Vault", tint = ElectricBlue)
                                }
                            }
                            if (task.status != MediaDownloaderEngine.DownloadStatus.DOWNLOADING) {
                                IconButton(onClick = { onRemove(task.id, false) }) {
                                    Icon(Icons.Default.Delete, contentDescription = "Remove from History", tint = AlertRed)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
