package com.adshield.pro.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileCopy
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import com.adshield.pro.domain.model.DuplicateFileGroup
import com.adshield.pro.domain.model.FileScanProgress
import com.adshield.pro.domain.model.ManagedFile
import com.adshield.pro.domain.model.ManagedFileListing
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue

@Composable
fun FileManagerScreen(
    listing: ManagedFileListing?,
    busy: Boolean,
    message: String?,
    error: String?,
    query: String,
    scanProgress: FileScanProgress,
    duplicates: List<DuplicateFileGroup>,
    onOpenTree: (Uri) -> Unit,
    onRefresh: () -> Unit,
    onOpenFolder: (ManagedFile) -> Unit,
    onBack: () -> Boolean,
    onQuery: (String) -> Unit,
    onCreateFolder: (String) -> Unit,
    onRename: (ManagedFile, String) -> Unit,
    onDelete: (ManagedFile) -> Unit,
    onImport: (Uri, String, String) -> Unit,
    onScan: () -> Unit,
    onFindDuplicates: () -> Unit,
    onClearMessages: () -> Unit
) {
    val context = LocalContext.current
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showNewFolder by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<ManagedFile?>(null) }
    var deleteTarget by remember { mutableStateOf<ManagedFile?>(null) }
    val treePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) onOpenTree(uri)
    }
    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        uris.forEach { uri ->
            val metadata = querySafMetadata(context, uri)
            onImport(uri, metadata.first, metadata.second)
        }
    }

    Column(Modifier.fillMaxSize()) {
        if (listing == null) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp)
            ) {
                item(key = "grant-storage") {
                    CyberPanel("UNIVERSAL FILE MANAGER", "Android Storage Access Framework • user-granted trees only") {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(48.dp))
                        Spacer(Modifier.height(12.dp))
                        Text("Choose a folder or storage provider to begin. AdShield cannot inspect other apps’ private directories and does not request all-files access.")
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = { runCatching { treePicker.launch(null) } }, modifier = Modifier.fillMaxWidth()) { Text("Grant a storage folder") }
                    }
                }
            }
            return@Column
        }

        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { onBack() }, enabled = listing.documentId != listing.documentId.substringBeforeLast('/')) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Parent folder")
            }
            Column(Modifier.weight(1f)) {
                Text("SAF File Manager", style = MaterialTheme.typography.titleMedium)
                Text(listing.documentId, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            IconButton(onClick = { showNewFolder = true }) { Icon(Icons.Default.CreateNewFolder, contentDescription = "New folder") }
            IconButton(onClick = { runCatching { importPicker.launch(arrayOf("*/*")) } }) { Icon(Icons.Default.FileCopy, contentDescription = "Import files") }
            IconButton(onClick = onRefresh) { Icon(Icons.Default.Refresh, contentDescription = "Refresh") }
        }
        Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(selected = selectedTab == 0, onClick = { selectedTab = 0 }, label = { Text("Files") })
            FilterChip(selected = selectedTab == 1, onClick = { selectedTab = 1 }, label = { Text("Duplicates") })
            FilterChip(selected = selectedTab == 2, onClick = { selectedTab = 2 }, label = { Text("Security scan") })
        }
        if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        StatusMessage(message, error, onClearMessages)
        when (selectedTab) {
            0 -> FileList(
                listing = listing,
                query = query,
                onQuery = onQuery,
                onOpenFolder = onOpenFolder,
                onPreview = { file -> previewSafFile(context, file) },
                onShare = { file -> shareSafFile(context, file) },
                onRename = { renameTarget = it },
                onDelete = { deleteTarget = it }
            )
            1 -> DuplicateList(duplicates, busy, onFindDuplicates)
            else -> ScanPanel(scanProgress, onScan)
        }
    }

    if (showNewFolder) {
        SafNameDialog("Create folder", "", onDismiss = { showNewFolder = false }) {
            onCreateFolder(it); showNewFolder = false
        }
    }
    renameTarget?.let { file ->
        SafNameDialog("Rename item", file.name, onDismiss = { renameTarget = null }) {
            onRename(file, it); renameTarget = null
        }
    }
    deleteTarget?.let { file ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete ${file.name}?") },
            text = { Text(if (file.isDirectory) "The storage provider will permanently delete this folder and its contents where supported." else "The storage provider will permanently delete this document where supported. AdShield cannot undo it.") },
            confirmButton = { TextButton(onClick = { onDelete(file); deleteTarget = null }) { Text("Delete permanently", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun FileList(
    listing: ManagedFileListing,
    query: String,
    onQuery: (String) -> Unit,
    onOpenFolder: (ManagedFile) -> Unit,
    onPreview: (ManagedFile) -> Unit,
    onShare: (ManagedFile) -> Unit,
    onRename: (ManagedFile) -> Unit,
    onDelete: (ManagedFile) -> Unit
) {
    val filtered = listing.files.filter { query.isBlank() || it.name.contains(query.trim(), true) }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item(key = "file-search") {
            OutlinedTextField(query, onQuery, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Search current folder") })
        }
        if (filtered.isEmpty()) {
            item(key = "empty-file-list") { Text("No visible items match.", modifier = Modifier.padding(16.dp)) }
        }
        items(filtered, key = { it.uri }, contentType = { "managed-file" }) { file ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(if (file.isDirectory) Icons.Default.Folder else Icons.Default.Description, contentDescription = null, tint = if (file.isDirectory) CyberCyan else ElectricBlue)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(file.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(if (file.isDirectory) "Folder" else "${formatBytes(file.sizeBytes)} • ${file.mimeType}", style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                    Row {
                        if (file.isDirectory) TextButton(onClick = { onOpenFolder(file) }) { Text("Open") }
                        else {
                            TextButton(onClick = { onPreview(file) }) { Icon(Icons.Default.FileOpen, contentDescription = null, Modifier.size(16.dp)); Spacer(Modifier.width(3.dp)); Text("Preview") }
                            TextButton(onClick = { onShare(file) }) { Icon(Icons.Default.Share, contentDescription = null, Modifier.size(16.dp)); Spacer(Modifier.width(3.dp)); Text("Share") }
                        }
                        TextButton(onClick = { onRename(file) }) { Text("Rename") }
                        TextButton(onClick = { onDelete(file) }) { Icon(Icons.Default.Delete, contentDescription = "Delete", Modifier.size(16.dp)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun DuplicateList(duplicates: List<DuplicateFileGroup>, busy: Boolean, onFind: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "duplicate-action") {
            CyberPanel("SHA-256 DUPLICATE DETECTION", "Recursive, up to 250 files; same-size candidates are content hashed") {
                Button(onClick = onFind, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Find duplicate content") }
                Text("No duplicate is removed automatically. Providers that deny reads are skipped.", style = MaterialTheme.typography.bodySmall)
            }
        }
        items(duplicates, key = { it.sha256 + ":" + it.sizeBytes }, contentType = { "duplicate-group" }) { group ->
            Card {
                Column(Modifier.padding(12.dp)) {
                    Text("${group.files.size} copies • ${formatBytes(group.sizeBytes)} each", fontWeight = FontWeight.Bold)
                    Text("SHA-256 ${group.sha256}", style = MaterialTheme.typography.labelSmall)
                    group.files.forEach { Text("• ${it.name}\n  ${it.documentId}", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}

@Composable
private fun ScanPanel(progress: FileScanProgress, onScan: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp)
    ) {
        item(key = "scan-controls") {
            CyberPanel("FOLDER SECURITY SCAN", "Existing on-device signature, archive, script, and APK structural engines") {
                Text("Scans at most 250 files and skips individual files over 512 MiB to bound background work. Every completed result is persisted in Security → History. This is not a guarantee against unknown malware.")
                Spacer(Modifier.height(10.dp))
                Button(onClick = onScan, enabled = !progress.running, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Security, contentDescription = null); Spacer(Modifier.width(8.dp)); Text(if (progress.running) "Scanning…" else "Scan this tree")
                }
                if (progress.running || progress.total > 0) {
                    Spacer(Modifier.height(10.dp))
                    if (progress.total > 0) LinearProgressIndicator(progress = { progress.current.toFloat() / progress.total.coerceAtLeast(1) }, modifier = Modifier.fillMaxWidth())
                    else LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Text("${progress.current}/${progress.total} • ${progress.scanned} scanned • ${progress.skipped} skipped • ${progress.errors} errors")
                    progress.currentName?.let { Text(it, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}

@Composable
private fun StatusMessage(message: String?, error: String?, onClear: () -> Unit) {
    val text = error ?: message ?: return
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = if (error != null) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onClear) { Text("Dismiss") }
        }
    }
}

@Composable
private fun SafNameDialog(title: String, initial: String, onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(value, { value = it }, singleLine = true, label = { Text("Name") }) },
        confirmButton = { Button(onClick = { onConfirm(value) }, enabled = value.isNotBlank()) { Text("Confirm") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

private fun previewSafFile(context: Context, file: ManagedFile) {
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(Uri.parse(file.uri), file.mimeType)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    runCatching { context.startActivity(intent) }
        .onFailure { Toast.makeText(context, "No installed app can preview this format", Toast.LENGTH_LONG).show() }
}

private fun shareSafFile(context: Context, file: ManagedFile) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = file.mimeType
        putExtra(Intent.EXTRA_STREAM, Uri.parse(file.uri))
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    runCatching { context.startActivity(Intent.createChooser(intent, "Share ${file.name}")) }
        .onFailure { Toast.makeText(context, "No sharing app is available", Toast.LENGTH_LONG).show() }
}

private fun querySafMetadata(context: Context, uri: Uri): Pair<String, String> {
    var name = "import-${System.currentTimeMillis()}"
    runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) name = cursor.getString(0) ?: name
        }
    }
    return name to (context.contentResolver.getType(uri) ?: "application/octet-stream")
}
