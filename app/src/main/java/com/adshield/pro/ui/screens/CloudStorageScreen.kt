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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Preview
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adshield.pro.domain.model.CloudObject
import com.adshield.pro.domain.model.CloudOperationState
import com.adshield.pro.domain.model.CloudPreview
import com.adshield.pro.domain.model.StorageProvider
import com.adshield.pro.domain.model.StorageProviderHealth
import com.adshield.pro.domain.model.StorageProviderKind
import com.adshield.pro.domain.model.VerifiedStorageCapacity
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.MetricSpec
import com.adshield.pro.ui.components.ResponsiveMetrics
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber
import java.util.Locale

@Composable
fun CloudStorageScreen(
    providers: List<StorageProvider>,
    capacity: VerifiedStorageCapacity,
    selectedProviderId: String?,
    currentPath: String,
    objects: List<CloudObject>,
    searchQuery: String,
    operation: CloudOperationState,
    shareLink: String?,
    preview: CloudPreview?,
    onSelectProvider: (String) -> Unit,
    onCloseProvider: () -> Unit,
    onRegisterProvider: (String, StorageProviderKind, String, String, String) -> Unit,
    onRemoveProvider: (String) -> Unit,
    onCheckProvider: (String) -> Unit,
    onRefresh: () -> Unit,
    onOpenFolder: (CloudObject) -> Unit,
    onGoToParent: () -> Unit,
    onGoToPath: (String) -> Unit,
    onSearchQuery: (String) -> Unit,
    onCreateFolder: (String) -> Unit,
    onRename: (CloudObject, String) -> Unit,
    onDelete: (CloudObject) -> Unit,
    onUpload: (Uri, String, String, Long) -> Unit,
    onDownload: (CloudObject, Uri) -> Unit,
    onPreview: (CloudObject) -> Unit,
    onClearPreview: () -> Unit,
    onCreateShare: (CloudObject) -> Unit,
    onClearShare: () -> Unit,
    onClearOperation: () -> Unit
) {
    val context = LocalContext.current
    var showAddProvider by remember { mutableStateOf(false) }
    var showNewFolder by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<CloudObject?>(null) }
    var deleteTarget by remember { mutableStateOf<CloudObject?>(null) }
    var removeTarget by remember { mutableStateOf<StorageProvider?>(null) }
    var pendingDownload by remember { mutableStateOf<CloudObject?>(null) }
    val selected = providers.firstOrNull { it.id == selectedProviderId }

    val uploadPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && selectedProviderId != null) {
            val metadata = queryUriMetadata(context, uri)
            onUpload(uri, metadata.name, metadata.mimeType, metadata.size)
        }
    }
    val destinationPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val item = pendingDownload
        if (uri != null && item != null) onDownload(item, uri)
        pendingDownload = null
    }

    LaunchedEffect(preview?.contentUri) {
        val value = preview ?: return@LaunchedEffect
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(Uri.parse(value.contentUri), value.mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        runCatching { context.startActivity(intent) }
            .onFailure { Toast.makeText(context, "No installed app can preview this file type", Toast.LENGTH_LONG).show() }
        onClearPreview()
    }

    if (selected == null) {
        ProviderDashboard(
            providers = providers,
            capacity = capacity,
            operation = operation,
            onAdd = { showAddProvider = true },
            onSelect = onSelectProvider,
            onCheck = onCheckProvider,
            onRemove = { removeTarget = it },
            onClearOperation = onClearOperation
        )
    } else {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onCloseProvider) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "All storage providers")
                }
                Column(Modifier.weight(1f)) {
                    Text(selected.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("/$currentPath", style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                IconButton(onClick = { showNewFolder = true }) { Icon(Icons.Default.CreateNewFolder, contentDescription = "New folder") }
                IconButton(onClick = { runCatching { uploadPicker.launch(arrayOf("*/*")) } }) { Icon(Icons.Default.CloudUpload, contentDescription = "Upload file") }
                IconButton(onClick = onRefresh) { Icon(Icons.Default.Refresh, contentDescription = "Refresh") }
            }
            if (currentPath.isNotEmpty()) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    TextButton(onClick = { onGoToPath("") }) { Text("Root") }
                    TextButton(onClick = onGoToParent) { Text("Up one level") }
                }
            }
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQuery,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                singleLine = true,
                label = { Text("Search this remote folder") }
            )
            OperationCard(operation, onClearOperation)
            val filtered = objects.filter {
                searchQuery.isBlank() || it.name.contains(searchQuery.trim(), ignoreCase = true)
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (filtered.isEmpty() && !operation.running) {
                    item(key = "empty-folder") {
                        Text(
                            if (objects.isEmpty()) "This folder is empty, or the server returned no visible entries." else "No item matches the current folder search.",
                            modifier = Modifier.padding(20.dp),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                items(filtered, key = { it.providerId + ":" + it.path }, contentType = { "cloud-object" }) { item ->
                    CloudObjectCard(
                        item = item,
                        nextcloud = selected.kind == StorageProviderKind.NEXTCLOUD,
                        onOpen = { onOpenFolder(item) },
                        onRename = { renameTarget = item },
                        onDelete = { deleteTarget = item },
                        onDownload = {
                            pendingDownload = item
                            runCatching { destinationPicker.launch(item.name) }
                        },
                        onPreview = { onPreview(item) },
                        onShare = { onCreateShare(item) }
                    )
                }
            }
        }
    }

    if (showAddProvider) {
        AddProviderDialog(
            busy = operation.running,
            onDismiss = { showAddProvider = false },
            onRegister = { name, kind, url, user, password ->
                onRegisterProvider(name, kind, url, user, password)
                showAddProvider = false
            }
        )
    }
    if (showNewFolder) {
        NameDialog("Create remote folder", "Folder name", onDismiss = { showNewFolder = false }) {
            onCreateFolder(it); showNewFolder = false
        }
    }
    renameTarget?.let { item ->
        NameDialog("Rename remote item", "New name", initial = item.name, onDismiss = { renameTarget = null }) {
            onRename(item, it); renameTarget = null
        }
    }
    deleteTarget?.let { item ->
        ConfirmDialog(
            title = "Delete ${item.name}?",
            text = if (item.isDirectory) "This asks the server to permanently delete the folder and everything inside it." else "This asks the server to permanently delete the remote file. Server versioning/trash behavior depends on the provider.",
            confirm = "Delete remotely",
            onDismiss = { deleteTarget = null },
            onConfirm = { onDelete(item); deleteTarget = null }
        )
    }
    removeTarget?.let { provider ->
        ConfirmDialog(
            title = "Remove ${provider.name}?",
            text = "This removes only the connection and its encrypted app credential. It does not delete server files or the server account.",
            confirm = "Remove connection",
            onDismiss = { removeTarget = null },
            onConfirm = { onRemoveProvider(provider.id); removeTarget = null }
        )
    }
    shareLink?.let { link ->
        val clipboard = LocalClipboardManager.current
        AlertDialog(
            onDismissRequest = onClearShare,
            title = { Text("Public link created") },
            text = {
                Column {
                    Text("Anyone with this link may access the shared item. Manage expiration/password policy in Nextcloud if required.")
                    Spacer(Modifier.height(8.dp))
                    Text(link, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(link))
                    Toast.makeText(context, "Link copied", Toast.LENGTH_SHORT).show()
                }) { Text("Copy") }
            },
            dismissButton = {
                TextButton(onClick = {
                    context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"; putExtra(Intent.EXTRA_TEXT, link)
                    }, "Share public link"))
                }) { Text("Share") }
            }
        )
    }
}

@Composable
private fun ProviderDashboard(
    providers: List<StorageProvider>,
    capacity: VerifiedStorageCapacity,
    operation: CloudOperationState,
    onAdd: () -> Unit,
    onSelect: (String) -> Unit,
    onCheck: (String) -> Unit,
    onRemove: (StorageProvider) -> Unit,
    onClearOperation: () -> Unit
) {
    val columns = if (LocalConfiguration.current.screenWidthDp >= 600) 4 else 2
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "infinity-capacity") {
            CyberPanel("OMNISHIELD PRIVATE CLOUD", "Infinity authorized storage network • measured DAV quota only") {
                ResponsiveMetrics(
                    metrics = listOf(
                        MetricSpec("Verified capacity", formatBytes(capacity.provisionedBytes), "${capacity.verifiedProviders} online provider(s) with quota", EmeraldPrimary),
                        MetricSpec("Available", formatBytes(capacity.availableBytes), "Usable only on verified online endpoints", CyberCyan),
                        MetricSpec("Used", formatBytes(capacity.usedBytes), "Derived from verified total − available", ElectricBlue),
                        MetricSpec("Not counted", (capacity.unavailableProviders + capacity.unreportedProviders).toString(), "Offline or quota-unreported endpoints", WarningAmber)
                    ),
                    columns = columns
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    "No capacity is assumed. Offline, disconnected, unauthorized, or quota-unreported servers do not increase the totals. This dashboard aggregates independent providers; distributed striping/replication is not enabled.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        item(key = "add-provider") {
            Button(onClick = onAdd, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Connect an authorized Nextcloud / WebDAV server")
            }
        }
        item(key = "operation") { OperationCard(operation, onClearOperation) }
        if (providers.isEmpty()) {
            item(key = "no-providers") {
                Text(
                    "No storage is connected. Supply your own HTTPS server and an app-specific account/password. A self-hosted Nextcloud deployment is documented in infra/. No free 1 TB claim is made.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }
        items(providers, key = { it.id }, contentType = { "storage-provider" }) { provider ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Cloud, contentDescription = null, tint = CyberCyan)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(provider.name, fontWeight = FontWeight.Bold)
                            Text(provider.kind.label, style = MaterialTheme.typography.labelSmall)
                        }
                        StatusPill(provider.health.name, if (provider.health == StorageProviderHealth.ONLINE) EmeraldPrimary else WarningAmber)
                    }
                    Text(provider.baseUrl, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text(
                        if (provider.totalBytes != null) "Last DAV quota: ${formatBytes(provider.totalBytes)} total • ${formatBytes(provider.availableBytes ?: 0)} available" else "DAV quota not reported; zero capacity counted",
                        style = MaterialTheme.typography.bodySmall
                    )
                    provider.lastError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(onClick = { onSelect(provider.id) }, enabled = provider.health == StorageProviderHealth.ONLINE) { Text("Open") }
                        OutlinedButton(onClick = { onCheck(provider.id) }) {
                            Icon(Icons.Default.HealthAndSafety, contentDescription = null, Modifier.size(17.dp))
                            Spacer(Modifier.width(4.dp)); Text("Verify")
                        }
                        TextButton(onClick = { onRemove(provider) }) { Text("Remove") }
                    }
                }
            }
        }
    }
}

@Composable
private fun CloudObjectCard(
    item: CloudObject,
    nextcloud: Boolean,
    onOpen: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    onDownload: () -> Unit,
    onPreview: () -> Unit,
    onShare: () -> Unit
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (item.isDirectory) Icons.Default.Folder else Icons.Default.Description, contentDescription = null, tint = if (item.isDirectory) CyberCyan else ElectricBlue)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(item.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text(if (item.isDirectory) "Remote folder" else "${formatBytes(item.sizeBytes)} • ${item.path}", style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                if (item.isDirectory) TextButton(onClick = onOpen) { Text("Open") }
                else {
                    TextButton(onClick = onPreview) { Icon(Icons.Default.Preview, contentDescription = "Preview", Modifier.size(17.dp)); Spacer(Modifier.width(3.dp)); Text("Preview") }
                    TextButton(onClick = onDownload) { Icon(Icons.Default.CloudDownload, contentDescription = "Download", Modifier.size(17.dp)); Spacer(Modifier.width(3.dp)); Text("Download") }
                }
                if (nextcloud) TextButton(onClick = onShare) { Icon(Icons.Default.Share, contentDescription = "Create public link", Modifier.size(17.dp)) }
            }
            Row {
                TextButton(onClick = onRename) { Text("Rename") }
                TextButton(onClick = onDelete) { Icon(Icons.Default.Delete, contentDescription = null, Modifier.size(16.dp)); Spacer(Modifier.width(4.dp)); Text("Delete") }
            }
        }
    }
}

@Composable
private fun OperationCard(operation: CloudOperationState, onClear: () -> Unit) {
    if (!operation.running && operation.label == null && operation.error == null) return
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 5.dp),
        colors = CardDefaults.cardColors(containerColor = if (operation.error != null) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(10.dp)) {
            if (operation.running) {
                val total = operation.totalBytes
                if (total != null && total > 0L) {
                    LinearProgressIndicator(progress = { (operation.completedBytes.toFloat() / total).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                Spacer(Modifier.height(6.dp))
            }
            Text(operation.error ?: operation.label ?: "Working…", style = MaterialTheme.typography.bodySmall)
            if (operation.running && operation.totalBytes != null) Text("${formatBytes(operation.completedBytes)} / ${formatBytes(operation.totalBytes)}", style = MaterialTheme.typography.labelSmall)
            if (!operation.running) TextButton(onClick = onClear) { Text("Dismiss") }
        }
    }
}

@Composable
private fun AddProviderDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onRegister: (String, StorageProviderKind, String, String, String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf(StorageProviderKind.NEXTCLOUD) }
    var url by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Connect authorized storage") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("Server display name") }, singleLine = true)
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    StorageProviderKind.entries.forEach { value ->
                        FilterChip(selected = kind == value, onClick = { kind = value }, label = { Text(if (value == StorageProviderKind.NEXTCLOUD) "Nextcloud" else "WebDAV") })
                    }
                }
                OutlinedTextField(url, { url = it }, label = { Text("HTTPS WebDAV root URL") }, singleLine = true, placeholder = { Text("https://host/remote.php/dav/files/USER/") })
                OutlinedTextField(username, { username = it }, label = { Text("Username (optional for open WebDAV)") }, singleLine = true)
                OutlinedTextField(password, { password = it }, label = { Text("App password / password") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                Text("The password is encrypted with Android Keystore. Registration performs a real PROPFIND health/quota check; failure leaves the provider offline and uncounted.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            Button(onClick = { onRegister(name, kind, url, username, password) }, enabled = name.isNotBlank() && url.isNotBlank() && !busy) { Text("Verify & connect") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun NameDialog(title: String, label: String, initial: String = "", onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(value, { value = it }, label = { Text(label) }, singleLine = true) },
        confirmButton = { Button(onClick = { onConfirm(value) }, enabled = value.isNotBlank()) { Text("Confirm") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun ConfirmDialog(title: String, text: String, confirm: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm, color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

private data class UriMetadata(val name: String, val mimeType: String, val size: Long)

private fun queryUriMetadata(context: Context, uri: Uri): UriMetadata {
    var name = "upload-${System.currentTimeMillis()}"
    var size = -1L
    runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                name = cursor.getString(0) ?: name
                if (!cursor.isNull(1)) size = cursor.getLong(1)
            }
        }
    }
    return UriMetadata(name, context.contentResolver.getType(uri) ?: "application/octet-stream", size)
}

internal fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val units = arrayOf("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    var value = bytes.toDouble()
    var unit = 0
    while (value >= 1024.0 && unit < units.lastIndex) { value /= 1024.0; unit++ }
    return String.format(Locale.ROOT, if (unit == 0) "%.0f %s" else "%.2f %s", value, units[unit])
}
