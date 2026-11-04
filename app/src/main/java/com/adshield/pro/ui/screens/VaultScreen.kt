package com.adshield.pro.ui.screens

import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.DriveFileMove
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.engine.optimizer.RuleBasedOptimizationPredictor
import com.adshield.pro.engine.storage.PrivateCloudBoxEngine
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber
import java.io.File

@Composable
fun VaultScreen(
    items: List<PrivateCloudBoxEngine.VaultItem>,
    summary: PrivateCloudBoxEngine.VaultStorageSummary,
    cloudConfig: PrivateCloudBoxEngine.CloudEndpointConfig,
    selectedFolder: String?,
    selectedCategory: PrivateCloudBoxEngine.VaultCategory?,
    searchQuery: String,
    preview: PrivateCloudBoxEngine.VaultPreview?,
    isBusy: Boolean,
    onSelectFolder: (String?) -> Unit,
    onSelectCategory: (PrivateCloudBoxEngine.VaultCategory?) -> Unit,
    onSearchChange: (String) -> Unit,
    onCreateFolder: (String) -> Unit,
    onMoveItem: (String, String) -> Unit,
    onUploadUri: (Uri, String?) -> Unit,
    onExportItemToUri: (String, Uri) -> Unit,
    onPreviewItem: (String) -> Unit,
    onClosePreview: () -> Unit,
    onOpenPreviewExternally: (File, String) -> Unit,
    onDeleteItem: (String, Boolean) -> Unit,
    onSetPin: (String) -> Unit,
    onUnlock: (String) -> Unit,
    onLock: () -> Unit,
    onRemovePin: (String) -> Unit,
    onConfigureCloud: (PrivateCloudBoxEngine.CloudEndpointConfig) -> Unit,
    onSyncItem: (String) -> Unit,
    onSyncAll: () -> Unit
) {
    var pendingExportItem by remember { mutableStateOf<PrivateCloudBoxEngine.VaultItem?>(null) }
    var showFolderDialog by remember { mutableStateOf(false) }
    var showPinDialog by remember { mutableStateOf(false) }
    var showCloudDialog by remember { mutableStateOf(false) }
    var moveTargetItem by remember { mutableStateOf<PrivateCloudBoxEngine.VaultItem?>(null) }
    var unlockInput by rememberSaveable { mutableStateOf("") }

    val uploadPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            onUploadUri(uri, selectedFolder)
        }
    }

    val exportCreator = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { destUri ->
        val target = pendingExportItem
        pendingExportItem = null
        if (destUri != null && target != null) {
            onExportItemToUri(target.id, destUri)
        }
    }

    if (summary.isLocked) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = ElectricBlue, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(10.dp))
                    Text("Private Cloud Storage Box Locked", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Files and index are AES-256-GCM encrypted at rest. Enter your PIN/passphrase to unlock.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp, bottom = 14.dp)
                    )
                    OutlinedTextField(
                        value = unlockInput,
                        onValueChange = { unlockInput = it },
                        label = { Text("Vault PIN / Passphrase") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = {
                            onUnlock(unlockInput)
                            unlockInput = ""
                        },
                        enabled = unlockInput.length >= 4,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Unlock Vault")
                    }
                }
            }
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "vault-header") {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CloudDone, contentDescription = null, tint = ElectricBlue, modifier = Modifier.size(26.dp))
                        Spacer(Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Private Cloud Storage Box", style = MaterialTheme.typography.titleLarge)
                            Text(
                                if (summary.cloudConfigured) {
                                    "AES-256-GCM Vault · Synced with ${summary.cloudEndpointLabel} (${summary.syncedCount}/${summary.itemCount})"
                                } else {
                                    "AES-256-GCM Encrypted Vault · Connect HTTPS WebDAV or export to SAF Cloud Drive"
                                },
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    val usedFraction = if (summary.quotaBytes > 0L) {
                        (summary.usedBytes.toFloat() / summary.quotaBytes.toFloat()).coerceIn(0f, 1f)
                    } else 0f

                    LinearProgressIndicator(
                        progress = { usedFraction },
                        modifier = Modifier.fillMaxWidth(),
                        color = EmeraldPrimary
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "${RuleBasedOptimizationPredictor.formatBytes(summary.usedBytes)} / ${RuleBasedOptimizationPredictor.formatBytes(summary.quotaBytes)} used (${summary.itemCount} files)",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Free on device: ${RuleBasedOptimizationPredictor.formatBytes(summary.deviceFreeBytes)}",
                            fontSize = 11.sp,
                            color = CyberCyan
                        )
                    }

                    if (isBusy) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = ElectricBlue)
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { runCatching { uploadPicker.launch(arrayOf("*/*")) } },
                            enabled = !isBusy,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.CloudUpload, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Upload File", maxLines = 1)
                        }
                        OutlinedButton(onClick = { showFolderDialog = true }) {
                            Icon(Icons.Default.CreateNewFolder, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Folder", maxLines = 1)
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { showCloudDialog = true },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.CloudSync, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(if (summary.cloudConfigured) "Cloud Settings" else "Connect Cloud", maxLines = 1)
                        }
                        if (summary.cloudConfigured) {
                            OutlinedButton(onClick = onSyncAll, enabled = !isBusy) {
                                Text("Sync All", maxLines = 1)
                            }
                        }
                        OutlinedButton(onClick = { showPinDialog = true }) {
                            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(if (summary.isPinConfigured) "PIN / Lock" else "Set PIN", maxLines = 1)
                        }
                    }
                }
            }
        }

        item(key = "vault-filters") {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = onSearchChange,
                    placeholder = { Text("Search documents, photos, videos, audio…") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = selectedCategory == null,
                        onClick = { onSelectCategory(null) },
                        label = { Text("All Types") }
                    )
                    PrivateCloudBoxEngine.VaultCategory.entries.forEach { cat ->
                        FilterChip(
                            selected = selectedCategory == cat,
                            onClick = { onSelectCategory(if (selectedCategory == cat) null else cat) },
                            label = { Text(cat.displayName) }
                        )
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = selectedFolder == null,
                        onClick = { onSelectFolder(null) },
                        label = { Text("All Folders") }
                    )
                    summary.folderNames.forEach { folder ->
                        FilterChip(
                            selected = selectedFolder.equals(folder, ignoreCase = true),
                            onClick = { onSelectFolder(if (selectedFolder.equals(folder, ignoreCase = true)) null else folder) },
                            label = { Text(folder) }
                        )
                    }
                }
            }
        }

        if (items.isEmpty()) {
            item(key = "vault-empty") {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        "No files in this view yet. Tap Upload File to encrypt documents, photos, videos, audio, or archives into your Private Cloud Storage Box.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        } else {
            items(items, key = { it.id }, contentType = { "vault-item" }) { item ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    item.displayName,
                                    style = MaterialTheme.typography.titleMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "${item.folder} · ${item.category.displayName} · ${RuleBasedOptimizationPredictor.formatBytes(item.originalSizeBytes)}",
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Surface(
                                color = (if (item.cloudSyncedAtEpochMs != null) EmeraldPrimary else ElectricBlue).copy(alpha = 0.15f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    if (item.cloudSyncedAtEpochMs != null) "SYNCED" else "AES-256",
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (item.cloudSyncedAtEpochMs != null) EmeraldPrimary else ElectricBlue,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            IconButton(onClick = { onPreviewItem(item.id) }) {
                                Icon(Icons.Default.Visibility, contentDescription = "Preview", tint = CyberCyan)
                            }
                            IconButton(onClick = {
                                pendingExportItem = item
                                runCatching { exportCreator.launch(item.displayName) }
                            }) {
                                Icon(Icons.Default.Download, contentDescription = "Download / Export", tint = EmeraldPrimary)
                            }
                            IconButton(onClick = { moveTargetItem = item }) {
                                Icon(Icons.Default.DriveFileMove, contentDescription = "Move to Folder", tint = WarningAmber)
                            }
                            if (summary.cloudConfigured) {
                                IconButton(onClick = { onSyncItem(item.id) }) {
                                    Icon(Icons.Default.CloudSync, contentDescription = "Sync to Cloud", tint = ElectricBlue)
                                }
                            }
                            IconButton(onClick = { onDeleteItem(item.id, summary.cloudConfigured) }) {
                                Icon(Icons.Default.Delete, contentDescription = "Delete", tint = AlertRed)
                            }
                        }
                    }
                }
            }
        }
    }

    if (showFolderDialog) {
        var folderInput by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showFolderDialog = false },
            title = { Text("Create Vault Folder") },
            text = {
                OutlinedTextField(
                    value = folderInput,
                    onValueChange = { folderInput = it },
                    label = { Text("Folder name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(onClick = {
                    onCreateFolder(folderInput)
                    showFolderDialog = false
                }) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { showFolderDialog = false }) { Text("Cancel") }
            }
        )
    }

    moveTargetItem?.let { item ->
        var chosenFolder by remember(item) { mutableStateOf(item.folder) }
        AlertDialog(
            onDismissRequest = { moveTargetItem = null },
            title = { Text("Move '${item.displayName}'") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = chosenFolder,
                        onValueChange = { chosenFolder = it },
                        label = { Text("Destination folder") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        summary.folderNames.forEach { f ->
                            FilterChip(
                                selected = chosenFolder.equals(f, true),
                                onClick = { chosenFolder = f },
                                label = { Text(f) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    onMoveItem(item.id, chosenFolder)
                    moveTargetItem = null
                }) { Text("Move") }
            },
            dismissButton = {
                TextButton(onClick = { moveTargetItem = null }) { Text("Cancel") }
            }
        )
    }

    if (showPinDialog) {
        var pinInput by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showPinDialog = false },
            title = { Text("Vault Privacy Controls") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        "Protect access to your Private Cloud Storage Box with a PBKDF2-HMAC-SHA256 PIN or passphrase (4–64 chars).",
                        style = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = pinInput,
                        onValueChange = { pinInput = it },
                        label = { Text(if (summary.isPinConfigured) "Current or New PIN" else "New PIN (min 4 chars)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (summary.isPinConfigured) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = {
                                onLock()
                                showPinDialog = false
                            }) { Text("Lock Now") }
                            OutlinedButton(onClick = {
                                onRemovePin(pinInput)
                                showPinDialog = false
                            }) { Text("Remove PIN") }
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        onSetPin(pinInput)
                        showPinDialog = false
                    },
                    enabled = pinInput.trim().length >= 4
                ) { Text("Save PIN") }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false }) { Text("Close") }
            }
        )
    }

    if (showCloudDialog) {
        var url by remember(cloudConfig) { mutableStateOf(cloudConfig.serverBaseUrl) }
        var user by remember(cloudConfig) { mutableStateOf(cloudConfig.username) }
        var pass by remember(cloudConfig) { mutableStateOf(cloudConfig.passwordOrToken) }
        var encryptEnvelope by remember(cloudConfig) { mutableStateOf(cloudConfig.uploadEncryptedEnvelope) }
        var autoSync by remember(cloudConfig) { mutableStateOf(cloudConfig.autoSyncOnUpload) }

        AlertDialog(
            onDismissRequest = { showCloudDialog = false },
            title = { Text("HTTPS WebDAV Cloud Sync") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "Connect Nextcloud, ownCloud, Koofr, Fastmail, or any HTTPS WebDAV endpoint. Credentials are stored AES-256-GCM encrypted on-device.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = url,
                        onValueChange = { url = it },
                        label = { Text("HTTPS WebDAV Folder URL") },
                        placeholder = { Text("https://cloud.example.com/remote.php/dav/files/user/Vault") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = user,
                        onValueChange = { user = it },
                        label = { Text("Username (optional for Bearer token)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = pass,
                        onValueChange = { pass = it },
                        label = { Text("App Password or Bearer Token") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = encryptEnvelope, onCheckedChange = { encryptEnvelope = it })
                        Text("Zero-knowledge upload (.enc ciphertext)", fontSize = 12.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = autoSync, onCheckedChange = { autoSync = it })
                        Text("Auto-sync new uploads to cloud", fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    onConfigureCloud(
                        PrivateCloudBoxEngine.CloudEndpointConfig(
                            serverBaseUrl = url,
                            username = user,
                            passwordOrToken = pass,
                            uploadEncryptedEnvelope = encryptEnvelope,
                            autoSyncOnUpload = autoSync
                        )
                    )
                    showCloudDialog = false
                }) { Text("Save") }
            },
            dismissButton = {
                TextButton(onClick = { showCloudDialog = false }) { Text("Cancel") }
            }
        )
    }

    preview?.let { pv ->
        AlertDialog(
            onDismissRequest = onClosePreview,
            title = {
                val title = when (pv) {
                    is PrivateCloudBoxEngine.VaultPreview.TextPreview -> pv.title
                    is PrivateCloudBoxEngine.VaultPreview.ImagePreview -> pv.title
                    is PrivateCloudBoxEngine.VaultPreview.MediaOrBinaryPreview -> pv.title
                }
                Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis)
            },
            text = {
                when (pv) {
                    is PrivateCloudBoxEngine.VaultPreview.TextPreview -> {
                        Column(
                            modifier = Modifier
                                .heightIn(max = 340.dp)
                                .verticalScroll(rememberScrollState())
                        ) {
                            Text(pv.text, fontSize = 12.sp)
                            if (pv.truncated) {
                                Spacer(Modifier.height(6.dp))
                                Text("(Preview truncated — export to view full file)", fontSize = 11.sp, color = WarningAmber)
                            }
                        }
                    }
                    is PrivateCloudBoxEngine.VaultPreview.ImagePreview -> {
                        val bmp = remember(pv.decryptedTempFile) {
                            runCatching { BitmapFactory.decodeFile(pv.decryptedTempFile.absolutePath)?.asImageBitmap() }.getOrNull()
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            if (bmp != null) {
                                Image(
                                    bitmap = bmp,
                                    contentDescription = pv.title,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(max = 280.dp)
                                )
                            } else {
                                Text("Image decoded (${RuleBasedOptimizationPredictor.formatBytes(pv.sizeBytes)}).")
                            }
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = { onOpenPreviewExternally(pv.decryptedTempFile, "image/*") }) {
                                Text("Open in Gallery Viewer")
                            }
                        }
                    }
                    is PrivateCloudBoxEngine.VaultPreview.MediaOrBinaryPreview -> {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("Category: ${pv.category.displayName}", fontSize = 13.sp)
                            Text("MIME Type: ${pv.mimeType}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text("Size: ${RuleBasedOptimizationPredictor.formatBytes(pv.sizeBytes)}", fontSize = 12.sp)
                            Text("SHA-256: ${pv.sha256.take(24)}…", fontSize = 11.sp, color = CyberCyan)
                            Spacer(Modifier.height(6.dp))
                            Button(
                                onClick = { onOpenPreviewExternally(pv.decryptedTempFile, pv.mimeType) },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Open / Play Securely")
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = onClosePreview) { Text("Close") }
            }
        )
    }
}
