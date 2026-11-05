package com.adshield.pro.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.cloud.CloudFileKind
import com.adshield.pro.cloud.QuotaManager
import com.adshield.pro.data.local.db.CloudDnsBackupEntity
import com.adshield.pro.data.local.db.CloudFileEntity
import com.adshield.pro.data.local.db.CloudTransferEntity
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldGlow
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.TextSecondaryDark
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.CloudViewModel

private enum class CloudSection(val label: String) {
    OVERVIEW("Overview"), FILES("My Files"), PHOTOS("Photos"), VIDEOS("Videos"),
    DOCS("Documents"), BACKUPS("Backups"), SHARED("Shared"), UPLOADS("Upload Mgr"),
    SECURITY("Security"), SETTINGS("Settings")
}

@Composable
fun CloudScreen(viewModel: CloudViewModel) {
    val session by viewModel.session.collectAsStateWithLifecycle()
    val apiBaseUrl by viewModel.apiBaseUrl.collectAsStateWithLifecycle()
    val files by viewModel.files.collectAsStateWithLifecycle()
    val transfers by viewModel.transfers.collectAsStateWithLifecycle()
    val backups by viewModel.dnsBackups.collectAsStateWithLifecycle()
    val quota by viewModel.quota.collectAsStateWithLifecycle()
    val quotaState by viewModel.quotaState.collectAsStateWithLifecycle()
    val shares by viewModel.shares.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()

    var section by remember { mutableStateOf(CloudSection.OVERVIEW) }
    var pendingPick by remember { mutableStateOf<((Uri) -> Unit)?>(null) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { pendingPick?.invoke(it) }
    }

    LaunchedEffect(Unit) { viewModel.refreshAll() }

    if (message != null) {
        AlertDialog(
            onDismissRequest = { viewModel.clearMessage() },
            confirmButton = { TextButton(onClick = { viewModel.clearMessage() }) { Text("OK") } },
            text = { Text(message!!) }
        )
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                items(CloudSection.entries) { s ->
                    OutlinedButton(
                        onClick = { section = s },
                        shape = RoundedCornerShape(10.dp),
                        border = null,
                        modifier = Modifier.background(
                            if (section == s) Color(0xFF12365A) else Color.Transparent,
                            RoundedCornerShape(10.dp)
                        )
                    ) {
                        Text(
                            s.label,
                            fontSize = 11.sp,
                            color = if (section == s) CyberCyan else TextSecondaryDark
                        )
                    }
                }
            }
        }

        when (section) {
            CloudSection.OVERVIEW -> item {
                OverviewSection(
                    configured = apiBaseUrl.startsWith("https://"),
                    signedIn = session != null,
                    quota = quota,
                    quotaState = quotaState,
                    files = files,
                    transfers = transfers,
                    onRefresh = { viewModel.refreshAll() }
                )
            }
            CloudSection.FILES -> item {
                FilesSection(
                    files = files,
                    onPickUpload = { uri ->
                        pendingPick = { viewModel.upload(it, "file", "/") }
                        picker.launch(arrayOf("*/*"))
                    },
                    onDownload = { file ->
                        pendingPick = { viewModel.download(file.id, file.name, it) }
                        picker.launch(arrayOf("*/*"))
                    },
                    onDelete = { viewModel.delete(it, permanent = false) },
                    onShare = { viewModel.share(it, ttlHours = 24, maxDownloads = 10) }
                )
            }
            CloudSection.PHOTOS -> item { KindSection("Photos", files, CloudFileKind.PHOTO) }
            CloudSection.VIDEOS -> item { KindSection("Videos", files, CloudFileKind.VIDEO) }
            CloudSection.DOCS -> item { KindSection("Documents", files, CloudFileKind.DOCUMENT) }
            CloudSection.BACKUPS -> item {
                BackupsSection(backups = backups, onBackup = { viewModel.backupDnsConfig("DNS config ${System.currentTimeMillis() % 100000}") },
                    onRestore = { viewModel.restoreDnsBackup(it) })
            }
            CloudSection.SHARED -> item { SharedSection(shares = shares) }
            CloudSection.UPLOADS -> item {
                UploadsSection(
                    transfers = transfers,
                    onPause = { viewModel.pause(it) },
                    onResume = { viewModel.resume(it) },
                    onCancel = { viewModel.cancel(it) }
                )
            }
            CloudSection.SECURITY -> item { SecuritySection(configured = apiBaseUrl.startsWith("https://")) }
            CloudSection.SETTINGS -> item {
                SettingsSection(
                    apiBaseUrl = apiBaseUrl,
                    session = session,
                    onSaveUrl = { viewModel.setApiBaseUrl(it) },
                    onSignUp = { e, p -> viewModel.signUp(e, p) },
                    onSignIn = { e, p -> viewModel.signIn(e, p) },
                    onSignOut = { viewModel.signOut() }
                )
            }
        }
        item { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
private fun StatusChip(label: String, color: Color, icon: ImageVector) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.background(color.copy(alpha = 0.15f), RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(12.dp))
        Spacer(Modifier.width(4.dp))
        Text(label, color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun OverviewSection(
    configured: Boolean, signedIn: Boolean, quota: com.adshield.pro.cloud.QuotaInfo?,
    quotaState: QuotaManager.QuotaState, files: List<CloudFileEntity>,
    transfers: List<CloudTransferEntity>, onRefresh: () -> Unit
) {
    CyberPanel(title = "Cloud Overview", subtitle = "Real numbers from your cloud backend — nothing estimated", trailing = {
        IconButton(onClick = onRefresh) { Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan) }
    }) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            StatusChip(
                if (configured) "BACKEND LINKED" else "NOT CONFIGURED",
                if (configured) EmeraldGlow else WarningAmber,
                if (configured) Icons.Default.Cloud else Icons.Default.CloudOff
            )
            StatusChip(if (signedIn) "SIGNED IN" else "SIGNED OUT", if (signedIn) EmeraldGlow else TextSecondaryDark, Icons.Default.Cloud)
            StatusChip(
                when (quotaState) {
                    QuotaManager.QuotaState.OK -> "QUOTA OK"
                    QuotaManager.QuotaState.WARNING -> "QUOTA LOW"
                    QuotaManager.QuotaState.BLOCKED -> "QUOTA FULL"
                    QuotaManager.QuotaState.UNKNOWN -> "QUOTA UNKNOWN"
                },
                when (quotaState) {
                    QuotaManager.QuotaState.OK -> EmeraldGlow
                    QuotaManager.QuotaState.WARNING -> WarningAmber
                    QuotaManager.QuotaState.BLOCKED -> AlertRed
                    QuotaManager.QuotaState.UNKNOWN -> TextSecondaryDark
                },
                Icons.Default.Cloud
            )
        }
        Spacer(Modifier.height(10.dp))
        if (quota != null) {
            val fraction = if (quota.quotaBytes > 0) quota.usedBytes.toFloat() / quota.quotaBytes.toFloat() else 0f
            Text(
                "${QuotaManager.formatBytes(quota.usedBytes)} used of ${QuotaManager.formatBytes(quota.quotaBytes)} " +
                    "(${QuotaManager.formatBytes(quota.remainingBytes)} remaining)",
                color = TextSecondaryDark, fontSize = 12.sp
            )
            Spacer(Modifier.height(4.dp))
            LinearProgressIndicator(
                progress = { fraction.coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth().height(8.dp),
                color = if (quotaState == QuotaManager.QuotaState.BLOCKED) AlertRed else CyberCyan,
                trackColor = NavyBorder
            )
            Spacer(Modifier.height(8.dp))
            Text("Files in cloud: ${quota.fileCount}  •  All-time uploads: ${quota.uploadCountAllTime}  •  downloads: ${quota.downloadCountAllTime}",
                color = TextSecondaryDark, fontSize = 11.sp)
        } else {
            Text(
                if (!configured) "No cloud backend configured. Deploy the free-tier Worker (see Cloud → Settings) to see real storage numbers."
                else "Sign in to load your real storage usage.",
                color = WarningAmber, fontSize = 12.sp
            )
        }
        Spacer(Modifier.height(8.dp))
        Text("Cached files: ${files.size}  •  Active transfers: ${transfers.count { it.state == "RUNNING" || it.state == "QUEUED" }}",
            color = TextSecondaryDark, fontSize = 11.sp)
    }
}

@Composable
private fun FilesSection(
    files: List<CloudFileEntity>,
    onPickUpload: (Uri) -> Unit,
    onDownload: (CloudFileEntity) -> Unit,
    onDelete: (String) -> Unit,
    onShare: (String) -> Unit
) {
    CyberPanel(title = "My Files", subtitle = "Cloud files cached from the server") {
        OutlinedButton(onClick = { onPickUpload(Uri.EMPTY) }) {
            Icon(Icons.Default.Upload, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp)); Text("Upload file", fontSize = 12.sp)
        }
        Spacer(Modifier.height(8.dp))
        if (files.isEmpty()) {
            Text("No files yet — upload something or refresh.", color = TextSecondaryDark, fontSize = 12.sp)
        }
        files.forEach { file ->
            FileRow(
                name = file.name, detail = "${QuotaManager.formatBytes(file.sizeBytes)} • v${file.version} • ${file.folderPath}",
                onDownload = { onDownload(file) }, onShare = { onShare(file.id) }, onDelete = { onDelete(file.id) }
            )
        }
    }
}

@Composable
private fun KindSection(title: String, files: List<CloudFileEntity>, kind: CloudFileKind) {
    val filtered = files.filter { CloudFileKind.fromMime(it.mimeType) == kind }
    CyberPanel(title = title, subtitle = "${filtered.size} item(s) in this category") {
        if (filtered.isEmpty()) Text("Nothing here yet.", color = TextSecondaryDark, fontSize = 12.sp)
        filtered.forEach { FileRow(name = it.name, detail = QuotaManager.formatBytes(it.sizeBytes)) }
    }
}

@Composable
private fun FileRow(
    name: String, detail: String,
    onDownload: (() -> Unit)? = null, onShare: (() -> Unit)? = null, onDelete: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.InsertDriveFile, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(name, fontSize = 12.sp, maxLines = 1)
            Text(detail, fontSize = 10.sp, color = TextSecondaryDark, maxLines = 1)
        }
        if (onDownload != null) IconButton(onClick = onDownload) { Icon(Icons.Default.Download, contentDescription = "Download", tint = EmeraldGlow, modifier = Modifier.size(16.dp)) }
        if (onShare != null) IconButton(onClick = onShare) { Icon(Icons.Default.Share, contentDescription = "Share", tint = CyberCyan, modifier = Modifier.size(16.dp)) }
        if (onDelete != null) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, contentDescription = "Delete", tint = AlertRed, modifier = Modifier.size(16.dp)) }
    }
}

@Composable
private fun BackupsSection(
    backups: List<CloudDnsBackupEntity>, onBackup: () -> Unit, onRestore: (String) -> Unit
) {
    CyberPanel(title = "DNS Security Backups", subtitle = "Blocklists, allowlists, firewall & app config — SHA-256 verified on restore") {
        OutlinedButton(onClick = onBackup) {
            Icon(Icons.Default.Cloud, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp)); Text("Back up DNS config now", fontSize = 12.sp)
        }
        Spacer(Modifier.height(8.dp))
        if (backups.isEmpty()) Text("No cloud backups yet. The DNS blocker works fully offline regardless.", color = TextSecondaryDark, fontSize = 12.sp)
        backups.forEach { b ->
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Folder, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(b.label, fontSize = 12.sp, maxLines = 1)
                    Text("sha256 ${b.sha256.take(16)}…${if (b.restoredAtEpochMs != null) " • restored" else ""}".trimEnd(), fontSize = 10.sp, color = TextSecondaryDark)
                }
                TextButton(onClick = { onRestore(b.id) }) { Text("Restore", fontSize = 11.sp, color = EmeraldGlow) }
            }
        }
    }
}

@Composable
private fun SharedSection(shares: List<com.adshield.pro.cloud.ShareLink>) {
    CyberPanel(title = "Shared Files", subtitle = "Expiring download links you created") {
        if (shares.isEmpty()) Text("No active share links.", color = TextSecondaryDark, fontSize = 12.sp)
        shares.forEach { s ->
            val expired = s.isExpired(System.currentTimeMillis())
            FileRow(
                name = s.fileName,
                detail = "${if (expired) "EXPIRED" else "expires ${s.expiresAtEpochMs}"} • ${s.downloadCount}/${s.maxDownloads} downloads"
            )
        }
    }
}

@Composable
private fun UploadsSection(
    transfers: List<CloudTransferEntity>,
    onPause: (String) -> Unit, onResume: (String) -> Unit, onCancel: (String) -> Unit
) {
    CyberPanel(title = "Upload Manager", subtitle = "Resumable transfers — pause, resume, cancel") {
        if (transfers.isEmpty()) Text("No transfers yet.", color = TextSecondaryDark, fontSize = 12.sp)
        transfers.forEach { t ->
            val fraction = if (t.totalBytes > 0) t.doneBytes.toFloat() / t.totalBytes.toFloat() else 0f
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (t.direction == "UPLOAD") Icons.Default.Upload else Icons.Default.Download,
                    contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(t.displayName, fontSize = 12.sp, maxLines = 1)
                    Text("${t.state} • ${QuotaManager.formatBytes(t.doneBytes)} / ${QuotaManager.formatBytes(t.totalBytes)}", fontSize = 10.sp, color = TextSecondaryDark)
                    LinearProgressIndicator(
                        progress = { fraction.coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth().height(4.dp).padding(top = 2.dp),
                        color = CyberCyan, trackColor = NavyBorder
                    )
                }
                when (t.state) {
                    "RUNNING", "QUEUED" -> IconButton(onClick = { onPause(t.id) }) { Icon(Icons.Default.Pause, contentDescription = "Pause", tint = WarningAmber, modifier = Modifier.size(16.dp)) }
                    "PAUSED" -> IconButton(onClick = { onResume(t.id) }) { Icon(Icons.Default.PlayArrow, contentDescription = "Resume", tint = EmeraldGlow, modifier = Modifier.size(16.dp)) }
                }
                IconButton(onClick = { onCancel(t.id) }) { Icon(Icons.Default.Delete, contentDescription = "Cancel", tint = AlertRed, modifier = Modifier.size(16.dp)) }
            }
        }
    }
}

@Composable
private fun SecuritySection(configured: Boolean) {
    CyberPanel(title = "Cloud Security", subtitle = "What protects your files") {
        val rows = listOf(
            "Transport" to "HTTPS only (cleartext disabled in the manifest)",
            "Buckets" to "Private — objects are never public; access only via Worker",
            "Signed URLs" to "Short-lived (≤15 min), expiry verified client-side before every transfer",
            "Ownership" to "Every file/share/backup request is checked against your user id server-side",
            "Integrity" to "SHA-256 computed locally, stored in D1, re-verified on download/restore",
            "File types" to "Executables and active web content are rejected client- and server-side",
            "Credentials" to "No cloud secret is bundled in the APK — only your session JWT",
            "Offline" to "DNS blocking never depends on the cloud"
        )
        rows.forEach { (k, v) ->
            Column(Modifier.padding(vertical = 3.dp)) {
                Text(k.uppercase(), fontSize = 10.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
                Text(v, fontSize = 11.sp, color = TextSecondaryDark)
            }
        }
        if (!configured) {
            Spacer(Modifier.height(6.dp))
            Text("Backend not configured yet — connect a free-tier Worker in Settings.", color = WarningAmber, fontSize = 11.sp)
        }
    }
}

@Composable
private fun SettingsSection(
    apiBaseUrl: String, session: com.adshield.pro.cloud.AuthSession?,
    onSaveUrl: (String) -> Unit, onSignUp: (String, String) -> Unit,
    onSignIn: (String, String) -> Unit, onSignOut: () -> Unit
) {
    var url by remember(apiBaseUrl) { mutableStateOf(apiBaseUrl) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    CyberPanel(title = "Cloud Settings", subtitle = "Free-tier backend endpoint and account") {
        Text("WORKER BACKEND URL (https://…workers.dev)", fontSize = 10.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
        OutlinedTextField(
            value = url, onValueChange = { url = it }, singleLine = true,
            placeholder = { Text("https://your-free-worker.workers.dev", fontSize = 11.sp) },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(4.dp))
        OutlinedButton(onClick = { onSaveUrl(url) }) { Text("Save backend URL", fontSize = 12.sp) }
        Spacer(Modifier.height(10.dp))
        if (session == null) {
            OutlinedTextField(value = email, onValueChange = { email = it }, singleLine = true, placeholder = { Text("Email", fontSize = 11.sp) }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(value = password, onValueChange = { password = it }, singleLine = true, placeholder = { Text("Password", fontSize = 11.sp) }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { onSignIn(email, password) }) { Text("Sign in", fontSize = 12.sp) }
                OutlinedButton(onClick = { onSignUp(email, password) }) { Text("Create free account", fontSize = 12.sp) }
            }
            Text("Auth runs on the free tier of your own Supabase project via the Worker. No card required.", fontSize = 10.sp, color = TextSecondaryDark)
        } else {
            Text("Signed in as ${session.email}", fontSize = 12.sp, color = EmeraldGlow)
            Spacer(Modifier.height(4.dp))
            OutlinedButton(onClick = onSignOut) { Text("Sign out", fontSize = 12.sp) }
        }
    }
}
