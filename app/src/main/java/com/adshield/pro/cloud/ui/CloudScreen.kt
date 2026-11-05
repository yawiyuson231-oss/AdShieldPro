package com.adshield.pro.cloud.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.cloud.CloudConnectionState
import com.adshield.pro.cloud.CloudSection
import com.adshield.pro.cloud.CloudUiState
import com.adshield.pro.cloud.CloudViewModel
import com.adshield.pro.cloud.data.CloudBackupDto
import com.adshield.pro.cloud.data.CloudNodeDto
import com.adshield.pro.cloud.data.CloudShareDto
import com.adshield.pro.cloud.data.CloudTransferEntity
import com.adshield.pro.cloud.util.ByteFormat
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldGlow
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.PurpleAccent
import com.adshield.pro.ui.theme.WarningAmber
import kotlinx.coroutines.launch

/**
 * Cloud dashboard — ten sections, all driven by live API data.
 *
 * When the deployment is unconfigured or the user is signed out the screen shows an honest
 * setup/sign-in gate instead of placeholder capacity or fake statistics.
 */
@Composable
fun CloudScreen(viewModel: CloudViewModel = hiltViewModel()) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var section by remember { mutableStateOf(CloudSection.OVERVIEW) }

    LaunchedEffect(section) { viewModel.setSection(section) }

    Column(
        Modifier
            .fillMaxSize()
            .background(Color(0xFF050C18))
            .verticalScroll(rememberScrollState())
            .padding(14.dp)
    ) {
        CloudHeader(ui = ui, onRefresh = { viewModel.refreshAll() })

        Spacer(Modifier.height(12.dp))
        when {
            ui.connection == CloudConnectionState.UNCONFIGURED -> SetupGate(ui = ui, viewModel = viewModel)
            !ui.isSignedIn -> AuthGate(ui = ui, viewModel = viewModel)
            else -> {
                SectionChips(selected = section, onSelect = { section = it })
                Spacer(Modifier.height(12.dp))
                if (ui.quota.quotaBytes > 0 && ui.quota.percentUsed >= ui.config.warnAtPercent) {
                    QuotaWarningBanner(ui)
                    Spacer(Modifier.height(10.dp))
                }
                when (section) {
                    CloudSection.OVERVIEW -> OverviewSection(ui, viewModel, onNavigate = { section = it })
                    CloudSection.FILES -> FilesSection(ui, viewModel, context = context)
                    CloudSection.PHOTOS -> CategorySection(ui, viewModel, "Photos", "photos", context)
                    CloudSection.VIDEOS -> CategorySection(ui, viewModel, "Videos", "videos", context)
                    CloudSection.DOCUMENTS -> CategorySection(ui, viewModel, "Documents", "documents", context)
                    CloudSection.BACKUPS -> BackupsSection(ui, viewModel)
                    CloudSection.SHARED -> SharedSection(ui, viewModel)
                    CloudSection.UPLOADS -> UploadsSection(ui, viewModel, context)
                    CloudSection.SECURITY -> SecuritySection(ui, viewModel)
                    CloudSection.SETTINGS -> SettingsSection(ui, viewModel)
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun CloudHeader(ui: CloudUiState, onRefresh: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(44.dp)
                .background(EmeraldPrimary.copy(alpha = 0.14f), RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Default.Cloud, contentDescription = null, tint = EmeraldGlow, modifier = Modifier.size(24.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                "CYBERSHIELD CLOUD",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.6.sp,
                color = Color.White
            )
            Text(
                when (ui.connection) {
                    CloudConnectionState.ONLINE -> "Connected • ${ui.meta?.storageProvider?.uppercase() ?: "free tier"}"
                    CloudConnectionState.DEGRADED -> "Degraded — some operations may fail"
                    CloudConnectionState.OFFLINE -> "Offline — local protection still active"
                    CloudConnectionState.AUTH_REQUIRED -> if (ui.isSignedIn) "Signed in" else "Sign in required"
                    CloudConnectionState.UNCONFIGURED -> "No deployment configured"
                },
                style = MaterialTheme.typography.labelMedium,
                color = Color(0xFF8FA6C4)
            )
        }
        if (ui.isSignedIn) {
            StatusPill(
                text = if (ui.account?.quota?.canUpload == true) "FREE" else "FULL",
                color = if (ui.account?.quota?.canUpload == true) EmeraldPrimary else WarningAmber
            )
            Spacer(Modifier.width(4.dp))
        }
        IconButton(onClick = onRefresh) {
            Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan)
        }
    }
}

@Composable
private fun QuotaWarningBanner(ui: CloudUiState) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(WarningAmber.copy(alpha = 0.14f), RoundedCornerShape(14.dp))
            .border(1.dp, WarningAmber.copy(alpha = 0.5f), RoundedCornerShape(14.dp))
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.Warning, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(
            "${ui.quota.percentUsed.toInt()}% of your free quota is used — " +
                "${ByteFormat.human(ui.quota.remainingBytes)} left. Paid storage is never enabled automatically.",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFFFFE1A8)
        )
    }
}

@Composable
private fun SectionChips(selected: CloudSection, onSelect: (CloudSection) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        CloudSection.entries.forEach { entry ->
            FilterChip(
                selected = entry == selected,
                onClick = { onSelect(entry) },
                label = { Text(entry.title, fontSize = 12.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = EmeraldPrimary.copy(alpha = 0.22f),
                    selectedLabelColor = EmeraldGlow,
                    labelColor = Color(0xFF90A6C2)
                )
            )
        }
    }
}

// --------------------------------------------------------------------------- gates
@Composable
private fun SetupGate(ui: CloudUiState, viewModel: CloudViewModel) {
    var apiUrl by remember { mutableStateOf(ui.config.apiBaseUrl) }
    var supabaseUrl by remember { mutableStateOf(ui.config.supabaseUrl) }
    var anonKey by remember { mutableStateOf(ui.config.supabaseAnonKey) }

    GlassPanel(accent = CyberCyan) {
        SectionHeader("Connect your free cloud", "Runs on Cloudflare Workers + R2 + D1 free tiers", CyberCyan)
        Spacer(Modifier.height(10.dp))
        Text(
            "This app ships without any cloud credentials. Deploy the included worker to your own " +
                "free Cloudflare account (see docs/cloud/SETUP.md) and paste the three public values below. " +
                "No paid service is used and no card is required unless you choose R2 storage — the " +
                "Supabase Storage provider is completely card-free.",
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xFFA9BCD4)
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = apiUrl,
            onValueChange = { apiUrl = it },
            label = { Text("Worker URL (https://…)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = supabaseUrl,
            onValueChange = { supabaseUrl = it },
            label = { Text("Supabase project URL") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = anonKey,
            onValueChange = { anonKey = it },
            label = { Text("Supabase publishable (anon) key") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(12.dp))
        Row {
            Button(
                onClick = { viewModel.updateDeployment(apiUrl, supabaseUrl, anonKey) },
                colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary)
            ) { Text("Save & test connection") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { viewModel.exportLocalBackup("full") }) {
                Text("Export offline snapshot")
            }
        }
        ui.lastError?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = AlertRed, style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun AuthGate(ui: CloudUiState, viewModel: CloudViewModel) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var displayName by remember { mutableStateOf("") }
    var registerMode by remember { mutableStateOf(false) }

    GlassPanel(accent = PurpleAccent) {
        SectionHeader(
            if (registerMode) "Create account" else "Sign in",
            "Supabase Auth free tier — 50,000 monthly active users",
            PurpleAccent
        )
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        if (registerMode) {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = displayName,
                onValueChange = { displayName = it },
                label = { Text("Display name (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Text(
                "Sign-up is protected by Cloudflare Turnstile when enabled on your deployment.",
                style = MaterialTheme.typography.labelMedium,
                color = Color(0xFF8FA6C4),
                modifier = Modifier.padding(top = 6.dp)
            )
        }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = {
                    if (registerMode) {
                        viewModel.register(email, password, displayName, null)
                    } else {
                        viewModel.signIn(email, password)
                    }
                },
                enabled = !ui.isSigningIn && email.isNotBlank() && password.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary)
            ) {
                if (ui.isSigningIn) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.White)
                } else {
                    Text(if (registerMode) "Create account" else "Sign in")
                }
            }
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = { registerMode = !registerMode }) {
                Text(if (registerMode) "I already have an account" else "Create an account")
            }
        }
        Spacer(Modifier.height(4.dp))
        TextButton(onClick = { viewModel.requestRecovery(email, null) }) {
            Text("Forgot password?", color = CyberCyan)
        }
        ui.lastError?.let {
            Text(it, color = AlertRed, style = MaterialTheme.typography.labelMedium)
        }
        Text(
            "Your DNS blocker keeps working with no account and no connection.",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFF6F86A4),
            modifier = Modifier.padding(top = 6.dp)
        )
    }
}

// --------------------------------------------------------------------------- overview
@Composable
private fun OverviewSection(ui: CloudUiState, viewModel: CloudViewModel, onNavigate: (CloudSection) -> Unit) {
    val uploadLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) viewModel.upload(uri)
    }
    GlassPanel {
        StorageGauge(usedBytes = ui.quota.usedBytes, totalBytes = ui.quota.quotaBytes)
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile("Used", ByteFormat.human(ui.quota.usedBytes), "${ui.quota.percentUsed.toInt()}% of quota", EmeraldPrimary, modifier = Modifier.weight(1f))
            StatTile("Remaining", ByteFormat.human(ui.quota.remainingBytes), "${ui.account?.files?.files ?: 0} files", CyberCyan, modifier = Modifier.weight(1f))
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile("Backups", "${ui.backups.size}", ByteFormat.human(ui.account?.backups?.bytes ?: 0), PurpleAccent, modifier = Modifier.weight(1f))
            StatTile("Shares", "${ui.shares.count { !it.revoked }}", "active links", WarningAmber, modifier = Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        MetricBar(
            label = "Per-user quota",
            value = "${ui.quota.percentUsed.toInt()}%",
            fraction = (ui.quota.percentUsed / 100.0).toFloat(),
            accent = EmeraldPrimary
        )
        Spacer(Modifier.height(8.dp))
        MetricBar(
            label = "Daily API budget (${ui.account?.dailyUsage?.requests ?: 0}/${ui.account?.dailyUsage?.requestBudget ?: 0})",
            value = "${(ui.account?.dailyUsage?.percentOfBudget ?: 0.0).toInt()}%",
            fraction = ((ui.account?.dailyUsage?.percentOfBudget ?: 0.0) / 100.0).toFloat(),
            accent = CyberCyan
        )
        Spacer(Modifier.height(8.dp))
        MetricBar(
            label = "Shared free-tier pool",
            value = ByteFormat.human(ui.quota.globalRemainingBytes) + " left",
            fraction = if (ui.quota.globalCapBytes > 0) {
                (ui.quota.globalUsedBytes.toFloat() / ui.quota.globalCapBytes.toFloat()).coerceIn(0f, 1f)
            } else 0f,
            accent = PurpleAccent
        )
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel(accent = CyberCyan) {
        SectionHeader("Status", "Everything below is reported by the server", CyberCyan)
        Spacer(Modifier.height(10.dp))
        StatusRow("Cloud connection", when (ui.connection) {
            CloudConnectionState.ONLINE -> "Online"
            CloudConnectionState.DEGRADED -> "Degraded"
            CloudConnectionState.OFFLINE -> "Offline"
            CloudConnectionState.AUTH_REQUIRED -> "Signed out"
            CloudConnectionState.UNCONFIGURED -> "Not configured"
        }, ui.connection == CloudConnectionState.ONLINE)
        StatusRow(
            "Backup status",
            if (ui.backups.isEmpty()) "No backups yet" else "${ui.backups.size} stored • last ${formatRelative(ui.backups.maxOf { it.createdAt })}",
            ui.backups.isNotEmpty()
        )
        StatusRow(
            "Synchronisation",
            ui.transfers.count { it.status == "running" || it.status == "queued" }
                .let { if (it == 0) "Idle" else "$it transfer(s) in flight" },
            true
        )
        StatusRow(
            "Encryption",
            ui.security?.encryption?.let { "TLS in transit • AES-256 at rest • signed URLs ${it.signedUrlTtlSeconds}s" }
                ?: "TLS + AES-256 at rest",
            true
        )
        StatusRow(
            "Malware protection",
            ui.security?.scanning?.let { "${it.counts["clean"] ?: 0} clean • ${it.quarantined.size} quarantined" }
                ?: "Scanner idle",
            (ui.security?.scanning?.quarantined?.size ?: 0) == 0
        )
    }

    Spacer(Modifier.height(12.dp))
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = { uploadLauncher.launch(arrayOf("*/*")) },
            modifier = Modifier.weight(1f),
            colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary)
        ) {
            Icon(Icons.Default.CloudUpload, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Upload")
        }
        OutlinedButton(onClick = { onNavigate(CloudSection.BACKUPS) }, modifier = Modifier.weight(1f)) {
            Icon(Icons.Default.Backup, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Backup")
        }
    }

    Spacer(Modifier.height(12.dp))
    RecentPanel(
        title = "Recent uploads",
        nodes = ui.stats?.recentUploads ?: emptyList(),
        emptyText = "Nothing uploaded yet"
    )
    Spacer(Modifier.height(12.dp))
    RecentPanel(
        title = "Recent downloads",
        nodes = ui.stats?.recentDownloads ?: emptyList(),
        emptyText = "No downloads yet"
    )
}

@Composable
private fun StatusRow(label: String, value: String, healthy: Boolean) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(
            if (healthy) Icons.Default.CheckCircle else Icons.Default.Info,
            contentDescription = null,
            tint = if (healthy) EmeraldPrimary else WarningAmber,
            modifier = Modifier.size(15.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.bodyMedium, color = Color(0xFFB7C8DE), modifier = Modifier.weight(1f))
        Text(
            value,
            style = MaterialTheme.typography.labelMedium,
            color = if (healthy) EmeraldGlow else WarningAmber,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun RecentPanel(title: String, nodes: List<CloudNodeDto>, emptyText: String) {
    GlassPanel(accent = PurpleAccent) {
        SectionHeader(title, accent = PurpleAccent)
        Spacer(Modifier.height(8.dp))
        if (nodes.isEmpty()) {
            Text(emptyText, style = MaterialTheme.typography.labelMedium, color = Color(0xFF7D93B1))
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                nodes.take(5).forEach { node ->
                    FileRow(node = node, onClick = { })
                }
            }
        }
    }
}

// --------------------------------------------------------------------------- files
@Composable
private fun FilesSection(ui: CloudUiState, viewModel: CloudViewModel, context: android.content.Context) {
    val uploadLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) viewModel.upload(uri)
    }
    var showNewFolder by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<CloudNodeDto?>(null) }
    var shareTarget by remember { mutableStateOf<CloudNodeDto?>(null) }
    var versionsTarget by remember { mutableStateOf<CloudNodeDto?>(null) }
    var previewTarget by remember { mutableStateOf<CloudNodeDto?>(null) }

    GlassPanel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { viewModel.navigateUp() }) {
                Icon(Icons.Default.Folder, contentDescription = "Up", tint = CyberCyan)
            }
            Column(Modifier.weight(1f)) {
                Text(
                    if (ui.folderPath.isEmpty()) "My Files" else ui.folderPath.joinToString(" / ") { it.second },
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    "${ui.files.size} item(s) • ${ByteFormat.human(ui.files.sumOf { it.size })}",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF8FA6C4)
                )
            }
            IconButton(onClick = { showNewFolder = true }) {
                Icon(Icons.Default.Add, contentDescription = "New folder", tint = EmeraldGlow)
            }
            IconButton(onClick = { uploadLauncher.launch(arrayOf("*/*")) }) {
                Icon(Icons.Default.CloudUpload, contentDescription = "Upload", tint = EmeraldGlow)
            }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = ui.searchQuery,
            onValueChange = viewModel::search,
            label = { Text("Search all files") },
            singleLine = true,
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan) },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(10.dp))

        val list = if (ui.searchQuery.isNotBlank() && ui.searchResults.isNotEmpty()) ui.searchResults else ui.files
        if (ui.isLoading && list.isEmpty()) {
            Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = EmeraldPrimary, modifier = Modifier.size(22.dp), strokeWidth = 2.dp)
            }
        } else if (list.isEmpty()) {
            EmptyState(
                title = if (ui.searchQuery.isNotBlank()) "No matches" else "This folder is empty",
                message = if (ui.searchQuery.isNotBlank()) {
                    "Try a different file name."
                } else {
                    "Upload a file or create a folder to get started."
                }
            )
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                list.forEach { node ->
                    Box {
                        var menuOpen by remember { mutableStateOf(false) }
                        FileRow(
                            node = node,
                            onClick = {
                                if (node.isFolder) viewModel.openFolder(node)
                                else if (node.isImage) previewTarget = node
                                else viewModel.download(node)
                            },
                            trailing = {
                                IconButton(onClick = { menuOpen = true }) {
                                    Icon(Icons.Default.MoreVert, contentDescription = "Actions", tint = Color(0xFF9BB0CB))
                                }
                                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                                    if (!node.isFolder) {
                                        DropdownMenuItem(
                                            text = { Text("Download") },
                                            leadingIcon = { Icon(Icons.Default.Download, contentDescription = null) },
                                            onClick = { menuOpen = false; viewModel.download(node) }
                                        )
                                        DropdownMenuItem(
                                            text = { Text("Share link") },
                                            leadingIcon = { Icon(Icons.Default.Share, contentDescription = null) },
                                            onClick = { menuOpen = false; shareTarget = node }
                                        )
                                        DropdownMenuItem(
                                            text = { Text("Version history") },
                                            leadingIcon = { Icon(Icons.Default.History, contentDescription = null) },
                                            onClick = { menuOpen = false; versionsTarget = node }
                                        )
                                        DropdownMenuItem(
                                            text = { Text("Verify integrity") },
                                            leadingIcon = { Icon(Icons.Default.CheckCircle, contentDescription = null) },
                                            onClick = { menuOpen = false; viewModel.verifyFile(node) }
                                        )
                                        if (node.isQuarantined) {
                                            DropdownMenuItem(
                                                text = { Text("Release quarantine") },
                                                leadingIcon = { Icon(Icons.Default.Warning, contentDescription = null) },
                                                onClick = { menuOpen = false; viewModel.releaseQuarantine(node) }
                                            )
                                        }
                                    }
                                    DropdownMenuItem(
                                        text = { Text("Rename") },
                                        leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) },
                                        onClick = { menuOpen = false; renameTarget = node }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Copy") },
                                        leadingIcon = { Icon(Icons.Default.ContentCopy, contentDescription = null) },
                                        onClick = { menuOpen = false; viewModel.copy(node) }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Delete") },
                                        leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null) },
                                        onClick = { menuOpen = false; viewModel.trash(node) }
                                    )
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    if (showNewFolder) {
        TextInputDialog(
            title = "New folder",
            label = "Folder name",
            initial = "",
            onDismiss = { showNewFolder = false },
            onConfirm = { name -> showNewFolder = false; viewModel.createFolder(name) }
        )
    }
    renameTarget?.let { target ->
        TextInputDialog(
            title = "Rename",
            label = "Name",
            initial = target.name,
            onDismiss = { renameTarget = null },
            onConfirm = { name -> renameTarget = null; viewModel.rename(target, name) }
        )
    }
    shareTarget?.let { target ->
        ShareDialog(
            node = target,
            defaultExpiryHours = ui.config.shareDefaultExpiryHours,
            defaultPassword = ui.config.shareDefaultPassword,
            onDismiss = { shareTarget = null },
            onCreate = { hours, maxDownloads, password, allowPreview ->
                shareTarget = null
                viewModel.createShare(target, hours, maxDownloads, password, allowPreview)
            }
        )
    }
    versionsTarget?.let { target ->
        VersionsDialog(node = target, viewModel = viewModel, onDismiss = { versionsTarget = null })
    }
    previewTarget?.let { target ->
        PreviewDialog(node = target, viewModel = viewModel, context = context, onDismiss = { previewTarget = null })
    }
}

@Composable
private fun CategorySection(
    ui: CloudUiState,
    viewModel: CloudViewModel,
    title: String,
    category: String,
    context: android.content.Context
) {
    var previewTarget by remember { mutableStateOf<CloudNodeDto?>(null) }
    GlassPanel(accent = EmeraldGlow) {
        SectionHeader(title, "${ui.files.size} item(s) • ${ByteFormat.human(ui.files.sumOf { it.size })}")
        Spacer(Modifier.height(8.dp))
        if (ui.files.isEmpty()) {
            EmptyState(
                title = "Nothing here yet",
                message = "Upload $category files from My Files or the Overview tab."
            )
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                ui.files.forEach { node ->
                    FileRow(
                        node = node,
                        onClick = {
                            if (node.isImage) previewTarget = node else viewModel.download(node)
                        },
                        trailing = {
                            IconButton(onClick = { viewModel.download(node) }) {
                                Icon(Icons.Default.Download, contentDescription = "Download", tint = CyberCyan)
                            }
                        }
                    )
                }
            }
        }
    }
    previewTarget?.let { target ->
        PreviewDialog(node = target, viewModel = viewModel, context = context, onDismiss = { previewTarget = null })
    }
}

// --------------------------------------------------------------------------- backups
@Composable
private fun BackupsSection(ui: CloudUiState, viewModel: CloudViewModel) {
    var kind by remember { mutableStateOf("full") }
    var label by remember { mutableStateOf("Manual snapshot") }
    var passphrase by remember { mutableStateOf("") }
    var restoreTarget by remember { mutableStateOf<CloudBackupDto?>(null) }

    GlassPanel(accent = PurpleAccent) {
        SectionHeader("Encrypted configuration backup", "DNS rules, blocklists, firewall & preferences", PurpleAccent)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
            listOf(
                "full" to "Full",
                "dns_config" to "DNS config",
                "blocklists" to "Blocklists",
                "allowlist" to "Allowlist",
                "denylist" to "Denylist",
                "firewall" to "Firewall",
                "security_prefs" to "Security",
                "app_config" to "App config"
            ).forEach { (id, title) ->
                FilterChip(
                    selected = kind == id,
                    onClick = { kind = id },
                    label = { Text(title, fontSize = 11.sp) }
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = label,
            onValueChange = { label = it },
            label = { Text("Backup label") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = { Text("Passphrase (AES-256-GCM, stays on device)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "Leave empty to use this device's Keystore-bound key. A passphrase is required to restore on another phone.",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFF8FA6C4),
            modifier = Modifier.padding(top = 6.dp)
        )
        Spacer(Modifier.height(10.dp))
        Row {
            Button(
                onClick = { viewModel.createBackup(kind, label.ifBlank { "Manual snapshot" }, passphrase.ifBlank { null }) },
                enabled = !ui.isLoading,
                colors = ButtonDefaults.buttonColors(containerColor = PurpleAccent)
            ) { Text("Back up now") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { viewModel.exportLocalBackup(kind) }) { Text("Export offline") }
        }
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel {
        SectionHeader("Backup history", "${ui.backups.size} snapshot(s)", CyberCyan)
        Spacer(Modifier.height(8.dp))
        if (ui.backups.isEmpty()) {
            EmptyState(title = "No backups yet", message = "Create one above or enable automatic backups in Settings.")
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ui.backups.forEach { backup ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF0E1C30), RoundedCornerShape(14.dp))
                            .padding(12.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Backup, contentDescription = null, tint = PurpleAccent, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Column(Modifier.weight(1f)) {
                                Text(backup.label, style = MaterialTheme.typography.titleMedium, color = Color.White, maxLines = 1)
                                Text(
                                    "${backup.kind} • ${ByteFormat.human(backup.size)} • ${formatRelative(backup.createdAt)}",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = Color(0xFF8FA6C4)
                                )
                            }
                            StatusPill(
                                text = if (backup.integrityOk) "verified" else "unverified",
                                color = if (backup.integrityOk) EmeraldPrimary else WarningAmber
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedButton(onClick = { viewModel.verifyBackup(backup) }) { Text("Verify", fontSize = 12.sp) }
                            OutlinedButton(onClick = { restoreTarget = backup }) { Text("Restore", fontSize = 12.sp) }
                            OutlinedButton(onClick = { viewModel.deleteBackup(backup) }) { Text("Delete", fontSize = 12.sp) }
                        }
                    }
                }
            }
        }
    }

    restoreTarget?.let { backup ->
        var restorePassphrase by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { restoreTarget = null },
            title = { Text("Restore backup") },
            text = {
                Column {
                    Text("Restoring \"${backup.label}\" merges its rules and replaces DNS/firewall settings.")
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = restorePassphrase,
                        onValueChange = { restorePassphrase = it },
                        label = { Text("Passphrase (if used)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation()
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val target = backup
                    restoreTarget = null
                    viewModel.restoreBackup(target, restorePassphrase.ifBlank { null })
                }) { Text("Restore") }
            },
            dismissButton = { TextButton(onClick = { restoreTarget = null }) { Text("Cancel") } }
        )
    }
}

// --------------------------------------------------------------------------- shared
@Composable
private fun SharedSection(ui: CloudUiState, viewModel: CloudViewModel) {
    GlassPanel(accent = WarningAmber) {
        SectionHeader("Shared files", "Expiring, revocable, optionally password-protected", WarningAmber)
        Spacer(Modifier.height(8.dp))
        if (ui.shares.isEmpty()) {
            EmptyState(title = "No share links", message = "Open a file in My Files ▸ ⋮ ▸ Share link to create one.")
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ui.shares.forEach { share ->
                    ShareRow(share = share, onRevoke = { viewModel.revokeShare(share) })
                }
            }
        }
    }
}

@Composable
private fun ShareRow(share: CloudShareDto, onRevoke: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(Color(0xFF0E1C30), RoundedCornerShape(14.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Link, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(share.fileName, style = MaterialTheme.typography.titleMedium, color = Color.White, maxLines = 1)
                Text(
                    buildString {
                        append("${share.downloadCount} download(s)")
                        if (share.maxDownloads > 0) append(" of ${share.maxDownloads}")
                        append(" • expires ${formatTimestamp(share.expiresAt)}")
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF8FA6C4)
                )
            }
            if (share.passwordProtected) {
                Icon(Icons.Default.Lock, contentDescription = "Password", tint = EmeraldGlow, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
            }
            StatusPill(
                text = when {
                    share.revoked -> "revoked"
                    share.isExpired -> "expired"
                    else -> "active"
                },
                color = when {
                    share.revoked -> AlertRed
                    share.isExpired -> WarningAmber
                    else -> EmeraldPrimary
                }
            )
        }
        if (!share.revoked) {
            Spacer(Modifier.height(6.dp))
            TextButton(onClick = onRevoke) { Text("Revoke link", color = AlertRed, fontSize = 12.sp) }
        }
    }
}

// --------------------------------------------------------------------------- uploads
@Composable
private fun UploadsSection(ui: CloudUiState, viewModel: CloudViewModel, context: android.content.Context) {
    GlassPanel(accent = CyberCyan) {
        SectionHeader("Transfer manager", "Pause, resume and cancel — resumable at chunk level", CyberCyan)
        Spacer(Modifier.height(8.dp))
        if (ui.transfers.isEmpty()) {
            EmptyState(title = "No transfers", message = "Uploads and downloads appear here with live progress.")
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ui.transfers.forEach { transfer ->
                    TransferRow(
                        transfer = transfer,
                        onPause = { viewModel.pauseTransfer(transfer) },
                        onResume = { viewModel.resumeTransfer(transfer) },
                        onCancel = { viewModel.cancelTransfer(transfer) },
                        onOpen = {
                            val path = transfer.localPath
                            if (transfer.direction == "download" && !path.isNullOrBlank()) {
                                val file = java.io.File(path)
                                val uri = androidx.core.content.FileProvider.getUriForFile(
                                    context,
                                    "${context.packageName}.fileprovider",
                                    file
                                )
                                val intent = Intent(Intent.ACTION_VIEW)
                                    .setDataAndType(uri, transfer.mime)
                                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                runCatching { context.startActivity(intent) }
                            }
                        }
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = { viewModel.clearFinishedTransfers() }) {
                Text("Clear finished transfers", fontSize = 12.sp, color = Color(0xFF8FA6C4))
            }
        }
    }
}

@Composable
private fun TransferRow(
    transfer: CloudTransferEntity,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onOpen: () -> Unit
) {
    val accent = when (transfer.status) {
        "completed" -> EmeraldPrimary
        "failed" -> AlertRed
        "paused" -> WarningAmber
        "cancelled" -> Color(0xFF7D93B1)
        else -> CyberCyan
    }
    Column(
        Modifier
            .fillMaxWidth()
            .background(Color(0xFF0E1C30), RoundedCornerShape(14.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (transfer.direction == "upload") Icons.Default.CloudUpload else Icons.Default.Download,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(transfer.fileName, style = MaterialTheme.typography.titleMedium, color = Color.White, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${transfer.status} • ${ByteFormat.human(transfer.bytesDone)} / ${ByteFormat.human(transfer.size)}" +
                        (transfer.error?.let { " • $it" } ?: ""),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (transfer.error != null) AlertRed else Color(0xFF8FA6C4),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            when (transfer.status) {
                "running", "queued" -> IconButton(onClick = onPause) {
                    Icon(Icons.Default.Pause, contentDescription = "Pause", tint = WarningAmber)
                }
                "paused", "failed" -> IconButton(onClick = onResume) {
                    Icon(Icons.Default.PlayArrow, contentDescription = "Resume", tint = EmeraldGlow)
                }
                "completed" -> if (transfer.direction == "download") {
                    IconButton(onClick = onOpen) {
                        Icon(Icons.Default.Search, contentDescription = "Open", tint = CyberCyan)
                    }
                }
                else -> Unit
            }
            if (transfer.status != "completed") {
                IconButton(onClick = onCancel) {
                    Icon(Icons.Default.Delete, contentDescription = "Cancel", tint = AlertRed)
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            progress = { transfer.progress },
            modifier = Modifier.fillMaxWidth().height(6.dp),
            color = accent,
            trackColor = Color(0xFF15253C)
        )
    }
}

// --------------------------------------------------------------------------- security
@Composable
private fun SecuritySection(ui: CloudUiState, viewModel: CloudViewModel) {
    GlassPanel(accent = AlertRed) {
        SectionHeader("Cloud security", "Encryption, malware scanning and audit trail", AlertRed)
        Spacer(Modifier.height(10.dp))
        val security = ui.security
        StatusRow("In transit", security?.encryption?.inTransit ?: "TLS 1.2+", true)
        StatusRow("At rest", security?.encryption?.atRest ?: "AES-256 (provider managed)", true)
        StatusRow("Client-side encryption", security?.encryption?.clientSide ?: "available", true)
        StatusRow("Signed URL lifetime", "${security?.encryption?.signedUrlTtlSeconds ?: 300}s", true)
        StatusRow(
            "Scanner",
            "${security?.scanning?.engine ?: "cybershield"} • ${security?.scanning?.counts?.get("clean") ?: 0} clean",
            true
        )
        Spacer(Modifier.height(8.dp))
        MetricBar(
            label = "Quarantined files",
            value = "${security?.scanning?.quarantined?.size ?: 0}",
            fraction = ((security?.scanning?.quarantined?.size ?: 0) / 10f).coerceIn(0f, 1f),
            accent = AlertRed
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { viewModel.refreshSecurity() },
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1D3557))
        ) {
            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Re-check security posture")
        }
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel {
        SectionHeader("Quarantine", "Blocked from download until you release it", WarningAmber)
        Spacer(Modifier.height(8.dp))
        val quarantined = ui.security?.scanning?.quarantined ?: emptyList()
        if (quarantined.isEmpty()) {
            Text("No quarantined files.", style = MaterialTheme.typography.labelMedium, color = Color(0xFF7D93B1))
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                quarantined.forEach { item ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .background(AlertRed.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text(item.name, style = MaterialTheme.typography.titleMedium, color = Color.White, maxLines = 1)
                            Text(
                                "${item.scanStatus} • ${ByteFormat.human(item.size)}",
                                style = MaterialTheme.typography.labelMedium,
                                color = Color(0xFFE7A1A1)
                            )
                        }
                        TextButton(onClick = {
                            viewModel.releaseQuarantine(
                                CloudNodeDto(id = item.id, name = item.name, size = item.size, status = "quarantined")
                            )
                        }) { Text("Release", fontSize = 12.sp, color = WarningAmber) }
                    }
                }
            }
        }
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel(accent = CyberCyan) {
        SectionHeader("Audit log", "Server-recorded security events (IPs are hashed)", CyberCyan)
        Spacer(Modifier.height(8.dp))
        if (ui.audit.isEmpty()) {
            Text("No events recorded yet.", style = MaterialTheme.typography.labelMedium, color = Color(0xFF7D93B1))
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                ui.audit.take(30).forEach { entry ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(6.dp)
                                .background(if (entry.success) EmeraldPrimary else AlertRed, RoundedCornerShape(50))
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            entry.action.replace('_', ' '),
                            style = MaterialTheme.typography.labelMedium,
                            color = Color(0xFFB7C8DE),
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            formatRelative(entry.createdAt),
                            style = MaterialTheme.typography.labelMedium,
                            color = Color(0xFF6F86A4)
                        )
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------------------- settings
@Composable
private fun SettingsSection(ui: CloudUiState, viewModel: CloudViewModel) {
    var apiUrl by remember { mutableStateOf(ui.config.apiBaseUrl) }
    var supabaseUrl by remember { mutableStateOf(ui.config.supabaseUrl) }
    var anonKey by remember { mutableStateOf(ui.config.supabaseAnonKey) }
    var autoBackup by remember { mutableStateOf(ui.config.autoBackupEnabled) }
    var interval by remember { mutableStateOf(ui.config.autoBackupIntervalHours.toString()) }
    var backgroundUploads by remember { mutableStateOf(ui.config.backgroundUploadsEnabled) }
    var wifiOnly by remember { mutableStateOf(ui.config.wifiOnlyUploads) }
    var clientEncryption by remember { mutableStateOf(ui.config.clientSideEncryptionDefault) }
    var shareExpiry by remember { mutableStateOf(ui.config.shareDefaultExpiryHours.toString()) }
    var sharePassword by remember { mutableStateOf(ui.config.shareDefaultPassword) }

    GlassPanel(accent = CyberCyan) {
        SectionHeader("Deployment", "Only public values live in the app", CyberCyan)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(apiUrl, { apiUrl = it }, label = { Text("Worker URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(supabaseUrl, { supabaseUrl = it }, label = { Text("Supabase URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(anonKey, { anonKey = it }, label = { Text("Supabase publishable key") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { viewModel.updateDeployment(apiUrl, supabaseUrl, anonKey) },
            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan)
        ) { Text("Save deployment") }
        Spacer(Modifier.height(6.dp))
        Text(
            "Health: ${ui.health?.status ?: "unknown"} • DB ${ui.health?.database ?: "?"} • " +
                "storage ${ui.health?.storage ?: "?"} • ${ui.meta?.storageProvider ?: "provider ?"}",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFF8FA6C4)
        )
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel(accent = PurpleAccent) {
        SectionHeader("Backup & transfers", accent = PurpleAccent)
        Spacer(Modifier.height(6.dp))
        ToggleRow("Automatic backups", autoBackup) { autoBackup = it }
        OutlinedTextField(
            interval,
            { interval = it.filter { ch -> ch.isDigit() } },
            label = { Text("Backup interval (hours)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(6.dp))
        ToggleRow("Background uploads", backgroundUploads) { backgroundUploads = it }
        ToggleRow("Wi-Fi only uploads", wifiOnly) { wifiOnly = it }
        ToggleRow("Encrypt files by default (client-side)", clientEncryption) { clientEncryption = it }
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
            shareExpiry,
            { shareExpiry = it.filter { ch -> ch.isDigit() } },
            label = { Text("Default share expiry (hours)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth()
        )
        ToggleRow("Password-protect new share links", sharePassword) { sharePassword = it }
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = {
                viewModel.updatePreferences(
                    autoBackup = autoBackup,
                    intervalHours = interval.toIntOrNull() ?: 24,
                    backgroundUploads = backgroundUploads,
                    wifiOnly = wifiOnly,
                    clientEncryption = clientEncryption,
                    shareExpiryHours = shareExpiry.toIntOrNull() ?: 24,
                    sharePassword = sharePassword,
                    warnPercent = ui.config.warnAtPercent
                )
            },
            colors = ButtonDefaults.buttonColors(containerColor = PurpleAccent)
        ) { Text("Save preferences") }
    }

    Spacer(Modifier.height(12.dp))
    GlassPanel(accent = AlertRed) {
        SectionHeader("Account", accent = AlertRed)
        Spacer(Modifier.height(6.dp))
        Text(
            ui.account?.user?.email ?: "Not signed in",
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xFFB7C8DE)
        )
        Text(
            "Tier: ${ui.account?.user?.tier ?: "free"} • quota ${ByteFormat.human(ui.quota.quotaBytes)} • " +
                "free-tier pool ${ByteFormat.human(ui.quota.providerFreeBytes)}",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFF8FA6C4)
        )
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { viewModel.signOut() }) {
            Text("Sign out", color = AlertRed)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "No paid plan, no automatic upgrade, no credit card is ever requested by this app.",
            style = MaterialTheme.typography.labelMedium,
            color = Color(0xFF6F86A4)
        )
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = Color(0xFFB7C8DE), modifier = Modifier.weight(1f))
        androidx.compose.material3.Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = androidx.compose.material3.SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = EmeraldPrimary
            )
        )
    }
}

// --------------------------------------------------------------------------- dialogs
@Composable
private fun TextInputDialog(
    title: String,
    label: String,
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(label) },
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value) }, enabled = value.isNotBlank()) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun ShareDialog(
    node: CloudNodeDto,
    defaultExpiryHours: Int,
    defaultPassword: Boolean,
    onDismiss: () -> Unit,
    onCreate: (Int, Int, String?, Boolean) -> Unit
) {
    var hours by remember { mutableStateOf(defaultExpiryHours.toString()) }
    var maxDownloads by remember { mutableStateOf("0") }
    var password by remember { mutableStateOf("") }
    var allowPreview by remember { mutableStateOf(true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Share \"${node.name}\"") },
        text = {
            Column {
                OutlinedTextField(
                    hours,
                    { hours = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Expires in (hours)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    maxDownloads,
                    { maxDownloads = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Max downloads (0 = unlimited)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    password,
                    { password = it },
                    label = { Text("Password (optional)") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
                ToggleRow("Allow preview", allowPreview) { allowPreview = it }
                Text(
                    if (defaultPassword && password.isBlank()) {
                        "Tip: a password is enabled by default in Settings."
                    } else {
                        "Links expire automatically and can be revoked instantly."
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF8FA6C4)
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onCreate(hours.toIntOrNull() ?: 24, maxDownloads.toIntOrNull() ?: 0, password.ifBlank { null }, allowPreview)
            }) { Text("Create link") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun VersionsDialog(node: CloudNodeDto, viewModel: CloudViewModel, onDismiss: () -> Unit) {
    var versions by remember { mutableStateOf<List<com.adshield.pro.cloud.data.CloudVersionDto>>(emptyList()) }
    var current by remember { mutableStateOf(0) }
    LaunchedEffect(node.id) {
        viewModel.loadVersions(node) { list, currentVersion ->
            versions = list
            current = currentVersion
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Version history") },
        text = {
            Column {
                Text("Current version: v$current", style = MaterialTheme.typography.labelMedium, color = Color(0xFF8FA6C4))
                Spacer(Modifier.height(8.dp))
                if (versions.isEmpty()) {
                    Text("No versions recorded.", style = MaterialTheme.typography.bodyMedium)
                } else {
                    versions.forEach { version ->
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.weight(1f)) {
                                Text("v${version.version}", style = MaterialTheme.typography.titleMedium, color = Color.White)
                                Text(
                                    "${ByteFormat.human(version.size)} • ${formatRelative(version.createdAt)}",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = Color(0xFF8FA6C4)
                                )
                            }
                            if (version.version != current) {
                                TextButton(onClick = {
                                    viewModel.restoreVersion(node, version)
                                    onDismiss()
                                }) { Text("Restore", fontSize = 12.sp) }
                            } else {
                                StatusPill("current", EmeraldPrimary)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } }
    )
}

@Composable
private fun PreviewDialog(
    node: CloudNodeDto,
    viewModel: CloudViewModel,
    context: android.content.Context,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var bitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var failed by remember { mutableStateOf(false) }

    LaunchedEffect(node.id) {
        val url = viewModel.previewUrl(node)
        if (url == null) {
            failed = true
        } else {
            val loaded = viewModel.loadPreviewBitmap(url)
            if (loaded != null) bitmap = loaded else failed = true
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(node.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        text = {
            Column {
                when {
                    bitmap != null -> androidx.compose.foundation.Image(
                        bitmap = bitmap!!.asImageBitmap(),
                        contentDescription = node.name,
                        modifier = Modifier.fillMaxWidth().height(240.dp)
                    )
                    failed -> Text("Preview is not available for this file type.", color = Color(0xFF8FA6C4))
                    else -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                        CircularProgressIndicator(color = EmeraldPrimary, modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "${ByteFormat.human(node.size)} • ${node.mime ?: "unknown"}",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF8FA6C4)
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { scope.launch { viewModel.download(node) }; onDismiss() }) { Text("Download") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } }
    )
}
