package com.adshield.pro.globalvpn.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.globalvpn.model.TunnelPhase

private enum class GlobalVpnTab(val label: String) {
    DASHBOARD("Dashboard"),
    SERVERS("Servers"),
    PROVIDERS("Providers"),
    SECURITY("Security"),
    ANALYTICS("Analytics"),
    SPLIT("Split Tunnel"),
    SETTINGS("Settings"),
    HISTORY("History")
}

private const val CONNECT_FASTEST = "__fastest__"

@Composable
fun GlobalVpnScreen(viewModel: GlobalVpnViewModel) {
    val context = LocalContext.current
    val state by viewModel.state.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val servers by viewModel.servers.collectAsStateWithLifecycle()
    val scored by viewModel.scoredServers.collectAsStateWithLifecycle()
    val providerErrors by viewModel.providerErrors.collectAsStateWithLifecycle()
    val isRefreshing by viewModel.isRefreshing.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val history by viewModel.history.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()

    var tab by remember { mutableStateOf(GlobalVpnTab.DASHBOARD) }
    var pendingConnect by remember { mutableStateOf<String?>(null) }
    var exportServerId by remember { mutableStateOf<String?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-openvpn-profile")
    ) { uri ->
        val id = exportServerId
        exportServerId = null
        if (uri != null && id != null) {
            val config = viewModel.exportOpenVpn(id)
            if (config != null) {
                runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(config.toByteArray()) }
                }
            }
        }
    }

    val doConnect: () -> Unit = {
        when (val target = pendingConnect) {
            CONNECT_FASTEST -> viewModel.connectFastest()
            null -> Unit
            else -> viewModel.connect(target)
        }
        pendingConnect = null
    }

    // Notification permission is requested on the consent path; dialing does not depend on it.
    val ensureNotificationThenConnect: () -> Unit = { doConnect() }

    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> doConnect() }

    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK || VpnService.prepare(context) == null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                doConnect()
            }
        } else {
            pendingConnect = null
        }
    }

    val requestConnect: (String) -> Unit = { target ->
        pendingConnect = target
        val prepare = try {
            VpnService.prepare(context)
        } catch (e: Exception) {
            null
        }
        if (prepare != null) {
            try {
                consentLauncher.launch(prepare)
            } catch (e: Exception) {
                pendingConnect = null
            }
        } else {
            ensureNotificationThenConnect()
        }
    }

    LaunchedEffect(message) {
        val msg = message
        if (!msg.isNullOrBlank()) {
            snackbarHostState.showSnackbar(msg)
            viewModel.clearMessage()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                GlobalVpnTab.entries.forEach { entry ->
                    FilterChip(
                        selected = tab == entry,
                        onClick = { tab = entry },
                        label = { Text(entry.label, style = MaterialTheme.typography.labelMedium) }
                    )
                }
            }

            Box(modifier = Modifier.fillMaxSize()) {
                when (tab) {
                    GlobalVpnTab.DASHBOARD -> GlobalVpnDashboard(
                        state = state,
                        settings = settings,
                        scored = scored,
                        onConnect = {
                            if (state.phase == TunnelPhase.CONNECTED) viewModel.disconnect()
                            else requestConnect(settings.selectedServerId ?: CONNECT_FASTEST)
                        },
                        onConnectFastest = { requestConnect(CONNECT_FASTEST) },
                        onOpenServers = { tab = GlobalVpnTab.SERVERS },
                        onOpenProviders = { tab = GlobalVpnTab.PROVIDERS }
                    )
                    GlobalVpnTab.SERVERS -> GlobalVpnServers(
                        servers = servers,
                        scored = scored,
                        settings = settings,
                        isRefreshing = isRefreshing,
                        providerErrors = providerErrors,
                        onRefresh = viewModel::refresh,
                        onSelect = { viewModel.selectServer(it) },
                        onConnect = { requestConnect(it) },
                        onExport = { id ->
                            exportServerId = id
                            exportLauncher.launch("globalvpn-$id.ovpn")
                        }
                    )
                    GlobalVpnTab.PROVIDERS -> GlobalVpnProviders(
                        providers = viewModel.providers,
                        providerErrors = providerErrors,
                        onImport = viewModel::importConfig,
                        onDelete = viewModel::deleteImported,
                        servers = servers
                    )
                    GlobalVpnTab.SECURITY -> GlobalVpnSecurity(
                        state = state,
                        settings = settings,
                        featureMatrix = viewModel.featureMatrix,
                        onToggleKillSwitch = viewModel::setKillSwitch,
                        onToggleLeakProtection = viewModel::setLeakProtection,
                        diagnostics = viewModel::diagnostics
                    )
                    GlobalVpnTab.ANALYTICS -> GlobalVpnAnalytics(state = state, history = history)
                    GlobalVpnTab.SPLIT -> GlobalVpnSplitTunnel(
                        settings = settings,
                        apps = installedApps,
                        onLoadApps = viewModel::loadInstalledApps,
                        onSetMode = viewModel::setSplitMode,
                        onToggleApp = viewModel::toggleSplitApp
                    )
                    GlobalVpnTab.SETTINGS -> GlobalVpnSettings(
                        settings = settings,
                        onUpdate = viewModel::updateSettings,
                        onSetProtocol = viewModel::setProtocol,
                        onSetProvider = viewModel::setPreferredProvider,
                        onSetCountry = viewModel::setPreferredCountry
                    )
                    GlobalVpnTab.HISTORY -> GlobalVpnHistory(history = history, onClear = viewModel::clearHistory)
                }
            }
        }
    }
}
