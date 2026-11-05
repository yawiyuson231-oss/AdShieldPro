package com.adshield.pro.globalvpn.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.globalvpn.data.GlobalVpnSettingsStore
import com.adshield.pro.globalvpn.engine.GlobalVpnController
import com.adshield.pro.globalvpn.engine.ServerScorer
import com.adshield.pro.globalvpn.model.GlobalVpnFeatureMatrix
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.SplitTunnelMode
import com.adshield.pro.globalvpn.model.VpnProtocol
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class SplitApp(val packageName: String, val label: String, val isSystem: Boolean)

@HiltViewModel
class GlobalVpnViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val controller: GlobalVpnController,
    private val settingsStore: GlobalVpnSettingsStore
) : ViewModel() {

    val state = controller.state
    val servers = controller.servers
    val providerErrors = controller.providerErrors
    val isRefreshing = controller.isRefreshing
    val providers = controller.providers
    val featureMatrix = GlobalVpnFeatureMatrix.features

    val settings: StateFlow<GlobalVpnSettings> = settingsStore.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), GlobalVpnSettings())

    val history = settingsStore.history
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val scoredServers: StateFlow<List<ServerScorer.ScoredServer>> =
        combine(controller.servers, settings) { _, currentSettings ->
            controller.scoredServers(currentSettings)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _installedApps = MutableStateFlow<List<SplitApp>>(emptyList())
    val installedApps: StateFlow<List<SplitApp>> = _installedApps.asStateFlow()

    fun refresh() {
        viewModelScope.launch {
            controller.refreshProviders()
            controller.probeConnectableServers()
        }
    }

    fun connect(serverId: String) = controller.connect(serverId)
    fun connectFastest() = controller.connectFastest()
    fun disconnect() = controller.disconnect()

    fun selectServer(serverId: String) {
        viewModelScope.launch { settingsStore.update { it.copy(selectedServerId = serverId) } }
    }

    fun updateSettings(transform: (GlobalVpnSettings) -> GlobalVpnSettings) {
        viewModelScope.launch { settingsStore.update(transform) }
    }

    fun setKillSwitch(enabled: Boolean) = updateSettings { it.copy(killSwitch = enabled) }
    fun setLeakProtection(enabled: Boolean) = updateSettings { it.copy(leakProtection = enabled) }
    fun setAutoReconnect(enabled: Boolean) = updateSettings { it.copy(autoReconnect = enabled) }
    fun setAutoFailover(enabled: Boolean) = updateSettings { it.copy(autoFailover = enabled) }
    fun setBatterySaver(enabled: Boolean) = updateSettings { it.copy(batterySaver = enabled) }
    fun setProtocol(protocol: VpnProtocol) = updateSettings { it.copy(protocolPreference = protocol) }
    fun setPreferredProvider(provider: ProviderId?) = updateSettings { it.copy(preferredProvider = provider) }
    fun setPreferredCountry(code: String?) = updateSettings { it.copy(preferredCountryCode = code) }

    fun setSplitMode(mode: SplitTunnelMode) = updateSettings { it.copy(splitTunnelMode = mode) }

    fun toggleSplitApp(packageName: String) {
        viewModelScope.launch {
            settingsStore.update {
                val packages = it.splitTunnelPackages.toMutableSet()
                if (!packages.add(packageName)) packages.remove(packageName)
                it.copy(splitTunnelPackages = packages)
            }
        }
    }

    fun importConfig(name: String, provider: ProviderId, configText: String, countryCode: String?, countryName: String?) {
        val result = controller.importWireGuardConfig(name, provider, configText, countryCode, countryName)
        result.onSuccess {
            _message.value = "Configuration imported and encrypted on-device."
            viewModelScope.launch { controller.refreshProviders() }
        }.onFailure {
            _message.value = "Import failed: ${it.message}"
        }
    }

    fun deleteImported(id: String) {
        controller.deleteImported(id)
        _message.value = "Configuration removed."
    }

    fun exportOpenVpn(serverId: String): String? = controller.exportOpenVpnConfig(serverId)

    fun clearHistory() {
        viewModelScope.launch { settingsStore.clearHistory() }
    }

    fun diagnostics(): String = controller.diagnostics()

    fun clearMessage() {
        _message.value = null
    }

    fun loadInstalledApps() {
        viewModelScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val pm = context.packageManager
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .map { info ->
                        SplitApp(
                            packageName = info.packageName,
                            label = pm.getApplicationLabel(info).toString(),
                            isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        )
                    }
                    .sortedBy { it.label.lowercase() }
            }
            _installedApps.value = apps
        }
    }
}
