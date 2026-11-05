package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.vpn.FeatureStatus
import com.adshield.pro.vpn.VpnConnectionState
import com.adshield.pro.vpn.VpnEngine
import com.adshield.pro.vpn.VpnServer
import com.adshield.pro.vpn.VpnServerCatalog
import com.adshield.pro.vpn.VpnServerSelection
import com.adshield.pro.vpn.VpnStats
import com.adshield.pro.vpn.VpnThreatEvent
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class VpnViewModel @Inject constructor(
    private val engine: VpnEngine,
    private val catalog: VpnServerCatalog
) : ViewModel() {

    val connectionState: StateFlow<VpnConnectionState> = engine.connectionState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), VpnConnectionState.DISCONNECTED)
    val activeServer: StateFlow<VpnServer?> = engine.activeServer
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)
    val stats: StateFlow<VpnStats> = engine.stats
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000),
            VpnStats(null, 0, 0, null, null, true, null))
    val lastFeatureStatus: StateFlow<FeatureStatus?> = engine.lastFeatureStatus
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val servers: StateFlow<List<VpnServer>> = catalog.serversFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val threats: StateFlow<List<VpnThreatEvent>> = catalog.threatsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val displayServers: StateFlow<List<VpnServer>> = servers
        .map { VpnServerSelection.sortedForDisplay(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun connect(server: VpnServer) = viewModelScope.launch { engine.connect(server) }
    fun disconnect() = viewModelScope.launch { engine.disconnect() }
    fun probeServers() = viewModelScope.launch { engine.probeAllServers() }
    fun fastest() = viewModelScope.launch {
        val best = engine.fastestServer()
        if (best != null) engine.connect(best)
    }
    fun checkIp() = viewModelScope.launch { engine.checkPublicIp() }
    fun dnsLeakProbe() = viewModelScope.launch { engine.dnsLeakProbe() }
    fun addServer(server: VpnServer) = viewModelScope.launch { catalog.addServer(server) }
    fun removeServer(id: String) = viewModelScope.launch { catalog.removeServer(id) }
    fun toggleFavorite(id: String) = viewModelScope.launch { catalog.toggleFavorite(id) }
    fun clearThreats() = viewModelScope.launch { catalog.clearThreats() }
}
