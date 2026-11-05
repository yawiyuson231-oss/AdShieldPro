package com.adshield.pro.globalvpn.engine

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.core.content.ContextCompat
import com.adshield.pro.globalvpn.data.GlobalVpnSettingsStore
import com.adshield.pro.globalvpn.data.SecureTunnelVault
import com.adshield.pro.globalvpn.model.ConnectionHistoryEntry
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.GlobalVpnState
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.TunnelPhase
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import com.adshield.pro.globalvpn.provider.ProtonProvider
import com.adshield.pro.globalvpn.provider.RiseupProvider
import com.adshield.pro.globalvpn.provider.SelfHostedProvider
import com.adshield.pro.globalvpn.provider.VpnGateProvider
import com.adshield.pro.globalvpn.provider.VpnProviderAdapter
import com.adshield.pro.globalvpn.provider.WindscribeProvider
import com.adshield.pro.service.AdShieldVpnService
import com.wireguard.android.backend.Tunnel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates the Global VPN feature. It is intentionally isolated from the DNS system: the only
 * interaction is a runtime hand-off (Android permits a single active VpnService), performed by
 * sending the DNS service its own public STOP action when the user explicitly connects Global VPN.
 * No DNS setting, rule, log or code path is modified.
 */
@Singleton
class GlobalVpnController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val engine: WireGuardEngine,
    private val vault: SecureTunnelVault,
    private val settingsStore: GlobalVpnSettingsStore,
    private val prober: LatencyProber,
    proton: ProtonProvider,
    selfHosted: SelfHostedProvider,
    vpnGate: VpnGateProvider,
    riseup: RiseupProvider,
    windscribe: WindscribeProvider
) {
    val providers: List<VpnProviderAdapter> = listOf(selfHosted, proton, vpnGate, riseup, windscribe)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val _state = MutableStateFlow(GlobalVpnState())
    val state: StateFlow<GlobalVpnState> = _state.asStateFlow()

    private val _servers = MutableStateFlow<List<VpnServer>>(emptyList())
    val servers: StateFlow<List<VpnServer>> = _servers.asStateFlow()

    private val _providerErrors = MutableStateFlow<Map<ProviderId, String>>(emptyMap())
    val providerErrors: StateFlow<Map<ProviderId, String>> = _providerErrors.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    private val histories = ConcurrentHashMap<String, ServerScorer.ProbeHistory>()
    private var monitorJob: Job? = null
    private var desiredConnected = false
    private var activeServer: VpnServer? = null
    private var activeConfigText: String? = null
    private var currentSessionId: String? = null
    private var reconnectAttempts = 0
    private var failoverAttempts = 0

    private val ipClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .callTimeout(12, TimeUnit.SECONDS)
            .build()
    }

    init {
        engine.onStateChange = { newState ->
            if (newState == Tunnel.State.DOWN && desiredConnected) {
                scope.launch { attemptReconnect() }
            }
        }
        registerNetworkCallback()
        scope.launch { refreshProviders() }
    }

    private fun registerNetworkCallback() {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        runCatching {
            manager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (desiredConnected && _state.value.phase != TunnelPhase.CONNECTED) {
                        scope.launch { attemptReconnect() }
                    }
                }
            })
        }
    }

    suspend fun refreshProviders() {
        if (_isRefreshing.value) return
        _isRefreshing.value = true
        val merged = mutableListOf<VpnServer>()
        val errors = mutableMapOf<ProviderId, String>()
        for (provider in providers) {
            try {
                merged.addAll(provider.discover())
            } catch (e: Exception) {
                errors[provider.id] = e.message ?: "Discovery failed"
            }
        }
        _servers.value = merged
        _providerErrors.value = errors
        _isRefreshing.value = false
    }

    suspend fun probeConnectableServers() {
        val candidates = _servers.value.filter { it.isConnectable }.take(24)
        for (server in candidates) {
            val probe = prober.probe(server.id, server.endpointHost, server.endpointPort, server.protocol)
            val history = histories.getOrPut(server.id) { ServerScorer.ProbeHistory() }.record(probe)
            histories[server.id] = history
            _servers.update { list ->
                list.map {
                    if (it.id == server.id) it.copy(measuredLatencyMs = probe.latencyMs) else it
                }
            }
        }
    }

    fun scoredServers(settings: GlobalVpnSettings): List<ServerScorer.ScoredServer> =
        ServerScorer.rank(_servers.value, histories, settings)

    fun connectFastest() {
        scope.launch {
            val settings = settingsStore.current()
            val best = ServerScorer.fastestConnectable(_servers.value, histories, settings)
            if (best == null) {
                setError("No connectable WireGuard server. Import a Proton or self-hosted config first.")
            } else {
                connect(best.server.id)
            }
        }
    }

    fun connect(serverId: String) {
        scope.launch {
            val settings = settingsStore.current()
            val server = _servers.value.find { it.id == serverId }
            if (server == null) {
                setError("Server not found. Refresh the provider list.")
                return@launch
            }
            if (!server.isConnectable || server.protocol != VpnProtocol.WIREGUARD) {
                setError(server.unavailableReason ?: "This server cannot be dialed in-app (WireGuard only).")
                return@launch
            }
            val configText = server.configRef?.let { vault.readConfig(it) }
            if (configText.isNullOrBlank()) {
                setError("The encrypted configuration for this server is missing.")
                return@launch
            }

            _state.update {
                it.copy(
                    phase = TunnelPhase.CONNECTING,
                    server = server,
                    errorMessage = null,
                    statusNote = "Preparing secure tunnel…"
                )
            }

            val baselineIp = fetchPublicIp()
            val hardened = try {
                WireGuardConfigHardener.harden(
                    original = configText,
                    leakProtection = settings.leakProtection,
                    blockIpv6WhenUnsupported = settings.blockIpv6WhenUnsupported,
                    dnsServers = emptyList(),
                    splitMode = settings.splitTunnelMode,
                    splitPackages = settings.splitTunnelPackages
                )
            } catch (e: Exception) {
                setError("Invalid WireGuard configuration: ${e.message}")
                return@launch
            }

            // Runtime hand-off only: Android allows one active VPN. This uses the DNS service's own
            // public STOP action and does not modify any DNS code or setting.
            handOffFromLocalDnsVpn()

            val result = engine.connect(hardened)
            if (result.isFailure) {
                handleConnectFailure(server, result.exceptionOrNull())
                return@launch
            }

            desiredConnected = true
            activeServer = server
            activeConfigText = hardened
            reconnectAttempts = 0
            failoverAttempts = 0
            startKeeper()
            vault.touch(server.id)
            settingsStore.update { it.copy(selectedServerId = server.id) }

            val now = System.currentTimeMillis()
            val sessionId = "sess-$now"
            currentSessionId = sessionId
            settingsStore.recordSession(
                ConnectionHistoryEntry(
                    id = sessionId,
                    serverName = server.displayName,
                    provider = server.provider,
                    countryCode = server.countryCode,
                    protocol = server.protocol,
                    startedAtEpochMs = now
                )
            )

            _state.update {
                it.copy(
                    phase = TunnelPhase.CONNECTED,
                    connectedSinceEpochMs = now,
                    baselinePublicIp = baselineIp,
                    tunnelPublicIp = null,
                    ipChangeVerified = false,
                    killSwitchRequested = settings.killSwitch,
                    dnsLeakProtected = settings.leakProtection,
                    ipv6LeakProtected = settings.blockIpv6WhenUnsupported,
                    alwaysOnEnabled = engine.isAlwaysOn(),
                    lockdownEnabled = engine.isLockdownEnabled(),
                    statusNote = "Tunnel up. Verifying exit IP…"
                )
            }
            startMonitoring(settings)

            val tunnelIp = fetchPublicIp()
            _state.update {
                it.copy(
                    tunnelPublicIp = tunnelIp,
                    ipChangeVerified = tunnelIp != null && baselineIp != null && tunnelIp != baselineIp,
                    statusNote = if (tunnelIp != null && baselineIp != null && tunnelIp != baselineIp)
                        "Exit IP verified." else "Connected. Exit IP could not be verified."
                )
            }
        }
    }

    fun disconnect() {
        scope.launch {
            desiredConnected = false
            _state.update { it.copy(phase = TunnelPhase.DISCONNECTING, statusNote = "Closing tunnel…") }
            monitorJob?.cancel()
            engine.disconnect()
            stopKeeper()
            val sessionId = currentSessionId
            val stats = engine.stats()
            if (sessionId != null) {
                settingsStore.closeSession(
                    id = sessionId,
                    endedAtEpochMs = System.currentTimeMillis(),
                    rxBytes = stats?.rxBytes ?: _state.value.rxBytes,
                    txBytes = stats?.txBytes ?: _state.value.txBytes,
                    outcome = "disconnected"
                )
            }
            currentSessionId = null
            activeServer = null
            activeConfigText = null
            _state.update {
                GlobalVpnState(
                    killSwitchRequested = it.killSwitchRequested,
                    alwaysOnEnabled = engine.isAlwaysOn(),
                    lockdownEnabled = engine.isLockdownEnabled()
                )
            }
        }
    }

    private fun startMonitoring(settings: GlobalVpnSettings) {
        monitorJob?.cancel()
        monitorJob = scope.launch {
            var lastRx = 0L
            var lastTx = 0L
            var lastTime = System.currentTimeMillis()
            val interval = if (settings.batterySaver) 5000L else 2000L
            while (isActive && desiredConnected) {
                val stats = engine.stats()
                val now = System.currentTimeMillis()
                if (stats != null) {
                    val dt = (now - lastTime).coerceAtLeast(1L)
                    val rxRate = ((stats.rxBytes - lastRx) * 1000L / dt).coerceAtLeast(0L)
                    val txRate = ((stats.txBytes - lastTx) * 1000L / dt).coerceAtLeast(0L)
                    lastRx = stats.rxBytes
                    lastTx = stats.txBytes
                    lastTime = now
                    val handshakeAge =
                        if (stats.latestHandshakeEpochMs > 0) now - stats.latestHandshakeEpochMs else null
                    _state.update {
                        it.copy(
                            rxBytes = stats.rxBytes,
                            txBytes = stats.txBytes,
                            rxBytesPerSec = rxRate,
                            txBytesPerSec = txRate,
                            handshakeAgeMs = handshakeAge,
                            healthScore = computeHealth(handshakeAge),
                            alwaysOnEnabled = engine.isAlwaysOn(),
                            lockdownEnabled = engine.isLockdownEnabled()
                        )
                    }
                    if (handshakeAge != null && handshakeAge > HANDSHAKE_TIMEOUT_MS && settings.autoReconnect) {
                        attemptReconnect()
                    }
                }
                delay(interval)
            }
        }
    }

    private fun computeHealth(handshakeAgeMs: Long?): Int = when {
        handshakeAgeMs == null -> 40
        handshakeAgeMs < 30_000 -> 100
        handshakeAgeMs < 90_000 -> 75
        handshakeAgeMs < 180_000 -> 50
        else -> 20
    }

    private suspend fun attemptReconnect() {
        val config = activeConfigText ?: return
        if (!desiredConnected) return
        reconnectAttempts++
        if (reconnectAttempts > MAX_RECONNECT_BEFORE_FAILOVER) {
            failover()
            return
        }
        _state.update { it.copy(phase = TunnelPhase.RECONNECTING, statusNote = "Reconnecting (attempt $reconnectAttempts)…") }
        engine.disconnect()
        val result = engine.connect(config)
        if (result.isSuccess) {
            reconnectAttempts = 0
            _state.update { it.copy(phase = TunnelPhase.CONNECTED, statusNote = "Reconnected.", errorMessage = null) }
        } else {
            _state.update { it.copy(statusNote = "Reconnect failed: ${result.exceptionOrNull()?.message}") }
        }
    }

    private suspend fun failover() {
        val settings = settingsStore.current()
        if (!settings.autoFailover || failoverAttempts >= MAX_FAILOVER) {
            setError("Connection lost and failover is exhausted. Reconnect manually.")
            desiredConnected = false
            return
        }
        failoverAttempts++
        reconnectAttempts = 0
        val current = activeServer?.id
        val next = ServerScorer.rank(_servers.value, histories, settings)
            .firstOrNull { it.server.isConnectable && it.server.id != current }
        if (next == null) {
            setError("No alternative connectable server available for failover.")
            desiredConnected = false
            return
        }
        _state.update { it.copy(statusNote = "Failing over to ${next.server.displayName}…") }
        connect(next.server.id)
    }

    private suspend fun handleConnectFailure(server: VpnServer, error: Throwable?) {
        val history = histories.getOrPut(server.id) { ServerScorer.ProbeHistory() }
        histories[server.id] = history.copy(failures = history.failures + 1)
        setError("Could not connect to ${server.displayName}: ${error?.message ?: "unknown error"}")
        val settings = settingsStore.current()
        if (settings.autoFailover && failoverAttempts < MAX_FAILOVER) {
            failover()
        }
    }

    private fun startKeeper() {
        runCatching {
            ContextCompat.startForegroundService(
                context,
                Intent(context, GlobalVpnService::class.java).setAction(GlobalVpnService.ACTION_START)
            )
        }
    }

    private fun stopKeeper() {
        runCatching {
            context.startService(
                Intent(context, GlobalVpnService::class.java).setAction(GlobalVpnService.ACTION_STOP)
            )
        }
    }

    private fun handOffFromLocalDnsVpn() {
        runCatching {
            context.startService(
                Intent(context, AdShieldVpnService::class.java).apply {
                    action = AdShieldVpnService.ACTION_STOP_VPN
                }
            )
        }
    }

    private suspend fun fetchPublicIp(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val request = Request.Builder().url("https://api.ipify.org").get().build()
            ipClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@runCatching null
                response.body?.string()?.trim()?.takeIf { it.isNotBlank() && it.length <= 45 }
            }
        }.getOrNull()
    }

    private fun setError(message: String) {
        _state.update { it.copy(phase = TunnelPhase.ERROR, errorMessage = message, statusNote = null) }
    }

    fun importWireGuardConfig(
        name: String,
        provider: ProviderId,
        configText: String,
        countryCode: String?,
        countryName: String?
    ): Result<String> {
        return runCatching {
            val parsed = engine.parse(configText)
            require(parsed.peers.isNotEmpty()) { "Configuration has no peer" }
            val endpoint = WireGuardConfigHardener.endpointOf(configText)
                ?: error("Configuration has no reachable Endpoint")
            val (guessCode, guessCountry) = SecureTunnelVault.guessCountryFromName(name)
            val id = SecureTunnelVault.newId()
            val meta = com.adshield.pro.globalvpn.model.StoredTunnel(
                id = id,
                name = name.ifBlank { "WireGuard $id" },
                provider = provider,
                protocol = VpnProtocol.WIREGUARD,
                countryCode = countryCode ?: guessCode,
                countryName = countryName ?: guessCountry,
                endpointHost = endpoint.first,
                endpointPort = endpoint.second,
                addedAtEpochMs = System.currentTimeMillis()
            )
            vault.save(meta, configText)
            id
        }
    }

    fun deleteImported(id: String) {
        vault.delete(id)
        scope.launch { refreshProviders() }
    }

    fun exportOpenVpnConfig(serverId: String): String? =
        providers.firstNotNullOfOrNull { it.exportConfig(serverId) }

    fun diagnostics(): String {
        val s = _state.value
        return buildString {
            appendLine("Global VPN diagnostics")
            appendLine("phase=${s.phase}")
            appendLine("server=${s.server?.displayName ?: "none"}")
            appendLine("protocol=${s.server?.protocol ?: "none"}")
            appendLine("backend=${engine.backendVersion()}")
            appendLine("baselineIp=${s.baselinePublicIp ?: "unknown"}")
            appendLine("tunnelIp=${s.tunnelPublicIp ?: "unknown"}")
            appendLine("ipChangeVerified=${s.ipChangeVerified}")
            appendLine("handshakeAgeMs=${s.handshakeAgeMs ?: "n/a"}")
            appendLine("latency=${s.latencyMs ?: "n/a"} (${s.latencyMethod ?: "no probe"})")
            appendLine("alwaysOn=${s.alwaysOnEnabled} lockdown=${s.lockdownEnabled}")
            appendLine("killSwitchActive=${s.killSwitchActive}")
            appendLine("rx=${s.rxBytes} tx=${s.txBytes}")
        }
    }

    companion object {
        private const val HANDSHAKE_TIMEOUT_MS = 180_000L
        private const val MAX_RECONNECT_BEFORE_FAILOVER = 3
        private const val MAX_FAILOVER = 3
    }
}
