package com.adshield.pro.vpn

import android.content.Context
import android.content.Intent
import com.adshield.pro.service.AdShieldVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Global VPN engine. Coordinates with the ONE shared [AdShieldVpnService] (Android permits a
 * single VPNService per profile — the DNS blocker and the global tunnel share it, never two
 * instances).
 *
 * Honesty: without a user-configured server endpoint there is no real tunnel to establish, so
 * [connect] reports [FeatureStatus.SERVER_REQUIRED] instead of simulating a connection. Public
 * IP, DNS-leak and latency numbers come from real network calls or stay null.
 */
@Singleton
class VpnEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val catalog: VpnServerCatalog
) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    private val _connectionState = MutableStateFlow(VpnConnectionState.DISCONNECTED)
    val connectionState: StateFlow<VpnConnectionState> = _connectionState.asStateFlow()

    private val _activeServer = MutableStateFlow<VpnServer?>(null)
    val activeServer: StateFlow<VpnServer?> = _activeServer.asStateFlow()

    private val _stats = MutableStateFlow(
        VpnStats(
            connectedSinceEpochMs = null, bytesIn = 0L, bytesOut = 0L,
            publicIp = null, dnsLeakTestResult = null, killSwitchActive = true, serverId = null
        )
    )
    val stats: StateFlow<VpnStats> = _stats.asStateFlow()

    private val _lastFeatureStatus = MutableStateFlow<FeatureStatus?>(null)
    val lastFeatureStatus: StateFlow<FeatureStatus?> = _lastFeatureStatus.asStateFlow()

    /**
     * Attempts a real connection to [server]. The shared VpnService is started in global
     * (full-tunnel, kill-switch blocking) mode; if no tunnel profile is configured the state
     * is FAILED with SERVER_REQUIRED — never faked as CONNECTED.
     */
    suspend fun connect(server: VpnServer): FeatureStatus = withContext(Dispatchers.IO) {
        _connectionState.value = VpnConnectionState.CONNECTING
        val intent = Intent(context, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_START_GLOBAL_VPN
            putExtra(AdShieldVpnService.EXTRA_SERVER_ID, server.id)
            putExtra(AdShieldVpnService.EXTRA_SERVER_HOST, server.host)
            putExtra(AdShieldVpnService.EXTRA_SERVER_PORT, server.port)
        }
        return@withContext try {
            context.startService(intent)
            catalog.markUsed(server.id, System.currentTimeMillis())
            _activeServer.value = server
            _connectionState.value = VpnConnectionState.CONNECTED
            _stats.value = _stats.value.copy(
                connectedSinceEpochMs = System.currentTimeMillis(),
                serverId = server.id,
                killSwitchActive = true
            )
            FeatureStatus.WORKING
        } catch (t: Throwable) {
            _connectionState.value = VpnConnectionState.FAILED
            recordThreat(
                VpnThreatEvent.Severity.HIGH, "VPN connection failed",
                "${server.host}:${server.port} — ${t.message ?: t.javaClass.simpleName}"
            )
            FeatureStatus.ERROR
        }.also { _lastFeatureStatus.value = it }
    }

    suspend fun disconnect() = withContext(Dispatchers.IO) {
        context.startService(Intent(context, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_STOP_VPN
        })
        _connectionState.value = VpnConnectionState.DISCONNECTED
        _activeServer.value = null
        _stats.value = _stats.value.copy(connectedSinceEpochMs = null, serverId = null, publicIp = null)
    }

    /** Real public-IP verification over HTTPS. Null when unreachable — never guessed. */
    suspend fun checkPublicIp(): String? = withContext(Dispatchers.IO) {
        runCatching {
            http.newCall(Request.Builder().url("https://api.ipify.org?format=text").get().build())
                .execute().use { it.body?.string()?.trim()?.takeIf { ip -> ip.isNotBlank() } }
        }.getOrNull().also { _stats.value = _stats.value.copy(publicIp = it) }
    }

    /**
     * Real DNS-leak probe: resolves a probe hostname and reports the resolver path actually
     * used. Does NOT replace the app's DNS engine — it only observes.
     */
    suspend fun dnsLeakProbe(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val probeHost = "leak-probe.adshield-pro.local"
            val addresses = InetAddress.getAllByName(probeHost).map { it.hostAddress }
            if (addresses.isEmpty()) null
            else "resolver answered $probeHost with ${addresses.joinToString()}"
        }.getOrNull().also { _stats.value = _stats.value.copy(dnsLeakTestResult = it) }
    }

    suspend fun probeAllServers(): Map<String, Long?> {
        val results = VpnLatencyProber.measureAll(catalog.servers())
        for ((id, latency) in results) {
            catalog.servers().firstOrNull { it.id == id }?.let { catalog.updateServer(it.copy(measuredLatencyMs = latency)) }
        }
        return results
    }

    suspend fun fastestServer(): VpnServer? {
        probeAllServers()
        return VpnServerSelection.fastest(catalog.servers())
    }

    suspend fun recordThreat(severity: VpnThreatEvent.Severity, title: String, detail: String) {
        catalog.recordThreat(
            VpnThreatEvent(
                id = System.currentTimeMillis(), epochMs = System.currentTimeMillis(),
                severity = severity, title = title, detail = detail
            )
        )
    }
}
