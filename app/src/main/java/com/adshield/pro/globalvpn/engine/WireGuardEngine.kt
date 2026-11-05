package com.adshield.pro.globalvpn.engine

import android.content.Context
import com.adshield.pro.globalvpn.model.TunnelStats
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.StringReader
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Thin Kotlin wrapper over the official open-source WireGuard userspace backend. This is a real
 * tunnel (wireguard-go), not a simulation. The backend owns its own VpnService and already sets
 * blocking mode, protects its own sockets against routing loops, and applies per-app lists and DNS
 * from the parsed configuration.
 */
@Singleton
class WireGuardEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val backend: GoBackend by lazy { GoBackend(context) }

    @Volatile
    private var activeTunnel: NamedTunnel? = null

    var onStateChange: ((Tunnel.State) -> Unit)? = null

    private inner class NamedTunnel(private val name: String) : Tunnel {
        override fun getName(): String = name
        override fun onStateChange(newState: Tunnel.State) {
            this@WireGuardEngine.onStateChange?.invoke(newState)
        }
    }

    fun parse(configText: String): Config =
        Config.parse(BufferedReader(StringReader(configText)))

    suspend fun connect(configText: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val config = parse(configText)
            val tunnel = NamedTunnel(TUNNEL_NAME)
            activeTunnel = tunnel
            backend.setState(tunnel, Tunnel.State.UP, config)
            Unit
        }.onFailure { activeTunnel = null }
    }

    suspend fun disconnect(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val tunnel = activeTunnel ?: return@runCatching Unit
            backend.setState(tunnel, Tunnel.State.DOWN, null)
            activeTunnel = null
            Unit
        }
    }

    fun stats(): TunnelStats? {
        val tunnel = activeTunnel ?: return null
        return runCatching {
            val statistics = backend.getStatistics(tunnel)
            var latestHandshake = 0L
            for (key in statistics.peers()) {
                val peer = statistics.peer(key) ?: continue
                if (peer.latestHandshakeEpochMillis() > latestHandshake) {
                    latestHandshake = peer.latestHandshakeEpochMillis()
                }
            }
            TunnelStats(
                rxBytes = statistics.totalRx(),
                txBytes = statistics.totalTx(),
                latestHandshakeEpochMs = latestHandshake
            )
        }.getOrNull()
    }

    fun isAlwaysOn(): Boolean = runCatching { backend.isAlwaysOn }.getOrDefault(false)

    fun isLockdownEnabled(): Boolean = runCatching { backend.isLockdownEnabled }.getOrDefault(false)

    fun backendVersion(): String = runCatching { backend.version }.getOrDefault("unknown")

    companion object {
        // Must satisfy Tunnel.NAME_PATTERN ([a-zA-Z0-9_=+.-]{1,15}).
        const val TUNNEL_NAME = "adshield-gvpn"
    }
}
