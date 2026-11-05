package com.adshield.pro.globalvpn.engine

import com.adshield.pro.globalvpn.model.ServerProbe
import com.adshield.pro.globalvpn.model.VpnProtocol
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Real reachability / latency probes. No values are fabricated: a TCP connect handshake is timed
 * for OpenVPN TCP endpoints, and an ICMP/reachability round trip is timed for WireGuard UDP
 * endpoints. If a probe cannot be performed the result is reported as unreachable with a null
 * latency rather than a guessed number.
 */
@Singleton
class LatencyProber @Inject constructor() {

    suspend fun probe(
        serverId: String,
        host: String,
        port: Int,
        protocol: VpnProtocol,
        timeoutMs: Int = 2500
    ): ServerProbe = withContext(Dispatchers.IO) {
        val start = System.nanoTime()
        when (protocol) {
            VpnProtocol.OPENVPN -> tcpProbe(serverId, host, port, timeoutMs, start)
            VpnProtocol.WIREGUARD -> reachabilityProbe(serverId, host, timeoutMs, start)
        }
    }

    private fun tcpProbe(serverId: String, host: String, port: Int, timeoutMs: Int, start: Long): ServerProbe {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            val elapsed = (System.nanoTime() - start) / 1_000_000
            ServerProbe(serverId, true, elapsed, "tcp-connect", System.currentTimeMillis())
        } catch (e: Exception) {
            ServerProbe(serverId, false, null, "tcp-connect", System.currentTimeMillis())
        }
    }

    private fun reachabilityProbe(serverId: String, host: String, timeoutMs: Int, start: Long): ServerProbe {
        return try {
            val address = InetAddress.getByName(host)
            val reachable = address.isReachable(timeoutMs)
            val elapsed = (System.nanoTime() - start) / 1_000_000
            ServerProbe(
                serverId,
                reachable,
                if (reachable) elapsed else null,
                "icmp-reachability",
                System.currentTimeMillis()
            )
        } catch (e: Exception) {
            ServerProbe(serverId, false, null, "icmp-reachability", System.currentTimeMillis())
        }
    }
}
