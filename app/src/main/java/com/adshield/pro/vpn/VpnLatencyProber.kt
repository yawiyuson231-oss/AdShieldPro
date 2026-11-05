package com.adshield.pro.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Real latency measurement: opens an actual TCP connection to each server's endpoint and
 * times it. Servers that do not answer within [TIMEOUT_MS] get `null` (unknown), never a
 * fabricated number.
 */
object VpnLatencyProber {

    const val TIMEOUT_MS = 4000L

    suspend fun measure(server: VpnServer): Long? = withContext(Dispatchers.IO) {
        withTimeoutOrNull(TIMEOUT_MS) {
            val start = System.nanoTime()
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(server.host, server.port), TIMEOUT_MS.toInt())
                (System.nanoTime() - start) / 1_000_000L
            } catch (e: Exception) {
                null
            } finally {
                runCatching { socket.close() }
            }
        }
    }

    /** Probes all servers concurrently; results keep the server association. */
    suspend fun measureAll(servers: List<VpnServer>): Map<String, Long?> = coroutineScope {
        servers.map { server ->
            async { server.id to measure(server) }
        }.awaitAll().toMap()
    }
}
