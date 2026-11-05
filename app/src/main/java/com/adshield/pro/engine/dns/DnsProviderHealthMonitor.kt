package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/** Real query outcomes only; no synthetic latency or reachability values. */
data class DnsProviderHealth(
    val providerId: String,
    val protocol: DnsProtocol,
    val consecutiveFailures: Int = 0,
    val successfulQueries: Long = 0,
    val failedQueries: Long = 0,
    val ewmaLatencyMs: Long? = null,
    val lastLatencyMs: Long? = null,
    val circuitOpenUntilMs: Long = 0,
    val lastError: String? = null
) {
    fun isCircuitOpen(nowMs: Long): Boolean = circuitOpenUntilMs > nowMs
}

class ProviderCircuitOpenException(message: String) : java.io.IOException(message)

/** Thread-safe circuit breaker with bounded provider state and latency EWMA. */
@Singleton
class DnsProviderHealthMonitor @Inject constructor() {
    private val states = ConcurrentHashMap<String, DnsProviderHealth>()

    private fun key(providerId: String, protocol: DnsProtocol) = "${providerId}:${protocol.name}"

    fun snapshot(providerId: String, protocol: DnsProtocol): DnsProviderHealth =
        states[key(providerId, protocol)] ?: DnsProviderHealth(providerId, protocol)

    fun snapshots(): List<DnsProviderHealth> = states.values.sortedBy { it.providerId }

    fun checkAvailable(providerId: String, protocol: DnsProtocol, nowMs: Long) {
        val state = snapshot(providerId, protocol)
        if (state.isCircuitOpen(nowMs)) {
            throw ProviderCircuitOpenException(
                "${state.providerId} circuit open for ${state.circuitOpenUntilMs - nowMs} ms"
            )
        }
    }

    fun recordSuccess(providerId: String, protocol: DnsProtocol, latencyMs: Long, nowMs: Long) {
        states.compute(key(providerId, protocol)) { _, old ->
            val current = old ?: DnsProviderHealth(providerId, protocol)
            val previous = current.ewmaLatencyMs
            val ewma = if (previous == null) latencyMs else ((previous * 3) + latencyMs) / 4
            current.copy(
                consecutiveFailures = 0,
                successfulQueries = current.successfulQueries + 1,
                ewmaLatencyMs = ewma.coerceAtLeast(0),
                lastLatencyMs = latencyMs.coerceAtLeast(0),
                circuitOpenUntilMs = 0,
                lastError = null
            )
        }
    }

    fun recordFailure(
        providerId: String,
        protocol: DnsProtocol,
        error: Throwable,
        nowMs: Long,
        failureThreshold: Int = DEFAULT_FAILURE_THRESHOLD,
        cooldownMs: Long = DEFAULT_COOLDOWN_MS
    ) {
        // Cancellation and caller interruption are not provider health failures.
        if (error is kotlinx.coroutines.CancellationException || error is InterruptedException) return
        states.compute(key(providerId, protocol)) { _, old ->
            val current = old ?: DnsProviderHealth(providerId, protocol)
            val failures = current.consecutiveFailures + 1
            current.copy(
                consecutiveFailures = failures,
                failedQueries = current.failedQueries + 1,
                circuitOpenUntilMs = if (failures >= failureThreshold) nowMs + cooldownMs else 0,
                lastError = (error.message ?: error.javaClass.simpleName).take(240)
            )
        }
    }

    fun reset() = states.clear()

    companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 3
        const val DEFAULT_COOLDOWN_MS = 30_000L
    }
}
