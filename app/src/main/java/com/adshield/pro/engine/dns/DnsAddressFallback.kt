package com.adshield.pro.engine.dns

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import java.net.SocketTimeoutException

/** Try each address of the same selected provider with a short head start for the earlier ones. */
@OptIn(ExperimentalCoroutinesApi::class)
internal suspend fun <A, T : Any> firstUsableDnsAddress(
    addresses: List<A>,
    headStartMs: Long,
    exchange: suspend (A) -> T
): T = coroutineScope {
    if (addresses.isEmpty()) throw DnsTransportException("No usable resolver address configured")
    // The provider caller supplies distinct configured addresses and the overall deadline.
    val completed = Channel<Result<T>>(addresses.size)
    val jobs = mutableListOf<Job>()
    var next = 0
    var pending = 0
    fun startNext() {
        if (next == addresses.size) return
        val address = addresses[next++]
        pending++
        jobs += launch {
            val result = try {
                Result.success(exchange(address))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Result.failure(error)
            }
            completed.send(result)
        }
    }

    try {
        startNext()
        var lastFailure: Throwable? = null
        while (pending > 0) {
            val attempt = if (next < addresses.size) select<Result<T>?> {
                completed.onReceive { it }
                onTimeout(headStartMs) { null }
            } else completed.receive()
            if (attempt != null) {
                pending--
                attempt.getOrNull()?.let { return@coroutineScope it }
                val error = attempt.exceptionOrNull()
                // Preserve a well-formed upstream DNS failure/EDE over a different address's timeout.
                if (lastFailure !is DnsResponseValidationException || error is DnsResponseValidationException) lastFailure = error
            }
            startNext() // A definite failure advances immediately; a stall skips ahead on the timer.
        }
        throw lastFailure ?: DnsTransportException("No usable reply from configured addresses")
    } finally {
        jobs.forEach { it.cancel() }
    }
}

/** Null from UDP is reserved for a matching TC reply; only that triggers same-address TCP. */
internal suspend fun <T : Any> dnsUdpWithTcpRetry(
    tcpBudgetMs: Long,
    udp: suspend () -> T?,
    tcp: suspend () -> T
): T = udp() ?: (withTimeoutOrNull(tcpBudgetMs) { tcp() }
    ?: throw SocketTimeoutException("Upstream TCP DNS timed out"))
