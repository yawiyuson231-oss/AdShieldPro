package com.adshield.pro.engine.dns

import android.net.InetAddresses
import android.os.SystemClock
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.SocketFactory
import javax.net.ssl.SSLException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private data class TimedDnsReply(val result: UpstreamDnsResolver.UpstreamResult, val receivedAtMs: Long)
private data class ValidatedDnsReply(val wire: ByteArray, val inspection: DnsResponseInspection)

/** Fixed descriptions (no arbitrary HTTP, TLS or EDNS error text). */
data class DnsResolverIssue(val providerName: String, val reason: String, val extendedErrorCodes: List<Int> = emptyList())

internal fun dnsFailureReason(error: Throwable): String = when (error) {
    is DnsResponseValidationException, is DnsTransportException -> error.message ?: "Rejected DNS response"
    is ProviderCircuitOpenException -> "Resolver cooling down after failures"
    is SSLException -> "TLS connection or certificate check failed"
    is UnknownHostException -> "Could not resolve the upstream endpoint hostname"
    is InterruptedIOException -> "Timed out"
    else -> "Could not reach the resolver"
}

/** The coroutine is dispatched on IO. Closing the raw socket releases a blocked connect/read. */
internal suspend fun <S : Closeable, T> S.dnsExchange(block: (S) -> T): T = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { runCatching { close() } }
    if (continuation.isActive) continuation.resumeWith(runCatching { use(block) })
}

/**
 * Multi-protocol Upstream DNS Client supporting:
 * - DNS-over-HTTPS (RFC 8484 wireformat)
 * - DNS-over-TLS (RFC 7858 port 853 with TLS hostname verification)
 * - Protected UDP & TCP Port 53 with automatic TCP fallback on truncation (TC=1)
 * - Thread-safe TTL-aware LRU DNS cache
 */
@Singleton
class UpstreamDnsResolver @Inject constructor(
    private val healthMonitor: DnsProviderHealthMonitor
) {
    internal fun interface ProviderTransport {
        suspend fun query(
            query: DnsPacketCodec.ParsedDnsQuery,
            config: DnsResolverConfig,
            endpoint: DnsProviderEndpoint
        ): ByteArray
    }

    @Volatile
    internal var providerTransport: ProviderTransport? = null

    // TTLs must keep aging while the phone is asleep, without depending on wall-clock changes.
    internal var cacheClockMs: () -> Long = SystemClock::elapsedRealtime

    data class UpstreamResult(
        val responseBytes: ByteArray,
        val protocolUsed: String,
        val fromCache: Boolean,
        val latencyMs: Int,
        val providerId: String? = null,
        val dnssecStatus: DnssecStatus? = null,
        val inspection: DnsResponseInspection? = null,
        val issues: List<DnsResolverIssue> = emptyList()
    )

    private data class CachedDnsEntry(
        val response: DnsPacketCodec.CachedResponse,
        val receivedAtMs: Long,
        val protocolOrigin: String,
        val providerId: String?,
        val inspection: DnsResponseInspection?
    )

    private class ReplyCacheKey(private val resolverScope: String, rawQuery: ByteArray) {
        // A whole wire reply only matches this query's flags, question and EDNS options.
        // Exclude the transaction ID, the one request field we rewrite on a cache hit.
        private val wire = rawQuery.copyOfRange(2, rawQuery.size)
        private val hash = 31 * resolverScope.hashCode() + wire.contentHashCode()

        override fun hashCode(): Int = hash
        override fun equals(other: Any?): Boolean = other is ReplyCacheKey &&
            resolverScope == other.resolverScope && wire.contentEquals(other.wire)
    }

    private val dnsCache = object : LinkedHashMap<ReplyCacheKey, CachedDnsEntry>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ReplyCacheKey, CachedDnsEntry>?): Boolean = size > 1024
    }

    @Volatile
    private var currentProtector: ((Socket) -> Boolean)? = null

    @Volatile
    private var currentDatagramProtector: ((DatagramSocket) -> Boolean)? = null

    fun bindVpnSocketProtectors(
        protectTcp: ((Socket) -> Boolean)?,
        protectUdp: ((DatagramSocket) -> Boolean)?
    ) {
        currentProtector = protectTcp
        currentDatagramProtector = protectUdp
    }

    fun clearCache() {
        synchronized(dnsCache) {
            dnsCache.clear()
        }
    }

    fun getCacheSize(): Int {
        synchronized(dnsCache) {
            return dnsCache.size
        }
    }

    fun trimExpiredAndExcessCache(targetSize: Int = 128): Int {
        synchronized(dnsCache) {
            val before = dnsCache.size
            val now = cacheClockMs()
            val entries = dnsCache.values.iterator()
            while (entries.hasNext()) {
                val entry = entries.next()
                if (entry.response.isExpired(now - entry.receivedAtMs)) entries.remove()
            }
            val target = targetSize.coerceAtLeast(0)
            while (dnsCache.size > target) {
                val eldest = dnsCache.entries.firstOrNull()?.key ?: break
                dnsCache.remove(eldest)
            }
            return (before - dnsCache.size).coerceAtLeast(0)
        }
    }

    private fun protectTcp(socket: Socket): Socket {
        if (currentProtector?.invoke(socket) == false) {
            socket.close()
            throw DnsTransportException("Could not protect the VPN DNS socket")
        }
        return socket
    }

    private val protectedSocketFactory = object : SocketFactory() {
        override fun createSocket(): Socket = protectTcp(Socket())
        // The direct OkHttp client requests an unconnected socket; don't connect before protection.
        override fun createSocket(host: String?, port: Int) = unsupported()
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int) = unsupported()
        override fun createSocket(host: InetAddress?, port: Int) = unsupported()
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int) = unsupported()
        private fun unsupported(): Socket = throw DnsTransportException("DNS socket must be protected before connecting")
    }

    // Only custom DoH hostnames outside the preset table need a system lookup. Bound both the wait
    // and the number of blocking system lookups even when many Android apps are doing DNS at once.
    private val bootstrapExecutor by lazy {
        ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(8)) { work ->
            Thread(work, "adshield-doh-bootstrap").apply { isDaemon = true }
        }
    }

    private fun bootstrapDns(enableIpv6: Boolean) = Dns { hostname ->
        val literals = PRESET_BOOTSTRAP_IPS[hostname.lowercase().trimEnd('.')]
        val addresses = if (literals != null) {
            literals.map { InetAddresses.parseNumericAddress(it) }
        } else {
            val task = try {
                bootstrapExecutor.submit<List<InetAddress>> { Dns.SYSTEM.lookup(hostname) }
            } catch (_: RejectedExecutionException) {
                throw UnknownHostException("Endpoint DNS bootstrap is busy")
            }
            try {
                task.get(BOOTSTRAP_DNS_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } catch (error: Exception) {
                task.cancel(true)
                bootstrapExecutor.remove(task as Runnable)
                if (error is InterruptedException) Thread.currentThread().interrupt()
                throw UnknownHostException("Endpoint DNS bootstrap failed")
            }
        }
        addresses.filter { enableIpv6 || it is Inet4Address }
            .ifEmpty { throw UnknownHostException("No usable address for the upstream endpoint") }
    }

    private fun httpsTransport(enableIpv6: Boolean): DnsHttpsTransport = DnsHttpsTransport(
        OkHttpClient.Builder()
            .socketFactory(protectedSocketFactory)
            .proxy(Proxy.NO_PROXY)
            .dns(bootstrapDns(enableIpv6))
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .writeTimeout(4, TimeUnit.SECONDS)
            .build()
    )

    private val dohDualStack by lazy { httpsTransport(true) }
    private val dohV4Only by lazy { httpsTransport(false) }

    /**
     * Sends a single uncached live wire query directly to [endpoint] for multi-resolver
     * benchmarking. Does not read or populate [dnsCache] and does not trip circuit breakers on
     * providers the user has not selected as active.
     */
    suspend fun probeEndpoint(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig,
        endpoint: DnsProviderEndpoint
    ): UpstreamResult = withContext(Dispatchers.IO) {
        val startNanos = System.nanoTime()
        val reply = providerQuery(query, config, endpoint)
        upstreamResult(reply, endpoint, config.protocol, elapsedMs(startNanos))
    }

    /**
     * Resolves a parsed DNS query against the configured upstream resolver (or serves from TTL cache).
     */
    suspend fun resolve(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig,
        useCache: Boolean = true
    ): UpstreamResult = withContext(Dispatchers.IO) {
        val cacheKey = if (useCache && query.rawPayload.size in 12..MAX_CACHE_QUERY_BYTES) {
            ReplyCacheKey(buildCacheKey(query, config), query.rawPayload)
        } else null
        val hit = cacheKey?.let { key ->
            synchronized(dnsCache) {
                val entry = dnsCache[key] ?: return@synchronized null
                val ageMs = cacheClockMs() - entry.receivedAtMs
                if (entry.response.isExpired(ageMs)) {
                    dnsCache.remove(key)
                    null
                } else entry to ageMs
            }
        }
        if (hit != null) {
            val (cached, ageMs) = hit
            return@withContext UpstreamResult(
                responseBytes = cached.response.forQuery(query.transactionId, ageMs),
                protocolUsed = "${cached.protocolOrigin} (Cached)",
                fromCache = true,
                latencyMs = 0,
                providerId = cached.providerId,
                dnssecStatus = cached.inspection?.dnssecStatus,
                inspection = cached.inspection
            )
        }

        val configuredPlan = DnsProviderRegistry.queryPlan(config)
        val healthOrdered = DnsProviderRegistry.orderedByHealth(
            configuredPlan, healthMonitor, config.protocol, config.fastestHealthyProvider
        )
        val plan = mediaAwareOrder(healthOrdered, config, query.questionDomain)
        val issues = Collections.synchronizedList(mutableListOf<DnsResolverIssue>())
        val started = System.nanoTime()

        suspend fun attempt(endpoint: DnsProviderEndpoint): Result<TimedDnsReply> {
            val providerStart = System.nanoTime()
            return try {
                healthMonitor.checkAvailable(endpoint.providerId, config.protocol, System.currentTimeMillis())
                val reply = providerQuery(query, config, endpoint)
                currentCoroutineContext().ensureActive()
                val receivedAt = cacheClockMs()
                val latency = elapsedMs(providerStart)
                healthMonitor.recordSuccess(endpoint.providerId, config.protocol, latency.toLong(), System.currentTimeMillis())
                Result.success(TimedDnsReply(upstreamResult(reply, endpoint, config.protocol, latency), receivedAt))
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (error: Exception) {
                currentCoroutineContext().ensureActive()
                val reason = dnsFailureReason(error)
                if (error !is ProviderCircuitOpenException && (error !is DnsResponseValidationException || error.healthFailure)) {
                    healthMonitor.recordFailure(endpoint.providerId, config.protocol, IOException(reason), System.currentTimeMillis())
                }
                val extended = (error as? DnsResponseValidationException)?.inspection?.extendedErrorCodes.orEmpty()
                issues += DnsResolverIssue(endpoint.displayName, reason, extended)
                Result.failure(error)
            }
        }

        suspend fun race(primary: DnsProviderEndpoint, backup: DnsProviderEndpoint): TimedDnsReply? = coroutineScope {
            val first = async { attempt(primary) }
            // A definite failure skips the head start. A merely slow provider still has a chance.
            val early = withTimeoutOrNull(HEDGE_DELAY_MS) { first.await() }
            if (early != null) return@coroutineScope early.getOrNull() ?: attempt(backup).getOrNull()
            val second = async { attempt(backup) }
            try {
                val (outcome, other) = select {
                    first.onAwait { it to second }
                    second.onAwait { it to first }
                }
                outcome.getOrNull() ?: other.await().getOrNull()
            } finally {
                first.cancel()
                second.cancel()
            }
        }

        val nowMs = System.currentTimeMillis()
        val usable = plan.filter { endpoint ->
            val open = healthMonitor.snapshot(endpoint.providerId, config.protocol).isCircuitOpen(nowMs)
            if (open) issues += DnsResolverIssue(endpoint.displayName, "Resolver cooling down after failures")
            !open
        }
        var finishedPlan = false
        val resolved = withTimeoutOrNull(RESOLUTION_TIMEOUT_MS) {
            var answer: TimedDnsReply? = null
            var i = 0
            while (answer == null && i < usable.size) {
                val primary = usable[i++]
                val backup = usable.getOrNull(i)
                answer = if (backup == null) attempt(primary).getOrNull() else race(primary, backup).also { i++ }
            }
            finishedPlan = true
            answer
        }
        if (!finishedPlan) issues += DnsResolverIssue(config.protocol.label, "DNS lookup deadline reached")

        if (resolved != null) {
            val result = resolved.result.copy(issues = issues.toList(), latencyMs = elapsedMs(started))
            // A losing hedged request must not overwrite the reply that won.
            if (cacheKey != null) {
                val payload = DnsPacketCodec.prepareCachedResponse(result.responseBytes)
                if (payload != null && !payload.isExpired(cacheClockMs() - resolved.receivedAtMs)) {
                    synchronized(dnsCache) {
                        dnsCache[cacheKey] = CachedDnsEntry(payload, resolved.receivedAtMs, result.protocolUsed,
                            result.providerId, result.inspection)
                    }
                }
            }
            return@withContext result
        }

        // Fail closed at the DNS protocol layer: return SERVFAIL, never an unvalidated response
        // and never an implicit plaintext downgrade.
        UpstreamResult(
            responseBytes = DnsPacketCodec.buildServFailResponse(query),
            protocolUsed = "SERVFAIL (${config.protocol.label})",
            fromCache = false,
            latencyMs = elapsedMs(started),
            issues = issues.toList()
        )
    }

    private fun upstreamResult(reply: ValidatedDnsReply, endpoint: DnsProviderEndpoint, protocol: DnsProtocol, latencyMs: Int) =
        UpstreamResult(
            responseBytes = reply.wire,
            protocolUsed = "${protocol.name} (${endpoint.displayName}) · ${reply.inspection.dnssecStatus.name}",
            fromCache = false,
            latencyMs = latencyMs,
            providerId = endpoint.providerId,
            dnssecStatus = reply.inspection.dnssecStatus,
            inspection = reply.inspection
        )

    private suspend fun providerQuery(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig,
        endpoint: DnsProviderEndpoint
    ): ValidatedDnsReply = withTimeoutOrNull(PROVIDER_TIMEOUT_MS) {
        fun validate(wire: ByteArray, inspection: DnsResponseInspection = DnsResponseValidator.inspect(query, wire)) =
            ValidatedDnsReply(wire, DnsResponseValidator.accept(inspection, config.dnssecMode))
        val borrowed = providerTransport
        if (borrowed != null) return@withTimeoutOrNull validate(borrowed.query(query, config, endpoint))
        when (config.protocol) {
            DnsProtocol.DOH -> validate((if (config.enableIpv6) dohDualStack else dohV4Only).query(query.rawPayload, endpoint.dohUrl))
            DnsProtocol.DOT -> queryAddresses(endpoint, config.enableIpv6) { ip ->
                withTimeoutOrNull(ADDRESS_TIMEOUT_MS) { validate(queryDot(query.rawPayload, endpoint, ip)) }
                    ?: throw SocketTimeoutException("Upstream TLS DNS timed out")
            }
            DnsProtocol.UDP_TCP -> queryAddresses(endpoint, config.enableIpv6) { ip ->
                dnsUdpWithTcpRetry(
                    tcpBudgetMs = ADDRESS_TIMEOUT_MS,
                    udp = { queryUdp(query, ip)?.let { validate(it.wire, it.inspection) } },
                    tcp = { validate(queryTcp(query.rawPayload, ip)) }
                )
            }
        }
    } ?: throw SocketTimeoutException("DNS provider timed out")

    fun providerHealthSnapshots(): List<DnsProviderHealth> = healthMonitor.snapshots()

    private suspend fun queryAddresses(
        endpoint: DnsProviderEndpoint,
        enableIpv6: Boolean,
        exchange: suspend (InetAddress) -> ValidatedDnsReply
    ): ValidatedDnsReply {
        val addresses = buildList {
            // Try the other family after the first address rather than waiting for two dead routes.
            repeat(maxOf(endpoint.ipv4Addresses.size, if (enableIpv6) endpoint.ipv6Addresses.size else 0)) { i ->
                endpoint.ipv4Addresses.getOrNull(i)?.let(::add)
                if (enableIpv6) endpoint.ipv6Addresses.getOrNull(i)?.let(::add)
            }
        }.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        return firstUsableDnsAddress(addresses, ADDRESS_HEAD_START_MS) { ip ->
            val literal = try {
                InetAddresses.parseNumericAddress(ip)
            } catch (_: IllegalArgumentException) {
                throw DnsTransportException("Use a numeric IPv4 or IPv6 resolver address")
            }
            exchange(literal)
        }
    }

    private suspend fun queryDot(wire: ByteArray, endpoint: DnsProviderEndpoint, ip: InetAddress): ByteArray =
        Socket().dnsExchange { raw ->
            protectTcp(raw)
            raw.connect(InetSocketAddress(ip, endpoint.dotPort), ADDRESS_SOCKET_TIMEOUT_MS)
            raw.soTimeout = ADDRESS_SOCKET_TIMEOUT_MS
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val host = endpoint.dotHostname.trim().trimEnd('.')
            (factory.createSocket(raw, host, endpoint.dotPort, true) as SSLSocket).use { tls ->
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS" // JSSE checks the hostname during the handshake.
                    // SNI only permits hostnames; IP-based endpoints still require a matching IP SAN.
                    if (!runCatching { InetAddresses.parseNumericAddress(host) }.isSuccess) serverNames = listOf(SNIHostName(host))
                }
                tls.startHandshake()
                exchangeDnsFrame(tls, wire)
            }
        }

    /** Null means a matching TC reply and specifically requests TCP to the *same* address. */
    private suspend fun queryUdp(query: DnsPacketCodec.ParsedDnsQuery, ip: InetAddress): ValidatedDnsReply? =
        DatagramSocket().dnsExchange { socket ->
            if (currentDatagramProtector?.invoke(socket) == false) throw DnsTransportException("Could not protect the VPN DNS socket")
            socket.connect(ip, 53) // Kernel discards other sources before parsing.
            val wire = query.rawPayload
            socket.send(DatagramPacket(wire, wire.size, ip, 53))
            val buf = ByteArray(DnsPacketCodec.MAX_DNS_WIRE_BYTES) // Never parse just a truncated datagram prefix.
            val packet = DatagramPacket(buf, buf.size)
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(UDP_TIMEOUT_MS.toLong())
            while (true) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) throw SocketTimeoutException("Upstream UDP DNS timed out")
                socket.soTimeout = TimeUnit.NANOSECONDS.toMillis(remaining).toInt().coerceAtLeast(1)
                packet.length = buf.size
                socket.receive(packet)
                val response = buf.copyOf(packet.length)
                try {
                    if (DnsResponseValidator.matchingReplyFlags(query, response) and 0x0200 != 0) return@dnsExchange null
                    return@dnsExchange ValidatedDnsReply(response, DnsResponseValidator.inspect(query, response))
                } catch (_: DnsResponseValidationException) {
                    // Ignore unrelated/malformed datagrams without extending the receive deadline.
                }
            }
            @Suppress("UNREACHABLE_CODE")
            null
        }

    private suspend fun queryTcp(wire: ByteArray, ip: InetAddress): ByteArray = Socket().dnsExchange { socket ->
        protectTcp(socket)
        socket.connect(InetSocketAddress(ip, 53), ADDRESS_SOCKET_TIMEOUT_MS)
        socket.soTimeout = ADDRESS_SOCKET_TIMEOUT_MS
        exchangeDnsFrame(socket, wire)
    }

    private fun exchangeDnsFrame(socket: Socket, wire: ByteArray): ByteArray {
        val out = DataOutputStream(socket.getOutputStream())
        val input = DataInputStream(socket.getInputStream())
        out.writeShort(wire.size)
        out.write(wire)
        out.flush()
        val size = input.readUnsignedShort()
        if (size < 12) throw DnsTransportException("Short DNS stream frame")
        return ByteArray(size).also(input::readFully)
    }

    companion object {
        private fun elapsedMs(startNanos: Long): Int = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos)
            .coerceIn(1, Int.MAX_VALUE.toLong()).toInt()

        /**
         * Media-aware provider order.
         *
         * The authoritative server picks the video CDN edge from the resolver's
         * address, so a resolver that forwards EDNS Client Subnet returns an edge near
         * the user while a resolver that does not may return one in another region.
         * For media hostnames only, providers that forward a client subnet are moved
         * to the front of the plan. Everything else keeps the configured/health order,
         * so ordinary browsing is unaffected and no provider outside the user's plan
         * is ever contacted.
         */
        internal fun mediaAwareOrder(
            plan: List<DnsProviderEndpoint>,
            config: DnsResolverConfig,
            domain: String
        ): List<DnsProviderEndpoint> {
            if (!config.preferGeoAccurateMediaDns || plan.size < 2) return plan
            if (!DnsMediaPlaybackGuard.isProtectedPlaybackHost(domain)) return plan
            val (geoAccurate, rest) = plan.partition { endpoint ->
                DnsProviderPreset.entries.any {
                    it.id == endpoint.providerId && it.forwardsClientSubnet
                }
            }
            return if (geoAccurate.isEmpty()) plan else geoAccurate + rest
        }

        /**
         * How long the primary provider gets before the runner-up is started in
         * parallel. 250 ms covers a healthy resolver on a mobile network; past that
         * the user is waiting on a straggler that will probably never answer.
         */
        private const val HEDGE_DELAY_MS = 250L

        /** Hard bound on resolving a DoH endpoint's own hostname. */
        private const val BOOTSTRAP_DNS_TIMEOUT_MS = 1_500L

        /**
         * DoH/DoT endpoints are known ahead of time, so they are never resolved
         * through the tunnel. Literal addresses only: a hostname here would trigger
         * exactly the recursive lookup this map exists to avoid.
         */
        private val PRESET_BOOTSTRAP_IPS: Map<String, List<String>> = mapOf(
            "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
            "one.one.one.one" to listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
            "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
            // Quad9 Secure + ECS endpoints.
            "dns11.quad9.net" to listOf("9.9.9.11", "149.112.112.11", "2620:fe::11", "2620:fe::fe:11"),
            "unfiltered.adguard-dns.com" to listOf("94.140.14.140", "94.140.14.141", "2a10:50c0::1:ff", "2a10:50c0::2:ff"),
            "dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.14.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
            "dns.google" to listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
            "dns.nextdns.io" to listOf("45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::"),
            "dns.mullvad.net" to listOf("194.242.2.2", "2a07:e340::2"),
            "freedns.controld.com" to listOf("76.76.2.0", "76.76.10.0", "2606:1a40::", "2606:1a40:1::"),
            "p0.freedns.controld.com" to listOf("76.76.2.0", "76.76.10.0", "2606:1a40::", "2606:1a40:1::")
        )

        // Bound a complete provider exchange (including bootstrapping, TLS and the body) and
        // the whole configured plan, even if several providers are unreachable.
        private const val UDP_TIMEOUT_MS = 1800
        private const val ADDRESS_SOCKET_TIMEOUT_MS = 2000
        private const val ADDRESS_TIMEOUT_MS = 2700L
        private const val ADDRESS_HEAD_START_MS = 650L
        private const val PROVIDER_TIMEOUT_MS = 6500L
        private const val RESOLUTION_TIMEOUT_MS = 12_000L
        private const val MAX_CACHE_QUERY_BYTES = 4_096 // Bound memory for wire-exact cache keys.

        fun transactionIdOf(rawDnsMessage: ByteArray): Int {
            if (rawDnsMessage.size < 2) return -1
            return ((rawDnsMessage[0].toInt() and 0xFF) shl 8) or (rawDnsMessage[1].toInt() and 0xFF)
        }

        /**
         * True when [response] is a well-formed DNS *response* that echoes [transactionId].
         * Guards against cross-talk, truncated garbage and forged datagrams.
         */
        fun isValidDnsResponseForQuery(transactionId: Int, response: ByteArray): Boolean {
            if (response.size < 12 || transactionId < 0) return false
            if (transactionIdOf(response) != transactionId) return false
            val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
            return (flags and 0x8000) != 0 // QR = 1
        }

        /** Whether a complete response has a nonzero usable cache lifetime. */
        fun shouldCacheDnsResponse(response: ByteArray): Boolean = DnsPacketCodec.extractResponseTtlSeconds(response) > 0

        /**
         * Ordered plaintext DNS server list: IPv4 primary/secondary first (fastest, most
         * common), then IPv6 primary/secondary so IPv6-only networks still resolve.
         */
        fun upstreamUdpTcpServers(config: DnsResolverConfig): List<String> = buildList {
            add(config.activePrimaryIpv4)
            add(config.activeSecondaryIpv4)
            if (config.enableIpv6) {
                add(config.activePrimaryIpv6)
                add(config.activeSecondaryIpv6)
            }
        }.map { it.trim() }.filter { it.isNotEmpty() }.distinct()

        /**
         * Cache keys are scoped to the active resolver endpoint so that changing the upstream
         * provider can never replay answers obtained from the previous provider.
         */
        fun buildCacheKey(query: DnsPacketCodec.ParsedDnsQuery, config: DnsResolverConfig): String {
            val endpoint = when (config.protocol) {
                // The scheme/host may be case-insensitive, but the endpoint path and query aren't.
                DnsProtocol.DOH -> config.activeDohUrl
                DnsProtocol.DOT -> "${config.activeDotHost.lowercase()}:${config.preset.dotPort}@${upstreamUdpTcpServers(config).joinToString(",")}"
                DnsProtocol.UDP_TCP -> upstreamUdpTcpServers(config).joinToString(",")
            }
            val failoverScope = if (config.failoverEnabled && config.protocol != DnsProtocol.UDP_TCP) {
                "|plan=" + DnsProviderRegistry.queryPlan(config).joinToString(",") { it.providerId }
            } else ""
            return "${config.protocol.name}:${config.preset.id}@$endpoint$failoverScope|ipv6=${config.enableIpv6}|media=${config.preferGeoAccurateMediaDns}|dnssec=${config.dnssecMode.name}|${query.cacheKey}"
        }
    }
}
