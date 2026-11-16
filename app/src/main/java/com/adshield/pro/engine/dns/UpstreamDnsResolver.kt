package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.SocketFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Endpoint plus its settled outcome, used while racing two providers.
 * Top-level because Kotlin does not allow nested type aliases.
 */
private typealias AttemptOutcome = Pair<DnsProviderEndpoint, Result<UpstreamDnsResolver.UpstreamResult>>

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
        fun query(
            query: DnsPacketCodec.ParsedDnsQuery,
            config: DnsResolverConfig,
            endpoint: DnsProviderEndpoint
        ): ByteArray
    }

    @Volatile
    internal var providerTransport: ProviderTransport? = null


    data class UpstreamResult(
        val responseBytes: ByteArray,
        val protocolUsed: String,
        val fromCache: Boolean,
        val latencyMs: Int,
        val providerId: String? = null,
        val dnssecStatus: DnssecStatus? = null,
        /** True when this answer was produced by another coroutine's query for the same name. */
        val coalesced: Boolean = false
    )

    private data class CachedDnsEntry(
        val wireResponse: ByteArray,
        val expiresAtEpochMs: Long,
        val protocolOrigin: String
    )

    /**
     * Queries currently waiting on an upstream answer, keyed by cache key.
     *
     * A single page load fires many lookups for the same name; without this, each one becomes its
     * own upstream round trip. Followers wait for the leader with a bounded timeout and then fall
     * back to their own query, so a cancelled or stalled leader can never strand a client.
     */
    private val inFlight = HashMap<String, CompletableDeferred<UpstreamResult>>()

    /**
     * Wire bytes the cache may hold. 1024 maximally sized answers would be a few megabytes on a
     * device that can ill afford it, so the entry count is not the only bound: the least recently
     * used entries are dropped until the payload fits too.
     */
    @Volatile
    internal var cacheByteBudget: Int = DEFAULT_CACHE_BYTE_BUDGET

    private val dnsCache = object : LinkedHashMap<String, CachedDnsEntry>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedDnsEntry>?): Boolean = size > MAX_CACHE_ENTRIES
    }

    @Volatile
    private var currentProtector: ((Socket) -> Boolean)? = null

    @Volatile
    private var currentDatagramProtector: ((DatagramSocket) -> Boolean)? = null

    /** RFC 2308 §7.1 failure cache: a dead upstream must not be re-walked for every lookup. */
    internal val failureCache = DnsFailureCache()

    fun bindSocketProtectors(
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
        // A user who clears the cache is asking for a fresh start, including remembered failures.
        failureCache.clearAll()
    }

    /**
     * The stale answer for [cacheKey], or null when there is none inside the grace window.
     *
     * RFC 8767: when the upstream is unreachable, an answer that expired a moment ago is far more
     * useful than SERVFAIL, and its lifetime is reported as [STALE_TTL_SECONDS] so it is retried
     * promptly once the resolver comes back.
     */
    internal fun resolveStale(
        cacheKey: String,
        query: DnsPacketCodec.ParsedDnsQuery,
        nowMs: Long = System.currentTimeMillis()
    ): UpstreamResult? {
        val entry = synchronized(dnsCache) { dnsCache[cacheKey] } ?: return null
        val overdueBy = nowMs - entry.expiresAtEpochMs
        if (overdueBy < 0L || overdueBy > STALE_GRACE_MS) return null
        val aged = DnsPacketCodec.rewriteResponseTtls(entry.wireResponse, STALE_TTL_SECONDS)
            ?: entry.wireResponse
        return UpstreamResult(
            responseBytes = DnsPacketCodec.rewriteTransactionId(aged, query.transactionId),
            protocolUsed = "${entry.protocolOrigin} (Stale after upstream failure)",
            fromCache = true,
            latencyMs = 0
        )
    }

    /** Wire bytes currently held by the cache. */
    fun getCacheBytes(): Int = synchronized(dnsCache) { dnsCache.values.sumOf { it.wireResponse.size } }

    fun getCacheSize(): Int {
        synchronized(dnsCache) {
            return dnsCache.size
        }
    }

    fun trimExpiredAndExcessCache(targetSize: Int = 128, nowMs: Long = System.currentTimeMillis()): Int {
        synchronized(dnsCache) {
            val before = dnsCache.size
            val now = nowMs
            val snapshot = dnsCache.entries.toList()
            for (mapEntry in snapshot) {
                val key = mapEntry.key
                val entry = mapEntry.value
                // Recently expired entries are kept for [STALE_GRACE_MS]: they can still rescue a
                // lookup while the upstream is unreachable (RFC 8767), and they no longer count as
                // fresh answers.
                if (now >= entry.expiresAtEpochMs + STALE_GRACE_MS) {
                    dnsCache.remove(key)
                }
            }
            val target = targetSize.coerceAtLeast(0)
            while (dnsCache.size > target) {
                val eldest = dnsCache.entries.firstOrNull()?.key ?: break
                dnsCache.remove(eldest)
            }
            return (before - dnsCache.size).coerceAtLeast(0)
        }
    }

    private val protectedSocketFactory = object : SocketFactory() {
        private val delegate = getDefault()

        private fun protect(socket: Socket): Socket {
            currentProtector?.invoke(socket)
            return socket
        }

        override fun createSocket(): Socket = protect(delegate.createSocket())
        override fun createSocket(host: String?, port: Int): Socket = protect(delegate.createSocket(host, port))
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            protect(delegate.createSocket(host, port, localHost, localPort))
        override fun createSocket(host: InetAddress?, port: Int): Socket = protect(delegate.createSocket(host, port))
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            protect(delegate.createSocket(address, port, localAddress, localPort))
    }

    /**
     * Bootstrap DNS resolver for DoH endpoints so OkHttp never triggers a recursive DNS lookup
     * through the local DNS tunnel when resolving well-known DoH hostnames.
     *
     * The lookup itself is wrapped in a hard bound. `InetAddress.getByName("1.1.1.1")`
     * performs a *reverse* lookup when the string is not a literal, and Dns.SYSTEM
     * can block for seconds on a broken network. Because this sits inside the DoH
     * code path, an unbounded stall here delays every single query — first paint
     * included. When the bootstrap host cannot be resolved in time the query fails
     * fast instead of hanging on a socket open.
     */
    private val bootstrapDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val lower = hostname.lowercase().trimEnd('.')
            val presetIps = PRESET_BOOTSTRAP_IPS[lower]
            if (presetIps != null && presetIps.isNotEmpty()) {
                return presetIps.mapNotNull { ip ->
                    runCatching { InetAddress.getByName(ip) }.getOrNull()
                }.ifEmpty {
                    // Every literal failed: fall through to the system resolver
                    // rather than declaring the provider unreachable.
                    boundedSystemLookup(hostname)
                }
            }
            return boundedSystemLookup(hostname)
        }

        private fun boundedSystemLookup(hostname: String): List<InetAddress> {
            val task = java.util.concurrent.FutureTask { Dns.SYSTEM.lookup(hostname) }
            Thread(task, "adshield-doh-bootstrap").apply { isDaemon = true }.start()
            return try {
                task.get(BOOTSTRAP_DNS_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            } catch (timeout: java.util.concurrent.TimeoutException) {
                task.cancel(true)
                throw java.net.UnknownHostException("Bootstrap DNS timed out for $hostname")
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw java.net.UnknownHostException("Bootstrap DNS interrupted for $hostname")
            }
        }
    }

    private val dohHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .socketFactory(protectedSocketFactory)
            .dns(bootstrapDns)
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .writeTimeout(4, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    /**
     * Resolves a parsed DNS query against the configured upstream resolver (or serves from TTL cache).
     */
    suspend fun resolve(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig
    ): UpstreamResult {
        val now = System.currentTimeMillis()
        val cacheKey = buildCacheKey(query, config)
        val cached = synchronized(dnsCache) { dnsCache.get(cacheKey) }
        if (cached != null) {
            if (cached.expiresAtEpochMs > now) {
                // A cache hit must report the lifetime it has left, not the lifetime it had when
                // it was stored: clients honour the TTL they are handed, so serving the original
                // value would let them keep a stale answer past its real expiry.
                val remainingSeconds = (((cached.expiresAtEpochMs - now) + 999L) / 1000L).toInt()
                val aged = DnsPacketCodec.rewriteResponseTtls(cached.wireResponse, remainingSeconds)
                    ?: cached.wireResponse
                return UpstreamResult(
                    responseBytes = DnsPacketCodec.rewriteTransactionId(aged, query.transactionId),
                    protocolUsed = "${cached.protocolOrigin} (Cached)",
                    fromCache = true,
                    latencyMs = 0
                )
            }
        }

        // Single-flight: the first caller resolves, everyone asking the same question while that
        // is in progress shares the answer instead of opening a second upstream connection.
        val mine = CompletableDeferred<UpstreamResult>()
        val leader = synchronized(inFlight) {
            val existing = inFlight[cacheKey]
            if (existing == null) {
                inFlight[cacheKey] = mine
                null
            } else {
                existing
            }
        }
        if (leader != null) {
            val shared = runCatching {
                withTimeoutOrNull(FOLLOWER_TIMEOUT_MS) { leader.await() }
            }.getOrNull()
            if (shared != null) {
                // The shared answer carries the leader's transaction ID, so it must be rewritten
                // for this client before it is handed back.
                return shared.copy(
                    responseBytes = DnsPacketCodec.rewriteTransactionId(
                        shared.responseBytes,
                        query.transactionId
                    ),
                    coalesced = true
                )
            }
        }

        return try {
            val result = resolveUncached(query, config, cacheKey)
            mine.complete(result)
            result
        } catch (t: Throwable) {
            mine.completeExceptionally(t)
            throw t
        } finally {
            synchronized(inFlight) {
                if (inFlight[cacheKey] === mine) inFlight.remove(cacheKey)
            }
        }
    }

    /**
     * The upstream half of [resolve]: provider plan, racing, validation, caching and the
     * fail-closed SERVFAIL. Only reached by the coroutine that owns the cache key.
     */
    private suspend fun resolveUncached(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig,
        cacheKey: String
    ): UpstreamResult = withContext(Dispatchers.IO) {

        // A failure remembered a moment ago saves walking the whole plan again for the same
        // question. A recently expired answer still wins, because it is a real answer.
        val failureRemainingMs = failureCache.remainingMs(cacheKey)
        if (failureRemainingMs > 0L) {
            resolveStale(cacheKey, query)?.let { return@withContext it }
            return@withContext UpstreamResult(
                responseBytes = DnsPacketCodec.buildServFailResponse(query),
                protocolUsed = "SERVFAIL (cached failure, ${((failureRemainingMs + 999L) / 1000L)}s left)",
                fromCache = true,
                latencyMs = 0
            )
        }

        val configuredPlan = DnsProviderRegistry.queryPlan(config)
        val healthOrdered = DnsProviderRegistry.orderedByHealth(
            configuredPlan, healthMonitor, config.protocol, config.fastestHealthyProvider
        )
        val plan = mediaAwareOrder(healthOrdered, config, query.questionDomain)
        val failures = mutableListOf<String>()
        // Client-subnet normalisation happens once per resolve so every provider attempt sends
        // exactly the same bytes.
        val upstreamQueryPayload = if (forwardsClientSubnet(query.questionDomain, config)) {
            query.rawPayload
        } else {
            DnsPacketCodec.stripEdnsClientSubnet(query.rawPayload) ?: query.rawPayload
        }

        /**
         * One provider attempt. Returns only a response that passed
         * [DnsResponseValidator]; anything else throws.
         */
        suspend fun attempt(endpoint: DnsProviderEndpoint): UpstreamResult {
            val providerStart = System.currentTimeMillis()
            healthMonitor.checkAvailable(endpoint.providerId, config.protocol, providerStart)
            val response = providerTransport?.query(query, config, endpoint)
                ?: executeProviderQuery(query, config, endpoint, upstreamQueryPayload)
            val inspection = DnsResponseValidator.validate(upstreamQueryPayload, response, config.dnssecMode)
            val latency = (System.currentTimeMillis() - providerStart).coerceAtLeast(1)
            healthMonitor.recordSuccess(endpoint.providerId, config.protocol, latency, System.currentTimeMillis())
            val protocol = "${config.protocol.name} (${endpoint.displayName}) · ${inspection.dnssecStatus.name}"
            if (shouldCacheDnsResponse(response)) {
                val ttlSeconds = DnsPacketCodec.extractResponseTtlSeconds(response)
                synchronized(dnsCache) {
                    dnsCache.put(
                        cacheKey,
                        CachedDnsEntry(
                            wireResponse = response.copyOf(),
                            expiresAtEpochMs = System.currentTimeMillis() + ttlSeconds * 1000L,
                            protocolOrigin = protocol
                        )
                    )
                    trimCacheToByteBudget()
                }
            }
            return UpstreamResult(
                responseBytes = response,
                protocolUsed = protocol,
                fromCache = false,
                latencyMs = latency.toInt().coerceAtMost(Int.MAX_VALUE),
                providerId = endpoint.providerId,
                dnssecStatus = inspection.dnssecStatus
            )
        }

        fun noteFailure(endpoint: DnsProviderEndpoint, error: Throwable) {
            if (error !is ProviderCircuitOpenException) {
                healthMonitor.recordFailure(
                    endpoint.providerId, config.protocol, error, System.currentTimeMillis()
                )
            }
            failures += "${endpoint.providerId}: ${error.message ?: error.javaClass.simpleName}"
        }

        /** An attempt whose failure has already been recorded, so it can be raced. */
        suspend fun trackedAttempt(endpoint: DnsProviderEndpoint): AttemptOutcome =
            endpoint to try {
                Result.success(attempt(endpoint))
            } catch (cancel: kotlinx.coroutines.CancellationException) {
                throw cancel
            } catch (error: Throwable) {
                noteFailure(endpoint, error)
                Result.failure(error)
            }

        // Providers whose circuit breaker is open are skipped up front: they are
        // known to be failing, so racing one only delays the answer. When every
        // circuit is open the full plan is used anyway — a real attempt still beats
        // a synthetic SERVFAIL, and the failures stay visible in diagnostics.
        val nowMs = System.currentTimeMillis()
        val usable = plan.filter { endpoint ->
            runCatching { healthMonitor.checkAvailable(endpoint.providerId, config.protocol, nowMs) }
                .onFailure { failures += "${endpoint.providerId}: ${it.message}" }
                .isSuccess
        }.ifEmpty { plan }

        var resolved: UpstreamResult? = null
        var index = 0
        while (resolved == null && index < usable.size) {
            val primary = usable[index]
            val runnerUp = usable.getOrNull(index + 1)

            if (runnerUp == null) {
                resolved = trackedAttempt(primary).second.getOrNull()
                index += 1
                continue
            }

            // Give the primary a head start, then race the runner-up. Worst case is
            // HEDGE_DELAY_MS + one provider timeout instead of the sum of every
            // provider timeout — the difference between a dead resolver costing
            // 2.5 s and costing 12 s on every single app launch.
            val raced = coroutineScope {
                val first = async { trackedAttempt(primary) }
                val second = async {
                    delay(HEDGE_DELAY_MS)
                    trackedAttempt(runnerUp)
                }
                val winner = select<AttemptOutcome> {
                    first.onAwait { it }
                    second.onAwait { it }
                }
                // A fast failure from the primary must not swallow the runner-up:
                // hedging is for latency, not for dropping failover. Wait for the
                // other attempt when the first one to finish did not succeed.
                val outcome = if (winner.second.isSuccess) {
                    winner
                } else {
                    val other = if (winner.first.providerId == primary.providerId) second else first
                    val fallback = other.await()
                    if (fallback.second.isSuccess) fallback else winner
                }
                // Abandon the straggler so a hanging provider cannot hold the scope.
                first.cancel()
                second.cancel()
                outcome
            }
            resolved = raced.second.getOrNull()
            index += 2

            if (resolved == null) {
                // Both of this pair failed. Nothing is retried blindly: the loop
                // moves on to the next providers in the same validated plan.
                continue
            }
        }

        if (resolved != null) {
            failureCache.clear(cacheKey)
            return@withContext resolved as UpstreamResult
        }

        // A recently expired answer beats SERVFAIL when the upstream is down.
        resolveStale(cacheKey, query)?.let { return@withContext it }

        // Fail closed at the DNS protocol layer: return SERVFAIL, never an unvalidated response
        // and never an implicit plaintext downgrade. The failure is remembered briefly so the next
        // burst of lookups for this name fails fast instead of re-walking a dead plan.
        failureCache.recordFailure(cacheKey)
        UpstreamResult(
            responseBytes = DnsPacketCodec.buildServFailResponse(query),
            protocolUsed = "SERVFAIL (${failures.joinToString("; ").take(180)})",
            fromCache = false,
            latencyMs = 0
        )
    }

    private fun executeProviderQuery(
        query: DnsPacketCodec.ParsedDnsQuery,
        config: DnsResolverConfig,
        endpoint: DnsProviderEndpoint,
        payload: ByteArray
    ): ByteArray = when (config.protocol) {
        DnsProtocol.DOH -> queryDoh(payload, endpoint.dohUrl)
        DnsProtocol.DOT -> queryDot(payload, endpoint, config.enableIpv6)
        DnsProtocol.UDP_TCP -> queryUdpOrTcp(query, endpoint, config.enableIpv6, payload)
    }

    fun providerHealthSnapshots(): List<DnsProviderHealth> = healthMonitor.snapshots()

    /**
     * Executes an RFC 8484 DNS-over-HTTPS wireformat POST query.
     */
    fun queryDoh(rawDnsQuery: ByteArray, dohUrl: String): ByteArray {
        val requestBody = rawDnsQuery.toRequestBody(DNS_MESSAGE_MEDIA_TYPE)
        val request = Request.Builder()
            .url(dohUrl)
            .header("Accept", "application/dns-message")
            .post(requestBody)
            .build()

        dohHttpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("DoH HTTP ${response.code}")
            }
            val bytes = response.body?.bytes()
                ?: throw IllegalStateException("Empty DoH response body")
            if (bytes.size < 12) {
                throw IllegalStateException("Truncated DoH DNS message (${bytes.size} bytes)")
            }
            return bytes
        }
    }

    /**
     * Executes an RFC 7858 DNS-over-TLS query over port 853 with SNI and certificate verification.
     */
    fun queryDot(rawDnsQuery: ByteArray, endpoint: DnsProviderEndpoint, enableIpv6: Boolean = true): ByteArray {
        val candidates = buildList {
            addAll(endpoint.ipv4Addresses)
            if (enableIpv6) addAll(endpoint.ipv6Addresses)
        }.filter { it.isNotBlank() }.distinct()
        var lastFailure: Throwable? = null
        for (candidate in candidates) {
            try {
                return queryDotOverAddress(rawDnsQuery, endpoint, candidate)
            } catch (t: Throwable) {
                lastFailure = t
            }
        }
        throw lastFailure ?: IllegalStateException("No usable DoT resolver address configured")
    }

    private fun queryDotOverAddress(
        rawDnsQuery: ByteArray,
        endpoint: DnsProviderEndpoint,
        serverIp: String
    ): ByteArray {
        val rawSocket = Socket()
        currentProtector?.invoke(rawSocket)
        val targetIp = InetAddress.getByName(serverIp)
        rawSocket.connect(InetSocketAddress(targetIp, endpoint.dotPort), 3500)
        rawSocket.soTimeout = 3500

        val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val dotHost = endpoint.dotHostname
        val sslSocket = sslFactory.createSocket(rawSocket, dotHost, endpoint.dotPort, true) as SSLSocket
        sslSocket.use { tls ->
            tls.startHandshake()
            val session = tls.session
            val verified = HttpsURLConnection.getDefaultHostnameVerifier().verify(dotHost, session)
            if (!verified) {
                throw SecurityException("DoT TLS certificate hostname verification failed for $dotHost")
            }

            val out = DataOutputStream(tls.outputStream)
            val input = DataInputStream(tls.inputStream)

            // RFC 7858 / RFC 1035 Section 4.2.2: 2-byte unsigned length prefix
            out.writeShort(rawDnsQuery.size)
            out.write(rawDnsQuery)
            out.flush()

            val responseLen = input.readUnsignedShort()
            if (responseLen < 12 || responseLen > 65535) {
                throw IllegalStateException("Invalid DoT response length: $responseLen")
            }
            val responseBuf = ByteArray(responseLen)
            input.readFully(responseBuf)
            return responseBuf
        }
    }

    /**
     * Executes a protected UDP port 53 DNS query, automatically upgrading to protected TCP port 53
     * if the response has the TC (Truncated) bit set.
     */
    fun queryUdpOrTcp(
        query: DnsPacketCodec.ParsedDnsQuery,
        endpoint: DnsProviderEndpoint,
        enableIpv6: Boolean = true,
        payload: ByteArray = query.rawPayload
    ): ByteArray {
        val servers = buildList {
            addAll(endpoint.ipv4Addresses)
            if (enableIpv6) addAll(endpoint.ipv6Addresses)
        }.filter { it.isNotBlank() }.distinct()
        var lastError: Throwable? = null

        for (serverIp in servers) {
            try {
                val udpResponse = querySingleUdpServer(payload, serverIp)
                // Check TC (Truncation) bit (0x0200 in flags)
                val flags = ((udpResponse[2].toInt() and 0xFF) shl 8) or (udpResponse[3].toInt() and 0xFF)
                if ((flags and 0x0200) != 0) {
                    return querySingleTcpServer(payload, serverIp)
                }
                return udpResponse
            } catch (t: Throwable) {
                lastError = t
            }
        }
        throw lastError ?: IllegalStateException("All upstream UDP/TCP DNS servers failed")
    }

    private fun querySingleUdpServer(rawDnsQuery: ByteArray, serverIp: String): ByteArray {
        DatagramSocket().use { socket ->
            currentDatagramProtector?.invoke(socket)
            socket.soTimeout = UDP_TIMEOUT_MS
            val address = InetAddress.getByName(serverIp)
            val requestPacket = DatagramPacket(rawDnsQuery, rawDnsQuery.size, address, 53)
            socket.send(requestPacket)

            val receiveBuf = ByteArray(4096)
            val responsePacket = DatagramPacket(receiveBuf, receiveBuf.size)
            // Plain UDP/53 has no transport authentication: drop datagrams that do not come
            // from the server we queried, carry a different transaction ID, or are not marked
            // as responses. Without this check an off-path attacker could inject forged answers
            // that we would then cache for every app on the device.
            val deadline = System.currentTimeMillis() + UDP_TIMEOUT_MS
            while (true) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0L) throw SocketTimeoutException("Upstream UDP DNS timed out")
                socket.soTimeout = remaining.toInt().coerceAtLeast(1)
                responsePacket.length = receiveBuf.size
                socket.receive(responsePacket)
                val candidate = receiveBuf.copyOfRange(0, responsePacket.length)
                val fromQueriedServer = responsePacket.port == 53 &&
                    responsePacket.address == address
                if (fromQueriedServer && isValidDnsResponseForQuery(rawDnsQuery, candidate)) {
                    return candidate
                }
            }
        }
    }

    fun querySingleTcpServer(rawDnsQuery: ByteArray, serverIp: String): ByteArray {
        Socket().use { socket ->
            currentProtector?.invoke(socket)
            socket.connect(InetSocketAddress(InetAddress.getByName(serverIp), 53), 3000)
            socket.soTimeout = 3000
            val out = DataOutputStream(socket.getOutputStream())
            val input = DataInputStream(socket.getInputStream())
            out.writeShort(rawDnsQuery.size)
            out.write(rawDnsQuery)
            out.flush()
            val len = input.readUnsignedShort()
            if (len < 12) throw IllegalStateException("Short TCP DNS response: $len")
            val buf = ByteArray(len)
            input.readFully(buf)
            if (!isValidDnsResponseForQuery(rawDnsQuery, buf)) {
                throw IllegalStateException("Upstream TCP DNS response did not match the query")
            }
            return buf
        }
    }

    /**
     * Drops least-recently-used entries until the cache payload fits [cacheByteBudget]. Called on
     * every insert while holding the cache lock.
     */
    private fun trimCacheToByteBudget() {
        var total = dnsCache.values.sumOf { it.wireResponse.size }
        if (total <= cacheByteBudget) return
        val iterator = dnsCache.entries.iterator()
        while (total > cacheByteBudget && iterator.hasNext()) {
            val eldest = iterator.next()
            total -= eldest.value.wireResponse.size
            iterator.remove()
        }
    }

    companion object {
        private val DNS_MESSAGE_MEDIA_TYPE = "application/dns-message".toMediaType()

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
        /**
         * Whether the client subnet may be forwarded upstream for [domain].
         *
         * Geo-accurate answers for streaming hosts are the only reason this app lets a client
         * subnet reach the resolver. Every other query is normalised, so a CDN cannot use a
         * forwarded subnet to link unrelated lookups from the same device.
         */
        internal fun forwardsClientSubnet(domain: String, config: DnsResolverConfig): Boolean =
            config.preferGeoAccurateMediaDns && DnsMediaPlaybackGuard.isProtectedPlaybackHost(domain)

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

        /**
         * 2.5 s for UDP/53. A public resolver that has not answered in 2.5 s is
         * unreachable on this network, and every millisecond after that is a
         * millisecond the app waits before the failover provider is even tried.
         */
        private const val UDP_TIMEOUT_MS = 2500

        /** Hard entry ceiling, independent of the byte budget. */
        private const val MAX_CACHE_ENTRIES = 1024

        /** Default payload ceiling: 2 MiB of cached wire answers. */
        internal const val DEFAULT_CACHE_BYTE_BUDGET = 2 * 1024 * 1024

        /** How long an expired answer stays available as a stale fallback (RFC 8767). */
        internal const val STALE_GRACE_MS = 5 * 60 * 1000L

        /** Lifetime reported on a stale answer, so the client retries soon after recovery. */
        internal const val STALE_TTL_SECONDS = 30

        /**
         * How long a coalesced follower waits for the leader's answer before resolving on its own.
         * Comfortably longer than one provider timeout, short enough that a stalled leader cannot
         * turn into a visibly hung app.
         */
        private const val FOLLOWER_TIMEOUT_MS = 5_000L

        fun transactionIdOf(rawDnsMessage: ByteArray): Int {
            if (rawDnsMessage.size < 2) return -1
            return ((rawDnsMessage[0].toInt() and 0xFF) shl 8) or (rawDnsMessage[1].toInt() and 0xFF)
        }

        /**
         * True when [response] is a well-formed DNS *response* that echoes [transactionId].
         * Guards against cross-talk, truncated garbage and forged datagrams.
         */
        /**
         * Strict form used by the plaintext UDP/TCP transports: the answer must also echo the
         * question we asked (name, type, class). A datagram that merely repeats our transaction
         * ID can still be a forged answer for a different name, and accepting it would poison the
         * cache for every app on the device. An error response is allowed to omit the question
         * (some servers do), but a NOERROR answer without a question is never trusted.
         */
        fun isValidDnsResponseForQuery(query: ByteArray, response: ByteArray): Boolean {
            if (!isValidDnsResponseForQuery(transactionIdOf(query), response)) return false
            val asked = DnsPacketCodec.firstQuestion(query) ?: return false
            val answered = DnsPacketCodec.firstQuestion(response)
            if (answered == null) {
                val rcode = response[3].toInt() and 0x0F
                return rcode != 0
            }
            return asked == answered
        }

        fun isValidDnsResponseForQuery(transactionId: Int, response: ByteArray): Boolean {
            if (response.size < 12 || transactionId < 0) return false
            if (transactionIdOf(response) != transactionId) return false
            val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
            return (flags and 0x8000) != 0 // QR = 1
        }

        /**
         * Only NOERROR (0) and NXDOMAIN (3) answers are safe to cache. SERVFAIL (2), REFUSED (5),
         * FORMERR (1) and NOTIMP (4) describe a transient upstream/negative state and truncated
         * (TC=1) messages are incomplete, so they are always re-queried.
         */
        fun shouldCacheDnsResponse(response: ByteArray): Boolean {
            if (response.size < 12) return false
            val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
            if ((flags and 0x0200) != 0) return false
            val rcode = flags and 0x000F
            return rcode == 0 || rcode == 3
        }

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
                DnsProtocol.DOH -> config.activeDohUrl.lowercase()
                DnsProtocol.DOT -> "${config.activeDotHost.lowercase()}:${config.preset.dotPort}"
                DnsProtocol.UDP_TCP -> upstreamUdpTcpServers(config).joinToString(",")
            }
            val failoverScope = if (config.failoverEnabled && config.protocol != DnsProtocol.UDP_TCP) {
                "|plan=" + DnsProviderRegistry.queryPlan(config).joinToString(",") { it.providerId }
            } else ""
            // DNSSEC mode and the checking-disabled bit change what a valid answer means. An
            // answer accepted under REPORT_ONLY must never be replayed once the user switches to
            // REQUIRE_AUTHENTICATED_ANSWERS, and a CD=1 answer is not interchangeable with a
            // checked one.
            val validationScope = "|dnssec=${config.dnssecMode.name}|cd=${query.flags and 0x0010 != 0}"
            return "${config.protocol.name}@$endpoint$failoverScope$validationScope|${query.cacheKey}"
        }
    }
}
