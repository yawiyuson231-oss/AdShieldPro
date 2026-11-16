package com.adshield.pro.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Process
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.ProtectionArchitecture
import com.adshield.pro.domain.model.DnsStatus
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsRebindingGuard
import com.adshield.pro.engine.dns.DnsCnameGuard
import com.adshield.pro.engine.dns.DnsFirewallPolicyDecider
import com.adshield.pro.engine.dns.IpPacketFraming
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.filter.VideoAdNetworkCatalog
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InterruptedIOException
import javax.inject.Inject

/**
 * Layer 1 & Layer 2 — Production Local DNS-Filtering VPN Service.
 *
 * Key architectural guarantees:
 * - Routes ONLY virtual DNS server addresses (`10.215.173.2/32` and `fd00:ad5:1e1d::2/128`) into the TUN interface.
 * - All non-DNS TCP/UDP/QUIC application traffic flows directly over the physical network interface
 *   with zero throughput bottleneck and zero HTTPS payload interception.
 * - Protects all upstream DoH, DoT, and UDP/TCP sockets via [VpnService.protect] to prevent routing loops.
 * - Dynamically applies rule edits and protection mode changes in memory without restarting the tunnel.
 */
@AndroidEntryPoint
class AdShieldDnsService : VpnService() {

    @Inject lateinit var repository: AdShieldRepository
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var filterRuleEngine: FilterRuleEngine
    @Inject lateinit var upstreamDnsResolver: UpstreamDnsResolver

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunnelJob: Job? = null
    private val tunWriteLock = Any()
    private data class AppAttribution(val packageName: String, val label: String)
    private val appAttributionByUid = ConcurrentHashMap<Int, AppAttribution>()

    @Volatile
    private var isPaused: Boolean = false

    private var connectivityManager: ConnectivityManager? = null
    @Volatile private var currentTransport: NetworkTransportPolicy = NetworkTransportPolicy.OTHER
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        upstreamDnsResolver.bindSocketProtectors(
            protectTcp = { socket -> protect(socket) },
            protectUdp = { datagramSocket -> protect(datagramSocket) }
        )
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_PROTECTION -> {
                // The user explicitly turned protection off: this must be durable before
                // stopSelf() tears down the service scope, otherwise the pending DataStore
                // write is cancelled and protection would silently come back after a reboot.
                runCatching {
                    runBlocking {
                        withTimeout(SHUTDOWN_PERSIST_TIMEOUT_MS) {
                            preferencesRepository.setProtectionShouldRemainActive(false)
                        }
                    }
                }
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_PAUSE_PROTECTION -> {
                isPaused = true
                repository.updateDnsStatus(DnsStatus.PAUSED)
                updateForegroundNotification()
                return START_STICKY
            }
            ACTION_RESUME_PROTECTION -> {
                isPaused = false
                if (tunInterface != null && tunnelJob?.isActive == true) {
                    repository.updateDnsStatus(DnsStatus.CONNECTED)
                    updateForegroundNotification()
                } else {
                    startTunnel()
                }
                return START_STICKY
            }
            ACTION_RELOAD_TUNNEL_CONFIG -> {
                // Used only when per-app VPN exclusions or IPv6 interface routing changes
                if (tunInterface != null) {
                    startTunnel()
                }
                return START_STICKY
            }
            else -> {
                startForegroundWithNotification()
                startTunnel()
                return START_STICKY
            }
        }
    }

    private fun startTunnel() {
        tunnelJob?.cancel()
        closeTunInterface()

        repository.updateDnsStatus(DnsStatus.STARTING)

        tunnelJob = serviceScope.launch {
            try {
                val settings = preferencesRepository.getSettingsSnapshot()
                preferencesRepository.setProtectionShouldRemainActive(true)
                filterRuleEngine.updateProtectionMode(settings.protectionMode)
                repository.syncRuntimeModeAndResolver(settings.protectionMode, settings)

                val builder = Builder()
                    .setSession(getString(R.string.dns_session_name))
                    .setMtu(TUNNEL_MTU)
                    .setBlocking(true)
                    // IPv4 Virtual Tunnel & DNS Sinkhole Router. The addresses live in
                    // ProtectionArchitecture so the in-app explainer renders the same routes.
                    .addAddress(VIRTUAL_IPV4_CLIENT, ProtectionArchitecture.IPV4_CLIENT_PREFIX)
                    .addRoute(VIRTUAL_IPV4_DNS, ProtectionArchitecture.IPV4_DNS_PREFIX)
                    .addDnsServer(VIRTUAL_IPV4_DNS)

                if (settings.resolverConfig.enableIpv6) {
                    builder.addAddress(VIRTUAL_IPV6_CLIENT, ProtectionArchitecture.IPV6_CLIENT_PREFIX)
                    builder.addRoute(VIRTUAL_IPV6_DNS, ProtectionArchitecture.IPV6_DNS_PREFIX)
                    builder.addDnsServer(VIRTUAL_IPV6_DNS)
                }

                // Always exclude AdShield Pro itself so upstream requests never loop
                runCatching { builder.addDisallowedApplication(packageName) }

                // Apply per-app VPN exclusions configured by the user
                for (excludedPkg in settings.excludedAppPackages) {
                    if (excludedPkg.isNotBlank() && excludedPkg != packageName) {
                        runCatching { builder.addDisallowedApplication(excludedPkg) }
                    }
                }

                val configureIntent = PendingIntent.getActivity(
                    this@AdShieldDnsService,
                    0,
                    Intent(this@AdShieldDnsService, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                builder.setConfigureIntent(configureIntent)

                val establishedPfd = builder.establish()
                if (establishedPfd == null) {
                    repository.updateDnsStatus(
                        status = DnsStatus.ERROR,
                        error = "Android's VPN permission was not granted, or another Always-On VPN is blocking tunnel creation."
                    )
                    stopSelf()
                    return@launch
                }

                tunInterface = establishedPfd
                isPaused = false
                repository.updateDnsStatus(
                    status = DnsStatus.CONNECTED,
                    networkLabel = detectCurrentNetworkLabel()
                )
                updateForegroundNotification()

                runPacketLoop(establishedPfd)
            } catch (t: Throwable) {
                repository.updateDnsStatus(
                    status = DnsStatus.ERROR,
                    error = "DNS engine error: ${t.message ?: t.javaClass.simpleName}"
                )
                stopSelf()
            }
        }
    }

    private suspend fun runPacketLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val outputStream = FileOutputStream(pfd.fileDescriptor)
        val packetBuffer = ByteArray(MAX_PACKET_SIZE)

        try {
            while (serviceScope.isActive && tunInterface != null) {
                val length = try {
                    inputStream.read(packetBuffer)
                } catch (_: InterruptedIOException) {
                    break
                } catch (e: Exception) {
                    if (!serviceScope.isActive) break
                    continue
                }

                if (length <= 0) continue

                val parsedPacket = IpPacketFraming.parseIpPacket(packetBuffer, length) ?: continue

                when (parsedPacket) {
                    is IpPacketFraming.ParsedTransportPacket.UdpPacket -> {
                        if (parsedPacket.destinationPort == 53) {
                            serviceScope.launch {
                                handleUdpDnsPacket(parsedPacket, outputStream)
                            }
                        }
                    }
                    is IpPacketFraming.ParsedTransportPacket.TcpPacket -> {
                        if (parsedPacket.destinationPort == 53) {
                            serviceScope.launch {
                                handleTcpDnsPacket(parsedPacket, outputStream)
                            }
                        }
                    }
                }
            }
        } finally {
            runCatching { inputStream.close() }
            runCatching { outputStream.close() }
        }
    }

    private suspend fun handleUdpDnsPacket(
        udpPacket: IpPacketFraming.ParsedTransportPacket.UdpPacket,
        outputStream: FileOutputStream
    ) {
        val dnsQuery = DnsPacketCodec.parseQuery(udpPacket.payload) ?: return
        val app = resolveDnsOwner(IpPacketFraming.PROTOCOL_UDP, udpPacket)
        val dnsResponseBytes = processDnsQuery(dnsQuery, app)
        // Encrypted upstream transports can return answers far larger than the tunnel MTU.
        // Anything that does not fit is replaced by a TC=1 answer so the stub resolver retries
        // over TCP (handled below) instead of the client silently timing out.
        val udpCapacity = IpPacketFraming.udpPayloadCapacity(udpPacket.ipVersion, TUNNEL_MTU)
        val udpSafeResponse = DnsPacketCodec.fitResponseToUdpLimit(dnsQuery, dnsResponseBytes, udpCapacity)
        val responseIpPacket = IpPacketFraming.buildUdpResponsePacket(udpPacket, udpSafeResponse)
        writeToTunSafe(outputStream, responseIpPacket)
    }

    /**
     * Lightweight stateless TCP port 53 responder for the virtual DNS IP:
     * - SYN -> SYN+ACK
     * - PSH+ACK / payload with 2-byte length prefix -> DNS response with 2-byte length prefix + ACK
     * - FIN -> FIN+ACK
     */
    private suspend fun handleTcpDnsPacket(
        tcpPacket: IpPacketFraming.ParsedTransportPacket.TcpPacket,
        outputStream: FileOutputStream
    ) {
        val flags = tcpPacket.flags
        if ((flags and IpPacketFraming.TCP_FLAG_RST) != 0) return

        if ((flags and IpPacketFraming.TCP_FLAG_SYN) != 0 && (flags and IpPacketFraming.TCP_FLAG_ACK) == 0) {
            val synAck = IpPacketFraming.buildTcpResponsePacket(
                request = tcpPacket,
                seqNum = 1000L,
                ackNum = (tcpPacket.sequenceNumber + 1L) and 0xFFFFFFFFL,
                flags = IpPacketFraming.TCP_FLAG_SYN or IpPacketFraming.TCP_FLAG_ACK
            )
            writeToTunSafe(outputStream, synAck)
            return
        }

        if (tcpPacket.payload.size >= 14) {
            val dnsLen = ((tcpPacket.payload[0].toInt() and 0xFF) shl 8) or
                (tcpPacket.payload[1].toInt() and 0xFF)
            if (dnsLen >= 12 && 2 + dnsLen <= tcpPacket.payload.size) {
                val dnsQuery = DnsPacketCodec.parseQuery(tcpPacket.payload, 2, dnsLen)
                if (dnsQuery != null) {
                    val app = resolveDnsOwner(IpPacketFraming.PROTOCOL_TCP, tcpPacket)
                    val dnsResp = processDnsQuery(dnsQuery, app)
                    val tcpDnsPayload = ByteArray(2 + dnsResp.size)
                    tcpDnsPayload[0] = ((dnsResp.size ushr 8) and 0xFF).toByte()
                    tcpDnsPayload[1] = (dnsResp.size and 0xFF).toByte()
                    System.arraycopy(dnsResp, 0, tcpDnsPayload, 2, dnsResp.size)

                    // Large DNS answers must be segmented so every packet fits the tunnel MTU;
                    // a single oversized packet with DF set is dropped by the IP stack.
                    val segments = IpPacketFraming.buildTcpResponseSegments(
                        request = tcpPacket,
                        startSeqNum = tcpPacket.acknowledgmentNumber,
                        ackNum = (tcpPacket.sequenceNumber + tcpPacket.payload.size) and 0xFFFFFFFFL,
                        tcpPayload = tcpDnsPayload,
                        maxSegmentPayloadBytes = IpPacketFraming.tcpPayloadCapacity(tcpPacket.ipVersion, TUNNEL_MTU)
                    )
                    segments.forEach { segment -> writeToTunSafe(outputStream, segment) }
                }
            }
        }

        if ((flags and IpPacketFraming.TCP_FLAG_FIN) != 0) {
            val finAck = IpPacketFraming.buildTcpResponsePacket(
                request = tcpPacket,
                seqNum = tcpPacket.acknowledgmentNumber,
                ackNum = (tcpPacket.sequenceNumber + tcpPacket.payload.size + 1L) and 0xFFFFFFFFL,
                flags = IpPacketFraming.TCP_FLAG_FIN or IpPacketFraming.TCP_FLAG_ACK
            )
            writeToTunSafe(outputStream, finAck)
        }
    }

    private fun resolveDnsOwner(
        protocol: Int,
        packet: IpPacketFraming.ParsedTransportPacket
    ): AppAttribution? = runCatching {
        val manager = connectivityManager ?: return null
        val uid = manager.getConnectionOwnerUid(
            protocol,
            InetSocketAddress(InetAddress.getByAddress(packet.sourceAddress), packet.sourcePort),
            InetSocketAddress(InetAddress.getByAddress(packet.destinationAddress), packet.destinationPort)
        )
        if (uid == Process.INVALID_UID) return null
        appAttributionByUid[uid]?.let { return it }
        val packageName = packageManager.getPackagesForUid(uid)
            ?.firstOrNull { it != this.packageName }
            ?: packageManager.getPackagesForUid(uid)?.firstOrNull()
            ?: return null
        val appInfo = packageManager.getApplicationInfo(packageName, 0)
        val attribution = AppAttribution(packageName, packageManager.getApplicationLabel(appInfo).toString())
        appAttributionByUid[uid] = attribution
        attribution
    }.getOrNull()

    private suspend fun processDnsQuery(
        query: DnsPacketCodec.ParsedDnsQuery,
        app: AppAttribution?
    ): ByteArray {
        val currentSettings = preferencesRepository.getSettingsSnapshot()

        // If protection is temporarily paused by user, forward directly to encrypted upstream DNS
        if (isPaused) {
            val upstream = upstreamDnsResolver.resolve(query, currentSettings.resolverConfig)
            repository.recordDnsQueryEvent(
                domain = query.questionDomain,
                queryType = query.qTypeName,
                isBlocked = false,
                category = null,
                matchedRule = null,
                sourceList = "Paused (Passthrough)",
                latencyMs = upstream.latencyMs,
                protocolUsed = upstream.protocolUsed,
                fromCache = upstream.fromCache,
                appPackageName = app?.packageName,
                appName = app?.label
            )
            return upstream.responseBytes
        }

        // DNS-only app/network policy is enforced before upstream resolution. Non-DNS packets
        // are not routed through this service and therefore are not governed by these controls.
        val evaluation = filterRuleEngine.evaluate(query.questionDomain)
        val decision = DnsFirewallPolicyDecider.evaluate(
            evaluation = evaluation,
            appPackageName = app?.packageName,
            transport = currentTransport,
            policy = currentSettings.dnsFirewallPolicy
        )

        if (decision.isBlocked) {
            val mode = filterRuleEngine.getCurrentSnapshot().protectionMode
            val blockedBytes = DnsPacketCodec.buildBlockedResponse(
                query = query,
                sinkholeZeroIp = mode.blockSinkholeZeroIp
            )
            repository.recordDnsQueryEvent(
                domain = query.questionDomain,
                queryType = query.qTypeName,
                isBlocked = true,
                category = decision.matchedCategory,
                matchedRule = decision.matchedRule,
                sourceList = decision.sourceName,
                latencyMs = 0,
                protocolUsed = if (mode.blockSinkholeZeroIp) "Sinkhole 0.0.0.0" else "Local NXDOMAIN",
                fromCache = false,
                appPackageName = app?.packageName,
                appName = app?.label
            )
            maybeRefreshNotificationCounter()
            return blockedBytes
        }

        // Built-in video-advert baseline. It runs before the upstream lookup, so it works even
        // when no filter list is loaded or the installed list predates the network. The user
        // allowlist, per-app bypass and unprotected transports keep their say.
        val enforcementMode = filterRuleEngine.getCurrentSnapshot().protectionMode
        val videoAdMatch = if (
            currentSettings.dnsFirewallPolicy.videoAdBaselineEnabled &&
            !decision.bypassDomainFilters &&
            evaluation.sourceName != "User Allowlist" &&
            evaluation.sourceName != "System Safety Allowlist"
        ) {
            VideoAdNetworkCatalog.matchForEnforcement(
                input = query.questionDomain,
                allowConditional = enforcementMode.enforceConditionalVideoAds
            )
        } else {
            null
        }
        if (videoAdMatch?.blocked == true) {
            val blockedBytes = DnsPacketCodec.buildBlockedResponse(
                query = query,
                sinkholeZeroIp = enforcementMode.blockSinkholeZeroIp
            )
            repository.recordDnsQueryEvent(
                domain = query.questionDomain,
                queryType = query.qTypeName,
                isBlocked = true,
                category = RuleCategory.ADS,
                matchedRule = videoAdMatch.entry.suffix,
                sourceList = "Video ad infrastructure",
                latencyMs = 0,
                protocolUsed = if (enforcementMode.blockSinkholeZeroIp) "Sinkhole 0.0.0.0" else "Local NXDOMAIN",
                fromCache = false,
                appPackageName = app?.packageName,
                appName = app?.label
            )
            maybeRefreshNotificationCounter()
            return blockedBytes
        }

        // Allowed domain: resolve via configured DoH / DoT / Protected UDP-TCP resolver
        val upstreamResult = upstreamDnsResolver.resolve(query, currentSettings.resolverConfig)

        val cloakMode = filterRuleEngine.getCurrentSnapshot().protectionMode

        // DNS rebinding: a public name that answers with a private address is how a page reaches
        // the router or an intranet host without any exploit. Local names are exempt, the guard
        // never decides on wire data it could not walk, and only the aggressive modes enforce it.
        if (cloakMode.enforceRebindingGuard &&
            !decision.bypassDomainFilters &&
            !DnsRebindingGuard.isLocalName(query.questionDomain)
        ) {
            val privateAnswer = DnsRebindingGuard.firstPrivateAnswer(upstreamResult.responseBytes)
            if (privateAnswer != null) {
                repository.recordDnsQueryEvent(
                    domain = query.questionDomain,
                    queryType = query.qTypeName,
                    isBlocked = true,
                    category = RuleCategory.MALWARE,
                    matchedRule = "${privateAnswer.address} (${privateAnswer.range})",
                    sourceList = "DNS rebinding guard",
                    latencyMs = upstreamResult.latencyMs,
                    protocolUsed = upstreamResult.protocolUsed,
                    fromCache = upstreamResult.fromCache,
                    appPackageName = app?.packageName,
                    appName = app?.label
                )
                maybeRefreshNotificationCounter()
                // SERVFAIL, not NXDOMAIN: the name exists, the answer is the problem.
                return DnsPacketCodec.buildServFailResponse(query)
            }
        }

        // CNAME cloaking: the queried name is allowed, but the chain can still land on a blocked
        // tracker. Enforced only in modes that accept the compatibility risk, and never on wire
        // data the codec could not fully walk.
        // A per-app "allow all" or an unprotected transport already said "do not filter this
        // lookup", so the guard must not overrule that decision.
        if (cloakMode.enforceCnameCloaking && !decision.bypassDomainFilters) {
            val cloakTarget = DnsCnameGuard.firstBlockedTarget(upstreamResult.responseBytes) { target ->
                filterRuleEngine.evaluate(target).isBlocked
            }
            if (cloakTarget != null) {
                val targetEvaluation = filterRuleEngine.evaluate(cloakTarget)
                val cloakedBytes = DnsPacketCodec.buildBlockedResponse(
                    query = query,
                    sinkholeZeroIp = cloakMode.blockSinkholeZeroIp
                )
                repository.recordDnsQueryEvent(
                    domain = query.questionDomain,
                    queryType = query.qTypeName,
                    isBlocked = true,
                    category = targetEvaluation.matchedCategory,
                    matchedRule = cloakTarget,
                    sourceList = "CNAME cloaking guard",
                    latencyMs = upstreamResult.latencyMs,
                    protocolUsed = upstreamResult.protocolUsed,
                    fromCache = upstreamResult.fromCache,
                    appPackageName = app?.packageName,
                    appName = app?.label
                )
                maybeRefreshNotificationCounter()
                return cloakedBytes
            }
        }

        repository.recordDnsQueryEvent(
            domain = query.questionDomain,
            queryType = query.qTypeName,
            isBlocked = false,
            category = null,
            matchedRule = decision.matchedRule,
            sourceList = decision.sourceName,
            latencyMs = upstreamResult.latencyMs,
            protocolUsed = upstreamResult.protocolUsed,
            fromCache = upstreamResult.fromCache,
            appPackageName = app?.packageName,
            appName = app?.label
        )
        maybeRefreshNotificationCounter()
        return upstreamResult.responseBytes
    }

    private fun writeToTunSafe(outputStream: FileOutputStream, packetBytes: ByteArray) {
        synchronized(tunWriteLock) {
            runCatching {
                outputStream.write(packetBytes)
                outputStream.flush()
            }
        }
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        connectivityManager = cm
        currentTransport = detectCurrentTransport()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                runCatching { setUnderlyingNetworks(arrayOf(network)) }
                currentTransport = detectCurrentTransport()
                val label = detectCurrentNetworkLabel()
                if (tunInterface != null && !isPaused) {
                    repository.updateDnsStatus(DnsStatus.CONNECTED, networkLabel = label)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                val label = detectCurrentNetworkLabel()
                if (tunInterface != null && !isPaused) {
                    repository.updateDnsStatus(DnsStatus.CONNECTED, networkLabel = label)
                }
            }

            override fun onLost(network: Network) {
                val label = detectCurrentNetworkLabel()
                if (tunInterface != null && !isPaused) {
                    repository.updateDnsStatus(DnsStatus.CONNECTED, networkLabel = label)
                }
            }
        }

        networkCallback = callback
        runCatching {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, callback)
        }
    }

    private fun detectCurrentTransport(): NetworkTransportPolicy {
        val manager = connectivityManager ?: return NetworkTransportPolicy.OTHER
        val network = manager.activeNetwork ?: return NetworkTransportPolicy.OTHER
        return manager.getNetworkCapabilities(network)?.let(::transportFrom) ?: NetworkTransportPolicy.OTHER
    }

    private fun transportFrom(capabilities: NetworkCapabilities): NetworkTransportPolicy = when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkTransportPolicy.WIFI
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkTransportPolicy.CELLULAR
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkTransportPolicy.ETHERNET
        else -> NetworkTransportPolicy.OTHER
    }

    private fun detectCurrentNetworkLabel(): String {
        val cm = connectivityManager ?: (getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager)
            ?: return "Active Network"
        val activeNetwork = cm.activeNetwork ?: return "Offline / Switching"
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return "Active Network"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile Data"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Connected"
        }
    }

    private var lastNotificationUpdateMs = 0L

    private fun maybeRefreshNotificationCounter() {
        val now = System.currentTimeMillis()
        if (now - lastNotificationUpdateMs >= 4000L) {
            lastNotificationUpdateMs = now
            updateForegroundNotification()
        }
    }

    private fun startForegroundWithNotification() {
        val notification = buildStatusNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateForegroundNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        nm.notify(NOTIFICATION_ID, buildStatusNotification())
    }

    private fun buildStatusNotification(): Notification {
        val state = repository.dnsRuntimeState.value
        val openAppIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, AdShieldDnsService::class.java).apply { action = ACTION_STOP_PROTECTION },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val togglePauseAction = if (isPaused) {
            val resumePending = PendingIntent.getService(
                this,
                3,
                Intent(this, AdShieldDnsService::class.java).apply { action = ACTION_RESUME_PROTECTION },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            NotificationCompat.Action.Builder(0, "Resume", resumePending).build()
        } else {
            val pausePending = PendingIntent.getService(
                this,
                3,
                Intent(this, AdShieldDnsService::class.java).apply { action = ACTION_PAUSE_PROTECTION },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            NotificationCompat.Action.Builder(0, "Pause", pausePending).build()
        }

        val title = if (isPaused) {
            "AdShield Pro — Protection Paused"
        } else {
            "AdShield Pro Active (${state.activeMode.title})"
        }

        val content = "Blocked ${state.sessionBlockedQueries} of ${state.sessionTotalQueries} DNS queries • ${state.resolverConfig.protocol.name}"

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(title)
            .setContentText(content)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openAppIntent)
            .addAction(togglePauseAction)
            .addAction(NotificationCompat.Action.Builder(0, "Stop", stopIntent).build())
            .build()
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.dns_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.dns_notification_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    override fun onRevoke() {
        // Triggered when the user or another VPN application revokes our VPN permission
        serviceScope.launch {
            preferencesRepository.setProtectionShouldRemainActive(false)
        }
        stopTunnel(reason = "Android revoked the VPN permission; another VPN app may have taken over.")
        stopSelf()
        super.onRevoke()
    }

    private fun stopTunnel(reason: String? = null) {
        tunnelJob?.cancel()
        tunnelJob = null
        closeTunInterface()
        repository.updateDnsStatus(DnsStatus.DISCONNECTED, error = reason)
    }

    private fun closeTunInterface() {
        runCatching { tunInterface?.close() }
        tunInterface = null
    }

    override fun onDestroy() {
        networkCallback?.let { cb ->
            runCatching { connectivityManager?.unregisterNetworkCallback(cb) }
        }
        upstreamDnsResolver.bindSocketProtectors(null, null)
        stopTunnel()
        // The daily counter is batched in memory; write the tail before the scope
        // dies so the last second of activity is never lost.
        runCatching { runBlocking { withTimeout(SHUTDOWN_PERSIST_TIMEOUT_MS) { repository.flushDailyStats() } } }
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START_PROTECTION = "com.adshield.pro.action.START_DNS_PROTECTION"
        const val ACTION_STOP_PROTECTION = "com.adshield.pro.action.STOP_DNS_PROTECTION"
        const val ACTION_PAUSE_PROTECTION = "com.adshield.pro.action.PAUSE_DNS_PROTECTION"
        const val ACTION_RESUME_PROTECTION = "com.adshield.pro.action.RESUME_DNS_PROTECTION"
        const val ACTION_RELOAD_TUNNEL_CONFIG = "com.adshield.pro.action.RELOAD_TUNNEL_CONFIG"

        private const val NOTIFICATION_CHANNEL_ID = "adshield_vpn_channel"
        private const val NOTIFICATION_ID = 2001

        private const val TUNNEL_MTU = 1500
        private const val SHUTDOWN_PERSIST_TIMEOUT_MS = 1_500L
        private const val MAX_PACKET_SIZE = 32767

        const val VIRTUAL_IPV4_CLIENT = ProtectionArchitecture.IPV4_CLIENT_ADDRESS
        const val VIRTUAL_IPV4_DNS = ProtectionArchitecture.IPV4_DNS_ADDRESS
        const val VIRTUAL_IPV6_CLIENT = ProtectionArchitecture.IPV6_CLIENT_ADDRESS
        const val VIRTUAL_IPV6_DNS = ProtectionArchitecture.IPV6_DNS_ADDRESS
    }
}
