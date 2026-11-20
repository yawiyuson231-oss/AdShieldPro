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
import com.adshield.pro.ProcessScopeOwner
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.VpnExclusionSetup
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnTunnelReceipt
import com.adshield.pro.engine.dns.CnameCloakingInspector
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsFirewallPolicyDecider
import com.adshield.pro.engine.dns.IpPacketFraming
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeController
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicLong
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
class AdShieldVpnService : VpnService() {

    @Inject lateinit var repository: AdShieldRepository
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var filterRuleEngine: FilterRuleEngine
    @Inject lateinit var upstreamDnsResolver: UpstreamDnsResolver
    @Inject lateinit var snoozeController: ProtectionSnoozeController

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val tunnelLock = Any()
    private var tunnelGeneration: Long? = null
    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
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
        upstreamDnsResolver.bindVpnSocketProtectors(
            protectTcp = { socket -> protect(socket) },
            protectUdp = { datagramSocket -> protect(datagramSocket) }
        )
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                stopVpnTunnel()
                // The user explicitly turned protection off: this must be durable before
                // stopSelf() tears down the component scope, otherwise the pending DataStore
                // write is cancelled and protection would silently come back after a reboot.
                persistShutdownState()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_PAUSE_VPN -> {
                synchronized(tunnelLock) {
                    // A setup in progress can take a pause request, but don't claim a paused
                    // tunnel before Android has returned a descriptor and a fresh setup receipt.
                    if (tunnelGeneration != null) {
                        isPaused = true
                        if (vpnInterface != null) {
                            repository.updateVpnStatus(VpnStatus.PAUSED)
                            updateForegroundNotification()
                        }
                    }
                }
                return START_STICKY
            }
            ACTION_RESUME_VPN -> {
                serviceScope.launch { runCatching { snoozeController.clearSnooze() } }
                synchronized(tunnelLock) {
                    if (vpnInterface != null && tunnelJob?.isActive == true) {
                        isPaused = false
                        repository.updateVpnStatus(VpnStatus.CONNECTED)
                        updateForegroundNotification()
                    } else {
                        startForegroundWithNotification()
                        startVpnTunnel()
                    }
                }
                return START_STICKY
            }
            ACTION_RELOAD_TUNNEL_CONFIG -> {
                // Exclusion and IPv6 route changes require a new setup receipt.
                synchronized(tunnelLock) {
                    if (tunnelGeneration != null) {
                        startForegroundWithNotification()
                        startVpnTunnel(keepPause = true)
                    }
                }
                return START_STICKY
            }
            else -> {
                serviceScope.launch { runCatching { snoozeController.clearSnooze() } }
                startForegroundWithNotification()
                startVpnTunnel()
                return START_STICKY
            }
        }
    }

    private fun startVpnTunnel(keepPause: Boolean = false) = synchronized(tunnelLock) {
        // Invalidate the old receipt before tearing down its descriptor. A settings rebuild
        // changes the exclusion list, not the user's decision to pause filtering.
        repository.updateVpnStatus(VpnStatus.STARTING)
        discardTunnelLocked(clearPause = !keepPause)
        val generation = nextTunnelGeneration.incrementAndGet()
        tunnelGeneration = generation

        tunnelJob = serviceScope.launch {
            try {
                // establish() can outlive cancellation and may replace the existing OS VPN.
                // Begin setup from fresh settings after earlier establishment work has exited.
                val pfd = establishMutex.withLock {
                    currentCoroutineContext().ensureActive()
                    if (synchronized(tunnelLock) { tunnelGeneration != generation }) return@withLock null
                    // Read committed settings after the queue wait, not while an earlier
                    // OS setup can still be finishing.
                    val settings = repository.refreshProtectionSettings()
                    preferencesRepository.setVpnShouldRemainActive(true)
                    val builder = Builder()
                        .setSession(getString(R.string.vpn_session_name))
                        .setMtu(VPN_MTU)
                        .setBlocking(true)
                        .addAddress(VIRTUAL_IPV4_CLIENT, 30)
                        .addRoute(VIRTUAL_IPV4_DNS, 32)
                        .addDnsServer(VIRTUAL_IPV4_DNS)
                    val ipv6 = settings.resolverConfig.enableIpv6
                    if (ipv6) {
                        builder.addAddress(VIRTUAL_IPV6_CLIENT, 126)
                        builder.addRoute(VIRTUAL_IPV6_DNS, 128)
                        builder.addDnsServer(VIRTUAL_IPV6_DNS)
                    }

                    // The app's own automatic exclusion keeps upstream requests out of the tunnel.
                    // It is not a user exception and is not counted in the receipt.
                    tryAddExclusion(builder, packageName)
                    val exclusions = VpnExclusionSetup.collect(settings.excludedAppPackages, packageName) {
                        tryAddExclusion(builder, it)
                    }
                    val configureIntent = PendingIntent.getActivity(
                        this@AdShieldVpnService, 0, Intent(this@AdShieldVpnService, MainActivity::class.java),
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                    )
                    builder.setConfigureIntent(configureIntent)
                    val networkLabel = detectCurrentNetworkLabel()

                    currentCoroutineContext().ensureActive()
                    if (synchronized(tunnelLock) { tunnelGeneration != generation }) return@withLock null
                    val established = builder.establish() ?: error("Android did not establish the VPN. Check VPN consent and always-on settings.")
                    synchronized(tunnelLock) {
                        if (tunnelGeneration != generation) {
                            runCatching { established.close() }
                            null
                        } else {
                            vpnInterface = established
                            // The earlier snapshot built routes only. Replaying its protection
                            // mode here could overwrite a newer edit saved during establish().
                            repository.updateVpnStatus(
                                status = if (isPaused) VpnStatus.PAUSED else VpnStatus.CONNECTED,
                                networkLabel = networkLabel,
                                establishedTunnel = VpnTunnelReceipt(generation, System.currentTimeMillis(), ipv6,
                                    exclusions.accepted, exclusions.rejected)
                            )
                            established
                        }
                    }
                } ?: return@launch

                updateForegroundNotification()
                runPacketLoop(pfd)
                failCurrentTunnel(generation, "Android closed the DNS tunnel.")
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (e: Exception) {
                failCurrentTunnel(generation, "VPN Engine Error: ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    @Suppress("DEPRECATION") // Use the same PackageManager lookup on the API 29 path.
    private fun tryAddExclusion(builder: Builder, packageName: String): Boolean = try {
        // Some Android versions accept an unknown package name in Builder but omit its UID
        // from the established VPN. Don't count an unavailable package as an accepted exclusion.
        packageManager.getApplicationInfo(packageName, 0)
        builder.addDisallowedApplication(packageName)
        true
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        false
    }

    private fun failCurrentTunnel(generation: Long, message: String) = synchronized(tunnelLock) {
        if (tunnelGeneration == generation) {
            repository.updateVpnStatus(VpnStatus.ERROR, error = message)
            discardTunnelLocked()
            stopSelf()
        }
    }

    private suspend fun runPacketLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val outputStream = FileOutputStream(pfd.fileDescriptor)
        val packetBuffer = ByteArray(MAX_PACKET_SIZE)

        try {
            while (currentCoroutineContext().isActive && vpnInterface === pfd) {
                val length = inputStream.read(packetBuffer)
                if (length < 0) break
                if (length == 0) continue

                val parsedPacket = IpPacketFraming.parseIpPacket(packetBuffer, length) ?: continue
                when (parsedPacket) {
                    is IpPacketFraming.ParsedTransportPacket.UdpPacket -> {
                        if (parsedPacket.destinationPort == 53) {
                            serviceScope.launch { handleUdpDnsPacket(parsedPacket, outputStream, pfd) }
                        }
                    }
                    is IpPacketFraming.ParsedTransportPacket.TcpPacket -> {
                        if (parsedPacket.destinationPort == 53) {
                            serviceScope.launch { handleTcpDnsPacket(parsedPacket, outputStream, pfd) }
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
        outputStream: FileOutputStream,
        pfd: ParcelFileDescriptor
    ) {
        val dnsQuery = DnsPacketCodec.parseQuery(udpPacket.payload) ?: return
        val app = resolveDnsOwner(IpPacketFraming.PROTOCOL_UDP, udpPacket)
        val dnsResponseBytes = processDnsQuery(dnsQuery, app, pfd)
        // Encrypted upstream transports can return answers far larger than the tunnel MTU.
        // Anything that does not fit is replaced by a TC=1 answer so the stub resolver retries
        // over TCP (handled below) instead of the client silently timing out.
        val udpCapacity = IpPacketFraming.udpPayloadCapacity(udpPacket.ipVersion, VPN_MTU)
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
        outputStream: FileOutputStream,
        pfd: ParcelFileDescriptor
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

        var nextServerSeq = tcpPacket.acknowledgmentNumber
        if (tcpPacket.payload.size >= 14) {
            val dnsLen = ((tcpPacket.payload[0].toInt() and 0xFF) shl 8) or
                (tcpPacket.payload[1].toInt() and 0xFF)
            if (dnsLen >= 12 && 2 + dnsLen <= tcpPacket.payload.size) {
                val dnsQuery = DnsPacketCodec.parseQuery(tcpPacket.payload, 2, dnsLen)
                if (dnsQuery != null) {
                    val app = resolveDnsOwner(IpPacketFraming.PROTOCOL_TCP, tcpPacket)
                    val dnsResp = processDnsQuery(dnsQuery, app, pfd)
                    val tcpDnsPayload = ByteArray(2 + dnsResp.size)
                    tcpDnsPayload[0] = ((dnsResp.size ushr 8) and 0xFF).toByte()
                    tcpDnsPayload[1] = (dnsResp.size and 0xFF).toByte()
                    System.arraycopy(dnsResp, 0, tcpDnsPayload, 2, dnsResp.size)

                    // Large DNS answers must be segmented so every packet fits the tunnel MTU;
                    // a single oversized packet with DF set is dropped by the IP stack.
                    val segments = IpPacketFraming.buildTcpResponseSegments(
                        request = tcpPacket,
                        startSeqNum = nextServerSeq,
                        ackNum = (tcpPacket.sequenceNumber + tcpPacket.payload.size) and 0xFFFFFFFFL,
                        tcpPayload = tcpDnsPayload,
                        maxSegmentPayloadBytes = IpPacketFraming.tcpPayloadCapacity(tcpPacket.ipVersion, VPN_MTU)
                    )
                    segments.forEach { segment -> writeToTunSafe(outputStream, segment) }
                    nextServerSeq = (nextServerSeq + tcpDnsPayload.size) and 0xFFFFFFFFL
                }
            }
        }

        if ((flags and IpPacketFraming.TCP_FLAG_FIN) != 0) {
            val finAck = IpPacketFraming.buildTcpResponsePacket(
                request = tcpPacket,
                seqNum = nextServerSeq,
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
        app: AppAttribution?,
        pfd: ParcelFileDescriptor
    ): ByteArray {
        val currentSettings = preferencesRepository.getSettingsSnapshot()

        // Opportunistically end timed pause on the very first packet after its deadline even if
        // Doze deferred AlarmManager's inexact wake-up slightly.
        if (isPaused && ProtectionSnoozeEngine.isSnoozeDue(
                snoozeUntilEpochMs = currentSettings.vpnSnoozeUntilEpochMs,
                vpnShouldRemainActive = true,
                nowEpochMs = System.currentTimeMillis()
            )
        ) {
            val resumed = synchronized(tunnelLock) {
                // A packet queued by a replaced descriptor must not revive its status.
                if (vpnInterface !== pfd || !isPaused) false else {
                    isPaused = false
                    repository.updateVpnStatus(VpnStatus.CONNECTED)
                    updateForegroundNotification()
                    true
                }
            }
            if (resumed) runCatching { snoozeController.clearSnooze() }
        }

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

        // Allowed domain: resolve via configured DoH / DoT / Protected UDP-TCP resolver
        val upstreamResult = upstreamDnsResolver.resolve(query, currentSettings.resolverConfig)

        // Check returned aliases, including on cache hits, against the current rules.
        val aliasDecision = CnameCloakingInspector.inspect(
            questionDomain = query.questionDomain,
            dnsResponse = upstreamResult.responseBytes,
            filterEngine = filterRuleEngine,
            enabled = currentSettings.cnameUncloakingEnabled,
            bypassDomainFilters = decision.bypassDomainFilters
        )
        if (aliasDecision.shouldBlock) {
            val mode = filterRuleEngine.getCurrentSnapshot().protectionMode
            val blockedReply = CnameCloakingInspector.blockedReply(query, mode.blockSinkholeZeroIp)
            val target = aliasDecision.cloakedTarget
            val rule = aliasDecision.matchedRule
            val ruleLabel = if (target != null && rule != null && rule != target) "$target ($rule)" else target ?: rule
            repository.recordDnsQueryEvent(
                domain = query.questionDomain,
                queryType = query.qTypeName,
                isBlocked = true,
                category = aliasDecision.matchedCategory,
                matchedRule = ruleLabel,
                sourceList = aliasDecision.sourceName,
                latencyMs = upstreamResult.latencyMs,
                protocolUsed = blockedReply.label,
                fromCache = upstreamResult.fromCache,
                appPackageName = app?.packageName,
                appName = app?.label
            )
            maybeRefreshNotificationCounter()
            return blockedReply.bytes
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
                refreshActiveNetworkLabel()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                currentTransport = transportFrom(networkCapabilities)
                refreshActiveNetworkLabel()
            }

            override fun onLost(network: Network) {
                val active = cm.activeNetwork?.takeIf { it != network }
                runCatching { setUnderlyingNetworks(active?.let { arrayOf(it) }) }
                currentTransport = detectCurrentTransport()
                refreshActiveNetworkLabel()
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

    private fun refreshActiveNetworkLabel() {
        val label = detectCurrentNetworkLabel()
        synchronized(tunnelLock) {
            if (vpnInterface != null && !isPaused) {
                repository.updateVpnStatus(VpnStatus.CONNECTED, networkLabel = label)
            }
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
    private var lastWidgetUpdateMs = 0L

    private fun maybeRefreshNotificationCounter() {
        val now = System.currentTimeMillis()
        if (now - lastNotificationUpdateMs >= 4000L) {
            lastNotificationUpdateMs = now
            updateForegroundNotification()
        }
        if (now - lastWidgetUpdateMs >= 12_000L) {
            lastWidgetUpdateMs = now
            runCatching { AdShieldWidgetProvider.refreshAll(applicationContext) }
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
        val state = repository.vpnRuntimeState.value
        val openAppIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, AdShieldVpnService::class.java).apply { action = ACTION_STOP_VPN },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val togglePauseAction = if (isPaused) {
            val resumePending = PendingIntent.getService(
                this,
                3,
                Intent(this, AdShieldVpnService::class.java).apply { action = ACTION_RESUME_VPN },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            NotificationCompat.Action.Builder(0, "Resume", resumePending).build()
        } else {
            val pausePending = PendingIntent.getService(
                this,
                3,
                Intent(this, AdShieldVpnService::class.java).apply { action = ACTION_PAUSE_VPN },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            NotificationCompat.Action.Builder(0, "Pause", pausePending).build()
        }

        val title = if (isPaused) {
            val deadline = preferencesRepository.cachedSettingsOrNull()?.vpnSnoozeUntilEpochMs ?: 0L
            val nowMs = System.currentTimeMillis()
            if (ProtectionSnoozeEngine.isSnoozeActive(deadline, nowMs)) {
                "AdShield Pro — Paused (${ProtectionSnoozeEngine.formatRemainingCompact(deadline, nowMs)} left)"
            } else {
                "AdShield Pro — Protection Paused"
            }
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
            getString(R.string.vpn_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    override fun onRevoke() {
        stopVpnTunnel(reason = "VPN permission was revoked or superseded by another VPN app.")
        // Triggered when the user or another VPN application revokes our VPN permission;
        // persist durably before stopSelf() cancels the component scope.
        persistShutdownState()
        stopSelf()
        super.onRevoke()
    }

    /**
     * Writes the "protection is off" state on the *application* scope, then waits for it
     * within a fixed budget.
     *
     * The writes used to run on `serviceScope` (and on the callers' scopes), which
     * `stopSelf()` cancels a few statements later — so the preferences could be dropped
     * and the boot receiver would bring protection back on after a reboot, silently
     * overriding the user's decision to turn it off. The write now belongs to a scope
     * that outlives this service; only the (bounded) wait happens here.
     */
    private fun persistShutdownState() {
        val block: suspend () -> Unit = {
            snoozeController.cancelResumeAlarm()
            preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
            preferencesRepository.setVpnShouldRemainActive(false)
        }
        val processScope = (application as? ProcessScopeOwner)?.appScope
        if (processScope == null) {
            // Fail closed: an unexpected Application type still persists, exactly as before.
            runCatching { runBlocking { withTimeout(SHUTDOWN_PERSIST_TIMEOUT_MS) { block() } } }
            return
        }
        val job = processScope.async { withTimeoutOrNull(SHUTDOWN_PERSIST_TIMEOUT_MS) { block() } }
        runCatching { runBlocking { job.await() } }
    }

    private fun stopVpnTunnel(reason: String? = null) = synchronized(tunnelLock) {
        repository.updateVpnStatus(VpnStatus.DISCONNECTED, error = reason)
        discardTunnelLocked()
    }

    private fun discardTunnelLocked(clearPause: Boolean = true) {
        tunnelGeneration = null
        tunnelJob?.cancel()
        tunnelJob = null
        val oldInterface = vpnInterface
        vpnInterface = null
        if (clearPause) isPaused = false
        runCatching { oldInterface?.close() }
    }

    override fun onDestroy() {
        networkCallback?.let { cb ->
            runCatching { connectivityManager?.unregisterNetworkCallback(cb) }
        }
        upstreamDnsResolver.bindVpnSocketProtectors(null, null)
        synchronized(tunnelLock) {
            if (tunnelGeneration != null) stopVpnTunnel()
        }
        // The daily counter is batched in memory; write the tail on the process scope so a
        // cancellation racing this teardown cannot drop the last seconds of activity.
        val flushScope = (application as? ProcessScopeOwner)?.appScope
        if (flushScope != null) {
            runCatching { runBlocking { withTimeoutOrNull(SHUTDOWN_PERSIST_TIMEOUT_MS) { flushScope.async { repository.flushDailyStats() }.await() } } }
        } else {
            runCatching { runBlocking { withTimeout(SHUTDOWN_PERSIST_TIMEOUT_MS) { repository.flushDailyStats() } } }
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START_VPN = "com.adshield.pro.action.START_VPN"
        const val ACTION_STOP_VPN = "com.adshield.pro.action.STOP_VPN"
        const val ACTION_PAUSE_VPN = "com.adshield.pro.action.PAUSE_VPN"
        const val ACTION_RESUME_VPN = "com.adshield.pro.action.RESUME_VPN"
        const val ACTION_RELOAD_TUNNEL_CONFIG = "com.adshield.pro.action.RELOAD_TUNNEL_CONFIG"

        private val nextTunnelGeneration = AtomicLong()
        private val establishMutex = Mutex()

        private const val NOTIFICATION_CHANNEL_ID = "adshield_vpn_channel"
        private const val NOTIFICATION_ID = 2001

        private const val VPN_MTU = 1500
        private const val SHUTDOWN_PERSIST_TIMEOUT_MS = 1_500L
        private const val MAX_PACKET_SIZE = 32767

        const val VIRTUAL_IPV4_CLIENT = "10.215.173.1"
        const val VIRTUAL_IPV4_DNS = "10.215.173.2"
        const val VIRTUAL_IPV6_CLIENT = "fd00:ad5:1e1d::1"
        const val VIRTUAL_IPV6_DNS = "fd00:ad5:1e1d::2"
    }
}
