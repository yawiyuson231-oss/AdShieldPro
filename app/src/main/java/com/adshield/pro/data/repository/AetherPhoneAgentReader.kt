package com.adshield.pro.data.repository

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.SupplicantState
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.PowerManager
import android.os.StatFs
import com.adshield.pro.data.local.preferences.ScanJournalStore
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.engine.aether.AetherPhoneAgent as Agent
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** The Agent reads only local receipts and passive Android reports. No probes or writes. */
class AetherPhoneAgentReader @Inject constructor(
    @ApplicationContext private val context: Context,
    private val repository: AdShieldRepository,
    private val journal: ScanJournalStore
) {
    suspend fun check(): Agent.Report = withContext(Dispatchers.IO) {
        val settings = repository.settingsFlow.first()
        val policy = settings.dnsFirewallPolicy
        val vpn = repository.vpnRuntimeState.value
        val dns = async {
            if (settings.detailedDnsLoggingEnabled) readOptional { repository.recentLogsFlow.first() } else null
        }
        val history = async {
            readOptional {
                val records = journal.historySnapshot()
                Agent.ScanHistory(
                    retained = records.size,
                    flaggedTargets = records.count { it.kind != ScanKind.APP_AUDIT && it.threatLevel != SecurityLevel.CLEAN },
                    flaggedAppAudits = records.count { it.kind == ScanKind.APP_AUDIT && it.threatLevel != SecurityLevel.CLEAN }
                )
            }
        }
        val network = runCatching { readNetwork() }.getOrNull() ?: Agent.Network(Agent.Transport.UNKNOWN)
        val device = readDevice()
        Agent.review(Agent.Snapshot(
            settings = Agent.Settings(
                vpnRequested = settings.vpnShouldRemainActive,
                protocol = settings.resolverConfig.protocol,
                resolver = settings.resolverConfig.preset,
                mode = settings.protectionMode,
                allowlistOnly = policy.emergencyAllowlistOnly,
                aliasShieldOn = settings.cnameUncloakingEnabled,
                dnsLoggingOn = settings.detailedDnsLoggingEnabled,
                excludedApps = settings.excludedAppPackages.size,
                allowDnsOverrides = policy.appPolicies.values.count { it == AppDnsPolicy.ALLOW_ALL },
                unfilteredNetworks = NetworkTransportPolicy.entries.count { it !in policy.protectedTransports },
                blocksThirdPartyCookies = settings.browserBlockThirdPartyCookies,
                automaticFilterUpdates = settings.autoUpdateFiltersEnabled,
                scheduledScans = settings.scheduledScanEnabled
            ),
            protection = Agent.Protection(vpn.status, vpn.loadedRuleCount, vpn.sessionTotalQueries, vpn.sessionBlockedQueries),
            network = network,
            device = device,
            dnsRecords = dns.await(),
            scanHistory = history.await(),
            capturedAtMs = System.currentTimeMillis()
        ))
    }

    private suspend fun <T> readOptional(read: suspend () -> T): T? = try {
        read()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        null
    }

    @Suppress("DEPRECATION") // Fallback on older Android; only read connected Wi-Fi metadata, never SSID/BSSID.
    private fun readNetwork(): Agent.Network {
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return Agent.Network(Agent.Transport.UNKNOWN)
        val active = cm.activeNetwork ?: return Agent.Network(Agent.Transport.NONE)
        val caps = cm.getNetworkCapabilities(active) ?: return Agent.Network(Agent.Transport.UNKNOWN)
        // Do not guess which radio is in use when Android only exposes a VPN transport.
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Agent.Transport.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Agent.Transport.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Agent.Transport.ETHERNET
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> Agent.Transport.VPN
            else -> Agent.Transport.OTHER
        }
        val wifi = if (transport == Agent.Transport.WIFI) runCatching {
            (caps.transportInfo as? WifiInfo) ?: context.applicationContext
                .getSystemService(WifiManager::class.java)?.connectionInfo
                ?.takeIf { it.supplicantState == SupplicantState.COMPLETED }
        }.getOrNull() else null
        val wifiMode = if (wifi != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (wifi.currentSecurityType) {
                WifiInfo.SECURITY_TYPE_OPEN -> Agent.WifiSecurity.OPEN
                WifiInfo.SECURITY_TYPE_WEP -> Agent.WifiSecurity.WEP
                WifiInfo.SECURITY_TYPE_PSK -> Agent.WifiSecurity.WPA_PERSONAL
                WifiInfo.SECURITY_TYPE_EAP -> Agent.WifiSecurity.WPA_ENTERPRISE
                WifiInfo.SECURITY_TYPE_SAE -> Agent.WifiSecurity.WPA3_PERSONAL
                WifiInfo.SECURITY_TYPE_OWE -> Agent.WifiSecurity.ENHANCED_OPEN
                else -> null
            }
        } else null
        return Agent.Network(
            transport = transport,
            internetValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            captivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            wifiSecurity = wifiMode,
            signalDbm = wifi?.rssi
        )
    }

    private fun readDevice(): Agent.Device = Agent.Device(
        lowMemory = runCatching {
            context.getSystemService(ActivityManager::class.java)?.let { manager ->
                ActivityManager.MemoryInfo().apply { manager.getMemoryInfo(this) }.lowMemory
            }
        }.getOrNull(),
        freeStorageBytes = runCatching { StatFs(context.filesDir.path).availableBytes }.getOrNull(),
        thermal = runCatching {
            context.getSystemService(PowerManager::class.java)?.currentThermalStatus?.let { status ->
                when (status) {
                    PowerManager.THERMAL_STATUS_NONE -> Agent.Thermal.NORMAL
                    PowerManager.THERMAL_STATUS_LIGHT, PowerManager.THERMAL_STATUS_MODERATE -> Agent.Thermal.ELEVATED
                    in PowerManager.THERMAL_STATUS_SEVERE..PowerManager.THERMAL_STATUS_SHUTDOWN -> Agent.Thermal.SEVERE
                    else -> null
                }
            }
        }.getOrNull()
    )
}
