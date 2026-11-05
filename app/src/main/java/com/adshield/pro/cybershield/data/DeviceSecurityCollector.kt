package com.adshield.pro.cybershield.data

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.adshield.pro.cybershield.DeviceSecuritySnapshot
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Collects REAL device security signals through public, permission-respecting
 * Android APIs. Anything Android does not expose to third-party apps is listed
 * in [DeviceSecuritySnapshot.unavailable] instead of being guessed.
 *
 * No root, no accessibility abuse, no other apps' private data, no location.
 */
@Singleton
class DeviceSecurityCollector @Inject constructor(
    @ApplicationContext private val context: Context
) {
    suspend fun collect(): DeviceSecuritySnapshot = withContext(Dispatchers.IO) {
        val unavailable = mutableListOf(
            "Play Protect scan status (Google Play services does not expose it to third-party apps)",
            "Verified Boot / bootloader state (system-only signal)",
            "Other apps' network payloads and private files (Android sandbox)",
            "Full antivirus file scanning of other apps (not permitted without root)"
        )

        val keyguard = runCatching {
            (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        }.getOrNull()

        val dpm = runCatching {
            context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        }.getOrNull()
        val encrypted = runCatching {
            when (dpm?.storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> true
                DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED,
                DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> false
                else -> null
            }
        }.getOrNull()

        val adb = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        }.getOrNull()
        val devOptions = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }.getOrNull()

        val patch = Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() }
        val patchAge = patch?.let {
            runCatching {
                ChronoUnit.DAYS.between(LocalDate.parse(it), LocalDate.now()).toInt().coerceAtLeast(0)
            }.getOrNull()
        }

        // App inventory (QUERY_ALL_PACKAGES is already declared for the per-app
        // VPN exclusion feature). "Sideloaded" = user app with no installer of
        // record; Android cannot tell us whether the APK content is malicious.
        var totalApps: Int? = null
        var userApps: Int? = null
        var sideloaded: Int? = null
        val sideloadedPackages = ArrayList<String>()
        runCatching {
            val pm = context.packageManager
            val apps = pm.getInstalledApplications(0)
            totalApps = apps.size
            val user = apps.filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            userApps = user.size
            var count = 0
            for (app in user) {
                if (app.packageName == context.packageName) continue
                val installer = runCatching {
                    if (Build.VERSION.SDK_INT >= 30) {
                        pm.getInstallSourceInfo(app.packageName).installingPackageName
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getInstallerPackageName(app.packageName)
                    }
                }.getOrNull()
                if (installer.isNullOrBlank()) {
                    count++
                    if (sideloadedPackages.size < 25) sideloadedPackages.add(app.packageName)
                }
            }
            sideloaded = count
        }

        // Active network + system DNS configuration (no SSID / no location).
        val cm = runCatching {
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        }.getOrNull()
        var transport: String? = null
        var validated: Boolean? = null
        var metered: Boolean? = null
        var dnsServers = emptyList<String>()
        var vpnActive: Boolean? = null
        runCatching {
            if (cm != null) {
                val active = cm.activeNetwork
                val caps = active?.let { cm.getNetworkCapabilities(it) }
                if (caps != null) {
                    transport = when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                        else -> "Other"
                    }
                    validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                }
                dnsServers = cm.getLinkProperties(active)?.dnsServers
                    ?.mapNotNull { it.hostAddress } ?: emptyList()
                vpnActive = cm.allNetworks.any { network ->
                    cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                }
                // When our VPN is up, the underlying network's transport is more useful.
                if (transport == "VPN") {
                    val underlying = cm.allNetworks.firstNotNullOfOrNull { network ->
                        val c = cm.getNetworkCapabilities(network) ?: return@firstNotNullOfOrNull null
                        if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) null
                        else when {
                            c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                            c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                            c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                            else -> null
                        }
                    }
                    if (underlying != null) transport = underlying
                }
            }
        }

        DeviceSecuritySnapshot(
            collectedAtEpochMs = System.currentTimeMillis(),
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            androidVersion = Build.VERSION.RELEASE ?: "",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = patch,
            patchAgeDays = patchAge,
            screenLockSecure = keyguard,
            storageEncrypted = encrypted,
            adbEnabled = adb,
            developerOptionsEnabled = devOptions,
            totalApps = totalApps,
            userApps = userApps,
            sideloadedApps = sideloaded,
            sideloadedPackages = sideloadedPackages,
            networkTransport = transport,
            networkValidated = validated,
            networkMetered = metered,
            dnsServers = dnsServers,
            systemVpnActive = vpnActive,
            unavailable = unavailable
        )
    }
}
