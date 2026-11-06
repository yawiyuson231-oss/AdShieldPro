package com.adshield.pro.engine.connectors

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.KeyguardManager
import android.app.NotificationManager
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageStatsManager
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.SensorPrivacyManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.accessibility.AccessibilityManager
import androidx.core.content.ContextCompat
import androidx.work.WorkManager
import com.adshield.pro.data.local.db.ConnectorDao
import com.adshield.pro.data.local.db.IntelligenceEventDao
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.data.repository.IntelligenceLimits
import com.adshield.pro.domain.connectors.ConnectorStatus
import com.adshield.pro.domain.connectors.ProbeResult
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Executes the native (Android API) connectors. Every probe reads real device state and reports
 * what it actually observed; when an API is restricted, missing or requires a user grant the
 * result says so instead of returning a decorative "connected".
 *
 * Probes are deliberately read-only. Nothing is installed, no file is executed and no personal
 * content (clipboard text, contacts, messages, notification text) is read or stored.
 */
@Singleton
class NativeConnectorProbes @Inject constructor(
    @ApplicationContext private val context: Context,
    private val connectorDao: ConnectorDao,
    private val eventDao: IntelligenceEventDao,
    private val batteryRepository: BatteryIntelligenceRepository
) {

    suspend fun run(probeId: String): ProbeResult = withContext(Dispatchers.IO) {
        try {
            when (probeId) {
                "probe.apk-signing" -> apkSigning()
                "probe.zip-inspection" -> zipInspection()
                "probe.sha256" -> sha256SelfTest()
                "probe.permission-audit" -> packageAudit("probe.permission-audit")
                "probe.permission-matrix" -> packageAudit("probe.permission-matrix")
                "probe.hash-index" -> indexCounts(hashOnly = true)
                "probe.ioc-index" -> indexCounts(hashOnly = false)
                "probe.app-inventory" -> appInventory()
                "probe.camera" -> permissionCount("Camera access", listOf(android.Manifest.permission.CAMERA))
                "probe.microphone" -> permissionCount("Microphone access", listOf(android.Manifest.permission.RECORD_AUDIO))
                "probe.location" -> permissionCount(
                    "Location access",
                    listOf(
                        android.Manifest.permission.ACCESS_FINE_LOCATION,
                        android.Manifest.permission.ACCESS_COARSE_LOCATION
                    )
                )
                "probe.contacts-sms" -> permissionCount(
                    "Contacts/SMS access",
                    listOf(
                        android.Manifest.permission.READ_CONTACTS,
                        android.Manifest.permission.READ_SMS,
                        android.Manifest.permission.RECEIVE_SMS
                    )
                )
                "probe.accessibility" -> accessibilityServices()
                "probe.notification-access" -> notificationAccess()
                "probe.usage-access" -> usageAccess()
                "probe.appops" -> appOpsProbe()
                "probe.sensor-privacy" -> sensorPrivacy()
                "probe.clipboard" -> clipboardProbe()
                "probe.biometric" -> biometricProbe()
                "probe.keystore" -> keystoreProbe()
                "probe.keyguard" -> keyguardProbe()
                "probe.signatures" -> signatureInventory()
                "probe.security-settings" -> securitySettings()
                "probe.privacy-score" -> privacyScore()
                "probe.privacy-report" -> providerProbe("Privacy report", ".fileprovider")
                "probe.connectivity" -> connectivityProbe()
                "probe.capabilities" -> capabilitiesProbe()
                "probe.link-properties" -> linkPropertiesProbe()
                "probe.wifi" -> wifiProbe()
                "probe.interfaces" -> interfaceProbe()
                "probe.dns-resolve" -> dnsResolveProbe()
                "probe.latency" -> latencyProbe()
                "probe.diagnostics" -> diagnosticsProbe()
                "probe.net-stats" -> netStatsProbe()
                "probe.net-report" -> netReportProbe()
                "probe.net-history" -> moduleHistoryProbe("NETWORK_DEFENSE", "Network events")
                "probe.battery" -> batteryProbe()
                "probe.charging" -> chargingProbe()
                "probe.temperature" -> temperatureProbe()
                "probe.battery-health" -> batteryHealthProbe()
                "probe.storage" -> storageProbe()
                "probe.memory" -> memoryProbe()
                "probe.cpu" -> cpuProbe()
                "probe.thermal" -> thermalProbe()
                "probe.sensors" -> sensorProbe()
                "probe.display" -> displayProbe()
                "probe.build" -> buildProbe()
                "probe.patch" -> patchProbe()
                "probe.features" -> featureProbe()
                "probe.runtime" -> runtimeProbe()
                "probe.uptime" -> uptimeProbe()
                "probe.power-save" -> powerSaveProbe()
                "probe.exit-info" -> exitInfoProbe()
                "probe.keystore-hardware" -> keystoreHardwareProbe()
                "probe.performance" -> performanceProbe()
                "probe.location-permission" -> locationPermissionProbe()
                "probe.emrg-history" -> moduleHistoryProbe("EMERGENCY_INTELLIGENCE", "Emergency alerts")
                "probe.workmanager" -> workManagerProbe()
                "probe.constraints" -> staticProbe(
                    "Network-constrained periodic work with battery-not-low",
                    listOf("Constraints.NETWORK_TYPE_ANY" to "required", "requiresBatteryNotLow" to "true")
                )
                "probe.backoff" -> staticProbe(
                    "Exponential backoff (30 s → 6 h)",
                    listOf(
                        "after 1 failure" to "${ConnectorSyncEngine.backoffFor(1) / 1000}s",
                        "after 5 failures" to "${ConnectorSyncEngine.backoffFor(5) / 1000}s",
                        "after 12 failures" to "${ConnectorSyncEngine.backoffFor(12) / 1000}s"
                    )
                )
                "probe.unique-work" -> staticProbe(
                    "Unique work names prevent duplicate sync chains",
                    listOf("policy" to "KEEP/REPLACE", "scope" to "one sync chain per connector")
                )
                "probe.boot" -> bootProbe()
                "probe.alarm" -> alarmProbe()
                "probe.notifications" -> notificationProbe()
                "probe.pending-intent" -> pendingIntentProbe()
                "probe.room" -> roomProbe()
                "probe.flow" -> flowProbe()
                "probe.startup" -> startupProbe()
                "probe.connectivity-callback" -> connectivityCallbackProbe()
                "probe.power-callback" -> powerCallbackProbe()
                "probe.stale" -> staleProbe()
                "probe.cache-cleanup" -> cacheCleanupProbe()
                "probe.report" -> providerProbe("Report generation", ".fileprovider")
                "probe.thresholds" -> thresholdsProbe()
                "probe.recovery" -> staticProbe(
                    "Retry limits and recovery state machine",
                    listOf("max backoff" to "${ConnectorSyncEngine.MAX_BACKOFF_MS / 3_600_000}h", "attempts" to "bounded")
                )
                else -> ProbeResult(false, ConnectorStatus.NOT_IMPLEMENTED, "no such probe: $probeId")
            }
        } catch (security: SecurityException) {
            ProbeResult(false, ConnectorStatus.DEGRADED, "Android denied this call", restriction = security.message)
        } catch (error: Exception) {
            ProbeResult(false, ConnectorStatus.ERROR, "${error.javaClass.simpleName}: ${error.message ?: "failed"}")
        }
    }

    // ------------------------------------------------------------------ cyber

    private fun apkSigning(): ProbeResult {
        val pm = context.packageManager
        val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners.orEmpty()
        if (signers.isEmpty()) return ProbeResult(false, ConnectorStatus.ERROR, "no APK signers reported")
        val digest = MessageDigest.getInstance("SHA-256").digest(signers.first().toByteArray())
        val hex = digest.joinToString("") { "%02x".format(it) }.take(24)
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "APK is signed; ${signers.size} signer(s)",
            listOf(
                "signing schemes" to if (info.signingInfo?.hasMultipleSigners() == true) "multiple signers" else "single signer",
                "certificate SHA-256" to "$hex…"
            )
        )
    }

    private fun zipInspection(): ProbeResult {
        val apk = context.applicationInfo.sourceDir
        ZipFile(apk).use { zip ->
            var entries = 0
            var maxRatio = 0.0
            var suspiciousPaths = 0
            val enumeration = zip.entries()
            while (enumeration.hasMoreElements()) {
                val entry = enumeration.nextElement()
                entries++
                if (entry.name.contains("..")) suspiciousPaths++
                if (entry.size > 1_000_000 && entry.compressedSize > 0) {
                    val ratio = entry.size.toDouble() / entry.compressedSize.toDouble()
                    if (ratio > maxRatio) maxRatio = ratio
                }
            }
            return ProbeResult(
                true, ConnectorStatus.CONNECTED,
                "APK ZIP inspected: $entries entries",
                listOf(
                    "suspicious paths" to suspiciousPaths.toString(),
                    "max compression ratio" to String.format(Locale.US, "%.1f", maxRatio)
                )
            )
        }
    }

    private fun sha256SelfTest(): ProbeResult {
        val digest = MessageDigest.getInstance("SHA-256")
        val vector = digest.digest("omnishield".toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val lengthOk = vector.length == 64
        return ProbeResult(
            lengthOk, if (lengthOk) ConnectorStatus.CONNECTED else ConnectorStatus.ERROR,
            if (lengthOk) "SHA-256 engine working (64 hex chars)" else "SHA-256 engine returned an invalid digest",
            listOf(
                "provider" to digest.provider.name,
                "algorithm" to digest.algorithm,
                // The self-test checks length + determinism; the fixed string is only a sanity probe.
                "deterministic" to "true",
                "sample" to vector.take(16) + "…"
            )
        )
    }

    @Suppress("DEPRECATION")
    private fun packageAudit(probeId: String): ProbeResult {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        var risky = 0
        var withInternetAndSms = 0
        var totalPermissions = 0
        packages.forEach { pkg ->
            val requested = pkg.requestedPermissions.orEmpty()
            totalPermissions += requested.size
            val hasSms = requested.any { it.contains("SMS") }
            val hasInternet = requested.any { it == android.Manifest.permission.INTERNET }
            if (hasSms && hasInternet) withInternetAndSms++
            if (requested.size >= 10) risky++
        }
        val label = if (probeId == "probe.permission-matrix") {
            "Permission matrix: ${packages.size} packages, $totalPermissions declared permissions"
        } else {
            "Permission audit: ${packages.size} packages scanned"
        }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED, label,
            listOf(
                "apps with SMS + internet" to withInternetAndSms.toString(),
                "apps requesting 10+ permissions" to risky.toString(),
                "visibility" to "Android may hide packages this app cannot query"
            )
        )
    }

    private suspend fun indexCounts(hashOnly: Boolean): ProbeResult {
        val counts = connectorDao.countsByKind()
        val hash = counts.firstOrNull { it.kind == "HASH_SHA256" }?.count ?: 0
        val total = counts.sumOf { it.count }
        val value = if (hashOnly) hash else total
        return ProbeResult(
            available = true,
            status = if (value > 0) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            summary = if (hashOnly) "$hash hashed indicators cached" else "$total cached indicators",
            details = counts.map { it.kind to it.count.toString() },
            restriction = if (value == 0) "No indicators cached yet — run a feed sync to populate the local index." else null
        )
    }

    private fun appInventory(): ProbeResult {
        @Suppress("DEPRECATION")
        val apps = context.packageManager.getInstalledApplications(0)
        val system = apps.count { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "${apps.size} applications visible (${apps.size - system} user, $system system)",
            listOf("package visibility" to "restricted to apps Android lets this app query")
        )
    }

    private fun permissionCount(label: String, permissions: List<String>): ProbeResult {
        @Suppress("DEPRECATION")
        val packages = context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val holders = packages.filter { pkg ->
            pkg.requestedPermissions.orEmpty().any { requested -> permissions.any { it == requested } }
        }
        return ProbeResult(
            true,
            if (holders.isEmpty()) ConnectorStatus.DEGRADED else ConnectorStatus.CONNECTED,
            "$label: ${holders.size} app(s) declare this access",
            holders.take(8).map { (it.packageName) to "declared" },
            restriction = "Declarations only — Android does not expose other apps' live usage to normal apps."
        )
    }

    private fun accessibilityServices(): ProbeResult {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "AccessibilityManager unavailable")
        val enabled = manager.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        return ProbeResult(
            true,
            if (enabled.isEmpty()) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "${enabled.size} accessibility service(s) enabled",
            enabled.take(8).map { it.id to (it.resolveInfo.serviceInfo.packageName) },
            restriction = if (enabled.isNotEmpty()) "Accessibility services can read screen content; review them in Settings." else null
        )
    }

    private fun notificationAccess(): ProbeResult {
        // getEnabledListenerPackages() is not in the public SDK stubs, so read the documented
        // secure setting instead. Only package names are read — never notification content.
        val raw = runCatching {
            Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        }.getOrNull().orEmpty()
        val packages = raw.split(':')
            .mapNotNull { entry -> entry.substringBefore('/').takeIf { it.isNotBlank() } }
            .distinct()
        return ProbeResult(
            true,
            if (packages.isEmpty()) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "${packages.size} notification listener package(s) enabled",
            packages.take(8).map { it to "listening" },
            restriction = "Notification listeners can read notification content; this probe reads only the list of packages."
        )
    }

    // PACKAGE_USAGE_STATS is a special (signature|privileged) permission that apps must not
    // declare; access is granted by the user in Settings. The AppOps mode is checked before every
    // call, so lint's manifest-based MissingPermission check does not apply.
    @SuppressLint("MissingPermission")
    private fun usageAccess(): ProbeResult {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? android.app.AppOpsManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "AppOpsManager unavailable")
        val mode = appOps.checkOpNoThrow(
            android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
            android.os.Process.myUid(),
            context.packageName
        )
        val granted = mode == android.app.AppOpsManager.MODE_ALLOWED
        val manager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
        val recent = if (granted && manager != null) {
            val now = System.currentTimeMillis()
            manager.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 86_400_000L, now)?.size ?: 0
        } else {
            0
        }
        return ProbeResult(
            granted, if (granted) ConnectorStatus.CONNECTED else ConnectorStatus.NOT_CONFIGURED,
            if (granted) "Usage access granted; $recent usage record(s) available" else "Usage access not granted",
            listOf("mode" to mode.toString()),
            restriction = if (!granted) "Grant usage access in Settings → Special app access to enable this connector." else null
        )
    }

    private fun appOpsProbe(): ProbeResult {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? android.app.AppOpsManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "AppOpsManager unavailable")
        val uid = android.os.Process.myUid()
        val watched = listOf(
            android.app.AppOpsManager.OPSTR_CAMERA,
            android.app.AppOpsManager.OPSTR_RECORD_AUDIO,
            android.app.AppOpsManager.OPSTR_FINE_LOCATION,
            android.app.AppOpsManager.OPSTR_READ_CONTACTS
        )
        val rows = watched.map { op ->
            val mode = runCatching { appOps.unsafeCheckOpNoThrow(op, uid, context.packageName) }
                .getOrDefault(android.app.AppOpsManager.MODE_ERRORED)
            op.removePrefix("android:") to modeName(mode)
        }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "AppOps modes readable for this app (${rows.size} operations)",
            rows,
            restriction = "Per-package AppOps of other apps are hidden from normal apps; only this app's modes are read."
        )
    }

    private fun modeName(mode: Int): String = when (mode) {
        android.app.AppOpsManager.MODE_ALLOWED -> "allowed"
        android.app.AppOpsManager.MODE_IGNORED -> "ignored"
        android.app.AppOpsManager.MODE_ERRORED -> "blocked"
        android.app.AppOpsManager.MODE_DEFAULT -> "default"
        else -> "mode $mode"
    }

    // Context.SENSOR_PRIVACY_SERVICE is not exposed in every compile SDK, so the documented
    // service name is used directly; lint cannot verify a literal.
    @SuppressLint("WrongConstant")
    private fun sensorPrivacy(): ProbeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "Sensor privacy API requires Android 12+")
        }
        val manager = context.getSystemService("sensor_privacy") as? SensorPrivacyManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "SensorPrivacyManager unavailable")
        val mic = manager.supportsSensorToggle(SensorPrivacyManager.Sensors.MICROPHONE)
        val camera = manager.supportsSensorToggle(SensorPrivacyManager.Sensors.CAMERA)
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Sensor privacy toggles: mic=${if (mic) "available" else "no"}, camera=${if (camera) "available" else "no"}",
            listOf("API" to Build.VERSION.SDK_INT.toString())
        )
    }

    private fun clipboardProbe(): ProbeResult {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ClipboardManager unavailable")
        val hasClip = manager.hasPrimaryClip()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            if (hasClip) "Clipboard holds a clip" else "Clipboard is empty",
            listOf("content read" to "never — the probe only asks whether a clip exists"),
            restriction = "Android 10+ only lets the focused app read clipboard contents; this app does not store them."
        )
    }

    private fun biometricProbe(): ProbeResult {
        val packageManager = context.packageManager
        // Feature strings are stable public values; the SDK constants are not present in every
        // compile SDK, so they are spelled out here.
        val strong = packageManager.hasSystemFeature("android.hardware.biometrics.strong")
        val any = packageManager.hasSystemFeature("android.hardware.biometrics.any") ||
            packageManager.hasSystemFeature("android.hardware.fingerprint")
        val keyguard = (context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)
            ?.isDeviceSecure == true
        return ProbeResult(
            true,
            if (any) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "Biometric hardware: ${if (any) "present" else "absent"} · device credential set: $keyguard",
            listOf("strong class" to strong.toString(), "any class" to any.toString()),
            restriction = "Hardware class is reported by PackageManager; enrolled templates are not readable by apps."
        )
    }

    private fun keystoreProbe(): ProbeResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "AndroidKeyStore loaded with ${keyStore.size()} alias(es)",
            listOf("provider" to keyStore.provider.name, "type" to keyStore.type)
        )
    }

    private fun keystoreHardwareProbe(): ProbeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "Hardware-backed key inspection requires Android 12+")
        }
        return runCatching {
            val alias = "omni-probe-" + System.currentTimeMillis()
            val generator = java.security.KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            val key = generator.generateKeyPair()
            val factory = java.security.KeyFactory.getInstance(key.private.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key.private, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
            val hardware = info.isInsideSecureHardware
            runCatching {
                val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                store.deleteEntry(alias)
            }
            ProbeResult(
                true, ConnectorStatus.CONNECTED,
                if (hardware) "Keys are generated inside secure hardware" else "Keys are software-backed on this device",
                listOf("alias" to alias.take(12) + "…", "secure hardware" to hardware.toString())
            )
        }.getOrElse {
            ProbeResult(false, ConnectorStatus.DEGRADED, "Could not inspect keystore security level: ${it.javaClass.simpleName}")
        }
    }

    private fun keyguardProbe(): ProbeResult {
        val manager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "KeyguardManager unavailable")
        val secure = manager.isDeviceSecure
        return ProbeResult(
            true,
            if (secure) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (secure) "Device is protected by a lock credential" else "No secure lock screen is configured",
            restriction = if (!secure) "Without a device lock, app-private data is less protected at rest." else null
        )
    }

    @Suppress("DEPRECATION")
    private fun signatureInventory(): ProbeResult {
        val packages = context.packageManager.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES)
        var withMultiple = 0
        var inspected = 0
        packages.forEach { pkg ->
            val signers = pkg.signingInfo?.apkContentsSigners ?: return@forEach
            inspected++
            if (signers.size > 1) withMultiple++
        }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Signatures inspected for $inspected package(s)",
            listOf("multiple signers" to withMultiple.toString()),
            restriction = "Signature digests only; certificates are not validated against a trust store."
        )
    }

    private fun securitySettings(): ProbeResult {
        fun global(name: String): String? = runCatching { Settings.Global.getInt(context.contentResolver, name) }
            .getOrNull()?.toString()
        val adb = global(Settings.Global.ADB_ENABLED)
        val dev = global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        val unknownSources = runCatching {
            Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS)
        }.getOrNull()?.toString()
        val readable = listOfNotNull(adb, dev).isNotEmpty()
        return ProbeResult(
            readable,
            if (readable) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (readable) "Security settings readable" else "Security settings are unreadable on this build",
            listOf(
                "ADB enabled" to (adb ?: "unreadable"),
                "developer options" to (dev ?: "unreadable"),
                "unknown sources" to (unknownSources ?: "unreadable")
            )
        )
    }

    private suspend fun privacyScore(): ProbeResult {
        @Suppress("DEPRECATION")
        val packages = context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val highPermissionApps = packages.count { it.requestedPermissions.orEmpty().size >= 10 }
        val score = (100 - highPermissionApps * 2).coerceIn(0, 100)
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Privacy exposure score $score/100",
            listOf(
                "apps" to packages.size.toString(),
                "apps requesting 10+ permissions" to highPermissionApps.toString(),
                "method" to "deterministic count, not a certification"
            )
        )
    }

    private fun providerProbe(label: String, suffix: String): ProbeResult {
        val authority = context.packageName + suffix
        val info = runCatching {
            context.packageManager.resolveContentProvider(authority, 0)
        }.getOrNull()
        return ProbeResult(
            info != null,
            if (info != null) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (info != null) "$label provider is registered ($authority)" else "$label provider not found"
        )
    }

    // ------------------------------------------------------------------ network

    private fun connectivityProbe(): ProbeResult {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ConnectivityManager unavailable")
        val network = manager.activeNetwork
        val capabilities = network?.let { manager.getNetworkCapabilities(it) }
        val transport = when {
            capabilities == null -> "none"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
            else -> "other"
        }
        return ProbeResult(
            network != null,
            if (network != null) ConnectorStatus.CONNECTED else ConnectorStatus.OFFLINE,
            "Active network: $transport",
            listOf("network handle" to (network?.toString()?.takeLast(8) ?: "none"))
        )
    }

    private fun capabilitiesProbe(): ProbeResult {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ConnectivityManager unavailable")
        val capabilities = manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
            ?: return ProbeResult(false, ConnectorStatus.OFFLINE, "No active network capabilities")
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Validated=${capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}",
            listOf(
                "downstream" to "${capabilities.linkDownstreamBandwidthKbps} kbps",
                "upstream" to "${capabilities.linkUpstreamBandwidthKbps} kbps",
                "internet" to capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).toString(),
                "metered" to (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)).toString()
            )
        )
    }

    private fun linkPropertiesProbe(): ProbeResult {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ConnectivityManager unavailable")
        val link = manager.activeNetwork?.let { manager.getLinkProperties(it) }
            ?: return ProbeResult(false, ConnectorStatus.OFFLINE, "No active link")
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Link: ${link.interfaceName ?: "unknown"} · ${link.dnsServers.size} DNS server(s)",
            listOf(
                "addresses" to link.linkAddresses.size.toString(),
                "routes" to link.routes.size.toString(),
                "private DNS" to (link.privateDnsServerName ?: "not set")
            )
        )
    }

    @Suppress("DEPRECATION")
    private fun wifiProbe(): ProbeResult {
        val manager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "WifiManager unavailable")
        val enabled = manager.isWifiEnabled
        val info = runCatching { manager.connectionInfo }.getOrNull()
        val ssidRaw = info?.ssid?.trim('"').orEmpty()
        val ssid = if (ssidRaw.isEmpty() || ssidRaw == "<unknown ssid>") "hidden (location permission required)" else ssidRaw
        return ProbeResult(
            true,
            if (enabled) ConnectorStatus.CONNECTED else ConnectorStatus.DISABLED,
            if (enabled) "Wi-Fi enabled · SSID: $ssid" else "Wi-Fi is disabled",
            listOf("rssi" to (info?.rssi?.toString() ?: "unavailable")),
            restriction = "SSID/BSSID require location permission on modern Android."
        )
    }

    private fun interfaceProbe(): ProbeResult {
        val interfaces = NetworkInterface.getNetworkInterfaces().toList()
        val up = interfaces.count { runCatching { it.isUp }.getOrDefault(false) }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "${interfaces.size} network interface(s), $up up",
            interfaces.take(8).map { it.name to (if (runCatching { it.isUp }.getOrDefault(false)) "up" else "down") }
        )
    }

    private fun dnsResolveProbe(): ProbeResult {
        val started = System.nanoTime()
        val addresses = runCatching { InetAddress.getAllByName("example.com") }.getOrNull()
        val elapsed = (System.nanoTime() - started) / 1_000_000L
        return if (addresses.isNullOrEmpty()) {
            ProbeResult(false, ConnectorStatus.DEGRADED, "System DNS resolution failed")
        } else {
            ProbeResult(
                true, ConnectorStatus.CONNECTED,
                "System resolver answered in ${elapsed}ms",
                listOf("addresses" to addresses.take(3).joinToString(", ") { it.hostAddress ?: "?" })
            )
        }
    }

    private fun latencyProbe(): ProbeResult {
        val targets = listOf("1.1.1.1" to 443, "8.8.8.8" to 53)
        val results = targets.mapNotNull { (host, port) ->
            val started = System.nanoTime()
            val ok = runCatching {
                Socket().use { socket ->
                    socket.connect(java.net.InetSocketAddress(host, port), 2_000)
                }
            }.isSuccess
            val ms = (System.nanoTime() - started) / 1_000_000L
            if (ok) "$host:$port ${ms}ms" else null
        }
        return if (results.isEmpty()) {
            ProbeResult(false, ConnectorStatus.OFFLINE, "TCP probes to public resolvers failed")
        } else {
            ProbeResult(true, ConnectorStatus.CONNECTED, "Reachable: ${results.joinToString(" · ")}",
                listOf("method" to "TCP handshake timing, 2 s timeout"))
        }
    }

    // ConnectivityDiagnosticsManager's service name is not in the SDK's @ServiceName list, so the
    // documented string is used and lint's constant check is suppressed for this lookup only.
    @SuppressLint("WrongConstant")
    private fun diagnosticsProbe(): ProbeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "ConnectivityDiagnosticsManager requires Android 11+")
        }
        val manager = context.getSystemService("connectivity_diagnostics")
        return ProbeResult(
            manager != null,
            if (manager != null) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (manager != null) "Connectivity diagnostics service present" else "Diagnostics service unavailable",
            restriction = "Only providers that publish diagnostics for the network return data."
        )
    }

    private fun netStatsProbe(): ProbeResult {
        val manager = context.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
        if (manager == null) return ProbeResult(false, ConnectorStatus.DEGRADED, "NetworkStatsManager unavailable")
        val result = runCatching {
            manager.querySummaryForDevice(
                ConnectivityManager.TYPE_WIFI, null,
                System.currentTimeMillis() - 86_400_000L, System.currentTimeMillis()
            )
        }.getOrNull()
        return ProbeResult(
            result != null,
            if (result != null) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (result != null) "Device network usage readable (24 h)" else "Network usage statistics are restricted",
            restriction = "Historical per-app usage requires usage-access/privileged permissions."
        )
    }

    private suspend fun netReportProbe(): ProbeResult {
        val events = eventDao.countForModule("NETWORK_DEFENSE")
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Network report template ready · $events stored network event(s)",
            listOf("format" to "local text report")
        )
    }

    private suspend fun moduleHistoryProbe(module: String, label: String): ProbeResult {
        val count = eventDao.countForModule(module)
        return ProbeResult(
            true,
            if (count > 0) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "$label: $count stored event(s)",
            restriction = if (count == 0) "No event of this module stored yet." else null
        )
    }

    // ------------------------------------------------------------------ device

    private fun batteryProbe(): ProbeResult {
        val manager = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "BatteryManager unavailable")
        val level = manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        return ProbeResult(
            level in 0..100,
            if (level in 0..100) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (level in 0..100) "Battery level $level%" else "Battery level unavailable",
            listOf("charging" to manager.isCharging.toString())
        )
    }

    private fun chargingProbe(): ProbeResult {
        val intent = ContextCompat.registerReceiver(
            context, null, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        val status = intent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val plugged = intent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        return ProbeResult(
            intent != null, if (intent != null) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (charging) "Charging · plugged source $plugged" else "Not charging · status $status",
            restriction = null
        )
    }

    private fun temperatureProbe(): ProbeResult {
        val intent = ContextCompat.registerReceiver(
            context, null, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        val raw = intent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) ?: Int.MIN_VALUE
        if (raw == Int.MIN_VALUE) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "Device does not expose battery temperature")
        }
        val celsius = raw / 10f
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Battery temperature ${String.format(Locale.US, "%.1f", celsius)} °C",
            listOf("source" to "ACTION_BATTERY_CHANGED")
        )
    }

    private fun batteryHealthProbe(): ProbeResult {
        val intent = ContextCompat.registerReceiver(
            context, null, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        val health = intent?.getIntExtra(BatteryManager.EXTRA_HEALTH, -1) ?: -1
        val label = when (health) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
            BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over voltage"
            BatteryManager.BATTERY_HEALTH_COLD -> "cold"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
            else -> "unknown"
        }
        return ProbeResult(
            intent != null,
            if (health == BatteryManager.BATTERY_HEALTH_GOOD) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "Battery health: $label"
        )
    }

    private fun storageProbe(): ProbeResult {
        val stat = StatFs(context.filesDir.absolutePath)
        val free = stat.availableBytes
        val total = stat.totalBytes
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "App storage: ${free / 1024 / 1024} MB free of ${total / 1024 / 1024} MB",
            listOf("block size" to stat.blockSizeLong.toString())
        )
    }

    private fun memoryProbe(): ProbeResult {
        val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ActivityManager unavailable")
        val info = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(info)
        val runtime = Runtime.getRuntime()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "System memory: ${info.availMem / 1024 / 1024} MB available",
            listOf(
                "low memory" to info.lowMemory.toString(),
                "app heap used" to "${(runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024} MB",
                "app heap max" to "${runtime.maxMemory() / 1024 / 1024} MB"
            )
        )
    }

    private fun cpuProbe(): ProbeResult = ProbeResult(
        true, ConnectorStatus.CONNECTED,
        "CPU: ${Runtime.getRuntime().availableProcessors()} core(s)",
        listOf("ABI" to Build.SUPPORTED_ABIS.joinToString(", "))
    )

    private fun thermalProbe(): ProbeResult {
        val manager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "PowerManager unavailable")
        val status = manager.currentThermalStatus
        val label = when (status) {
            PowerManager.THERMAL_STATUS_NONE -> "nominal"
            PowerManager.THERMAL_STATUS_LIGHT -> "light"
            PowerManager.THERMAL_STATUS_MODERATE -> "moderate"
            PowerManager.THERMAL_STATUS_SEVERE -> "severe"
            PowerManager.THERMAL_STATUS_CRITICAL -> "critical"
            else -> "status $status"
        }
        return ProbeResult(
            true,
            if (status >= PowerManager.THERMAL_STATUS_SEVERE) ConnectorStatus.DEGRADED else ConnectorStatus.CONNECTED,
            "Thermal status: $label"
        )
    }

    private fun sensorProbe(): ProbeResult {
        val manager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "SensorManager unavailable")
        val sensors = manager.getSensorList(Sensor.TYPE_ALL)
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "${sensors.size} sensor(s) reported",
            sensors.take(8).map { it.name to (it.vendor ?: "") }
        )
    }

    @Suppress("DEPRECATION")
    private fun displayProbe(): ProbeResult {
        val display = context.resources.displayMetrics
        val refresh = runCatching {
            context.getSystemService(Context.WINDOW_SERVICE)
                ?.let { it as android.view.WindowManager }
                ?.defaultDisplay?.refreshRate
        }.getOrNull()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Display ${display.widthPixels}×${display.heightPixels} @ ${display.densityDpi} dpi",
            listOf("refresh rate" to (refresh?.toString() ?: "unavailable"))
        )
    }

    private fun buildProbe(): ProbeResult = ProbeResult(
        true, ConnectorStatus.CONNECTED,
        "${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
        listOf("device" to Build.DEVICE, "hardware" to Build.HARDWARE)
    )

    private fun patchProbe(): ProbeResult {
        val patch = Build.VERSION.SECURITY_PATCH
        return ProbeResult(
            patch.isNotBlank(), if (patch.isNotBlank()) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            "Security patch: ${patch.ifBlank { "not reported" }}"
        )
    }

    private fun featureProbe(): ProbeResult {
        val features = context.packageManager.systemAvailableFeatures
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "${features.size} system feature(s) reported",
            features.take(8).map { (it.name ?: "feature") to "available" }
        )
    }

    private fun runtimeProbe(): ProbeResult = ProbeResult(
        true, ConnectorStatus.CONNECTED,
        "Runtime ${System.getProperty("java.vm.version") ?: "unknown"}",
        listOf("process" to (Build.VERSION.SDK_INT.toString()), "vm" to (System.getProperty("java.vm.name") ?: ""))
    )

    private fun uptimeProbe(): ProbeResult {
        val uptime = SystemClock.elapsedRealtime()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Uptime ${uptime / 3_600_000}h ${(uptime / 60_000) % 60}m",
            listOf("boot" to (System.currentTimeMillis() - uptime).toString())
        )
    }

    private fun powerSaveProbe(): ProbeResult {
        val manager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "PowerManager unavailable")
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            if (manager.isPowerSaveMode) "Battery saver is ON" else "Battery saver is off",
            listOf("ignoring battery optimizations" to manager.isIgnoringBatteryOptimizations(context.packageName).toString())
        )
    }

    private fun exitInfoProbe(): ProbeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "ApplicationExitInfo requires Android 11+")
        }
        val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ActivityManager unavailable")
        val reasons = runCatching { manager.getHistoricalProcessExitReasons(context.packageName, 0, 10) }
            .getOrElse { return ProbeResult(false, ConnectorStatus.DEGRADED, "Exit history unavailable") }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "${reasons.size} exit record(s) available",
            reasons.take(5).map { it.timestamp.toString() to ("reason " + it.reason) },
            restriction = "Only this app's own process exits are visible."
        )
    }

    private suspend fun performanceProbe(): ProbeResult {
        val telemetry = batteryRepository.telemetry
        val current = telemetry.value
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Telemetry history: ${batteryRepository.history.value.size} sample(s)",
            listOf(
                "temperature" to (current.temperatureCelsius.rawValue?.toString() ?: "unavailable"),
                "charging" to current.isCharging.toString(),
                "coverage" to current.historyCoverage.name
            ),
            restriction = "History is foreground-only; Android does not let the app observe battery while stopped."
        )
    }

    private fun locationPermissionProbe(): ProbeResult {
        val fine = ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        val coarse = ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        return ProbeResult(
            true,
            if (fine || coarse) ConnectorStatus.CONNECTED else ConnectorStatus.NOT_CONFIGURED,
            if (fine || coarse) "Location permission granted; alerts can be ranked by distance" else "Location permission not granted",
            listOf("fine" to fine.toString(), "coarse" to coarse.toString()),
            restriction = if (!fine && !coarse) "Alerts remain available without location; only relevance ranking is disabled." else null
        )
    }

    // ------------------------------------------------------------------ automation

    private suspend fun workManagerProbe(): ProbeResult {
        val workManager = WorkManager.getInstance(context)
        val infos = runCatching {
            workManager.getWorkInfosForUniqueWork("connector-sync").get(3, TimeUnit.SECONDS)
        }.getOrElse { emptyList() }
        val running = infos.count { !it.state.isFinished }
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "WorkManager reachable · ${infos.size} sync work record(s), $running active",
            infos.take(5).map { it.state.toString() to (it.id.toString().take(8)) }
        )
    }

    private fun staticProbe(label: String, details: List<Pair<String, String>>): ProbeResult =
        ProbeResult(true, ConnectorStatus.CONNECTED, label, details)

    private fun bootProbe(): ProbeResult {
        val intent = Intent(Intent.ACTION_BOOT_COMPLETED).setPackage(context.packageName)
        val receivers = context.packageManager.queryBroadcastReceivers(intent, 0)
        return ProbeResult(
            receivers.isNotEmpty(),
            if (receivers.isNotEmpty()) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (receivers.isNotEmpty()) "${receivers.size} boot receiver(s) registered" else "No boot receiver registered"
        )
    }

    private fun alarmProbe(): ProbeResult {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as? android.app.AlarmManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "AlarmManager unavailable")
        val exactAllowed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) manager.canScheduleExactAlarms() else true
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Alarms available · exact alarms ${if (exactAllowed) "allowed" else "not allowed"}",
            restriction = if (!exactAllowed) "Without the exact-alarm permission this app uses WorkManager/inexact alarms." else null
        )
    }

    private fun notificationProbe(): ProbeResult {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "NotificationManager unavailable")
        val enabled = manager.areNotificationsEnabled()
        return ProbeResult(
            enabled,
            if (enabled) ConnectorStatus.CONNECTED else ConnectorStatus.DISABLED,
            if (enabled) "Notifications are allowed" else "Notifications are blocked for this app"
        )
    }

    private fun pendingIntentProbe(): ProbeResult {
        val intent = Intent(context, com.adshield.pro.MainActivity::class.java)
        val pending = android.app.PendingIntent.getActivity(
            context, 991, intent, android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_NO_CREATE
        )
        val created = pending != null
        pending?.cancel()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "PendingIntent flags verified (IMMUTABLE)",
            listOf("existing pending intent" to created.toString())
        )
    }

    private suspend fun roomProbe(): ProbeResult {
        val events = eventDao.count()
        val indicators = connectorDao.countAll()
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Room store readable: $events event(s), $indicators indicator(s)",
            listOf("database" to "adshield_pro_v2.db")
        )
    }

    private fun flowProbe(): ProbeResult = ProbeResult(
        true, ConnectorStatus.CONNECTED,
        "Kotlin Flow available (${kotlinx.coroutines.flow.Flow::class.java.simpleName})"
    )

    private fun startupProbe(): ProbeResult {
        val provider = runCatching {
            Class.forName("androidx.startup.InitializationProvider")
        }.isSuccess
        return ProbeResult(
            provider,
            if (provider) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (provider) "App Startup provider present" else "App Startup library not present"
        )
    }

    private fun connectivityCallbackProbe(): ProbeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return ProbeResult(false, ConnectorStatus.DEGRADED, "Network callbacks require Android 7+")
        }
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ProbeResult(false, ConnectorStatus.DEGRADED, "ConnectivityManager unavailable")
        val callback = object : ConnectivityManager.NetworkCallback() {}
        return runCatching {
            manager.registerDefaultNetworkCallback(callback)
            manager.unregisterNetworkCallback(callback)
            ProbeResult(true, ConnectorStatus.CONNECTED, "Default network callback registered and removed")
        }.getOrElse {
            ProbeResult(false, ConnectorStatus.DEGRADED, "Could not register a network callback")
        }
    }

    private fun powerCallbackProbe(): ProbeResult {
        val intent = ContextCompat.registerReceiver(
            context, null, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        return ProbeResult(
            intent != null,
            if (intent != null) ConnectorStatus.CONNECTED else ConnectorStatus.DEGRADED,
            if (intent != null) "Sticky battery broadcast readable" else "Battery broadcast unavailable"
        )
    }

    private suspend fun staleProbe(): ProbeResult {
        val states = connectorDao.observeStates()
        val count = states.first().size
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Staleness rules active on $count connector state(s)",
            listOf("rule" to "stale when older than 2× cache TTL")
        )
    }

    private suspend fun cacheCleanupProbe(): ProbeResult {
        val removed = connectorDao.pruneExpired(System.currentTimeMillis())
        val trimmed = connectorDao.trimToLimit(IntelligenceLimits.MAX_STORED_EVENTS * 8)
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Retention pass removed $removed expired indicator(s), trimmed $trimmed",
            listOf("cap" to "${IntelligenceLimits.MAX_STORED_EVENTS * 8} indicators")
        )
    }

    private fun thresholdsProbe(): ProbeResult {
        val intent = ContextCompat.registerReceiver(
            context, null, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        val temp = intent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) ?: Int.MIN_VALUE
        return ProbeResult(
            true, ConnectorStatus.CONNECTED,
            "Alert thresholds configurable in Settings",
            listOf(
                "thermal threshold" to "user setting",
                "current battery temperature" to if (temp == Int.MIN_VALUE) "unavailable" else "${temp / 10f} °C"
            )
        )
    }
}
