package com.adshield.pro.engine.location

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * AdShield Pro — Safe GPS capture (Android).
 *
 * Uses the platform [LocationManager] and nothing else: no Google Play Services dependency, no
 * account, no network request, no background service, no foreground service. Capture runs only
 * while the Safe GPS screen asks for it and is cancelled when the screen leaves composition.
 *
 * The sampling policy is the only honest way to get a *better* fix:
 *
 *  - each enabled provider is watched with `requestLocationUpdates`;
 *  - a cold GNSS receiver needs tens of seconds to converge, so the session keeps collecting until
 *    the device itself reports the target accuracy, the sample budget is spent, or time is up;
 *  - `Location.isMock` is propagated instead of hidden: a simulated fix must never be presented
 *    as a real emergency position;
 *  - timing uses [SystemClock.elapsedRealtimeNanos] (monotonic) so a clock change can never
 *    produce a fake "implausible movement" warning.
 */
class SafeGpsLocator(private val context: Context) {

    companion object {
        const val DEFAULT_SAMPLE_BUDGET = 12
        const val DEFAULT_TIMEOUT_MS = 30_000L
        /** A fix older than this is only a starting point, never a result. */
        private const val STALE_AFTER_MS = 120_000L
    }

    private val locationManager: LocationManager? =
        context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager

    fun hasProvider(): Boolean = runCatching {
        locationManager?.allProviders?.isNotEmpty() == true
    }.getOrDefault(false)

    fun permissionState(): LocationPermission {
        val coarse = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        val fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        if (fine != PackageManager.PERMISSION_GRANTED && coarse != PackageManager.PERMISSION_GRANTED) {
            return LocationPermission.NOT_DETERMINED
        }
        return LocationPermission.GRANTED
    }

    fun isPreciseGranted(): Boolean = ContextCompat.checkSelfPermission(
        context, Manifest.permission.ACCESS_FINE_LOCATION
    ) == PackageManager.PERMISSION_GRANTED

    /** Reads the device facts the checklist needs. Anything unreadable stays null ("unknown"). */
    @SuppressLint("MissingPermission")
    fun deviceContext(mockProvidersEnabled: Boolean? = null): DeviceLocationContext {
        val resolver = context.contentResolver
        val locationEnabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching { locationManager?.isLocationEnabled }.getOrNull()
        } else {
            runCatching {
                Settings.Secure.getInt(
                    resolver, Settings.Secure.LOCATION_MODE, Settings.Secure.LOCATION_MODE_OFF
                ) != Settings.Secure.LOCATION_MODE_OFF
            }.getOrNull()
        }
        // Hidden constant avoided: the public API exposes the same setting.
        val wifiScanning = runCatching {
            (context.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
                ?.isScanAlwaysAvailable
        }.getOrNull()
        val developerOptions = runCatching {
            Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }.getOrNull()
        return DeviceLocationContext(
            permission = permissionState(),
            systemLocationEnabled = locationEnabled,
            wifiScanningEnabled = wifiScanning,
            precisePermissionGranted = isPreciseGranted(),
            developerOptionsEnabled = developerOptions,
            // Only a reported fix can prove a mock provider is active; otherwise it stays unknown.
            mockProvidersEnabled = mockProvidersEnabled,
            encryptedNetworkAvailable = encryptedNetworkAvailable(),
            screenLockKnown = false
        )
    }

    private fun encryptedNetworkAvailable(): Boolean? = runCatching {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@runCatching null
        val network = connectivity.activeNetwork ?: return@runCatching null
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return@runCatching null
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
    }.getOrNull()

    /** The settings screen that actually fixes the blocker the checklist found. */
    fun settingIntent(target: DeviceSettingTarget): Intent = when (target) {
        DeviceSettingTarget.LOCATION_SOURCE,
        DeviceSettingTarget.LOCATION_SCAN -> Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)

        DeviceSettingTarget.DEVELOPER_OPTIONS -> Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)

        DeviceSettingTarget.APP_LOCATION_PERMISSIONS -> Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.parse("package:${context.packageName}")
        )
    }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * Emits every fix the platform reports, so the screen can show convergence while it happens.
     * Never completes on its own: the caller cancels, which unregisters the updates.
     */
    @SuppressLint("MissingPermission")
    fun collectFixes(providers: List<String>? = null): Flow<LocationFix> = callbackFlow {
        val manager = locationManager
        if (manager == null || permissionState() != LocationPermission.GRANTED) {
            close()
            return@callbackFlow
        }
        val enabled = (providers ?: runCatching { manager.getProviders(true) }.getOrDefault(emptyList()))
            .filter { provider ->
                provider != LocationManager.PASSIVE_PROVIDER &&
                    runCatching { manager.isProviderEnabled(provider) }.getOrDefault(false)
            }
        if (enabled.isEmpty()) {
            close()
            return@callbackFlow
        }

        // A recently cached fix is useful only as a fast first reading; it keeps its own accuracy
        // and timestamp, so the analysis shows it as the (worse) starting point instead of hiding it.
        runCatching { manager.getLastKnownLocation(LocationManager.GPS_PROVIDER) }
            .getOrNull()
            ?.takeIf { SystemClock.elapsedRealtime() - it.elapsedRealtimeNanos / 1_000_000 <= STALE_AFTER_MS }
            ?.let { trySend(it.toFix()) }

        val listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                trySend(location.toFix())
            }

            // Deprecated on API 29+ but still part of the interface on older devices.
            @Deprecated("Required by the platform interface")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit

            override fun onProviderEnabled(provider: String) = Unit

            override fun onProviderDisabled(provider: String) = Unit
        }

        for (provider in enabled) {
            runCatching { manager.requestLocationUpdates(provider, 500L, 0f, listener, context.mainLooper) }
        }

        awaitClose { runCatching { manager.removeUpdates(listener) } }
    }

    /**
     * One capture session: collects fixes until the target accuracy is reported [minSamples] times,
     * the sample budget is spent, or [timeoutMs] passes. Returns what it actually received — an
     * empty result is a valid answer and is reported as such by the UI.
     */
    suspend fun captureOnce(
        targetAccuracyMeters: Double = 10.0,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        sampleBudget: Int = DEFAULT_SAMPLE_BUDGET,
        minSamples: Int = 3,
        onFix: (fix: LocationFix, accepted: List<LocationFix>) -> Unit = { _, _ -> }
    ): CaptureResult = coroutineScope {
        if (permissionState() != LocationPermission.GRANTED) {
            return@coroutineScope CaptureResult(
                fixes = emptyList(),
                stopReason = "Location permission is not granted, so nothing can be located.",
                timedOut = false
            )
        }
        if (!hasProvider()) {
            return@coroutineScope CaptureResult(
                fixes = emptyList(),
                stopReason = "This device reports no location provider.",
                timedOut = false
            )
        }

        val accepted = mutableListOf<LocationFix>()
        var targetHits = 0
        val done = CompletableDeferred<String>()
        val collector = launch {
            collectFixes().collect { fix ->
                if (!LocationAnalyzer.isUsable(fix)) return@collect
                accepted += fix
                if (fix.accuracyMeters <= targetAccuracyMeters) targetHits++
                onFix(fix, accepted.toList())
                when {
                    targetHits >= minSamples -> done.complete("Target accuracy reached after ${accepted.size} fixes.")
                    accepted.size >= sampleBudget -> done.complete("Sample budget of $sampleBudget fixes reached.")
                }
            }
        }
        val reason = withTimeoutOrNull(timeoutMs) { done.await() }
        collector.cancelAndJoin()
        val timedOut = reason == null
        CaptureResult(
            fixes = accepted.toList(),
            stopReason = when {
                reason != null -> reason
                accepted.isEmpty() -> "No fix arrived within ${timeoutMs / 1000} s. Check the device location " +
                    "switch, and try again with a clear view of the sky."
                else -> "Deadline reached after ${accepted.size} fixes; the accuracy below is what the device " +
                    "reported at that point."
            },
            timedOut = timedOut
        )
    }
}

/** What a capture session actually received. */
data class CaptureResult(
    val fixes: List<LocationFix>,
    val stopReason: String,
    val timedOut: Boolean
) {
    val isEmpty: Boolean get() = fixes.isEmpty()
}

/** Converts a platform fix without inventing values it did not report. */
internal fun Location.toFix(): LocationFix = LocationFix(
    latitude = latitude,
    longitude = longitude,
    accuracyMeters = if (hasAccuracy()) accuracy.toDouble() else Double.NaN,
    elapsedRealtimeMs = elapsedRealtimeNanos / 1_000_000,
    wallClockMs = time,
    altitudeMeters = if (hasAltitude()) altitude else null,
    verticalAccuracyMeters = if (hasVerticalAccuracy()) verticalAccuracyMeters.toDouble() else null,
    speedMetersPerSecond = if (hasSpeed()) speed else null,
    source = when (provider) {
        LocationManager.GPS_PROVIDER -> FixSource.GNSS
        LocationManager.NETWORK_PROVIDER -> FixSource.NETWORK
        LocationManager.FUSED_PROVIDER -> FixSource.FUSED
        else -> FixSource.UNKNOWN
    },
    mock = isMocked()
)

/** `isMock` replaced `isFromMockProvider` in Android 12; both mean "the platform flagged this". */
@Suppress("DEPRECATION")
internal fun Location.isMocked(): Boolean {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return isMock
    return runCatching { isFromMockProvider }.getOrDefault(false)
}
