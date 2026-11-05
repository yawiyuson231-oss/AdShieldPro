package com.adshield.pro.gps.engine

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.GnssStatus
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.OnNmeaMessageListener
import android.os.Build
import android.os.Bundle
import android.os.Looper
import androidx.core.content.ContextCompat
import com.adshield.pro.gps.geo.GeoPoint
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.callbackFlow
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AdShield Pro — GNSS source.
 *
 * Uses `LocationManager` directly rather than a fused provider, on purpose:
 *  - the raw GNSS provider exposes satellite counts, Doppler speed/bearing and accuracy that a
 *    fused/network blend hides;
 *  - no Google Play Services dependency, so the module works on de-Googled devices and adds no
 *    binary that needs network access.
 *
 * Everything delivered here is a real system fix. Nothing is synthesized: if the provider has no
 * fix, the flow stays silent and the UI shows "Searching for satellites".
 */
class GnssLocationSource(
    private val context: Context
) {

    private val locationManager: LocationManager? =
        context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager

    private val _satellites = MutableSharedFlow<SatelliteSnapshot>(replay = 1, extraBufferCapacity = 8)
    val satellites: Flow<SatelliteSnapshot> = _satellites.asSharedFlow()

    /** True while a location request is registered. */
    private val listening = AtomicBoolean(false)
    val isListening: Boolean get() = listening.get()

    fun hasFinePermission(): Boolean = ContextCompat.checkSelfPermission(
        context, Manifest.permission.ACCESS_FINE_LOCATION
    ) == PackageManager.PERMISSION_GRANTED

    fun hasCoarsePermission(): Boolean = ContextCompat.checkSelfPermission(
        context, Manifest.permission.ACCESS_COARSE_LOCATION
    ) == PackageManager.PERMISSION_GRANTED

    fun isLocationEnabled(): Boolean = try {
        locationManager?.isLocationEnabled == true
    } catch (t: Throwable) {
        false
    }

    fun hasGpsProvider(): Boolean = try {
        locationManager?.allProviders?.contains(LocationManager.GPS_PROVIDER) == true
    } catch (t: Throwable) {
        false
    }

    fun enabledProviders(): List<String> = try {
        locationManager?.getProviders(true)?.toList().orEmpty()
    } catch (t: Throwable) {
        emptyList()
    }

    /**
     * Streams fixes until the collector is cancelled. The provider is chosen from the permissions
     * actually held, so a coarse-only grant degrades to network fixes instead of throwing.
     */
    @SuppressLint("MissingPermission")
    fun fixes(
        intervalMs: Long = 1_000L,
        minDistanceMeters: Float = 0f,
        preferGnss: Boolean = true
    ): Flow<GnssFix> = callbackFlow {
        val manager = locationManager
        if (manager == null || (!hasFinePermission() && !hasCoarsePermission())) {
            close()
            return@callbackFlow
        }

        val wanted = buildList {
            if (preferGnss && hasFinePermission() && hasGpsProvider()) add(LocationManager.GPS_PROVIDER)
            if (hasFinePermission()) add(LocationManager.FUSED_PROVIDER)
            if (hasCoarsePermission()) add(LocationManager.NETWORK_PROVIDER)
            if (hasFinePermission()) add(LocationManager.PASSIVE_PROVIDER)
        }.distinct()

        val listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                trySend(location.toGnssFix())
            }

            @Deprecated("Required by the platform interface below API 30")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit

            override fun onProviderEnabled(provider: String) = Unit

            override fun onProviderDisabled(provider: String) = Unit
        }

        // The last known fix is delivered first so the UI is not blank while the receiver locks on.
        // It is flagged as cached so the integrity monitor can treat it as possibly stale.
        runCatching {
            manager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: manager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
        }.getOrNull()?.let { last ->
            trySend(last.toGnssFix(cached = true))
        }

        wanted.forEach { provider ->
            runCatching {
                manager.requestLocationUpdates(provider, intervalMs, minDistanceMeters, listener, Looper.getMainLooper())
            }
        }
        listening.set(true)

        awaitClose {
            listening.set(false)
            runCatching { manager.removeUpdates(listener) }
        }
    }

    /**
     * Satellite diagnostics from `GnssStatus`. Only emitted on devices that actually report status;
     * on a device without GNSS hardware the flow never emits and the UI says so.
     */
    @SuppressLint("MissingPermission")
    fun satelliteStatus(): Flow<SatelliteSnapshot> = callbackFlow {
        val manager = locationManager
        if (manager == null || !hasFinePermission()) {
            close()
            return@callbackFlow
        }
        // Local, self-contained builder: a private function would capture the channel differently
        // and a nested one is easier to keep free of outer state.
        val onStatus: (GnssStatus) -> Unit = { status ->
            val visible = status.satelliteCount
            var usedInFix = 0
            var snrSum = 0.0
            var snrCount = 0
            var best = 0.0f
            val constellations = LinkedHashSet<String>()
            val satellites = ArrayList<SatelliteInfo>(visible)
            for (index in 0 until visible) {
                val constellation = constellationName(status.getConstellationType(index))
                constellations += constellation
                val usedInFixAtIndex = status.usedInFix(index)
                if (usedInFixAtIndex) usedInFix++
                val snr = status.getCn0DbHz(index)
                if (usedInFixAtIndex && snr > 0f) {
                    snrSum += snr
                    snrCount++
                    if (snr > best) best = snr
                }
                // Almanac/ephemeris flags are not part of the public GnssStatus API: a receiver that
                // knows them does not expose them to apps, so they stay "unknown" (false) here
                // rather than being guessed.
                satellites += SatelliteInfo(
                    svid = status.getSvid(index),
                    constellation = constellation,
                    azimuthDegrees = status.getAzimuthDegrees(index),
                    elevationDegrees = status.getElevationDegrees(index),
                    snrDbHz = snr,
                    usedInFix = usedInFixAtIndex
                )
            }
            val snapshot = SatelliteSnapshot(
                satellitesVisible = visible,
                satellitesUsedInFix = usedInFix,
                averageSnrDbHz = if (snrCount > 0) snrSum / snrCount else null,
                bestSnrDbHz = if (best > 0f) best.toDouble() else null,
                constellations = constellations.toList(),
                satellites = satellites
            )
            _satellites.tryEmit(snapshot)
            trySend(snapshot)
        }

        val callback = object : GnssStatus.Callback() {
            override fun onSatelliteStatusChanged(status: GnssStatus) {
                onStatus(status)
            }
        }

        // Register and remember whether it actually worked: a receiver that refuses the callback
        // must surface as an empty radar, not as a silent never-emitting flow.
        val registered: Boolean = try {
            manager.registerGnssStatusCallback(callback, Looper.getMainLooper())
            true
        } catch (error: SecurityException) {
            false
        } catch (error: IllegalArgumentException) {
            false
        }

        if (!registered) {
            close()
            return@callbackFlow
        }

        awaitClose {
            try {
                manager.unregisterGnssStatusCallback(callback)
            } catch (error: IllegalArgumentException) {
                // Already unregistered (e.g. the provider was torn down); nothing to do.
            }
        }
    }

    /**
     * Raw NMEA sentences for the diagnostics screen. Purely observational: parsed values are shown
     * next to the raw sentence so a user can verify the numbers rather than trust a summary.
     */
    @SuppressLint("MissingPermission")
    fun nmeaMessages(): Flow<String> = callbackFlow {
        val manager = locationManager
        if (manager == null || !hasFinePermission() || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            close()
            return@callbackFlow
        }
        val listener = OnNmeaMessageListener { message, _ -> trySend(message) }
        val ok = runCatching { manager.addNmeaListener(listener, null) }.isSuccess
        if (!ok) { close(); return@callbackFlow }
        awaitClose { runCatching { manager.removeNmeaListener(listener) } }
    }

    /** Emits when the provider is enabled/disabled or a provider's status changes. */
    fun providerChanges(): Flow<String> = callbackFlow {
        val manager = locationManager ?: run { close(); return@callbackFlow }
        val listener = object : android.location.LocationListener {
            override fun onLocationChanged(location: Location) = Unit
            @Deprecated("Required by the platform interface below API 30")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {
                trySend("$provider:${status}")
            }
            override fun onProviderEnabled(provider: String) { trySend("$provider:enabled") }
            override fun onProviderDisabled(provider: String) { trySend("$provider:disabled") }
        }
        // requestLocationUpdates with a huge interval is the only portable way to observe provider
        // toggles without a deprecated broadcast on newer targets.
        val registered: Boolean = if (hasFinePermission() || hasCoarsePermission()) {
            try {
                manager.requestLocationUpdates(
                    if (hasFinePermission()) LocationManager.PASSIVE_PROVIDER else LocationManager.NETWORK_PROVIDER,
                    3_600_000L, 0f, listener, Looper.getMainLooper()
                )
                true
            } catch (error: SecurityException) {
                false
            } catch (error: IllegalArgumentException) {
                false
            }
        } else {
            false
        }
        if (!registered) { close(); return@callbackFlow }
        awaitClose {
            try {
                manager.removeUpdates(listener)
            } catch (error: IllegalArgumentException) {
                // Listener already gone; the flow is closing anyway.
            }
        }
    }

    companion object {
        fun constellationName(type: Int): String = when (type) {
            GnssStatus.CONSTELLATION_GPS -> "GPS"
            GnssStatus.CONSTELLATION_SBAS -> "SBAS"
            GnssStatus.CONSTELLATION_GLONASS -> "GLONASS"
            GnssStatus.CONSTELLATION_QZSS -> "QZSS"
            GnssStatus.CONSTELLATION_BEIDOU -> "BeiDou"
            GnssStatus.CONSTELLATION_GALILEO -> "Galileo"
            GnssStatus.CONSTELLATION_IRNSS -> "NavIC"
            else -> "Other"
        }

        fun sourceFor(provider: String): FixSource = when (provider) {
            LocationManager.GPS_PROVIDER -> FixSource.GNSS
            LocationManager.FUSED_PROVIDER -> FixSource.FUSED
            LocationManager.NETWORK_PROVIDER -> FixSource.NETWORK
            LocationManager.PASSIVE_PROVIDER -> FixSource.PASSIVE
            else -> FixSource.LAST_KNOWN
        }
    }
}

/**
 * Maps a platform [Location] onto the module's own model.
 *
 * Android can omit values (a network fix has no altitude, a stationary GNSS fix has no bearing);
 * those stay `null` instead of becoming 0.0, because a fabricated 0 shows up as "sea level" and
 * "facing north" on the dashboard.
 */
fun Location.toGnssFix(cached: Boolean = false): GnssFix {
    val mock = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) isMock else {
        @Suppress("DEPRECATION")
        (extras?.getBoolean("mockLocation", false) == true)
    }
    return GnssFix(
        position = GeoPoint(latitude, longitude),
        timeMs = time,
        elapsedRealtimeNanos = elapsedRealtimeNanos,
        accuracyMeters = accuracy,
        altitudeMeters = if (hasAltitude()) altitude else null,
        verticalAccuracyMeters = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O &&
            hasVerticalAccuracy()
        ) {
            verticalAccuracyMeters
        } else {
            null
        },
        speedMps = if (hasSpeed()) speed else null,
        speedAccuracyMps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && hasSpeedAccuracy()) {
            speedAccuracyMetersPerSecond
        } else {
            null
        },
        bearingDegrees = if (hasBearing()) bearing else null,
        bearingAccuracyDegrees = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && hasBearingAccuracy()) {
            bearingAccuracyDegrees
        } else {
            null
        },
        source = GnssLocationSource.sourceFor(provider ?: ""),
        mockProviderFlag = mock,
        isCached = cached
    )
}
