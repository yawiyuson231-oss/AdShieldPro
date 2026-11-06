package com.adshield.pro.gps.engine

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.adshield.pro.gps.geo.Geodesy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import java.util.concurrent.CopyOnWriteArrayList

/**
 * AdShield Pro — GPS engine.
 *
 * Owns the lifecycle of the supported location flow and produces a single [GpsFrame] for the UI:
 *
 *   GNSS fixes -> integrity monitor -> stationary detector -> heading fusion -> frame
 *
 * Rules this class enforces:
 *  - a frame with no fix has `fix == null` and never carries a fabricated coordinate;
 *  - the newest fix is only published when it passed basic range validation;
 *  - movement classification is hysteretic, so the dashboard does not flicker between
 *    "Stationary" and "Driving" at a traffic light;
 *  - nothing leaves the device from here (see TelemetryGate for that decision).
 *
 * It is deliberately *not* a foreground service: the engine runs while the UI (or the navigation
 * service) collects it, and stops as soon as the last collector goes away.
 */
class GpsEngine(
    private val context: Context,
    private val scope: CoroutineScope,
    private val locationSource: GnssLocationSource = GnssLocationSource(context),
    private val headingSensor: HeadingSensor = HeadingSensor(context),
    private val integrityMonitor: GpsIntegrityMonitor = GpsIntegrityMonitor(),
    private val stationaryDetector: StationaryDetector = StationaryDetector(),
    private val headingFusion: HeadingFusion = HeadingFusion()
) {

    private val _frame = MutableStateFlow(GpsFrame.EMPTY)
    val frame: StateFlow<GpsFrame> = _frame.asStateFlow()

    private val _satellites = MutableStateFlow<SatelliteSnapshot?>(null)
    val satellites: StateFlow<SatelliteSnapshot?> = _satellites.asStateFlow()

    private val _diagnostics = MutableStateFlow(GpsDiagnostics())
    val diagnostics: StateFlow<GpsDiagnostics> = _diagnostics.asStateFlow()

    /** Trip accumulator; reset per trip by the navigation flow. */
    private var trackDistanceMeters = 0.0
    private var acceptedSamples = 0
    private var rejectedSamples = 0
    private var maxSpeedKmh = 0.0
    private var speedSum = 0.0
    private var movingSeconds = 0L
    private var lastAccepted: GnssFix? = null

    private var locationJob: Job? = null
    private var satelliteJob: Job? = null
    private var headingJob: Job? = null
    private var staleJob: Job? = null

    private var latestHeading: HeadingSample? = null
    private var latestIntegrity: IntegrityReport = IntegrityReport.NONE

    private val listeners = CopyOnWriteArrayList<(GnssFix) -> Unit>()

    /**
     * Serialises state mutation.
     *
     * Three coroutines write engine state — the fix collector, the heading collector and the stale
     * ticker — plus [resetTrip]/[release]/[stop] from the UI thread. Trip counters were plain
     * fields, so a fix and a stale tick could interleave and produce a frame with, for example, the
     * previous fix's integrity report but the new fix's distance. Every mutation and every frame
     * publication now runs on this single thread.
     */
    private val stateLock = Any()

    /** Extra consumers (trip recorder, traffic recorder) receive every accepted fix. */
    fun addFixListener(listener: (GnssFix) -> Unit) {
        if (listener !in listeners) listeners += listener
    }

    fun removeFixListener(listener: (GnssFix) -> Unit) {
        listeners -= listener
    }

    val isRunning: Boolean get() = locationSource.isListening

    /**
     * Holders that asked for fixes: the GPS screen and/or the navigation foreground service.
     *
     * The engine is an app singleton, and both the UI and the service legitimately want the same
     * stream. Counting holders is what stops one of them from shutting the receiver down while the
     * other is still using it — the bug being a "Stop" tap in the notification freezing the open map.
     */
    private val holders = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /**
     * Starts collecting on behalf of [holder]. Safe to call repeatedly; the existing collection is
     * kept and the holder is simply remembered.
     */
    @JvmOverloads
    fun start(intervalMs: Long = 1_000L, holder: String = DEFAULT_HOLDER) {
        holders += holder
        if (locationJob != null) return
        if (!locationSource.hasFinePermission() && !locationSource.hasCoarsePermission()) {
            publishState(FixState.NO_PERMISSION)
            return
        }
        if (!locationSource.isLocationEnabled()) {
            publishState(FixState.DISABLED)
            return
        }
        if (!locationSource.hasGpsProvider() && !locationSource.hasCoarsePermission()) {
            publishState(FixState.UNSUPPORTED)
            return
        }

        publishState(FixState.SEARCHING)
        locationJob = scope.launch {
            locationSource.fixes(intervalMs = intervalMs, minDistanceMeters = 0f, preferGnss = true)
                .collect { fix -> onFix(fix) }
        }
        satelliteJob = scope.launch {
            locationSource.satelliteStatus().collect { snapshot ->
                synchronized(stateLock) {
                    _satellites.value = snapshot
                    _diagnostics.value = _diagnostics.value.copy(
                        gnssStatusAvailable = true,
                        updatedAtMs = System.currentTimeMillis()
                    )
                }
            }
        }
        headingJob = scope.launch {
            headingSensor.headings().collect { sample ->
                latestHeading = sample
                refreshFrame()
            }
        }
        staleJob = scope.launch {
            // Independent of fix delivery: makes "stale" appear even if the provider goes silent.
            while (true) {
                delay(2_000)
                synchronized(stateLock) {
                    val current = _frame.value
                    val fix = current.fix ?: return@synchronized
                    val age = System.currentTimeMillis() - fix.timeMs
                    // FIX_ACQUIRED / COMPROMISED are re-derived from the last real fix instead of
                    // being hard-coded back to FIX_ACQUIRED: a compromised position used to be
                    // relabelled as healthy here two seconds after it arrived.
                    val settled = when {
                        age > STALE_AFTER_MS -> FixState.STALE
                        current.integrity.verdict == IntegrityVerdict.COMPROMISED -> FixState.COMPROMISED
                        else -> FixState.FIX_ACQUIRED
                    }
                    if (current.fixState != settled || current.lastFixAgeMs != age) {
                        _frame.value = current.copy(fixState = settled, lastFixAgeMs = age)
                    }
                }
            }
        }
    }

    /**
     * Drops [holder]'s request. Collection keeps running while any other holder still wants fixes,
     * and shuts down completely only when the last one leaves.
     */
    @JvmOverloads
    fun release(holder: String = DEFAULT_HOLDER) {
        holders -= holder
        if (holders.isEmpty()) stop()
    }

    /**
     * Stops collection unconditionally, whichever holders remain. Used when location must be
     * abandoned immediately (permission revoked, ViewModel destroyed, process going away).
     */
    fun stop() {
        synchronized(stateLock) {
            holders.clear()
            locationJob?.cancel(); locationJob = null
            satelliteJob?.cancel(); satelliteJob = null
            headingJob?.cancel(); headingJob = null
            staleJob?.cancel(); staleJob = null
            // Drop the fix and say so. Leaving the last frame in place made a stopped engine look
            // like a live one: the speed and accuracy stayed on screen indefinitely.
            _frame.value = GpsFrame.EMPTY.copy(
                fixState = FixState.SEARCHING,
                satellites = _satellites.value,
                updatedAtMs = System.currentTimeMillis()
            )
            _diagnostics.value = _diagnostics.value.copy(
                lastFixAtMs = 0L,
                updatedAtMs = System.currentTimeMillis()
            )
        }
    }

    fun resetTrip() {
        synchronized(stateLock) {
            trackDistanceMeters = 0.0
            acceptedSamples = 0
            rejectedSamples = 0
            maxSpeedKmh = 0.0
            speedSum = 0.0
            movingSeconds = 0L
            lastAccepted = null
            stationaryDetector.reset()
            integrityMonitor.reset()
            // The last verdict and heading belong to the trip that just ended. Keeping them made a
            // fresh trip start under the previous trip's COMPROMISED badge.
            latestIntegrity = IntegrityReport.NONE
            latestHeading = null
            _frame.value = _frame.value.copy(
                trackStats = TrackStats(),
                integrity = IntegrityReport.NONE,
                heading = null,
                fixState = _frame.value.fix?.let { FixState.FIX_ACQUIRED } ?: _frame.value.fixState
            )
        }
    }

    private fun publishState(state: FixState) {
        synchronized(stateLock) {
            _frame.value = _frame.value.copy(fixState = state, updatedAtMs = System.currentTimeMillis())
        }
    }

    private fun onFix(fix: GnssFix) {
        val deliver = synchronized(stateLock) { onFixLocked(fix) }
        // Dispatched outside the lock on purpose: a listener runs on the caller's thread and may
        // touch the engine again (or hop to the main thread, which may be waiting on this lock).
        if (deliver) listeners.forEach { listener -> runCatching { listener(fix) } }
    }

    /**
     * Body of [onFix], always called while holding [stateLock].
     *
     * @return true when the fix should be handed to the registered listeners.
     */
    private fun onFixLocked(fix: GnssFix): Boolean {
        if (!fix.position.isValid) {
            rejectedSamples++
            return false
        }
        // Reject fixes Android itself flags as mocked *for accounting*, but still display them so
        // the user can see the spoofing rather than a frozen map. They never enter the track stats.
        val integrity = integrityMonitor.inspect(fix)
        latestIntegrity = integrity
        if (integrity.shouldRejectObservation) {
            rejectedSamples++
        }
        val movement = stationaryDetector.update(fix)

        if (lastAccepted != null && !integrity.shouldRejectObservation) {
            val previous = lastAccepted!!
            val delta = Geodesy.distanceMeters(previous.position, fix.position)
            val seconds = (fix.timeMs - previous.timeMs) / 1000.0
            val plausible = seconds > 0 && delta / seconds <= Geodesy.PHYSICAL_MAX_SPEED_MPS &&
                delta < maxOf(previous.accuracyMeters.toDouble(), fix.accuracyMeters.toDouble()) * 25
            if (plausible) {
                trackDistanceMeters += delta
                acceptedSamples++
                val speedKmh = fix.speedKmh
                if (speedKmh != null) {
                    speedSum += speedKmh
                    if (speedKmh > maxSpeedKmh) maxSpeedKmh = speedKmh
                }
                if (movement == MovementState.MOVING || movement == MovementState.DRIVING) {
                    movingSeconds += ((fix.timeMs - previous.timeMs) / 1000L).coerceAtLeast(0L)
                }
                lastAccepted = fix
            } else {
                rejectedSamples++
            }
        } else if (!integrity.shouldRejectObservation) {
            lastAccepted = fix
            acceptedSamples++
            fix.speedKmh?.let { speedSum += it; if (it > maxSpeedKmh) maxSpeedKmh = it }
        }

        val fusedHeading = headingFusion.update(latestHeading, fix)
        val bearing = when {
            fix.speedMps != null && fix.speedMps >= 3.0f && fix.bearingDegrees != null -> fix.bearingDegrees.toDouble()
            fusedHeading != null -> fusedHeading.degrees
            else -> null
        }

        val stats = TrackStats(
            samples = acceptedSamples + rejectedSamples,
            distanceMeters = trackDistanceMeters,
            maxSpeedKmh = maxSpeedKmh,
            averageSpeedKmh = if (acceptedSamples > 0) speedSum / acceptedSamples else 0.0,
            movingSeconds = movingSeconds,
            acceptedSamples = acceptedSamples,
            rejectedSamples = rejectedSamples
        )

        val resolutionNote = if (_satellites.value == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            "Satellite status is unavailable from this receiver."
        } else {
            _diagnostics.value.satelliteNote
        }

        _frame.value = GpsFrame(
            fix = fix,
            // A compromised position is a distinct, visible state — the earlier version had the
            // same value in both branches, so spoofing looked exactly like a healthy fix.
            fixState = if (integrity.verdict == IntegrityVerdict.COMPROMISED) {
                FixState.COMPROMISED
            } else {
                FixState.FIX_ACQUIRED
            },
            heading = fusedHeading,
            navigationBearingDegrees = bearing,
            movement = movement,
            satellites = _satellites.value,
            trackStats = stats,
            accuracyBand = fix.accuracyBand,
            lastFixAgeMs = System.currentTimeMillis() - fix.timeMs,
            integrity = integrity,
            updatedAtMs = System.currentTimeMillis()
        )
        _diagnostics.value = GpsDiagnostics(
            gnssStatusAvailable = _satellites.value != null,
            satelliteNote = resolutionNote,
            providerName = fix.source.label,
            lastFixAtMs = fix.timeMs,
            mockLocationObserved = integrity.findings.any { it.kind == IntegrityFindingKind.MOCK_LOCATION },
            updatedAtMs = System.currentTimeMillis()
        )
        return true
    }

    /** Recomputes the fused heading for the current fix; called when the compass reports. */
    private fun refreshFrame() {
        synchronized(stateLock) {
            val current = _frame.value
            val fix = current.fix ?: return@synchronized
            val fused = headingFusion.update(latestHeading, fix)
            val bearing = when {
                fix.speedMps != null && fix.speedMps >= 3.0f && fix.bearingDegrees != null ->
                    fix.bearingDegrees.toDouble()
                fused != null -> fused.degrees
                else -> null
            }
            _frame.value = current.copy(
                heading = fused,
                navigationBearingDegrees = bearing,
                updatedAtMs = System.currentTimeMillis()
            )
        }
    }

    /** Human-readable device capability line for the GPS screen header. */
    fun describeReceiver(): ReceiverCapabilities = ReceiverCapabilities(
        hasGnss = locationSource.hasGpsProvider(),
        hasCompass = headingSensor.hasCompass(),
        hasAccelerometer = headingSensor.hasAccelerometer(),
        finePermission = locationSource.hasFinePermission(),
        coarsePermission = locationSource.hasCoarsePermission(),
        locationEnabled = locationSource.isLocationEnabled(),
        enabledProviders = locationSource.enabledProviders(),
        sensorSummary = headingSensor.describe()
    )

    fun currentIntegrity(): IntegrityReport = latestIntegrity

    companion object {
        const val STALE_AFTER_MS = 12_000L

        /** Holder id for the GPS screen / ViewModel. */
        const val DEFAULT_HOLDER = "ui"

        /** Reads Android's own "allow mock locations" developer switch without modifying it. */
        fun isMockLocationAllowed(context: Context): Boolean = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? android.app.AppOpsManager
                @Suppress("DEPRECATION")
                val mode = appOps?.checkOpNoThrow(
                    "android:mock_location",
                    android.os.Process.myUid(),
                    context.packageName
                )
                mode == android.app.AppOpsManager.MODE_ALLOWED
            } else {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0) != 0
            }
        } catch (t: Throwable) {
            false
        }

        fun hasPermission(context: Context): Boolean =
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
    }
}

data class ReceiverCapabilities(
    val hasGnss: Boolean,
    val hasCompass: Boolean,
    val hasAccelerometer: Boolean,
    val finePermission: Boolean,
    val coarsePermission: Boolean,
    val locationEnabled: Boolean,
    val enabledProviders: List<String>,
    val sensorSummary: String
) {
    fun summaryLines(): List<String> = buildList {
        add(
            when {
                !finePermission && !coarsePermission -> "Location permission: not granted"
                finePermission -> "Location permission: precise (GNSS available)"
                else -> "Location permission: approximate only (GNSS unavailable)"
            }
        )
        add(if (locationEnabled) "System location: on" else "System location: off")
        add(if (hasGnss) "GNSS receiver: present" else "GNSS receiver: not reported by this device")
        add("Sensors: $sensorSummary")
        if (enabledProviders.isNotEmpty()) add("Active providers: ${enabledProviders.joinToString(", ")}")
    }
}

data class GpsDiagnostics(
    val gnssStatusAvailable: Boolean = false,
    val satelliteNote: String? = null,
    val providerName: String = "—",
    val lastFixAtMs: Long = 0L,
    val mockLocationObserved: Boolean = false,
    val updatedAtMs: Long = 0L
)
