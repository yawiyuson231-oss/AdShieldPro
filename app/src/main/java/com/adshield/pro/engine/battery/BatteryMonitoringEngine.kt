package com.adshield.pro.engine.battery

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.SystemClock
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — real-time battery monitoring engine.
 *
 * Two update paths, both driven by the device (nothing here is simulated):
 *
 *  1. **Event path.** `ACTION_BATTERY_CHANGED` is registered once for the process lifetime. It is
 *     the only source for level, temperature, health, charging state and charging source, and it
 *     fires on every plug/unplug/level change. Each event produces a full snapshot and a history
 *     sample, so state changes appear on screen without waiting for a poll.
 *
 *  2. **Fast path.** While the Battery screen is visible the engine polls *only*
 *     `BATTERY_PROPERTY_CURRENT_NOW` once per second. That property refreshes roughly 1 Hz on most
 *     hardware while the broadcast is throttled to ~10 s, so this is what makes mA and W feel live.
 *     It is stopped the moment the screen stops being observed, and skipped entirely on devices
 *     with no current sensor, so it cannot cause background drain.
 *
 * Freshness is measured with `SystemClock.elapsedRealtime()`, never with wall-clock time, so an
 * NTP correction cannot make a stale reading look live.
 */
@Singleton
class BatteryMonitoringEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val telemetrySource: BatteryTelemetrySource,
    private val historyStore: BatteryHistoryStore
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // --- Observable state ---------------------------------------------------------------------

    val telemetry: StateFlow<BatteryTelemetry> = telemetrySource.telemetry

    private val _history = MutableStateFlow(historyStore.load())
    /** Rolling samples for the charts, live trends and screen-on/off analysis. */
    val history: StateFlow<List<BatteryDiagnostics.Sample>> = _history.asStateFlow()

    private val _engineState = MutableStateFlow(EngineState.PAUSED)
    val engineState: StateFlow<EngineState> = _engineState.asStateFlow()

    private val _fastCharge = MutableStateFlow<FastChargeSignal>(FastChargeSignal.NONE)
    val fastCharge: StateFlow<FastChargeSignal> = _fastCharge.asStateFlow()

    private val _screenOn = MutableStateFlow(telemetrySource.isScreenOn())
    val screenOn: StateFlow<Boolean> = _screenOn.asStateFlow()

    private val _freshness = MutableStateFlow(DataFreshness.of(0))
    val freshness: StateFlow<DataFreshness> = _freshness.asStateFlow()

    private val _sensors = MutableStateFlow(
        BatteryMonitor.sensorStatuses(telemetrySource.telemetry.value, DataFreshness.of(0))
    )
    val sensors: StateFlow<List<SensorStatus>> = _sensors.asStateFlow()

    /** True when fast-path current polling is running (i.e. the Battery screen is visible). */
    private val _livePolling = MutableStateFlow(false)
    val livePolling: StateFlow<Boolean> = _livePolling.asStateFlow()

    // --- Internals ----------------------------------------------------------------------------

    private var pollJob: Job? = null
    private var freshnessJob: Job? = null
    private var lastPersistedAtMs = 0L
    private var lastSampleAtMs = 0L
    private var receiverRegistered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != Intent.ACTION_BATTERY_CHANGED) return
            onBroadcast()
        }
    }

    private fun ensureReceiver() {
        if (receiverRegistered) return
        runCatching {
            // ACTION_BATTERY_CHANGED is a sticky, system-only broadcast. Registering it is cheap:
            // the framework delivers it on state changes, not on a timer.
            @Suppress("DEPRECATION")
            context.registerReceiver(receiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            receiverRegistered = true
        }.onFailure {
            _engineState.value = EngineState.ERROR
        }
    }

    private fun onBroadcast() {
        val snapshot = telemetrySource.refresh()
        _fastCharge.value = telemetrySource.fastChargeSignal
        _screenOn.value = telemetrySource.isScreenOn()
        record(snapshot)
        _engineState.value = if (_engineState.value == EngineState.STOPPED) EngineState.PAUSED else EngineState.ACTIVE
        updateFreshness()
    }

    /**
     * Appends one history sample. High-resolution samples are kept in memory; a coarser copy is
     * persisted every [BatteryHistoryStore.PERSIST_SPACING_MS] so history survives process death
     * without writing to disk on every tick.
     */
    private fun record(snapshot: BatteryTelemetry) {
        val now = SystemClock.elapsedRealtime()
        // Do not append two samples less than a second apart from the two update paths.
        if (now - lastSampleAtMs < MIN_SAMPLE_SPACING_MS) {
            _freshness.value = DataFreshness.LIVE
            return
        }
        lastSampleAtMs = now
        val sample = BatteryDiagnostics.Sample(
            timestampEpochMs = snapshot.timestampEpochMs,
            levelPercent = snapshot.levelPercent.rawValue,
            isCharging = snapshot.isCharging || snapshot.isFull,
            temperatureCelsius = snapshot.temperatureCelsius.rawValue,
            voltageVolts = snapshot.voltageVolts.rawValue,
            currentMilliAmps = snapshot.currentMilliAmps.rawValue,
            powerWatts = snapshot.powerWatts.rawValue,
            screenOn = _screenOn.value,
            elapsedRealtimeMs = snapshot.elapsedRealtimeMs
        )
        var inMemory = (_history.value + sample).takeLast(MAX_IN_MEMORY_SAMPLES)
        if (now - lastPersistedAtMs >= BatteryHistoryStore.PERSIST_SPACING_MS) {
            lastPersistedAtMs = now
            inMemory = historyStore.append(sample, inMemory)
        }
        _history.value = inMemory
        _sensors.value = BatteryMonitor.sensorStatuses(snapshot, DataFreshness.of(snapshot.ageMs(now)))
    }

    private fun updateFreshness() {
        val snapshot = telemetrySource.telemetry.value
        val age = snapshot.ageMs(SystemClock.elapsedRealtime())
        _freshness.value = DataFreshness.of(if (snapshot.elapsedRealtimeMs == 0L) null else age)
    }

    // --- Lifecycle ----------------------------------------------------------------------------

    /** Called when the Battery screen becomes visible / the app resumes. */
    fun start(enableFastPolling: Boolean = true) {
        ensureReceiver()
        _screenOn.value = telemetrySource.isScreenOn()
        // The sticky broadcast gives the current state immediately, even before the receiver fires.
        onBroadcast()
        _engineState.value = EngineState.ACTIVE
        startFreshnessWatchdog()
        if (enableFastPolling) startFastPolling()
    }

    /** Called when the screen is backgrounded. Keeps the event receiver (it is free) but stops polling. */
    fun pause() {
        stopFastPolling()
        _engineState.value = if (receiverRegistered) EngineState.PAUSED else EngineState.STOPPED
        _livePolling.value = false
    }

    /** Starts the 1 Hz current-only poll; no-op when the device has no current sensor. */
    fun startFastPolling() {
        if (pollJob?.isActive == true) return
        if (!telemetrySource.hasCurrentSensor()) {
            _livePolling.value = false
            return
        }
        _livePolling.value = true
        pollJob = scope.launch {
            while (isActive) {
                delay(BatteryMonitor.recommendedRefreshIntervalMs(
                    freshness = _freshness.value,
                    screenOn = _screenOn.value,
                    engineState = _engineState.value
                ))
                val snapshot = telemetrySource.refreshCurrent()
                if (snapshot == null) {
                    // The property disappeared (vendor quirk): stop polling instead of spinning.
                    _livePolling.value = false
                    break
                }
                record(snapshot)
                updateFreshness()
            }
        }
    }

    fun stopFastPolling() {
        pollJob?.cancel()
        pollJob = null
        _livePolling.value = false
    }

    /**
     * Watches the age of the newest reading so "Live"/"Delayed"/"Stale" changes even when no
     * broadcast arrives at all. This is a 2 s timer that only reads two Longs — no sensor access.
     */
    private fun startFreshnessWatchdog() {
        if (freshnessJob?.isActive == true) return
        freshnessJob = scope.launch {
            while (isActive) {
                delay(FRESHNESS_TICK_MS)
                updateFreshness()
                _screenOn.value = telemetrySource.isScreenOn()
            }
        }
    }

    fun stop() {
        stopFastPolling()
        freshnessJob?.cancel()
        freshnessJob = null
        _engineState.value = EngineState.STOPPED
    }

    /**
     * One-shot full re-read of every hardware input (the "Re-read hardware" button). Unlike
     * [start] this does not touch the polling loop, so pressing it repeatedly cannot leave a
     * second poll running.
     */
    fun refreshNow(): BatteryTelemetry {
        ensureReceiver()
        val snapshot = telemetrySource.refresh()
        _fastCharge.value = telemetrySource.fastChargeSignal
        record(snapshot)
        updateFreshness()
        return snapshot
    }

    /** Parses an OEM charger-protocol string; exposed for the diagnostics/tests. */
    fun fastChargeSignal(statusProperty: Int?, chargeProtocol: String?): FastChargeSignal =
        FastChargeSignal.from(statusProperty, chargeProtocol)

    private companion object {
        /** Never append more than one history point per second, whichever path produced it. */
        const val MIN_SAMPLE_SPACING_MS = 900L
        /** ~30 minutes of 1 Hz samples; the persisted store holds the longer view. */
        const val MAX_IN_MEMORY_SAMPLES = 1_800
        const val FRESHNESS_TICK_MS = 2_000L
    }
}
