package com.adshield.pro.data.repository

import android.content.Context
import com.adshield.pro.engine.battery.BatteryDiagnostic
import com.adshield.pro.engine.battery.BatteryDiagnostics
import com.adshield.pro.engine.battery.BatteryIntelligenceReport
import com.adshield.pro.engine.battery.BatteryMonitor
import com.adshield.pro.engine.battery.BatteryMonitoringEngine
import com.adshield.pro.engine.battery.BatterySession
import com.adshield.pro.engine.battery.BatterySessionStore
import com.adshield.pro.engine.battery.BatteryStatusReport
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.battery.DataFreshness
import com.adshield.pro.engine.battery.EngineState
import com.adshield.pro.engine.battery.FastChargeSignal
import com.adshield.pro.engine.battery.MonitoringStatus
import com.adshield.pro.engine.battery.SensorStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — Battery Intelligence state holder.
 *
 * Owns nothing about Android hardware itself: [BatteryMonitoringEngine] does the reading. This
 * class turns measured state into the derived view models the Command Center renders (status,
 * monitoring health, intelligence report, diagnostics, sessions) and keeps those derivations in
 * lock-step with the live flow, so the UI never displays a status computed from an older reading.
 */
@Singleton
class BatteryIntelligenceRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val engine: BatteryMonitoringEngine,
    private val sessionStore: BatterySessionStore
) {

    val telemetry: StateFlow<BatteryTelemetry> = engine.telemetry
    val history: StateFlow<List<BatteryDiagnostics.Sample>> = engine.history
    val freshness: StateFlow<DataFreshness> = engine.freshness
    val sensors: StateFlow<List<SensorStatus>> = engine.sensors
    val engineState: StateFlow<EngineState> = engine.engineState
    val fastCharge: StateFlow<FastChargeSignal> = engine.fastCharge
    val livePolling: StateFlow<Boolean> = engine.livePolling
    val screenOn: StateFlow<Boolean> = engine.screenOn

    private val _sessions = MutableStateFlow(sessionStore.load())
    val sessions: StateFlow<List<BatterySession>> = _sessions.asStateFlow()

    private val _diagnostics = MutableStateFlow(emptyList<BatteryDiagnostic>())
    val diagnostics: StateFlow<List<BatteryDiagnostic>> = _diagnostics.asStateFlow()

    private val _averageTemperature = MutableStateFlow<Float?>(null)
    val averageTemperature: StateFlow<Float?> = _averageTemperature.asStateFlow()

    private val _lastDiagnosticAtMs = MutableStateFlow(0L)
    val lastDiagnosticAtMs: StateFlow<Long> = _lastDiagnosticAtMs.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Open session bookkeeping (not exposed; mirrored into _sessions when it closes).
    private var sessionStartMs = System.currentTimeMillis()
    private var sessionStartLevel: Int? = null
    private var sessionWasCharging = telemetry.value.isCharging
    private var sessionPeakTemp: Float? = null
    private var sessionVoltageSum = 0.0
    private var sessionVoltageCount = 0
    private var sessionCurrentSum = 0.0
    private var sessionCurrentCount = 0
    private var sessionPeakPower: Float? = null
    private var sessionInterruptions = 0
    private var lastChargingState = telemetry.value.isCharging

    /**
     * Everything the Command Center shows, recomputed from the newest reading and the observed
     * history. One combined flow means "last measurement time", "status" and "freshness" can never
     * disagree with each other.
     */
    data class BatteryDashboardState(
        val telemetry: BatteryTelemetry,
        val freshness: DataFreshness,
        val sensors: List<SensorStatus>,
        val monitoring: MonitoringStatus,
        val status: BatteryStatusReport,
        val intelligence: BatteryIntelligenceReport,
        val healthScore: Int,
        val chargeRatePercentPerHour: Float?,
        val drainRatePercentPerHour: Float?,
        val minutesToFull: Int?,
        val minutesToEmpty: Int?,
        val livePolling: Boolean,
        val engineState: EngineState
    )

    /** Internally combined live inputs; four flows is the widest typed `combine` overload. */
    private data class LiveCore(
        val telemetry: BatteryTelemetry,
        val freshness: DataFreshness,
        val history: List<BatteryDiagnostics.Sample>,
        val fastCharge: FastChargeSignal
    )

    private val liveCore: kotlinx.coroutines.flow.Flow<LiveCore> = combine(
        engine.telemetry,
        engine.freshness,
        engine.history,
        engine.fastCharge
    ) { telemetry, freshness, history, fastCharge -> LiveCore(telemetry, freshness, history, fastCharge) }

    val dashboard: StateFlow<BatteryDashboardState> = combine(
        liveCore,
        engine.sensors,
        engine.engineState,
        engine.livePolling
    ) { core, sensors, engineState, livePolling ->
        val snapshot = core.telemetry
        val samples = core.history
        val chargeRate = BatteryDiagnostics.chargeRatePercentPerHour(samples)
        val drainRate = BatteryDiagnostics.drainRatePercentPerHour(samples)
        val averagePower = samples.mapNotNull { it.powerWatts }.takeLast(60)
            .takeIf { it.isNotEmpty() }?.average()?.toFloat()
        val recentTemperatures = samples.mapNotNull { it.temperatureCelsius }.takeLast(60)
        val healthScore = BatteryDiagnostics.healthScore(
            telemetry = snapshot,
            capacityHealthPercent = snapshot.capacityHealthPercent,
            averageTemperatureCelsius = recentTemperatures.takeIf { it.size >= 3 }?.average()?.toFloat(),
            cycleCount = snapshot.cycleCount.rawValue
        )
        val monitoring = BatteryMonitor.monitoringStatus(
            telemetry = snapshot,
            sensors = sensors,
            freshness = core.freshness,
            engineState = engineState,
            nowElapsedRealtimeMs = snapshot.elapsedRealtimeMs
        )
        BatteryDashboardState(
            telemetry = snapshot,
            freshness = core.freshness,
            sensors = sensors,
            monitoring = monitoring,
            status = BatteryMonitor.condition(
                telemetry = snapshot,
                freshness = core.freshness,
                chargeRatePercentPerHour = chargeRate,
                drainRatePercentPerHour = drainRate,
                averagePowerWatts = averagePower,
                healthScore = healthScore,
                hasFastChargeSignal = core.fastCharge.isPresent,
                fastChargeSource = core.fastCharge.source
            ),
            intelligence = BatteryMonitor.intelligence(
                samples = samples,
                telemetry = snapshot,
                chargeRatePercentPerHour = chargeRate,
                drainRatePercentPerHour = drainRate,
                capacityWattHours = BatteryMonitor.capacityWattHours(snapshot),
                chargingInterruptions = interruptionCount
            ),
            healthScore = healthScore,
            chargeRatePercentPerHour = chargeRate,
            drainRatePercentPerHour = drainRate,
            minutesToFull = BatteryDiagnostics.minutesToFull(snapshot.levelPercent.rawValue, chargeRate),
            minutesToEmpty = BatteryDiagnostics.minutesToEmpty(snapshot.levelPercent.rawValue, drainRate),
            livePolling = livePolling,
            engineState = engineState
        )
    }.stateIn(scope, SharingStarted.WhileSubscribed(SUBSCRIPTION_GRACE_MS), initialState())

    init {
        // Session bookkeeping only needs the event stream; the engine already owns the receiver.
        scope.launch {
            var sawFirst = false
            engine.telemetry.collect { snapshot ->
                if (!sawFirst) {
                    sawFirst = true
                    sessionStartLevel = snapshot.levelPercent.rawValue
                    sessionWasCharging = snapshot.isCharging || snapshot.isFull
                    lastChargingState = sessionWasCharging
                    return@collect
                }
                onNewReading(snapshot)
            }
        }
    }

    private fun initialState(): BatteryDashboardState {
        val snapshot = telemetry.value
        val fast = engine.fastCharge.value
        return BatteryDashboardState(
            telemetry = snapshot,
            freshness = DataFreshness.of(null),
            sensors = sensors.value,
            monitoring = BatteryMonitor.monitoringStatus(
                snapshot, sensors.value, DataFreshness.of(null), EngineState.PAUSED, snapshot.elapsedRealtimeMs
            ),
            status = BatteryMonitor.condition(
                telemetry = snapshot,
                freshness = DataFreshness.of(null),
                chargeRatePercentPerHour = null,
                drainRatePercentPerHour = null,
                averagePowerWatts = null,
                healthScore = 100,
                hasFastChargeSignal = fast.isPresent,
                fastChargeSource = fast.source
            ),
            intelligence = BatteryMonitor.intelligence(
                samples = emptyList(),
                telemetry = snapshot,
                chargeRatePercentPerHour = null,
                drainRatePercentPerHour = null,
                capacityWattHours = BatteryMonitor.capacityWattHours(snapshot)
            ),
            healthScore = 100,
            chargeRatePercentPerHour = null,
            drainRatePercentPerHour = null,
            minutesToFull = null,
            minutesToEmpty = null,
            livePolling = false,
            engineState = EngineState.PAUSED
        )
    }

    /** Visible to the dashboard flow so "charging stability" reflects the live session. */
    @Volatile
    private var interruptionCount: Int = 0

    private fun onNewReading(snapshot: BatteryTelemetry) {
        val now = System.currentTimeMillis()
        val level = snapshot.levelPercent.rawValue
        val chargingNow = snapshot.isCharging || snapshot.isFull

        snapshot.temperatureCelsius.rawValue?.let {
            sessionPeakTemp = listOfNotNull(sessionPeakTemp, it).maxOrNull()
        }
        snapshot.voltageVolts.rawValue?.let { sessionVoltageSum += it; sessionVoltageCount++ }
        snapshot.currentMilliAmps.rawValue?.let { sessionCurrentSum += kotlin.math.abs(it); sessionCurrentCount++ }
        snapshot.powerWatts.rawValue?.let {
            sessionPeakPower = listOfNotNull(sessionPeakPower, it).maxOrNull()
        }

        if (lastChargingState && !chargingNow) {
            sessionInterruptions++
            interruptionCount = sessionInterruptions
        }
        lastChargingState = chargingNow

        if (chargingNow != sessionWasCharging) closeSession(now, chargingNow, level)

        _averageTemperature.value = history.value.mapNotNull { it.temperatureCelsius }
            .takeLast(60)
            .takeIf { it.size >= 3 }
            ?.average()
            ?.toFloat()
    }

    private fun closeSession(now: Long, nextCharging: Boolean, endLevel: Int?) {
        val startLevel = sessionStartLevel
        val durationMs = now - sessionStartMs
        // Ignore blips shorter than 60 s or sessions without a readable level.
        if (startLevel != null && endLevel != null && durationMs >= MIN_SESSION_MS) {
            val session = BatterySession(
                id = now,
                startedEpochMs = sessionStartMs,
                endedEpochMs = now,
                startLevelPercent = startLevel,
                endLevelPercent = endLevel,
                peakTemperatureCelsius = sessionPeakTemp,
                averageVoltageVolts = if (sessionVoltageCount > 0) (sessionVoltageSum / sessionVoltageCount).toFloat() else null,
                averageCurrentMilliAmps = if (sessionCurrentCount > 0) (sessionCurrentSum / sessionCurrentCount).toFloat() else null,
                peakPowerWatts = sessionPeakPower,
                pluggedLabel = telemetry.value.pluggedLabel,
                wasCharging = sessionWasCharging,
                interruptions = sessionInterruptions
            )
            _sessions.value = sessionStore.append(session)
        }
        // Start a fresh session.
        sessionStartMs = now
        sessionStartLevel = endLevel
        sessionWasCharging = nextCharging
        sessionPeakTemp = null
        sessionVoltageSum = 0.0
        sessionVoltageCount = 0
        sessionCurrentSum = 0.0
        sessionCurrentCount = 0
        sessionPeakPower = null
        sessionInterruptions = 0
        interruptionCount = 0
        lastChargingState = nextCharging
    }

    // --- Monitoring lifecycle (driven by the screen) -------------------------------------------

    /** Start live monitoring; called when the Battery screen is visible. */
    fun startMonitoring(liveRefresh: Boolean = true) {
        engine.start(enableFastPolling = liveRefresh)
    }

    /** Stop the 1 Hz poll (screen off / tab changed). The event receiver stays registered. */
    fun pauseMonitoring() {
        engine.pause()
    }

    /** One-shot re-read of every hardware input, triggered by the "Re-read hardware" action. */
    fun refreshNow(): BatteryTelemetry = engine.refreshNow()

    // --- Diagnostics / projections -------------------------------------------------------------

    fun runDiagnostics(): List<BatteryDiagnostic> {
        val snapshot = telemetry.value
        val samples = history.value
        val result = BatteryDiagnostics.diagnose(
            telemetry = snapshot,
            history = samples,
            chargeRatePercentPerHour = BatteryDiagnostics.chargeRatePercentPerHour(samples),
            drainRatePercentPerHour = BatteryDiagnostics.drainRatePercentPerHour(samples),
            interruptions = sessionInterruptions
        )
        _diagnostics.value = result
        _lastDiagnosticAtMs.value = System.currentTimeMillis()
        return result
    }

    fun healthScore(): Int = dashboard.value.healthScore

    fun chargeRatePercentPerHour(): Float? = BatteryDiagnostics.chargeRatePercentPerHour(history.value)

    fun drainRatePercentPerHour(): Float? = BatteryDiagnostics.drainRatePercentPerHour(history.value)

    fun minutesToFull(): Int? = BatteryDiagnostics.minutesToFull(
        telemetry.value.levelPercent.rawValue,
        chargeRatePercentPerHour()
    )

    fun minutesToEmpty(): Int? = BatteryDiagnostics.minutesToEmpty(
        telemetry.value.levelPercent.rawValue,
        drainRatePercentPerHour()
    )

    fun clearSessions() {
        sessionStore.clear()
        _sessions.value = emptyList()
    }

    private companion object {
        const val MIN_SESSION_MS = 60_000L
        /** Keep derivations warm across a screen rotation without keeping them alive forever. */
        const val SUBSCRIPTION_GRACE_MS = 5_000L
    }
}
