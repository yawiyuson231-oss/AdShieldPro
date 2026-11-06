package com.adshield.pro.engine.intelligence

import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryReadingSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Process-lifetime observation of the two signal sources that have no natural publisher:
 *
 *  - **Battery telemetry** — real `ACTION_BATTERY_CHANGED` readings collected by
 *    [BatteryIntelligenceRepository]. Threshold crossings use hysteresis so a value hovering on
 *    the boundary produces one WARNING and one recovery event, not a stream of fake alarms.
 *  - **Settings transitions** — privacy and automation policy changes, which are real user
 *    actions worth recording on the map. The first emission is skipped because it is the current
 *    state, not a change.
 *
 * The monitor is scoped to the application process. It does not hold a wake lock, does not use a
 * timer and does not request background execution exemptions: when Android stops the process, the
 * monitor stops with it, which is exactly the behaviour the platform requires.
 */
@Singleton
class IntelligenceMonitor @Inject constructor(
    private val batteryRepository: BatteryIntelligenceRepository,
    private val preferencesRepository: UserPreferencesRepository,
    private val recorder: IntelligenceRecorder
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    private var started = false

    private var aboveThermalThreshold = false
    private var healthAlertActive = false
    private var telemetryUnavailableRecorded = false

    fun start() {
        if (started) return
        started = true
        scope.launch { monitorBattery() }
        scope.launch { monitorSettings() }
    }

    private suspend fun monitorBattery() {
        batteryRepository.telemetry.collectLatest { telemetry ->
            val settings = preferencesRepository.getSettingsSnapshot()
            val threshold = settings.gameBoosterTempWarningCelsius
                .toFloat()
                .takeIf { it > 0f }
                ?: IntelligenceAggregator.DEFAULT_THERMAL_WARNING_CELSIUS
            val now = System.currentTimeMillis()
            val temperature = telemetry.temperatureCelsius.rawValue

            if (telemetry.temperatureCelsius.source == BatteryReadingSource.UNSUPPORTED || temperature == null) {
                if (!telemetryUnavailableRecorded) {
                    telemetryUnavailableRecorded = true
                    recorder.record(
                        IntelligenceEventFactory.telemetryUnavailable(
                            reason = telemetry.temperatureCelsius.detail,
                            timestampEpochMs = now
                        )
                    )
                }
                return@collectLatest
            }
            telemetryUnavailableRecorded = false

            if (temperature >= threshold && !aboveThermalThreshold) {
                aboveThermalThreshold = true
                IntelligenceEventFactory.thermalWarning(telemetry, threshold, now)?.let { recorder.record(it) }
            } else if (temperature <= threshold - HYSTERESIS_CELSIUS && aboveThermalThreshold) {
                aboveThermalThreshold = false
                IntelligenceEventFactory.thermalRecovered(telemetry, threshold, now)?.let { recorder.record(it) }
            }

            val unhealthy = telemetry.health == BatteryHealthStatus.OVERHEAT ||
                telemetry.health == BatteryHealthStatus.FAILURE ||
                telemetry.health == BatteryHealthStatus.DEAD ||
                telemetry.health == BatteryHealthStatus.OVER_VOLTAGE ||
                telemetry.health == BatteryHealthStatus.COLD
            if (unhealthy && !healthAlertActive) {
                healthAlertActive = true
                IntelligenceEventFactory.batteryHealthAlert(telemetry, now)?.let { recorder.record(it) }
            } else if (!unhealthy && healthAlertActive) {
                healthAlertActive = false
            }
        }
    }

    private suspend fun monitorSettings() {
        var previous: AppSettingsState? = null
        preferencesRepository.settingsFlow.collectLatest { settings ->
            val before = previous
            previous = settings
            if (before == null) return@collectLatest
            val now = System.currentTimeMillis()

            if (before.dnsFirewallPolicy.emergencyAllowlistOnly != settings.dnsFirewallPolicy.emergencyAllowlistOnly) {
                recorder.record(
                    IntelligenceEventFactory.lockdownChanged(
                        enabled = settings.dnsFirewallPolicy.emergencyAllowlistOnly,
                        timestampEpochMs = now
                    )
                )
            }

            if (before.browserCosmeticFilteringEnabled != settings.browserCosmeticFilteringEnabled ||
                before.browserBlockThirdPartyCookies != settings.browserBlockThirdPartyCookies
            ) {
                recorder.record(
                    IntelligenceEventFactory.privacySettingChanged(
                        title = "Browser privacy shields updated",
                        detail = "cosmetic filtering=" + settings.browserCosmeticFilteringEnabled +
                            ", third-party cookies blocked=" + settings.browserBlockThirdPartyCookies,
                        timestampEpochMs = now
                    )
                )
            }

            if (before.scheduledScanEnabled != settings.scheduledScanEnabled ||
                before.autoUpdateFiltersEnabled != settings.autoUpdateFiltersEnabled ||
                before.smartAutoOptimizeEnabled != settings.smartAutoOptimizeEnabled
            ) {
                recorder.record(
                    IntelligenceEventFactory.automationSettingChanged(
                        title = "Automation schedule updated",
                        detail = "scheduled scan=" + settings.scheduledScanEnabled +
                            ", filter sync=" + settings.autoUpdateFiltersEnabled +
                            ", smart maintenance=" + settings.smartAutoOptimizeEnabled,
                        timestampEpochMs = now
                    )
                )
            }
        }
    }

    companion object {
        /** Recovery must drop this far below the configured threshold before it is reported. */
        const val HYSTERESIS_CELSIUS = 2f
    }
}
