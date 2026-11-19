package com.adshield.pro.worker

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.battery.BatteryTelemetrySource
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Background Battery Overheating & Charge-Completion Alert Worker.
 *
 * Evaluates real hardware battery telemetry via [BatteryTelemetrySource] during periodic WorkManager
 * maintenance passes and posts high-signal user notifications only when:
 * 1. Measured battery temperature reaches `>= 43.0 °C` or OS health reports `OVERHEAT`, OR
 * 2. The device is plugged in and reaches full charge (`100%` / `isFull`) so the user can unplug
 *    if desired (Android does not allow third-party apps to cut charging current directly).
 *
 * Missing or unsupported temperature/level readings never trigger guessed alerts, and per-kind
 * cooldowns prevent duplicate notification spam.
 */
@HiltWorker
class BatteryAlertWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val telemetrySource: BatteryTelemetrySource,
    private val preferencesRepository: UserPreferencesRepository
) : CoroutineWorker(appContext, workerParams) {

    enum class AlertKind { OVERHEAT_CRITICAL, OVERHEAT_WARNING, CHARGE_COMPLETE }

    data class BatteryAlertDecision(
        val kind: AlertKind,
        val title: String,
        val body: String
    )

    override suspend fun doWork(): Result {
        val settings = preferencesRepository.getSettingsSnapshot()
        if (!settings.batteryAlertsEnabled) return Result.success()

        val telemetry = telemetrySource.refresh()
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val lastKind = prefs.getString(KEY_LAST_ALERT_KIND, null)
        val lastAtMs = prefs.getLong(KEY_LAST_ALERT_AT_MS, 0L)
        val now = System.currentTimeMillis()

        val decision = evaluateAlert(
            telemetry = telemetry,
            alertsEnabled = settings.batteryAlertsEnabled,
            overheatWarningCelsius = settings.gameBoosterTempWarningCelsius.toFloat().coerceIn(40f, 46f),
            lastAlertKindName = lastKind,
            lastAlertEpochMs = lastAtMs,
            nowEpochMs = now
        ) ?: return Result.success()

        if (postNotification(decision)) {
            prefs.edit()
                .putString(KEY_LAST_ALERT_KIND, decision.kind.name)
                .putLong(KEY_LAST_ALERT_AT_MS, now)
                .apply()
        }
        return Result.success()
    }

    private fun postNotification(decision: BatteryAlertDecision): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(appContext, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Battery & Thermal Alerts",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Alerts for measured battery overheating and full-charge events"
        }
        manager.createNotificationChannel(channel)

        val tap = PendingIntent.getActivity(
            appContext,
            NOTIFICATION_ID,
            Intent(appContext, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(decision.title)
            .setContentText(decision.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(decision.body))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
        return true
    }

    companion object {
        const val WORK_NAME = "adshield_battery_alert_periodic"
        private const val CHANNEL_ID = "adshield_battery_alerts"
        private const val NOTIFICATION_ID = 4309
        private const val PREFS_NAME = "adshield_battery_alert_state"
        private const val KEY_LAST_ALERT_KIND = "last_alert_kind"
        private const val KEY_LAST_ALERT_AT_MS = "last_alert_at_ms"
        const val COOLDOWN_MS = 2L * 3600_000L // 2 hours between identical alert kinds

        /** Pure deterministic alert evaluator (unit-tested on the JVM without Android mocks). */
        fun evaluateAlert(
            telemetry: BatteryTelemetry,
            alertsEnabled: Boolean,
            overheatWarningCelsius: Float = 43.0f,
            lastAlertKindName: String? = null,
            lastAlertEpochMs: Long = 0L,
            nowEpochMs: Long = System.currentTimeMillis()
        ): BatteryAlertDecision? {
            if (!alertsEnabled) return null

            val tempC = telemetry.temperatureCelsius.rawValue
            val level = telemetry.levelPercent.rawValue

            val candidate: BatteryAlertDecision? = when {
                (tempC != null && tempC >= 46.0f) || telemetry.health == BatteryHealthStatus.OVERHEAT -> {
                    val tempLabel = tempC?.let { String.format(Locale.US, "%.1f °C", it) } ?: "OS OVERHEAT"
                    BatteryAlertDecision(
                        kind = AlertKind.OVERHEAT_CRITICAL,
                        title = "Critical battery temperature ($tempLabel)",
                        body = "Measured battery temperature reached $tempLabel. Unplug the charger or pause heavy gaming to reduce thermal wear."
                    )
                }
                tempC != null && tempC >= overheatWarningCelsius -> {
                    val tempLabel = String.format(Locale.US, "%.1f °C", tempC)
                    BatteryAlertDecision(
                        kind = AlertKind.OVERHEAT_WARNING,
                        title = "High battery temperature ($tempLabel)",
                        body = "Battery sensor reports $tempLabel${if (telemetry.isCharging) " while charging" else ""}. Allow airflow around the phone."
                    )
                }
                telemetry.isCharging && (telemetry.isFull || (level != null && level >= 100)) -> {
                    BatteryAlertDecision(
                        kind = AlertKind.CHARGE_COMPLETE,
                        title = "Battery charging complete (100%)",
                        body = "Measured charge reached 100% on ${telemetry.pluggedLabel}. Unplugging avoids prolonged trickle heat."
                    )
                }
                else -> null
            } ?: return null

            if (lastAlertKindName == candidate.kind.name &&
                lastAlertEpochMs > 0L &&
                (nowEpochMs - lastAlertEpochMs) in 0L until COOLDOWN_MS
            ) {
                return null
            }
            return candidate
        }

        fun applySchedule(context: Context, enabled: Boolean) {
            val wm = WorkManager.getInstance(context)
            if (!enabled) {
                wm.cancelUniqueWork(WORK_NAME)
                return
            }
            val req = PeriodicWorkRequestBuilder<BatteryAlertWorker>(30, TimeUnit.MINUTES).build()
            wm.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, req)
        }
    }
}
