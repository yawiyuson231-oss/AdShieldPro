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
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Background Battery Thermal & Charge-Complete Alert Worker.
 *
 * Samples real hardware battery telemetry periodically and posts non-spammy notifications
 * (cooldown-gated) when:
 * 1. Battery temperature reaches >= 45.0°C (critical overheating protection warning)
 * 2. Battery reaches 100% / FULL while plugged into a charger
 */
@HiltWorker
class BatteryAlertWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val batteryRepository: BatteryIntelligenceRepository
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                return@withContext Result.success()
            }
            val nmCompat = NotificationManagerCompat.from(applicationContext)
            if (!nmCompat.areNotificationsEnabled()) {
                return@withContext Result.success()
            }

            batteryRepository.runDiagnostics()
            val telemetry = batteryRepository.telemetry.value
            val prefs = applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val now = System.currentTimeMillis()

            val temp = telemetry.temperatureCelsius.rawValue
            val level = telemetry.levelPercent.rawValue
            val decision = evaluateAlertDecision(
                tempCelsius = temp,
                levelPercent = level,
                isCharging = telemetry.isCharging,
                isFull = telemetry.isFull,
                lastThermalAlertMs = prefs.getLong(KEY_LAST_THERMAL_MS, 0L),
                lastFullChargeAlertMs = prefs.getLong(KEY_LAST_FULL_MS, 0L),
                nowEpochMs = now
            ) ?: return@withContext Result.success()

            ensureChannel()
            val openIntent = PendingIntent.getActivity(
                applicationContext,
                decision.notificationId,
                Intent(applicationContext, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification_shield)
                .setContentTitle(decision.title)
                .setContentText(decision.body)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(openIntent)
                .setAutoCancel(true)
                .build()

            nmCompat.notify(decision.notificationId, notification)
            prefs.edit().putLong(decision.cooldownPrefKey, now).apply()
        }
        Result.success()
    }

    private fun ensureChannel() {
        val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Battery Safety Alerts",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Alerts for critical battery overheating and full-charge completion."
        }
        nm.createNotificationChannel(channel)
    }

    data class AlertDecision(
        val notificationId: Int,
        val title: String,
        val body: String,
        val cooldownPrefKey: String
    )

    companion object {
        private const val WORK_NAME = "adshield_battery_alert_worker"
        private const val CHANNEL_ID = "adshield_battery_alerts"
        private const val PREFS_NAME = "adshield_battery_alert_state"
        internal const val KEY_LAST_THERMAL_MS = "last_thermal_alert_ms"
        internal const val KEY_LAST_FULL_MS = "last_full_charge_alert_ms"
        private const val THERMAL_COOLDOWN_MS = 2L * 3600L * 1000L
        private const val FULL_CHARGE_COOLDOWN_MS = 6L * 3600L * 1000L

        fun evaluateAlertDecision(
            tempCelsius: Float?,
            levelPercent: Int?,
            isCharging: Boolean,
            isFull: Boolean,
            lastThermalAlertMs: Long,
            lastFullChargeAlertMs: Long,
            nowEpochMs: Long
        ): AlertDecision? {
            if (tempCelsius != null && tempCelsius >= 45.0f && nowEpochMs - lastThermalAlertMs >= THERMAL_COOLDOWN_MS) {
                return AlertDecision(
                    notificationId = 7101,
                    title = "High Battery Temperature (${"%.1f".format(java.util.Locale.US, tempCelsius)}°C)",
                    body = "Unplug the charger and pause heavy workloads to protect battery longevity.",
                    cooldownPrefKey = KEY_LAST_THERMAL_MS
                )
            }
            if ((isFull || (isCharging && levelPercent != null && levelPercent >= 100)) &&
                nowEpochMs - lastFullChargeAlertMs >= FULL_CHARGE_COOLDOWN_MS
            ) {
                return AlertDecision(
                    notificationId = 7102,
                    title = "Battery Fully Charged (100%)",
                    body = "Unplugging now reduces trickle-charge heat and preserves cycle health.",
                    cooldownPrefKey = KEY_LAST_FULL_MS
                )
            }
            return null
        }

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<BatteryAlertWorker>(30, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
