package com.adshield.pro.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.domain.model.BatteryThermalSnapshot
import com.adshield.pro.domain.model.MeasurementSource
import com.adshield.pro.engine.optimizer.SystemOptimizerEngine
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject

/**
 * Live battery monitor for the notification shade.
 *
 * While the user is on the Optimizer screen, [SystemOptimizerEngine.readBatteryThermalSnapshot]
 * is sampled on a timer and this service keeps a single ongoing notification in
 * sync so the measured current, power and temperature are readable without
 * opening the app.
 *
 * The service is started only while the Optimizer screen is resumed. It is a
 * *telemetry* service, not a background poller: it stops when the user leaves and
 * never keeps the device awake (no wake locks, no alarms).
 */
@AndroidEntryPoint
class BatteryTelemetryService : Service() {

    @Inject lateinit var optimizerEngine: SystemOptimizerEngine
    @Inject lateinit var preferencesRepository: UserPreferencesRepository

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var loop: Job? = null

    /** Kept so the notification can be rebuilt when the charging extra changes. */
    @Volatile private var lastSnapshot: BatteryThermalSnapshot? = null

    private val batteryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_BATTERY_CHANGED) {
                // Charging state changes warrant an immediate refresh rather than
                // waiting out the sampling interval.
                refreshNotification()
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification(fallback = null, settings = null))
        // Android 14+ requires an explicit export flag; this receiver only ever
        // listens to a protected system broadcast, so it stays unexported.
        ContextCompat.registerReceiver(
            this,
            batteryReceiver,
            IntentFilter(Intent.ACTION_BATTERY_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        loop = scope.launch {
            while (isActive) {
                sample()
                delay(SAMPLE_INTERVAL_MS)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(batteryReceiver) }
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun sample() {
        val settings = runCatching { preferencesRepository.getSettingsSnapshot() }.getOrNull() ?: return
        val snapshot = runCatching { optimizerEngine.readBatteryThermalSnapshot() }.getOrNull() ?: return
        lastSnapshot = snapshot
        refreshNotification(snapshot, settings)
        // Route the same measured snapshot through the alert engine, so heat and
        // heavy-draw alerts fire while the user is watching rather than only from
        // the scheduler.
        runCatching { BatteryHealthNotifier.evaluate(this, snapshot, settings) }
    }

    private fun refreshNotification(
        snapshot: BatteryThermalSnapshot? = lastSnapshot,
        settings: AppSettingsState? = null
    ) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(snapshot, settings))
    }

    private fun buildNotification(
        fallback: BatteryThermalSnapshot?,
        settings: AppSettingsState?
    ): Notification {
        val snapshot = fallback
        val compact = snapshot?.let { compactLine(it) } ?: "Reading battery telemetry…"
        val expanded = snapshot?.let { expandedText(it, settings) } ?: "Waiting for the first measurement."

        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, BatteryTelemetryService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(getString(R.string.battery_channel_monitor_name))
            .setContentText(compact)
            .setStyle(NotificationCompat.BigTextStyle().bigText(expanded))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openIntent)
            .addAction(NotificationCompat.Action.Builder(0, "Stop", stopIntent).build())
            .build()
    }

    /** Level, current and the hottest measured temperature. */
    private fun compactLine(snapshot: BatteryThermalSnapshot): String {
        val parts = mutableListOf("${snapshot.batteryPercent}%")
        when {
            snapshot.currentSource != MeasurementSource.MEASURED -> parts.add("current n/a")
            snapshot.currentMilliAmps >= 0 -> parts.add("+${snapshot.currentMilliAmps} mA")
            else -> parts.add("${snapshot.currentMilliAmps} mA")
        }
        hottest(snapshot)?.let { parts.add(String.format(Locale.US, "%.1f°C", it)) }
        return parts.joinToString(" • ")
    }

    /** The full measured picture, one value per line. */
    private fun expandedText(snapshot: BatteryThermalSnapshot, settings: AppSettingsState?): String {
        val lines = mutableListOf<String>()
        lines.add(snapshot.measuredDrawLabel)

        val watts = snapshot.powerMilliWatts?.let {
            String.format(Locale.US, "%+.1f W", it / 1000f)
        }
        if (watts != null) lines.add("Power: $watts")

        if (snapshot.batteryTemperatureSource == MeasurementSource.MEASURED) {
            lines.add(String.format(Locale.US, "Battery cell: %.1f°C", snapshot.temperatureCelsius))
        } else {
            lines.add("Battery cell: not reported")
        }
        if (snapshot.socTemperatureCelsius != null) {
            lines.add(String.format(Locale.US, "Chip: %.1f°C — %s", snapshot.socTemperatureCelsius, snapshot.socTemperatureSourceLabel))
        } else {
            lines.add("Chip: ${snapshot.socTemperatureSourceLabel}")
        }

        lines.add("State: ${snapshot.chargingSourceLabel} • Health: ${snapshot.healthStatusLabel}")
        snapshot.chargeCounterMilliAmpHours?.let { lines.add("Remaining: $it mAh") }
        snapshot.energyMilliWattHours?.let { lines.add("Stored: $it mWh") }

        val threshold = settings?.batteryTempWarningCelsius
        if (threshold != null && snapshot.isOverheating) {
            lines.add("Above your ${threshold}°C alert threshold.")
        }
        return lines.joinToString("\n")
    }

    private fun hottest(snapshot: BatteryThermalSnapshot): Float? {
        val readings = listOfNotNull(
            snapshot.temperatureCelsius.takeIf { snapshot.batteryTemperatureSource == MeasurementSource.MEASURED },
            snapshot.socTemperatureCelsius
        )
        return readings.maxOrNull()
    }

    private fun createChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.battery_channel_monitor_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.battery_channel_monitor_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL_ID = "adshield_battery_monitor"
        private const val NOTIFICATION_ID = 6100
        private const val SAMPLE_INTERVAL_MS = 5_000L

        /** Start the monitor. Safe to call when it is already running. */
        fun start(context: Context) {
            val intent = Intent(context, BatteryTelemetryService::class.java)
            // Background-start restrictions can refuse the start; a refused start must
            // never take the app down, so it is ignored and the next screen visit retries.
            runCatching {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }
        }

        /** Stop the monitor if it is running. */
        fun stop(context: Context) {
            context.stopService(Intent(context, BatteryTelemetryService::class.java))
        }
    }
}
