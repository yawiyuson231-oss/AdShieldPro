package com.adshield.pro.service

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.BatteryManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.engine.battery.BatteryAlertPolicy
import com.adshield.pro.engine.platform.DeviceCompatibility

/**
 * Posts the battery alerts decided by [BatteryAlertPolicy] while the app is backgrounded.
 *
 * Why a receiver and not a worker: WorkManager's minimum periodic interval is 15 minutes and it
 * is batched by Doze, so a temperature alert raised by a worker would arrive long after the heat
 * did. ACTION_BATTERY_CHANGED is a sticky system broadcast delivered to registered receivers, so
 * the [BootCompletedReceiver] registers this receiver while the device is charging — the exact
 * window in which overheat and charge-complete matter — and unregisters it otherwise.
 *
 * Honesty rules baked in here:
 *  - a missing POST_NOTIFICATIONS permission stops everything (Android 13+), it never silently
 *    pretends to have alerted
 *  - latching lives in SharedPreferences so a process death cannot cause a duplicate alert
 *  - a broadcast without a temperature extra is not treated as "cool"
 */
class BatteryAlertReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BATTERY_CHANGED) return
        if (!canPost(context)) return

        val levelPercent = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            .takeIf { it in 0..100 }
        val rawTempTenths = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
        val temperature = if (rawTempTenths == Int.MIN_VALUE) {
            null
        } else {
            (rawTempTenths / 10f).takeIf { BatteryAlertPolicy.isPlausibleTemperature(it) }
        }
        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING
        val chargingComplete = status == BatteryManager.BATTERY_STATUS_FULL

        val stored = readState(context)
        val outcome = BatteryAlertPolicy.evaluate(
            levelPercent = levelPercent,
            temperatureCelsius = temperature,
            isCharging = isCharging,
            chargingComplete = chargingComplete,
            previous = stored,
            // Alerts are on unless the user turned them off in Settings; the screen shows the
            // same switch, so the notification cannot contradict the UI.
            alertsEnabled = context.getSharedPreferences(SETTINGS_PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY_ALERTS_ENABLED, true)
        )
        if (outcome.state != stored) writeState(context, outcome.state)
        outcome.alerts.forEach { post(context, it) }
    }

    private fun post(context: Context, alert: BatteryAlertPolicy.Alert) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        ensureChannel(manager, alert)
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_OPEN_DESTINATION, "battery")
        }
        val pending = PendingIntent.getActivity(
            context,
            alert.kind.ordinal + 9000,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, alert.kind.channelId)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(alert.title)
            .setContentText(alert.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alert.body))
            .setPriority(if (alert.priorityHigh) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        runCatching { manager.notify(alert.key.hashCode(), notification) }
    }

    private fun ensureChannel(manager: NotificationManager, alert: BatteryAlertPolicy.Alert) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        if (manager.getNotificationChannel(alert.kind.channelId) != null) return
        val channel = NotificationChannel(
            alert.kind.channelId,
            when (alert.kind) {
                BatteryAlertPolicy.AlertKind.OVERHEAT -> "Battery temperature alerts"
                BatteryAlertPolicy.AlertKind.CHARGED -> "Charging complete"
                BatteryAlertPolicy.AlertKind.CRITICAL_LEVEL -> "Low battery alerts"
            },
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Raised from the same measured battery values the Battery screen shows."
        }
        manager.createNotificationChannel(channel)
    }

    /* ----- latch persistence ----- */

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun readState(context: Context): BatteryAlertPolicy.State {
        val store = prefs(context)
        return BatteryAlertPolicy.State(
            overheatLatched = store.getBoolean(KEY_OVERHEAT, false),
            chargedLatched = store.getBoolean(KEY_CHARGED, false),
            criticalLatched = store.getBoolean(KEY_CRITICAL, false)
        )
    }

    private fun writeState(context: Context, state: BatteryAlertPolicy.State) {
        prefs(context).edit()
            .putBoolean(KEY_OVERHEAT, state.overheatLatched)
            .putBoolean(KEY_CHARGED, state.chargedLatched)
            .putBoolean(KEY_CRITICAL, state.criticalLatched)
            .apply()
    }

    /** True when notifications may actually be posted; used by the Battery screen copy. */
    companion object {
        private const val PREFS_NAME = "adshield_battery_alerts"
        private const val KEY_OVERHEAT = "latch_overheat"
        private const val KEY_CHARGED = "latch_charged"
        private const val KEY_CRITICAL = "latch_critical"
        const val EXTRA_OPEN_DESTINATION = "open_destination"

        const val SETTINGS_PREFS = "adshield_settings"
        const val KEY_ALERTS_ENABLED = "battery_alerts_enabled"

        fun canPost(context: Context): Boolean {
            if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return false
            return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        }

        /** Registers the live listener while a battery event source is running. */
        fun register(context: Context): Boolean = runCatching {
            context.registerReceiver(
                BatteryAlertReceiver(),
                android.content.IntentFilter(Intent.ACTION_BATTERY_CHANGED)
            ) != null
        }.getOrDefault(false)

        /** Clears the latches so the next episode can alert again (used when settings change). */
        fun resetLatches(context: Context) {
            prefs(context).edit().clear().apply()
        }
    }
}
