package com.adshield.pro.service

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
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.BatteryThermalSnapshot
import com.adshield.pro.domain.model.MeasurementSource
import java.util.Locale

/**
 * Battery health notifications built from measured values only.
 *
 * Design constraints that came out of the app's own rules:
 *  - **Opt-in.** Nothing is posted unless the user enabled it in Settings.
 *  - **Measured numbers only.** Every line is built from a value that was actually
 *    read. When the device does not report current or a chip temperature, the text
 *    says so instead of substituting a typical figure.
 *  - **Rate limited, not chatty.** These are health alerts, not telemetry: each one
 *    has its own suppression window and its own state, so a hot phone does not
 *    produce a notification every sample.
 */
object BatteryHealthNotifier {

    const val ALERTS_CHANNEL_ID = "adshield_battery_alerts"
    const val HEALTH_CHANNEL_ID = "adshield_battery_health"

    private const val PREFS = "adshield_battery_notification_state"
    private const val KEY_LAST_TEMP_ALERT_MS = "last_temp_alert_ms"
    private const val KEY_LAST_TEMP_ALERT_VALUE = "last_temp_alert_value"
    private const val KEY_LAST_LOW_LEVEL = "last_low_level"
    private const val KEY_CURRENT_ALERT_MS = "last_current_alert_ms"
    private const val KEY_CHARGE_DONE_CYCLE = "charge_done_cycle"

    // -1L, not 0L: 0 is a valid timestamp argument, so it cannot double as "never
    // alerted" or the first alert would be suppressed when the clock starts at 0.
    private const val NEVER = -1L
    private const val TEMP_ALERT_COOLDOWN_MS = 30 * 60 * 1000L
    private const val CURRENT_ALERT_COOLDOWN_MS = 45 * 60 * 1000L
    private const val TEMP_REALERT_DELTA_C = 2.0f

    private const val ID_LOW_BATTERY = 6101
    private const val ID_CHARGE_DONE = 6102
    private const val ID_HEAT = 6103
    private const val ID_CURRENT = 6104
    private const val ID_TEST = 6109

    /** Creates both channels. Safe to call repeatedly; Android ignores duplicates. */
    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        nm.createNotificationChannel(
            NotificationChannel(
                HEALTH_CHANNEL_ID,
                context.getString(R.string.battery_channel_health_name),
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = context.getString(R.string.battery_channel_health_desc)
                setShowBadge(true)
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(
                ALERTS_CHANNEL_ID,
                context.getString(R.string.battery_channel_heat_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = context.getString(R.string.battery_channel_heat_desc)
                setShowBadge(true)
            }
        )
    }

    /** Whether the user has granted the Android 13+ notification permission. */
    fun canPostNotifications(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Evaluates one snapshot and posts whatever is warranted.
     *
     * @return the titles of the notifications that were actually posted, for tests
     *   and for the in-app "last check" line.
     */
    fun evaluate(
        context: Context,
        snapshot: BatteryThermalSnapshot,
        settings: AppSettingsState,
        nowMs: Long = System.currentTimeMillis()
    ): List<String> {
        if (!settings.batteryNotificationsEnabled) return emptyList()
        if (!canPostNotifications(context)) return emptyList()

        ensureChannels(context)
        val posted = mutableListOf<String>()
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val level = snapshot.batteryPercent
        val charging = snapshot.isEffectivelyCharging
        val temp = snapshot.effectiveTemperatureCelsius
        val tempMeasured = snapshot.batteryTemperatureSource == MeasurementSource.MEASURED ||
            snapshot.socTemperatureCelsius != null

        // --- 1. Low battery -----------------------------------------------------
        if (!charging && level <= settings.batteryLowPercentThreshold) {
            val lastLevel = prefs.getInt(KEY_LAST_LOW_LEVEL, -1)
            // Only once per drop below the threshold: re-notify only after the device
            // has recovered above it, or after another 5% of drain.
            if (lastLevel < 0 || level <= lastLevel - 5) {
                post(
                    context, ID_LOW_BATTERY, HEALTH_CHANNEL_ID,
                    title = "Battery low — $level%",
                    body = buildLine(snapshot) + " • AdShield keeps filtering; consider Battery Saver mode.",
                    priority = NotificationCompat.PRIORITY_DEFAULT
                )
                prefs.edit().putInt(KEY_LAST_LOW_LEVEL, level).apply()
                posted.add("Battery low")
            }
        } else if (charging) {
            // Charging resets the cycle so the next drop warns again.
            prefs.edit().putInt(KEY_LAST_LOW_LEVEL, -1).apply()
        }

        // --- 2. Charge complete --------------------------------------------------
        if (settings.batteryNotifyOnChargeComplete && charging && level >= settings.batteryFullPercentThreshold) {
            val cycle = prefs.getLong(KEY_CHARGE_DONE_CYCLE, -1L)
            val thisCycle = nowMs / (12 * 60 * 60 * 1000L) // coarse bucket, one alert per session
            if (cycle != thisCycle) {
                post(
                    context, ID_CHARGE_DONE, HEALTH_CHANNEL_ID,
                    title = "Charge complete — $level%",
                    body = buildLine(snapshot) + " • Unplugging near 80–90% is easier on cell life.",
                    priority = NotificationCompat.PRIORITY_DEFAULT
                )
                prefs.edit().putLong(KEY_CHARGE_DONE_CYCLE, thisCycle).apply()
                posted.add("Charge complete")
            }
        }

        // --- 3. Heat -------------------------------------------------------------
        if (tempMeasured && temp >= settings.batteryTempWarningCelsius) {
            val lastAt = prefs.getLong(KEY_LAST_TEMP_ALERT_MS, NEVER)
            val lastValue = prefs.getFloat(KEY_LAST_TEMP_ALERT_VALUE, 0f)
            val cooled = lastAt == NEVER || nowMs - lastAt >= TEMP_ALERT_COOLDOWN_MS
            val heatingUp = lastAt != NEVER && temp >= lastValue + TEMP_REALERT_DELTA_C
            if (lastAt == NEVER || cooled || heatingUp) {
                post(
                    context, ID_HEAT, ALERTS_CHANNEL_ID,
                    title = String.format(Locale.US, "Heat alert — %.1f°C", temp),
                    body = heatBody(snapshot, settings),
                    priority = NotificationCompat.PRIORITY_HIGH
                )
                prefs.edit()
                    .putLong(KEY_LAST_TEMP_ALERT_MS, nowMs)
                    .putFloat(KEY_LAST_TEMP_ALERT_VALUE, temp)
                    .apply()
                posted.add("Heat alert")
            }
        }

        // --- 4. Measured high discharge current ----------------------------------
        if (!charging &&
            snapshot.currentSource == MeasurementSource.MEASURED &&
            snapshot.currentMilliAmps < -settings.batteryCurrentAlertMilliAmps
        ) {
            val lastAt = prefs.getLong(KEY_CURRENT_ALERT_MS, NEVER)
            if (lastAt == NEVER || nowMs - lastAt >= CURRENT_ALERT_COOLDOWN_MS) {
                post(
                    context, ID_CURRENT, HEALTH_CHANNEL_ID,
                    title = "Heavy battery draw — ${-snapshot.currentMilliAmps} mA",
                    body = buildLine(snapshot) + " • A background app may be working hard.",
                    priority = NotificationCompat.PRIORITY_DEFAULT
                )
                prefs.edit().putLong(KEY_CURRENT_ALERT_MS, nowMs).apply()
                posted.add("Heavy draw")
            }
        }

        return posted
    }

    /** `42% • −812 mA (−3.1 W) • 27.4°C cell` — only components that were measured. */
    fun buildLine(snapshot: BatteryThermalSnapshot): String {
        val parts = mutableListOf("${snapshot.batteryPercent}%")

        if (snapshot.currentSource == MeasurementSource.MEASURED) {
            val amps = String.format(Locale.US, "%d mA", snapshot.currentMilliAmps)
            val watts = snapshot.powerMilliWatts?.let {
                String.format(Locale.US, " (%.1f W)", kotlin.math.abs(it) / 1000f)
            } ?: ""
            parts.add("$amps$watts")
        } else {
            parts.add("current not reported")
        }

        val cell = if (snapshot.batteryTemperatureSource == MeasurementSource.MEASURED) {
            String.format(Locale.US, "%.1f°C cell", snapshot.temperatureCelsius)
        } else {
            null
        }
        val soc = snapshot.socTemperatureCelsius?.let {
            String.format(Locale.US, "%.1f°C chip", it)
        }
        listOfNotNull(cell, soc).forEach(parts::add)

        if (cell == null && soc == null) parts.add("no temperature sensor readable")

        return parts.joinToString(" • ")
    }

    private fun heatBody(snapshot: BatteryThermalSnapshot, settings: AppSettingsState): String {
        val cell = snapshot.temperatureCelsius
        val soc = snapshot.socTemperatureCelsius
        val source = when {
            soc != null && snapshot.batteryTemperatureSource == MeasurementSource.MEASURED &&
                soc - cell >= 5f -> "The chip is hotter than the cell — this is workload heat, not charging."
            snapshot.batteryTemperatureSource == MeasurementSource.MEASURED -> "The battery cell is hot."
            soc != null -> "Measured from ${snapshot.socTemperatureSourceLabel}."
            else -> "Temperature source unavailable."
        }
        val advice = if (snapshot.isCharging) {
            "Unplug or slow-charge until it drops below ${settings.batteryTempWarningCelsius}°C."
        } else {
            "Close heavy apps until it drops below ${settings.batteryTempWarningCelsius}°C."
        }
        return buildLine(snapshot) + " • $source $advice"
    }

    /**
     * Posts one alert using the current measured reading, ignoring thresholds.
     *
     * This exists so "does this actually notify me?" is answerable from the settings
     * screen instead of waiting for a genuinely hot or flat battery.
     */
    fun postTestNotification(context: Context, snapshot: BatteryThermalSnapshot): Boolean {
        if (!canPostNotifications(context)) return false
        ensureChannels(context)
        post(
            context, ID_TEST, ALERTS_CHANNEL_ID,
            title = "Test alert — battery telemetry",
            body = buildLine(snapshot) + " • These are the values your alerts will use.",
            priority = NotificationCompat.PRIORITY_DEFAULT
        )
        return true
    }

    private fun post(
        context: Context,
        id: Int,
        channelId: String,
        title: String,
        body: String,
        priority: Int
    ) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val openIntent = PendingIntent.getActivity(
            context,
            id,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(priority)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setAutoCancel(true)
            .setContentIntent(openIntent)
            .build()
        nm.notify(id, notification)
    }
}
