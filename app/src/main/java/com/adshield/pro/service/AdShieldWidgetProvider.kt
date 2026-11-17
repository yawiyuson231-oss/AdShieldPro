package com.adshield.pro.service

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.StatusTone
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.WidgetAction
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Resizable Home-Screen AppWidget displaying real-time AdShield VPN protection state, active
 * protection mode & protocol, blocked query count, and one-tap controls (Start / Stop / Resume
 * plus 15-minute auto-resume Pause).
 *
 * Security design: this receiver only processes standard system `APPWIDGET_UPDATE` renders; all
 * control-action `PendingIntent`s target the non-exported [ProtectionSnoozeReceiver] so untrusted
 * third-party apps cannot forge explicit broadcasts to start, pause, or disable VPN protection.
 */
@AndroidEntryPoint
class AdShieldWidgetProvider : AppWidgetProvider() {

    @Inject lateinit var repository: AdShieldRepository
    @Inject lateinit var preferencesRepository: UserPreferencesRepository

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        if (appWidgetIds.isEmpty()) return
        val appCtx = context.applicationContext
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                renderWidgets(appCtx, appWidgetManager, appWidgetIds, repository, preferencesRepository)
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        const val ACTION_WIDGET_REFRESH = "com.adshield.pro.action.WIDGET_REFRESH"
        const val ACTION_WIDGET_START = "com.adshield.pro.action.WIDGET_START_VPN"
        const val ACTION_WIDGET_STOP = "com.adshield.pro.action.WIDGET_STOP_VPN"
        const val ACTION_WIDGET_RESUME = "com.adshield.pro.action.WIDGET_RESUME_VPN"
        const val ACTION_WIDGET_SNOOZE_15M = "com.adshield.pro.action.WIDGET_SNOOZE_15M"

        private const val REQ_OPEN_APP = 7400
        private const val REQ_START = 7401
        private const val REQ_STOP = 7402
        private const val REQ_RESUME = 7403
        private const val REQ_SNOOZE = 7404

        fun hasInstalledWidgets(context: Context): Boolean = runCatching {
            val app = context.applicationContext
            val manager = AppWidgetManager.getInstance(app)
            manager.getAppWidgetIds(ComponentName(app, AdShieldWidgetProvider::class.java)).isNotEmpty()
        }.getOrDefault(false)

        fun refreshAll(context: Context) {
            val app = context.applicationContext
            if (!hasInstalledWidgets(app)) return
            app.sendBroadcast(
                Intent(app, ProtectionSnoozeReceiver::class.java).apply {
                    action = ACTION_WIDGET_REFRESH
                }
            )
        }

        internal suspend fun updateInstalledWidgetsNow(
            context: Context,
            repository: AdShieldRepository,
            preferencesRepository: UserPreferencesRepository
        ) {
            val app = context.applicationContext
            val manager = AppWidgetManager.getInstance(app)
            val ids = manager.getAppWidgetIds(ComponentName(app, AdShieldWidgetProvider::class.java))
            if (ids.isEmpty()) return
            renderWidgets(app, manager, ids, repository, preferencesRepository)
        }

        private suspend fun renderWidgets(
            context: Context,
            manager: AppWidgetManager,
            appWidgetIds: IntArray,
            repository: AdShieldRepository,
            preferencesRepository: UserPreferencesRepository
        ) {
            val settings = runCatching { preferencesRepository.getSettingsSnapshot() }.getOrNull()
            val runtime = repository.vpnRuntimeState.value
            val totals = runCatching { repository.getAllTimeTotalsNow() }.getOrDefault(0L to 0L)

            val presentation = ProtectionSnoozeEngine.presentWidget(
                vpnStatus = runtime.status,
                vpnShouldRemainActive = settings?.vpnShouldRemainActive ?: false,
                snoozeUntilEpochMs = settings?.vpnSnoozeUntilEpochMs ?: 0L,
                sessionBlocked = runtime.sessionBlockedQueries,
                sessionTotal = runtime.sessionTotalQueries,
                allTimeBlocked = totals.first,
                allTimeTotal = totals.second,
                modeTitle = settings?.protectionMode?.title ?: "Standard Mode",
                protocolName = settings?.resolverConfig?.protocol?.name ?: "DOH"
            )

            val openAppPending = PendingIntent.getActivity(
                context,
                REQ_OPEN_APP,
                Intent(context, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            for (id in appWidgetIds) {
                val views = RemoteViews(context.packageName, R.layout.widget_adshield)
                views.setTextViewText(R.id.widget_status_pill, presentation.statusBadge)
                views.setInt(
                    R.id.widget_status_pill,
                    "setBackgroundResource",
                    when (presentation.statusTone) {
                        StatusTone.ACTIVE -> R.drawable.bg_widget_pill_active
                        StatusTone.PAUSED -> R.drawable.bg_widget_pill_paused
                        StatusTone.INACTIVE -> R.drawable.bg_widget_pill_inactive
                    }
                )
                views.setTextColor(
                    R.id.widget_status_pill,
                    when (presentation.statusTone) {
                        StatusTone.ACTIVE -> 0xFF10B981.toInt()
                        StatusTone.PAUSED -> 0xFFF59E0B.toInt()
                        StatusTone.INACTIVE -> 0xFF94A3B8.toInt()
                    }
                )
                views.setTextViewText(R.id.widget_subtitle, presentation.subtitle)
                views.setTextViewText(R.id.widget_blocked_count, presentation.blockedCountLabel)
                views.setTextViewText(R.id.widget_rate_label, presentation.totalAndRateLabel)

                views.setTextViewText(R.id.widget_btn_primary, presentation.primaryButtonLabel)
                views.setInt(
                    R.id.widget_btn_primary,
                    "setBackgroundResource",
                    if (presentation.primaryAction == WidgetAction.STOP_VPN) {
                        R.drawable.bg_widget_btn_danger
                    } else {
                        R.drawable.bg_widget_btn_primary
                    }
                )
                views.setTextColor(
                    R.id.widget_btn_primary,
                    if (presentation.primaryAction == WidgetAction.STOP_VPN) {
                        0xFFF87171.toInt()
                    } else {
                        0xFF061523.toInt()
                    }
                )
                views.setOnClickPendingIntent(
                    R.id.widget_btn_primary,
                    pendingForAction(context, presentation.primaryAction, openAppPending)
                )

                views.setTextViewText(R.id.widget_btn_secondary, presentation.secondaryButtonLabel)
                views.setOnClickPendingIntent(
                    R.id.widget_btn_secondary,
                    pendingForAction(context, presentation.secondaryAction, openAppPending)
                )

                views.setOnClickPendingIntent(R.id.widget_root, openAppPending)
                manager.updateAppWidget(id, views)
            }
        }

        private fun pendingForAction(
            context: Context,
            action: WidgetAction,
            openAppPending: PendingIntent
        ): PendingIntent = when (action) {
            WidgetAction.OPEN_APP -> openAppPending
            WidgetAction.START_VPN -> broadcastPending(context, ACTION_WIDGET_START, REQ_START)
            WidgetAction.STOP_VPN -> broadcastPending(context, ACTION_WIDGET_STOP, REQ_STOP)
            WidgetAction.RESUME_VPN -> broadcastPending(context, ACTION_WIDGET_RESUME, REQ_RESUME)
            WidgetAction.SNOOZE_15M -> broadcastPending(context, ACTION_WIDGET_SNOOZE_15M, REQ_SNOOZE)
        }

        private fun broadcastPending(context: Context, action: String, reqCode: Int): PendingIntent {
            // Targets non-exported ProtectionSnoozeReceiver — unforgeable by external apps.
            val intent = Intent(context, ProtectionSnoozeReceiver::class.java).apply {
                this.action = action
            }
            return PendingIntent.getBroadcast(
                context,
                reqCode,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }
    }
}
