package com.adshield.pro.service

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import androidx.core.content.ContextCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.engine.platform.ProtectionSnoozeController
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.StatusTone
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.WidgetAction
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Resizable Home-Screen protection widget displaying live shield status, blocked query counter,
 * block-rate summary, one-tap Protect / Turn Off / Resume control, and a quick 15-minute auto-resume
 * pause button.
 */
@AndroidEntryPoint
class AdShieldWidgetProvider : AppWidgetProvider() {

    @Inject lateinit var repository: AdShieldRepository
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var snoozeController: ProtectionSnoozeController

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        if (appWidgetIds.isEmpty()) return
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                renderWidgets(context.applicationContext, appWidgetManager, appWidgetIds)
            } finally {
                pendingResult.finish()
            }
        }
    }

    override fun onReceive(context: Context, intent: Intent?) {
        super.onReceive(context, intent)
        val action = intent?.action ?: return
        if (action == ACTION_WIDGET_REFRESH || action == ACTION_WIDGET_START ||
            action == ACTION_WIDGET_STOP || action == ACTION_WIDGET_RESUME ||
            action == ACTION_WIDGET_SNOOZE_15M
        ) {
            val appCtx = context.applicationContext
            val pendingResult = goAsync()
            CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                try {
                    handleWidgetAction(appCtx, action)
                } finally {
                    pendingResult.finish()
                }
            }
        }
    }

    private suspend fun handleWidgetAction(appCtx: Context, action: String) {
        when (action) {
            ACTION_WIDGET_START -> {
                snoozeController.clearSnooze()
                if (runCatching { VpnService.prepare(appCtx) }.getOrNull() != null) {
                    launchMainForConsent(appCtx)
                } else {
                    preferencesRepository.setVpnShouldRemainActive(true)
                    val started = runCatching {
                        ContextCompat.startForegroundService(
                            appCtx,
                            Intent(appCtx, AdShieldVpnService::class.java).apply {
                                this.action = AdShieldVpnService.ACTION_START_VPN
                            }
                        )
                    }.isSuccess
                    if (!started) launchMainForConsent(appCtx)
                }
            }
            ACTION_WIDGET_STOP -> {
                snoozeController.clearSnooze()
                preferencesRepository.setVpnShouldRemainActive(false)
                runCatching {
                    appCtx.startService(
                        Intent(appCtx, AdShieldVpnService::class.java).apply {
                            this.action = AdShieldVpnService.ACTION_STOP_VPN
                        }
                    )
                }
            }
            ACTION_WIDGET_RESUME -> {
                if (!snoozeController.resumeNow()) {
                    launchMainForConsent(appCtx)
                }
            }
            ACTION_WIDGET_SNOOZE_15M -> {
                snoozeController.snoozeProtection(
                    minutes = 15,
                    currentStatus = repository.vpnRuntimeState.value.status
                )
            }
            ACTION_WIDGET_REFRESH -> Unit
        }

        val manager = AppWidgetManager.getInstance(appCtx)
        val ids = manager.getAppWidgetIds(ComponentName(appCtx, AdShieldWidgetProvider::class.java))
        if (ids.isNotEmpty()) {
            renderWidgets(appCtx, manager, ids)
            if (action != ACTION_WIDGET_REFRESH) {
                delay(350L)
                renderWidgets(appCtx, manager, ids)
            }
        }
        if (action != ACTION_WIDGET_REFRESH) {
            runCatching { AdShieldTileService.requestSync(appCtx) }
        }
    }

    private suspend fun renderWidgets(
        context: Context,
        manager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        val runtime = repository.vpnRuntimeState.value
        val settings = preferencesRepository.getSettingsSnapshot()
        val allTimeBlocked = runCatching { repository.allTimeBlockedQueriesFlow.first() }.getOrDefault(0L)
        val allTimeTotal = runCatching { repository.allTimeTotalQueriesFlow.first() }.getOrDefault(0L)

        val presentation = ProtectionSnoozeEngine.presentWidget(
            vpnStatus = runtime.status,
            vpnShouldRemainActive = settings.vpnShouldRemainActive,
            snoozeUntilEpochMs = settings.vpnSnoozeUntilEpochMs,
            sessionBlocked = runtime.sessionBlockedQueries,
            sessionTotal = runtime.sessionTotalQueries,
            allTimeBlocked = allTimeBlocked,
            allTimeTotal = allTimeTotal,
            modeTitle = settings.protectionMode.title,
            protocolName = settings.resolverConfig.protocol.name,
            nowEpochMs = System.currentTimeMillis()
        )

        val openAppPending = PendingIntent.getActivity(
            context,
            REQ_OPEN_APP,
            Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val (badgeBg, badgeColor) = when (presentation.statusTone) {
            StatusTone.ACTIVE -> R.drawable.bg_widget_pill_active to 0xFF34D399.toInt()
            StatusTone.PAUSED -> R.drawable.bg_widget_pill_paused to 0xFFFBBF24.toInt()
            StatusTone.ALERT -> R.drawable.bg_widget_pill_paused to 0xFFF87171.toInt()
            StatusTone.INACTIVE -> R.drawable.bg_widget_pill_inactive to 0xFF94A3B8.toInt()
        }
        val primaryBg = if (presentation.primaryAction == WidgetAction.STOP_VPN) {
            R.drawable.bg_widget_btn_danger
        } else {
            R.drawable.bg_widget_btn_primary
        }

        for (id in appWidgetIds) {
            val views = RemoteViews(context.packageName, R.layout.widget_adshield)
            views.setTextViewText(R.id.widget_status_badge, presentation.statusBadge)
            views.setTextColor(R.id.widget_status_badge, badgeColor)
            views.setInt(R.id.widget_status_badge, "setBackgroundResource", badgeBg)
            views.setTextViewText(R.id.widget_subtitle, presentation.subtitle)
            views.setTextViewText(R.id.widget_blocked_count, presentation.blockedCountLabel)
            views.setTextViewText(R.id.widget_rate_label, presentation.totalAndRateLabel)

            views.setTextViewText(R.id.widget_btn_primary, presentation.primaryActionLabel)
            views.setInt(R.id.widget_btn_primary, "setBackgroundResource", primaryBg)
            views.setOnClickPendingIntent(
                R.id.widget_btn_primary,
                pendingForAction(context, presentation.primaryAction, openAppPending)
            )

            views.setTextViewText(R.id.widget_btn_secondary, presentation.secondaryActionLabel)
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
        val intent = Intent(context, AdShieldWidgetProvider::class.java).apply {
            this.action = action
        }
        return PendingIntent.getBroadcast(
            context,
            reqCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun launchMainForConsent(context: Context) {
        runCatching {
            context.startActivity(
                Intent(context, MainActivity::class.java).apply {
                    action = ProtectionSnoozeController.ACTION_START_VPN_WITH_CONSENT
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                }
            )
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
                Intent(app, AdShieldWidgetProvider::class.java).apply {
                    action = ACTION_WIDGET_REFRESH
                }
            )
        }
    }
}
