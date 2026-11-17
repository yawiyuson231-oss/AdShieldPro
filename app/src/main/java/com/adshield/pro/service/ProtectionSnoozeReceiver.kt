package com.adshield.pro.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.engine.platform.ProtectionSnoozeController
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Non-exported (`android:exported="false"`) internal receiver handling:
 * 1. Doze-aware auto-resume alarms when a timed protection pause (snooze) expires.
 * 2. Authenticated Home-Screen widget PendingIntent control actions (`START`, `STOP`, `RESUME`,
 *    `SNOOZE_15M`, `REFRESH`) so external apps can never forge broadcasts to toggle VPN state.
 */
@AndroidEntryPoint
class ProtectionSnoozeReceiver : BroadcastReceiver() {

    @Inject lateinit var snoozeController: ProtectionSnoozeController
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var repository: AdShieldRepository

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != ACTION_RESUME_SNOOZED_VPN &&
            action != AdShieldWidgetProvider.ACTION_WIDGET_REFRESH &&
            action != AdShieldWidgetProvider.ACTION_WIDGET_START &&
            action != AdShieldWidgetProvider.ACTION_WIDGET_STOP &&
            action != AdShieldWidgetProvider.ACTION_WIDGET_RESUME &&
            action != AdShieldWidgetProvider.ACTION_WIDGET_SNOOZE_15M
        ) {
            return
        }
        val appCtx = context.applicationContext
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                when (action) {
                    ACTION_RESUME_SNOOZED_VPN -> snoozeController.executeDueSnoozeResume()
                    AdShieldWidgetProvider.ACTION_WIDGET_START -> {
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
                        refreshWidgetWithFollowUp(appCtx)
                    }
                    AdShieldWidgetProvider.ACTION_WIDGET_STOP -> {
                        snoozeController.clearSnooze()
                        preferencesRepository.setVpnShouldRemainActive(false)
                        runCatching {
                            appCtx.startService(
                                Intent(appCtx, AdShieldVpnService::class.java).apply {
                                    this.action = AdShieldVpnService.ACTION_STOP_VPN
                                }
                            )
                        }
                        refreshWidgetWithFollowUp(appCtx)
                    }
                    AdShieldWidgetProvider.ACTION_WIDGET_RESUME -> {
                        if (!snoozeController.resumeNow()) {
                            launchMainForConsent(appCtx)
                        }
                        refreshWidgetWithFollowUp(appCtx)
                    }
                    AdShieldWidgetProvider.ACTION_WIDGET_SNOOZE_15M -> {
                        snoozeController.snoozeProtection(
                            minutes = 15,
                            currentStatus = repository.vpnRuntimeState.value.status
                        )
                        refreshWidgetWithFollowUp(appCtx)
                    }
                    AdShieldWidgetProvider.ACTION_WIDGET_REFRESH -> {
                        AdShieldWidgetProvider.updateInstalledWidgetsNow(appCtx, repository, preferencesRepository)
                    }
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    private suspend fun refreshWidgetWithFollowUp(appCtx: Context) {
        AdShieldWidgetProvider.updateInstalledWidgetsNow(appCtx, repository, preferencesRepository)
        runCatching { AdShieldTileService.requestSync(appCtx) }
        delay(350L)
        AdShieldWidgetProvider.updateInstalledWidgetsNow(appCtx, repository, preferencesRepository)
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
        const val ACTION_RESUME_SNOOZED_VPN = "com.adshield.pro.action.RESUME_SNOOZED_VPN"
    }
}
