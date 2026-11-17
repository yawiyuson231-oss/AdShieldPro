package com.adshield.pro.engine.platform

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.service.AdShieldTileService
import com.adshield.pro.service.AdShieldVpnService
import com.adshield.pro.service.AdShieldWidgetProvider
import com.adshield.pro.service.ProtectionSnoozeReceiver
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Coordinates timed protection pauses (auto-resume snooze) using inexact Doze-aware
 * [AlarmManager.setAndAllowWhileIdle] alarms (requiring zero exact-alarm permissions) plus
 * synchronization across the AdShield Quick Settings tile and Home-Screen widget.
 */
@Singleton
class ProtectionSnoozeController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferencesRepository: UserPreferencesRepository
) {

    /**
     * Pauses active DNS filtering for [minutes] (clamped to 1..720) and schedules an automatic
     * resume alarm. Returns the persisted resume deadline in epoch milliseconds.
     */
    suspend fun snoozeProtection(minutes: Int, currentStatus: VpnStatus): Long {
        if (currentStatus != VpnStatus.CONNECTED &&
            currentStatus != VpnStatus.STARTING &&
            currentStatus != VpnStatus.RECONNECTING &&
            currentStatus != VpnStatus.PAUSED
        ) {
            notifySurfacesChanged(context)
            return 0L
        }
        val clamped = ProtectionSnoozeEngine.clampMinutes(minutes)
        val deadline = ProtectionSnoozeEngine.computeDeadline(System.currentTimeMillis(), clamped)
        preferencesRepository.setVpnShouldRemainActive(true)
        preferencesRepository.setVpnSnoozeUntilEpochMs(deadline)
        scheduleResumeAlarm(deadline)

        runCatching {
            context.startService(
                Intent(context, AdShieldVpnService::class.java).apply {
                    action = AdShieldVpnService.ACTION_PAUSE_VPN
                }
            )
        }
        notifySurfacesChanged(context)
        return deadline
    }

    /** Clears any persisted snooze deadline and cancels the pending auto-resume alarm. */
    suspend fun clearSnooze() {
        cancelResumeAlarm()
        if (preferencesRepository.getSettingsSnapshot().vpnSnoozeUntilEpochMs != 0L) {
            preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
        }
    }

    /**
     * Immediately ends any active snooze and resumes VPN protection.
     * Returns `false` if Android VPN consent still needs to be granted in the foreground UI.
     */
    suspend fun resumeNow(): Boolean {
        clearSnooze()
        if (VpnService.prepare(context) != null) {
            notifySurfacesChanged(context)
            return false
        }
        preferencesRepository.setVpnShouldRemainActive(true)
        val resumeIntent = Intent(context, AdShieldVpnService::class.java).apply {
            action = AdShieldVpnService.ACTION_RESUME_VPN
        }
        val started = runCatching {
            ContextCompat.startForegroundService(context, resumeIntent)
        }.isSuccess
        notifySurfacesChanged(context)
        return started
    }

    /**
     * Idempotently checks whether a persisted snooze has reached its deadline and restarts/resumes
     * DNS protection if due; re-arms the alarm if still in the future.
     */
    suspend fun executeDueSnoozeResume() {
        val settings = preferencesRepository.getSettingsSnapshot()
        val now = System.currentTimeMillis()
        if (ProtectionSnoozeEngine.isSnoozeDue(settings.vpnSnoozeUntilEpochMs, settings.vpnShouldRemainActive, now)) {
            cancelResumeAlarm()
            if (VpnService.prepare(context) == null) {
                val resumeIntent = Intent(context, AdShieldVpnService::class.java).apply {
                    action = AdShieldVpnService.ACTION_RESUME_VPN
                }
                val started = runCatching {
                    ContextCompat.startForegroundService(context, resumeIntent)
                }.isSuccess
                // Clear deadline only when service start succeeded; if Android 12+ background FGS
                // restrictions block the alarm start, keeping the elapsed deadline allows the live
                // VPN packet loop to self-resume on the very next DNS query.
                if (started) {
                    preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
                }
            } else {
                preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
            }
        } else if (!settings.vpnShouldRemainActive && settings.vpnSnoozeUntilEpochMs != 0L) {
            preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
            cancelResumeAlarm()
        } else if (ProtectionSnoozeEngine.isSnoozeActive(settings.vpnSnoozeUntilEpochMs, now) &&
            settings.vpnShouldRemainActive
        ) {
            scheduleResumeAlarm(settings.vpnSnoozeUntilEpochMs)
        }
        notifySurfacesChanged(context)
    }

    /**
     * Reconciles any persisted snooze timer on `BOOT_COMPLETED` / `MY_PACKAGE_REPLACED`.
     * Returns `true` when protection is still inside an active timed pause window (so the caller
     * holds off starting active filtering until the re-armed alarm fires).
     */
    suspend fun reconcileOnBoot(): Boolean {
        val settings = preferencesRepository.getSettingsSnapshot()
        val deadline = settings.vpnSnoozeUntilEpochMs
        if (deadline <= 0L) return false
        val now = System.currentTimeMillis()
        return if (!settings.vpnShouldRemainActive || now >= deadline) {
            preferencesRepository.setVpnSnoozeUntilEpochMs(0L)
            cancelResumeAlarm()
            false
        } else {
            scheduleResumeAlarm(deadline)
            true
        }
    }

    private fun scheduleResumeAlarm(deadlineEpochMs: Long) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val pi = buildResumePendingIntent(PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            ?: return
        runCatching {
            alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, deadlineEpochMs, pi)
        }
    }

    fun cancelResumeAlarm() {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val pi = buildResumePendingIntent(PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE)
            ?: return
        runCatching {
            alarmManager.cancel(pi)
            pi.cancel()
        }
    }

    private fun buildResumePendingIntent(flags: Int): PendingIntent? {
        val intent = Intent(context, ProtectionSnoozeReceiver::class.java).apply {
            action = ProtectionSnoozeReceiver.ACTION_RESUME_SNOOZED_VPN
        }
        return PendingIntent.getBroadcast(context, REQUEST_CODE_RESUME_SNOOZE, intent, flags)
    }

    companion object {
        const val ACTION_START_VPN_WITH_CONSENT = "com.adshield.pro.action.START_VPN_WITH_CONSENT"
        private const val REQUEST_CODE_RESUME_SNOOZE = 7310

        fun notifySurfacesChanged(context: Context) {
            val appCtx = context.applicationContext
            runCatching { AdShieldTileService.requestSync(appCtx) }
            runCatching { AdShieldWidgetProvider.refreshAll(appCtx) }
        }
    }
}
