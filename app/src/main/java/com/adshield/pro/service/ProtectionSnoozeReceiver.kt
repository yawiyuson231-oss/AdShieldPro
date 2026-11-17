package com.adshield.pro.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.adshield.pro.engine.platform.ProtectionSnoozeController
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Receives Doze-aware auto-resume triggers when a timed protection pause (snooze) expires and
 * restores local DNS filtering idempotently via [ProtectionSnoozeController].
 */
@AndroidEntryPoint
class ProtectionSnoozeReceiver : BroadcastReceiver() {

    @Inject lateinit var snoozeController: ProtectionSnoozeController

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_RESUME_SNOOZED_VPN) return
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                snoozeController.executeDueSnoozeResume()
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        const val ACTION_RESUME_SNOOZED_VPN = "com.adshield.pro.action.RESUME_SNOOZED_VPN"
    }
}
