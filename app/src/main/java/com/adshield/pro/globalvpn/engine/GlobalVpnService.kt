package com.adshield.pro.globalvpn.engine

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.globalvpn.model.TunnelPhase
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Foreground keeper for an active Global VPN session. The real tunnel is owned by the WireGuard
 * backend's own VpnService; this service only provides the ongoing notification and keeps the
 * monitoring coroutine alive in the background. It performs no DNS work.
 */
@AndroidEntryPoint
class GlobalVpnService : Service() {

    @Inject lateinit var controller: GlobalVpnController

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                controller.disconnect()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification("Global VPN", "Starting…"))
                scope.launch {
                    controller.state.collectLatest { state ->
                        val title = when (state.phase) {
                            TunnelPhase.CONNECTED -> "Global VPN · ${state.server?.countryName ?: "Connected"}"
                            TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING -> "Global VPN · Connecting…"
                            TunnelPhase.ERROR -> "Global VPN · Error"
                            else -> "Global VPN"
                        }
                        val text = when (state.phase) {
                            TunnelPhase.CONNECTED ->
                                "↓ ${formatRate(state.rxBytesPerSec)}  ↑ ${formatRate(state.txBytesPerSec)}" +
                                    (state.tunnelPublicIp?.let { " · $it" } ?: "")
                            TunnelPhase.ERROR -> state.errorMessage ?: "Connection error"
                            else -> state.statusNote ?: "Working…"
                        }
                        notificationManager().notify(NOTIFICATION_ID, buildNotification(title, text))
                        if (state.phase == TunnelPhase.IDLE) {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelf()
                        }
                    }
                }
                return START_STICKY
            }
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, GlobalVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "Disconnect", stopIntent)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun createChannel() {
        val manager = notificationManager()
        val channel = NotificationChannel(
            CHANNEL_ID, "Global VPN", NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Active Global VPN connection status" }
        manager.createNotificationChannel(channel)
    }

    private fun notificationManager(): NotificationManager =
        getSystemService(NotificationManager::class.java)

    private fun formatRate(bytesPerSec: Long): String {
        val kb = bytesPerSec / 1024.0
        return if (kb >= 1024) String.format("%.1f MB/s", kb / 1024.0) else String.format("%.0f KB/s", kb)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.adshield.pro.globalvpn.START"
        const val ACTION_STOP = "com.adshield.pro.globalvpn.STOP"
        private const val CHANNEL_ID = "global_vpn_status"
        private const val NOTIFICATION_ID = 4711
    }
}
