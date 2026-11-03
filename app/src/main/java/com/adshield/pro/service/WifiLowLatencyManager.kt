package com.adshield.pro.service

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build

/**
 * OmniShield X — WiFi Low-Latency Lock (real, platform-supported lever).
 *
 * While the DNS tunnel is active, holds a low-latency WiFi lock (API 29+) or a
 * high-performance lock (older) so the radio avoids power-save doze between
 * packets. This genuinely reduces ping jitter for streaming/gaming WHILE the
 * screen is on. Honest limits: it cannot raise your ISP bandwidth, and Android
 * itself relaxes the lock when the screen turns off (system behavior). Costs
 * some battery — released on pause/stop.
 */
object WifiLowLatencyManager {

    @Volatile private var lock: WifiManager.WifiLock? = null

    fun acquire(context: Context) {
        runCatching {
            if (lock?.isHeld == true) return
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                WifiManager.WIFI_MODE_FULL_LOW_LATENCY
            else
                @Suppress("DEPRECATION") WifiManager.WIFI_MODE_FULL_HIGH_PERF
            val created = wm.createWifiLock(mode, "OmniShieldX:LowLatency")
            created.setReferenceCounted(false)
            created.acquire()
            lock = created
        }
    }

    fun release() {
        runCatching { lock?.let { if (it.isHeld) it.release() } }
        lock = null
    }
}
