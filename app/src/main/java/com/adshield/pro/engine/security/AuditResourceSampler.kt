package com.adshield.pro.engine.security

import android.app.ActivityManager
import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock

/** Best-effort OS readings; absent/failed probes remain unknown, never fabricated healthy. */
internal class AuditResourceSampler(private val context: Context) {
    private var previousWall: Long? = null
    private var previousCpu: Long? = null

    fun sample(): EvolutionWorkPolicy.Conditions {
        val memory = runCatching {
            context.getSystemService(ActivityManager::class.java)?.let { manager ->
                ActivityManager.MemoryInfo().also { manager.getMemoryInfo(it) }
            }
        }.getOrNull()
        val battery = runCatching {
            context.getSystemService(BatteryManager::class.java)
                ?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)?.takeIf { it in 0..100 }
        }.getOrNull()
        val thermal = runCatching {
            context.getSystemService(PowerManager::class.java)?.currentThermalStatus
                ?.let { it >= PowerManager.THERMAL_STATUS_SEVERE }
        }.getOrNull()
        val wall = SystemClock.elapsedRealtime()
        val cpu = Process.getElapsedCpuTime()
        val fraction = previousWall?.let { oldWall ->
            previousCpu?.let { oldCpu ->
                if (wall > oldWall && cpu >= oldCpu) {
                    ((cpu - oldCpu).toDouble() / (wall - oldWall) /
                        Runtime.getRuntime().availableProcessors().coerceAtLeast(1)).coerceIn(0.0, 1.0)
                } else null
            }
        }
        previousWall = wall
        previousCpu = cpu
        return EvolutionWorkPolicy.Conditions(
            lowMemory = memory?.lowMemory,
            availableRamBytes = memory?.availMem,
            batteryPercent = battery,
            severeThermal = thermal,
            appCpuFraction = fraction,
            freeStorageBytes = runCatching { context.cacheDir.usableSpace }.getOrNull()
        )
    }
}
