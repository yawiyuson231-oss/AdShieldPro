package com.adshield.pro.engine.worldmonitor

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
import com.adshield.pro.data.worldmonitor.WorldMonitorDao
import com.adshield.pro.data.worldmonitor.toDomain
import com.adshield.pro.data.worldmonitor.toEntity
import com.adshield.pro.domain.worldmonitor.FreshnessClass
import com.adshield.pro.domain.worldmonitor.WatchAlertRecord
import com.adshield.pro.domain.worldmonitor.WatchRegion
import com.adshield.pro.domain.worldmonitor.WorldEntity
import java.util.Locale

/**
 * Global Watchtower Geofence & Alert Evaluation Engine (Section 3).
 *
 * Pure matching function [findMatchingAlerts] is deterministic and unit-testable on JVM;
 * [evaluateAndPersist] persists deduplicated alerts in Room and posts Android notifications
 * when `POST_NOTIFICATIONS` permission is granted.
 */
object WatchtowerManager {

    const val CHANNEL_ID = "world_monitor_watchtower_channel"
    private const val NOTIFICATION_BASE_ID = 8800

    fun findMatchingAlerts(
        regions: List<WatchRegion>,
        entities: List<WorldEntity>,
        alreadySeenAlertIds: Set<String> = emptySet(),
        nowEpochMs: Long = System.currentTimeMillis()
    ): List<WatchAlertRecord> {
        val activeRegions = regions.filter { it.enabled }
        if (activeRegions.isEmpty()) return emptyList()

        val realEntities = entities.filter {
            it.freshness != FreshnessClass.SIMULATED &&
                GeoSpatialIndex.isValidCoordinate(it.latitude, it.longitude)
        }
        val alerts = ArrayList<WatchAlertRecord>()

        for (region in activeRegions) {
            for (entity in realEntities) {
                if (entity.severity.rank < region.minSeverity.rank) continue
                if (region.categories.isNotEmpty() && entity.category !in region.categories) continue
                if (!region.providerFilter.isNullOrBlank() &&
                    !entity.providerId.contains(region.providerFilter, ignoreCase = true) &&
                    !entity.providerName.contains(region.providerFilter, ignoreCase = true)
                ) continue

                val distKm = GeoSpatialIndex.haversineKm(
                    region.latitude,
                    region.longitude,
                    entity.latitude,
                    entity.longitude
                )
                if (distKm > region.radiusKm) continue

                val alertId = "alert:${region.id}:${entity.id}"
                if (alertId in alreadySeenAlertIds) continue

                alerts += WatchAlertRecord(
                    id = alertId,
                    watchRegionId = region.id,
                    watchRegionName = region.name,
                    entityId = entity.id,
                    title = "[${entity.severity.label}] ${entity.title}",
                    summary = "${"%.1f".format(Locale.US, distKm)} km from ${region.name} · ${entity.summary}",
                    category = entity.category,
                    severity = entity.severity,
                    providerName = entity.providerName,
                    sourceUrl = entity.sourceUrl,
                    latitude = entity.latitude,
                    longitude = entity.longitude,
                    triggeredAtEpochMs = nowEpochMs,
                    acknowledged = false
                )
            }
        }
        return alerts.sortedByDescending { it.severity.rank }
    }

    suspend fun evaluateAndPersist(
        context: Context,
        dao: WorldMonitorDao,
        candidates: List<WorldEntity>,
        notifyUser: Boolean = true
    ): List<WatchAlertRecord> {
        val regions = dao.getWatchRegionsSnapshot().map { it.toDomain() }
        if (regions.isEmpty()) return emptyList()

        val potential = findMatchingAlerts(regions, candidates)
        if (potential.isEmpty()) return emptyList()

        val freshAlerts = ArrayList<WatchAlertRecord>()
        for (alert in potential) {
            if (!dao.watchAlertExists(alert.id)) {
                dao.insertWatchAlert(alert.toEntity())
                freshAlerts += alert
            }
        }
        dao.trimWatchAlerts(500)

        if (notifyUser && freshAlerts.isNotEmpty()) {
            dispatchNotification(context, freshAlerts)
        }
        return freshAlerts
    }

    private fun dispatchNotification(context: Context, newAlerts: List<WatchAlertRecord>) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return
        }
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "World Monitor Watchtower",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Geofenced global hazard, weather, maritime, cyber, and space alerts"
            }
            nm.createNotificationChannel(channel)
        }

        val top = newAlerts.first()
        val intent = Intent(context, MainActivity::class.java).apply {
            putExtra("open_world_monitor", true)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            881,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val body = if (newAlerts.size == 1) {
            "${top.watchRegionName}: ${top.summary} (Source: ${top.providerName})"
        } else {
            "${top.watchRegionName}: ${top.title} + ${newAlerts.size - 1} additional regional alert(s)."
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle("Watchtower · ${top.title}")
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify(NOTIFICATION_BASE_ID + (top.watchRegionId.hashCode() and 0x7F), notification)
    }
}
