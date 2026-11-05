package com.adshield.pro.gps.engine

import kotlin.math.cos
import kotlin.math.sin

/**
 * AdShield Pro — GPS radar plotting.
 *
 * Projects real `GnssStatus` sky coordinates (azimuth 0..360 north-based, elevation 0..90 above the
 * horizon) onto a unit polar plot. This is the geometry a satellite radar needs, and it is pure math
 * so the plot can be verified without a device.
 *
 * Convention: centre = zenith, rim = horizon. X grows east, Y grows *down* in screen space, which is
 * why the sine term is negated — without that the sky plot is mirrored.
 */
object RadarGeometry {

    /** Where one satellite is drawn on the polar radar (unit circle, -1..1 in both axes). */
    data class PlotPoint(
        val svid: Int,
        val constellation: String,
        val x: Float,
        val y: Float,
        /** Distance from the centre, 0 (zenith) .. 1 (horizon). */
        val radius: Float,
        val snrDbHz: Float,
        val usedInFix: Boolean
    ) {
        val snrRatio: Float get() = ((snrDbHz - MIN_SNR) / (MAX_SNR - MIN_SNR)).coerceIn(0f, 1f)
    }

    const val MIN_SNR = 10f
    const val MAX_SNR = 50f

    fun project(satellites: List<SatelliteInfo>): List<PlotPoint> = satellites.map { satellite ->
        val elevation = satellite.elevationDegrees.coerceIn(0f, 90f)
        // Linear in zenith distance keeps a 45° satellite visually clear of the centre blob, which
        // is what a GNSS app user actually needs to see (are the high satellites there?).
        val zenithDistance = (90f - elevation) / 90f
        val azimuthRadians = Math.toRadians(satellite.azimuthDegrees.coerceIn(0f, 360f).toDouble())
        PlotPoint(
            svid = satellite.svid,
            constellation = satellite.constellation,
            x = (zenithDistance * sin(azimuthRadians)).toFloat(),
            y = (-zenithDistance * cos(azimuthRadians)).toFloat(),
            radius = zenithDistance,
            snrDbHz = satellite.snrDbHz,
            usedInFix = satellite.usedInFix
        )
    }

    /** Rings drawn on the radar: 0°, 30°, 60° elevation. */
    fun rings(): List<Float> = listOf(0f, 30f, 60f).map { elevation -> (90f - elevation) / 90f }

    /** Short camera-style label for a constellation. */
    fun constellationCode(name: String): String = when (name) {
        "GPS" -> "GPS"
        "GLONASS" -> "GLO"
        "Galileo" -> "GAL"
        "BeiDou" -> "BDS"
        "QZSS" -> "QZS"
        "NavIC" -> "NAV"
        "SBAS" -> "SBA"
        else -> name.take(3).uppercase()
    }

    /**
     * Simple 0..100 sky score: weight of satellites in fix, then average SNR, then constellation
     * diversity. Used only as a visual indicator, never as a promise of accuracy.
     */
    fun skyScore(snapshot: SatelliteSnapshot?): Int {
        if (snapshot == null || snapshot.satellitesVisible == 0) return 0
        val inFixScore = (snapshot.satellitesUsedInFix / 12.0).coerceIn(0.0, 1.0)
        val snrScore = snapshot.averageSnrDbHz?.let { ((it - MIN_SNR) / (MAX_SNR - MIN_SNR)).coerceIn(0.0, 1.0) } ?: 0.0
        val diversityScore = (snapshot.constellations.size / 3.0).coerceIn(0.0, 1.0)
        return ((inFixScore * 0.5 + snrScore * 0.35 + diversityScore * 0.15) * 100).toInt().coerceIn(0, 100)
    }

    /** What the radar should say when it has nothing to show. */
    fun emptyReason(hasPermission: Boolean, locationEnabled: Boolean, gnssReported: Boolean): String = when {
        !hasPermission -> "Grant precise location to read satellite status"
        !locationEnabled -> "System location is switched off"
        !gnssReported -> "This device's receiver does not report GnssStatus to apps"
        else -> "Waiting for the first satellite report…"
    }
}
