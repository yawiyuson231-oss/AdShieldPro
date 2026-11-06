package com.adshield.pro.gps.map

import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.geo.MapProjection
import kotlin.math.cos
import kotlin.math.sin

/** A position in screen pixels, origin at the top-left of the map view. */
data class ScreenPoint(val x: Double, val y: Double)

/**
 * AdShield Pro — screen-space math for the HUD overlays drawn on top of MapLibre.
 *
 * The map itself is a native `MapView`; the vehicle marker, its accuracy circle and the "your
 * position is that way" arrow are Compose layers above it. Those need the same projection the
 * native renderer uses, which this object computes for the flat (no-perspective) cases:
 *
 *  * [pixelsPerMeter] / [accuracyRadiusPx] — the accuracy circle is drawn in metres, so its pixel
 *    radius changes with zoom and latitude. Getting this from the Web-Mercator ground resolution is
 *    exact at any zoom, unlike a hard-coded pixel size.
 *  * [offsetFromCentre] — where a coordinate sits relative to the camera centre, including camera
 *    bearing. Used for the off-screen direction arrow and as the fallback when MapLibre's own
 *    projection is not available yet.
 *
 * The live marker itself prefers [MapLibreEngine.projectToScreen] (MapLibre's own projection), so
 * tilt and bearing are handled by the renderer instead of by an approximation here.
 */
object MapOverlayMath {

    const val DEFAULT_TILE_SIZE: Int = 256

    /** Ground metres per screen pixel at [latitude] and [zoom] (Web Mercator, 256 px tiles). */
    fun pixelsPerMeter(latitude: Double, zoom: Double, tileSize: Int = DEFAULT_TILE_SIZE): Double {
        val metersPerPixel = MapProjection.metersPerPixel(latitude, zoom, tileSize)
        return if (metersPerPixel <= 0.0) 0.0 else 1.0 / metersPerPixel
    }

    /**
     * Radius in pixels for a horizontal accuracy circle of [accuracyMeters].
     *
     * Returns 0 when the accuracy is unknown (a receiver that does not report it) — the caller then
     * draws no circle at all instead of inventing one.
     */
    fun accuracyRadiusPx(
        accuracyMeters: Float?,
        latitude: Double,
        zoom: Double,
        tileSize: Int = DEFAULT_TILE_SIZE
    ): Float {
        val accuracy = accuracyMeters ?: return 0f
        if (!accuracy.isFinite() || accuracy <= 0f) return 0f
        return (accuracy * pixelsPerMeter(latitude, zoom, tileSize)).toFloat()
    }

    /**
     * Offset in pixels from the camera centre to [point], with the map rotated by [bearingDegrees]
     * and no tilt.
     *
     * The sign convention matches a screen: +x is right, +y is down. At bearing 0 north is up, so a
     * point north of the centre has a negative y.
     */
    fun offsetFromCentre(
        point: GeoPoint,
        centre: GeoPoint,
        cameraBearingDegrees: Double,
        zoom: Double,
        tileSize: Int = DEFAULT_TILE_SIZE
    ): ScreenPoint {
        val worldSize = tileSize * 2.0.pow(zoom)
        val here = MapProjection.toMercator(centre)
        val there = MapProjection.toMercator(point)

        var dx = (there.x - here.x) * worldSize
        var dy = (there.y - here.y) * worldSize

        // Shortest way round the antimeridian: without this a point 1° east of the centre would be
        // drawn almost a full world away when the camera straddles ±180°.
        val halfWorld = worldSize / 2.0
        if (dx > halfWorld) dx -= worldSize
        if (dx < -halfWorld) dx += worldSize

        val rotation = Math.toRadians(bearingDegrees)
        // A camera bearing b turns the world so that b points up. A point at screen angle
        // (theta - b) clockwise from up has x = r·sin(theta - b) and y = -r·cos(theta - b); with
        // dx = r·sin(theta) and dy = -r·cos(theta) that expands to the two lines below.
        val rotatedX = dx * cos(rotation) + dy * sin(rotation)
        val rotatedY = dy * cos(rotation) - dx * sin(rotation)
        return ScreenPoint(rotatedX, rotatedY)
    }

    /**
     * Clamps an offset to the edge of a viewport, inset by [marginPx], so an off-screen target can
     * be shown as a direction arrow rather than silently disappearing.
     *
     * When the point is inside the viewport it is returned unchanged.
     */
    fun clampToViewport(
        offset: ScreenPoint,
        viewportWidthPx: Float,
        viewportHeightPx: Float,
        marginPx: Float = 28f
    ): ScreenPoint {
        val halfWidth = (viewportWidthPx / 2.0 - marginPx).coerceAtLeast(1.0)
        val halfHeight = (viewportHeightPx / 2.0 - marginPx).coerceAtLeast(1.0)
        val inside = offset.x in -halfWidth..halfWidth && offset.y in -halfHeight..halfHeight
        if (inside) return offset

        val scaleX = if (offset.x == 0.0) Double.MAX_VALUE else halfWidth / kotlin.math.abs(offset.x)
        val scaleY = if (offset.y == 0.0) Double.MAX_VALUE else halfHeight / kotlin.math.abs(offset.y)
        val scale = minOf(scaleX, scaleY)
        return ScreenPoint(offset.x * scale, offset.y * scale)
    }

    /** Bearing from the camera centre to [point], for the off-screen direction arrow. */
    fun arrowBearingDegrees(centre: GeoPoint, point: GeoPoint): Double =
        Geodesy.bearingDegrees(centre, point)

    private fun Double.pow(exponent: Double): Double = Math.pow(this, exponent)
}
