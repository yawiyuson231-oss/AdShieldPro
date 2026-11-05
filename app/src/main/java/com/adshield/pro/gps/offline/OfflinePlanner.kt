package com.adshield.pro.gps.offline

import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.MapProjection
import kotlin.math.roundToLong

/**
 * AdShield Pro — offline download planner.
 *
 * The planner answers one question honestly: *how big will this download be, and is it allowed?*
 *
 * Tile counts come from real Web-Mercator tile math ([MapProjection.estimateTileCount]), not a
 * guess, so the number the user approves is the number MapLibre will fetch. The limits implement
 * the OpenFreeMap fair-use terms verbatim (max 3 000 tiles or 50 MB per download, max 4 parallel
 * requests, unique User-Agent) so a free public instance cannot be abused by this app.
 *
 * Pure Kotlin: fully unit-tested.
 */
object OfflinePlanner {

    /** Vector tile payload per tile, used for the estimate. Measured on OpenMapTiles z14 city tiles. */
    const val AVERAGE_VECTOR_TILE_BYTES = 11_000L

    /** Glyph/sprite/style resources add roughly this share on top of the tile bytes. */
    const val RESOURCE_OVERHEAD_RATIO = 0.18

    data class Plan(
        val bounds: GeoBounds,
        val minZoom: Int,
        val maxZoom: Int,
        val tileCount: Long,
        val estimatedBytes: Long,
        val withinLimits: Boolean,
        val limitReason: String?,
        val perZoomBreakdown: List<Pair<Int, Long>>
    ) {
        val estimatedMegabytes: Double get() = estimatedBytes / (1024.0 * 1024.0)

        fun summary(): String = if (!withinLimits) {
            limitReason ?: "Outside the download limits"
        } else {
            "%,d tiles · about %.1f MB".format(tileCount, estimatedMegabytes)
        }
    }

    /**
     * Computes the plan and enforces all limits.
     *
     * [maxTiles] / [maxBytes] default to the free tile server policy. A user hosting their own
     * tiles can raise them; the UI makes that explicit instead of silently ignoring the terms.
     */
    fun plan(
        bounds: GeoBounds,
        minZoom: Int,
        maxZoom: Int,
        maxTiles: Int = GpsPreferences.MAX_OFFLINE_TILES_PER_PACK,
        maxBytes: Long = GpsPreferences.MAX_OFFLINE_BYTES_PER_PACK
    ): Plan {
        val safeMin = minZoom.coerceIn(0, 20)
        val safeMax = maxZoom.coerceIn(safeMin, 20)
        val breakdown = ArrayList<Pair<Int, Long>>()
        var tiles = 0L
        for (zoom in safeMin..safeMax) {
            val count = MapProjection.tileRange(bounds, zoom).tileCount
            // Short-circuit: once we are far over the limit there is no point counting further.
            if (tiles + count > maxTiles * 4L) {
                breakdown += zoom to count
                tiles += count
                break
            }
            breakdown += zoom to count
            tiles += count
        }
        val bytes = estimateBytes(tiles)
        val reason = when {
            bounds.approximateAreaKm2 <= 0.0 -> "Select a corridor with a non-zero area"
            bounds.latitudeSpan <= 0.0 || bounds.longitudeSpan <= 0.0 -> "The selected area is a single point"
            tiles > maxTiles -> "%,d tiles exceeds the %,d tile limit — reduce the zoom range or the area"
                .format(tiles, maxTiles)
            bytes > maxBytes -> "%.0f MB exceeds the %.0f MB limit — reduce the zoom range or the area"
                .format(bytes / (1024.0 * 1024.0), maxBytes / (1024.0 * 1024.0))
            else -> null
        }
        return Plan(
            bounds = bounds,
            minZoom = safeMin,
            maxZoom = safeMax,
            tileCount = tiles,
            estimatedBytes = bytes,
            withinLimits = reason == null,
            limitReason = reason,
            perZoomBreakdown = breakdown
        )
    }

    fun estimateBytes(tileCount: Long): Long {
        val tiles = tileCount * AVERAGE_VECTOR_TILE_BYTES
        return (tiles * (1.0 + RESOURCE_OVERHEAD_RATIO)).roundToLong()
    }

    /**
     * Suggests a zoom range that fits the budget for a given area. Used by the "auto-fit" button so a
     * user can download a city at z12–z15 instead of fighting a z6–z18 rejection.
     */
    fun autoFit(
        bounds: GeoBounds,
        maxZoomWanted: Int = 16,
        maxTiles: Int = GpsPreferences.MAX_OFFLINE_TILES_PER_PACK
    ): Plan {
        var best = plan(bounds, 10.coerceAtMost(maxZoomWanted), maxZoomWanted, maxTiles = maxTiles)
        var candidateMax = maxZoomWanted
        while (!best.withinLimits && candidateMax > 10) {
            candidateMax--
            best = plan(bounds, (candidateMax - 5).coerceAtLeast(8), candidateMax, maxTiles = maxTiles)
        }
        if (!best.withinLimits) {
            // Give up gracefully with a tiny area at the lowest useful zoom rather than a lie.
            best = plan(bounds, 0, 8, maxTiles = maxTiles)
        }
        return best
    }

    /** The area a corridor download should cover: the route plus a margin for reroutes. */
    fun corridorBounds(route: List<com.adshield.pro.gps.geo.GeoPoint>, marginMeters: Double = 2_500.0): GeoBounds? {
        val base = GeoBounds.of(route) ?: return null
        return base.expandedBy(marginMeters)
    }

    /** One-line policy statement shown above the download button. */
    fun policyLine(): String =
        "Free tile policy: max %s tiles or %s MB per download, %d parallel requests, unique User-Agent."
            .format(
                "%,d".format(GpsPreferences.MAX_OFFLINE_TILES_PER_PACK),
                GpsPreferences.MAX_OFFLINE_BYTES_PER_PACK / (1024 * 1024),
                GpsPreferences.MAX_PARALLEL_TILE_REQUESTS
            )
}
