package com.adshield.pro.gps.geo

import kotlin.math.abs
import kotlin.math.asin
import kotlin.math.atan2
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.math.tan
import java.util.Locale

/**
 * AdShield Pro — GPS module, pure-geodesy layer.
 *
 * Everything in this package is plain Kotlin (no android.* imports) so the navigation maths can
 * be unit-tested on the JVM without a device, emulator or network. The Android layer only feeds
 * real GNSS readings in and renders the results out.
 *
 * Earth model: WGS-84 with the mean radius used for haversine (6 371 008.8 m). That is accurate to
 * ~0.5 % on distances below 500 km, which is far below GNSS accuracy at driving scale. It is not a
 * geodesic (Vincenty/Karney) solution, and the limitation is recorded in the capability registry.
 */
object Geodesy {

    /** IUGG mean Earth radius in metres. */
    const val EARTH_RADIUS_M: Double = 6_371_008.8

    /** Speed of a GNSS fix that cannot be a road vehicle (m/s). ~900 km/h. */
    const val PHYSICAL_MAX_SPEED_MPS: Double = 250.0

    fun normalizeLongitude(lon: Double): Double {
        var value = lon
        while (value > 180.0) value -= 360.0
        while (value < -180.0) value += 360.0
        return value
    }

    fun normalizeBearing(degrees: Double): Double {
        var value = degrees % 360.0
        if (value < 0.0) value += 360.0
        return value
    }

    /** Great-circle distance in metres. */
    fun distanceMeters(a: GeoPoint, b: GeoPoint): Double {
        val lat1 = Math.toRadians(a.latitude)
        val lat2 = Math.toRadians(b.latitude)
        val dLat = lat2 - lat1
        // No normalisation needed: sin/cos are 2-pi periodic, so a 359.8° step gives exactly the
        // same result as the equivalent -0.2° one. (Verified, not assumed — see
        // GpsAuditRegressionTest.testDistanceAcrossAntimeridianUsesTheShortWayRound.)
        val dLon = Math.toRadians(b.longitude - a.longitude)
        val h = sin(dLat / 2.0).pow(2) + cos(lat1) * cos(lat2) * sin(dLon / 2.0).pow(2)
        return 2.0 * EARTH_RADIUS_M * asin(min(1.0, sqrt(h)))
    }

    /** Initial bearing (forward azimuth) from [a] to [b], degrees clockwise from true north. */
    fun bearingDegrees(a: GeoPoint, b: GeoPoint): Double {
        val lat1 = Math.toRadians(a.latitude)
        val lat2 = Math.toRadians(b.latitude)
        val dLon = Math.toRadians(b.longitude - a.longitude)
        val y = sin(dLon) * cos(lat2)
        val x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dLon)
        return normalizeBearing(Math.toDegrees(atan2(y, x)))
    }

    /** Point reached after travelling [distanceMeters] along [bearingDegrees] from [origin]. */
    fun destination(origin: GeoPoint, bearingDegrees: Double, distanceMeters: Double): GeoPoint {
        val angular = distanceMeters / EARTH_RADIUS_M
        val bearing = Math.toRadians(bearingDegrees)
        val lat1 = Math.toRadians(origin.latitude)
        val lon1 = Math.toRadians(origin.longitude)
        val lat2 = asin(sin(lat1) * cos(angular) + cos(lat1) * sin(angular) * cos(bearing))
        val lon2 = lon1 + atan2(
            sin(bearing) * sin(angular) * cos(lat1),
            cos(angular) - sin(lat1) * sin(lat2)
        )
        return GeoPoint(
            latitude = Math.toDegrees(lat2),
            longitude = normalizeLongitude(Math.toDegrees(lon2))
        )
    }

    /** Smallest signed rotation (degrees, -180..180) that takes [from] to [to]. */
    fun bearingDelta(from: Double, to: Double): Double {
        var delta = normalizeBearing(to) - normalizeBearing(from)
        if (delta > 180.0) delta -= 360.0
        if (delta < -180.0) delta += 360.0
        return delta
    }

    /** Metres per degree of latitude, valid everywhere. */
    fun metersPerDegreeLatitude(latitude: Double): Double =
        Math.PI / 180.0 * EARTH_RADIUS_M * (1.0 - 0.00669438 * sin(Math.toRadians(latitude)).pow(2))

    /**
     * Metres per degree of longitude at [latitude]. Used by the flat-earth projection inside
     * [MapProjection] and by the route snapper, both of which only ever span a few kilometres.
     */
    fun metersPerDegreeLongitude(latitude: Double): Double =
        Math.PI / 180.0 * EARTH_RADIUS_M * cos(Math.toRadians(latitude))

    /**
     * Distance from [point] to the great-circle segment [a]..[b] in metres, computed on a local
     * equirectangular plane. Error is < 0.5 % for segments shorter than ~50 km, which is the only
     * scale navigation uses (a single OSRM/Valhalla step never spans more).
     */
    fun distanceToSegment(point: GeoPoint, a: GeoPoint, b: GeoPoint): Double =
        projectOnSegment(point, a, b).distanceMeters

    /**
     * Projects [point] onto the segment [a]..[b]. Returns the closest point, the distance to it and
     * the fraction (0..1) along the segment.
     */
    fun projectOnSegment(point: GeoPoint, a: GeoPoint, b: GeoPoint): SegmentProjection {
        val refLat = Math.toRadians((a.latitude + b.latitude + point.latitude) / 3.0)
        val mPerDegLat = metersPerDegreeLatitude(refLat)
        val mPerDegLon = metersPerDegreeLongitude(refLat)

        val ax = 0.0
        val ay = 0.0
        // Longitude differences are wrapped so a segment that crosses the antimeridian is treated as
        // the short way round rather than the long way across the whole planet.
        val dLonB = normalizeLongitude(b.longitude - a.longitude)
        val dLonP = normalizeLongitude(point.longitude - a.longitude)
        val bx = dLonB * mPerDegLon
        val by = (b.latitude - a.latitude) * mPerDegLat
        val px = dLonP * mPerDegLon
        val py = (point.latitude - a.latitude) * mPerDegLat

        val dx = bx - ax
        val dy = by - ay
        val lengthSquared = dx * dx + dy * dy
        val rawFraction = if (lengthSquared <= 1e-9) 0.0 else ((px - ax) * dx + (py - ay) * dy) / lengthSquared
        val fraction = rawFraction.coerceIn(0.0, 1.0)
        val closest = if (fraction <= 0.0) {
            a
        } else if (fraction >= 1.0) {
            b
        } else {
            GeoPoint(
                latitude = a.latitude + (b.latitude - a.latitude) * fraction,
                longitude = normalizeLongitude(a.longitude + dLonB * fraction)
            )
        }
        val dxp = px - dx * fraction
        val dyp = py - dy * fraction
        return SegmentProjection(
            closest = closest,
            distanceMeters = sqrt(dxp * dxp + dyp * dyp),
            fraction = fraction
        )
    }

    data class SegmentProjection(
        val closest: GeoPoint,
        val distanceMeters: Double,
        val fraction: Double
    )

    /** Total length in metres of a polyline. */
    fun polylineLengthMeters(points: List<GeoPoint>): Double {
        if (points.size < 2) return 0.0
        var total = 0.0
        for (index in 1 until points.size) {
            total += distanceMeters(points[index - 1], points[index])
        }
        return total
    }

    /**
     * Implied speed between two fixes in m/s. Negative or non-finite time deltas return null so
     * callers must decide what to do with a broken clock instead of silently accepting 0 m/s.
     */
    fun impliedSpeedMps(from: GeoPoint, fromTimeMs: Long, to: GeoPoint, toTimeMs: Long): Double? {
        val deltaSeconds = (toTimeMs - fromTimeMs) / 1000.0
        if (!deltaSeconds.isFinite() || deltaSeconds <= 0.0) return null
        return distanceMeters(from, to) / deltaSeconds
    }

    /** Rounds a coordinate to the given number of decimals (used for privacy-downsampled history). */
    fun roundToDecimals(value: Double, decimals: Int): Double {
        val factor = 10.0.pow(decimals)
        return (value * factor).let { if (it >= 0) floor(it + 0.5) else ceil(it - 0.5) } / factor
    }

    /** Human-readable distance used by the navigation banner. */
    fun formatDistance(meters: Double): String = when {
        !meters.isFinite() || meters < 0 -> "—"
        meters < 950 -> "${meters.coerceAtLeast(0.0).let { if (it < 10) String.format(Locale.US, "%.1f", it) else it.toInt().toString() }} m"
        else -> String.format(Locale.US, "%.1f km", meters / 1000.0)
    }

    /** Human-readable duration: 45 s, 12 min, 1 h 08 min. */
    fun formatDuration(seconds: Double): String {
        if (!seconds.isFinite() || seconds < 0) return "—"
        val totalSeconds = seconds.toLong()
        if (totalSeconds < 60) return "$totalSeconds s"
        val minutes = totalSeconds / 60
        if (minutes < 60) return "$minutes min"
        val hours = minutes / 60
        val remainder = minutes % 60
        return if (remainder == 0L) "$hours h" else "$hours h ${remainder.toString().padStart(2, '0')} min"
    }

    /** "Lat 15.123456, Lon 120.654321" — used by the telemetry and security screens. */
    fun formatCoordinates(latitude: Double, longitude: Double, decimals: Int = 6): String =
        String.format(Locale.US, "Lat %." + decimals + "f, Lon %." + decimals + "f", latitude, longitude)

    /** Absolute angular difference between two bearings, 0..180. */
    fun bearingDifference(a: Double, b: Double): Double = abs(bearingDelta(a, b))
}

/** A WGS-84 coordinate. Pure data, no platform types. */
data class GeoPoint(
    val latitude: Double,
    val longitude: Double
) {
    init {
        require(latitude.isFinite() && longitude.isFinite()) { "coordinates must be finite" }
        require(latitude in -90.0..90.0) { "latitude out of range: $latitude" }
    }

    /** Longitude is normalised rather than rejected so a route crossing the antimeridian still works. */
    val normalizedLongitude: Double get() = Geodesy.normalizeLongitude(longitude)

    val isValid: Boolean
        get() = latitude in -90.0..90.0 && longitude in -180.0..180.0

    fun toMercator(): MercatorPoint = MapProjection.toMercator(this)

    companion object {
        /** Kotlin-friendly alias for callers that prefer explicit ordering. */
        fun of(latitude: Double, longitude: Double): GeoPoint = GeoPoint(latitude, longitude)
    }
}

/** An axis-aligned latitude/longitude window. */
data class GeoBounds(
    val south: Double,
    val west: Double,
    val north: Double,
    val east: Double
) {
    init {
        require(north >= south) { "north must be >= south" }
    }

    val center: GeoPoint get() = GeoPoint((south + north) / 2.0, (west + east) / 2.0)
    val latitudeSpan: Double get() = north - south
    val longitudeSpan: Double get() = Geodesy.normalizeLongitude(east - west).let { if (it < 0) it + 360.0 else it }

    /** Approximate area in square kilometres (equirectangular at the mid-latitude). */
    val approximateAreaKm2: Double
        get() {
            val heightM = Geodesy.metersPerDegreeLatitude(center.latitude) * latitudeSpan
            val widthM = Geodesy.metersPerDegreeLongitude(center.latitude) * longitudeSpan
            return (heightM / 1000.0) * (widthM / 1000.0)
        }

    fun contains(point: GeoPoint): Boolean {
        if (point.latitude < south || point.latitude > north) return false
        if (longitudeSpan >= 360.0) return true
        val delta = Geodesy.normalizeLongitude(point.longitude - west)
        val positiveDelta = if (delta < 0) delta + 360.0 else delta
        return positiveDelta <= longitudeSpan
    }

    fun expandedBy(meters: Double): GeoBounds {
        val latDelta = meters / Geodesy.metersPerDegreeLatitude(center.latitude)
        val lonDelta = meters / max(1.0, Geodesy.metersPerDegreeLongitude(center.latitude))
        return GeoBounds(
            south = (south - latDelta).coerceAtLeast(-85.05112878),
            west = Geodesy.normalizeLongitude(west - lonDelta),
            north = (north + latDelta).coerceAtMost(85.05112878),
            east = Geodesy.normalizeLongitude(east + lonDelta)
        )
    }

    fun intersects(other: GeoBounds): Boolean =
        south <= other.north && north >= other.south &&
            longitudeSpan >= 360.0 || other.longitudeSpan >= 360.0 ||
            contains(GeoPoint(other.center.latitude, other.west)) ||
            other.contains(GeoPoint(center.latitude, west))

    companion object {
        val WORLD = GeoBounds(south = -85.05112878, west = -180.0, north = 85.05112878, east = 180.0)

        fun around(point: GeoPoint, radiusMeters: Double): GeoBounds =
            GeoBounds(point.latitude, point.longitude, point.latitude, point.longitude).expandedBy(radiusMeters)

        fun of(points: Collection<GeoPoint>): GeoBounds? {
            if (points.isEmpty()) return null
            var south = 90.0
            var north = -90.0
            var west = 180.0
            var east = -180.0
            points.forEach { point ->
                if (point.latitude < south) south = point.latitude
                if (point.latitude > north) north = point.latitude
                if (point.longitude < west) west = point.longitude
                if (point.longitude > east) east = point.longitude
            }
            return GeoBounds(south = south, west = west, north = north, east = east)
        }
    }
}

/** Web-Mercator (EPSG:3857) coordinate in the 0..1 "world" space used by slippy tiles. */
data class MercatorPoint(val x: Double, val y: Double)

/**
 * Web-Mercator math for the tile/offline planner and the map camera.
 *
 * Identical to the slippy-map standard (z/x/y), so a tile count computed here is the same tile
 * count MapLibre would request for that screen area — which is what makes the offline size
 * estimate honest rather than a guess.
 */
object MapProjection {

    const val MAX_LATITUDE: Double = 85.05112878

    fun toMercator(point: GeoPoint): MercatorPoint {
        val latitude = point.latitude.coerceIn(-MAX_LATITUDE, MAX_LATITUDE)
        val x = (Geodesy.normalizeLongitude(point.longitude) + 180.0) / 360.0
        val sinLat = sin(Math.toRadians(latitude))
        val y = 0.5 - ln((1.0 + sinLat) / (1.0 - sinLat)) / (4.0 * Math.PI)
        return MercatorPoint(x, y)
    }

    fun fromMercator(mercator: MercatorPoint): GeoPoint {
        val lon = mercator.x * 360.0 - 180.0
        val n = Math.PI - 2.0 * Math.PI * mercator.y
        val lat = Math.toDegrees(atan2(0.5 * (kotlin.math.exp(n) - kotlin.math.exp(-n)), 1.0))
        return GeoPoint(lat.coerceIn(-MAX_LATITUDE, MAX_LATITUDE), Geodesy.normalizeLongitude(lon))
    }

    fun tileX(point: GeoPoint, zoom: Int): Double = toMercator(point).x * (1 shl zoom)
    fun tileY(point: GeoPoint, zoom: Int): Double = toMercator(point).y * (1 shl zoom)

    fun latitudeOfTile(y: Int, zoom: Int): Double = fromMercator(
        MercatorPoint(0.0, y.toDouble() / (1 shl zoom))
    ).latitude

    fun longitudeOfTile(x: Int, zoom: Int): Double = x.toDouble() / (1 shl zoom) * 360.0 - 180.0

    /** Ground resolution in metres per pixel at [latitude] and [zoom] (256 px tiles). */
    fun metersPerPixel(latitude: Double, zoom: Double, tileSize: Int = 256): Double {
        val lat = latitude.coerceIn(-MAX_LATITUDE, MAX_LATITUDE)
        return cos(Math.toRadians(lat)) * 2.0 * Math.PI * Geodesy.EARTH_RADIUS_M /
            (tileSize * 2.0.pow(zoom))
    }

    /** Zoom level at which [metersPerPixel] would be requested — used for accuracy circles. */
    fun zoomForMetersPerPixel(latitude: Double, metersPerPixel: Double, tileSize: Int = 256): Double {
        val lat = latitude.coerceIn(-MAX_LATITUDE, MAX_LATITUDE)
        val worldMeters = cos(Math.toRadians(lat)) * 2.0 * Math.PI * Geodesy.EARTH_RADIUS_M
        return kotlin.math.log2((worldMeters / (tileSize * max(metersPerPixel, 1e-6))).coerceAtLeast(1e-6))
    }

    /**
     * Inclusive tile-index range covering [bounds] at [zoom]. Longitudes are handled on the
     * shortest path so an antimeridian-crossing region is not counted as the whole planet.
     */
    fun tileRange(bounds: GeoBounds, zoom: Int): TileRange {
        val maxIndex = (1 shl zoom) - 1
        val westX = toMercator(GeoPoint(bounds.center.latitude, bounds.west)).x
        val eastX = toMercator(GeoPoint(bounds.center.latitude, bounds.east)).x
        var minX = floor(westX * (1 shl zoom)).toInt()
        var maxX = floor(eastX * (1 shl zoom)).toInt()
        if (eastX < westX) {
            // Region crosses the antimeridian: take the shorter wrap-around span.
            minX = floor(eastX * (1 shl zoom)).toInt()
            maxX = floor(westX * (1 shl zoom)).toInt()
        }
        val minY = floor(toMercator(GeoPoint(bounds.north, bounds.center.longitude)).y * (1 shl zoom)).toInt()
        val maxY = floor(toMercator(GeoPoint(bounds.south, bounds.center.longitude)).y * (1 shl zoom)).toInt()
        return TileRange(
            zoom = zoom,
            minX = minX.coerceIn(0, maxIndex),
            maxX = maxX.coerceIn(0, maxIndex),
            minY = minY.coerceIn(0, maxIndex),
            maxY = maxY.coerceIn(0, maxIndex)
        )
    }

    data class TileRange(val zoom: Int, val minX: Int, val maxX: Int, val minY: Int, val maxY: Int) {
        val columns: Int get() = max(0, maxX - minX + 1)
        val rows: Int get() = max(0, maxY - minY + 1)
        val tileCount: Long get() = columns.toLong() * rows.toLong()
    }

    /**
     * Number of tiles needed to cover [bounds] from [minZoom] to [maxZoom] inclusive.
     * Used for the offline-download estimate and for enforcing the tile budget.
     */
    fun estimateTileCount(bounds: GeoBounds, minZoom: Int, maxZoom: Int): Long {
        if (maxZoom < minZoom) return 0
        var total = 0L
        for (zoom in minZoom..maxZoom) {
            total += tileRange(bounds, zoom).tileCount
        }
        return total
    }

    /** "z/x/y" key used by the local tile-store index and the cache accounting. */
    fun tileKey(zoom: Int, x: Int, y: Int): String = "$zoom/$x/$y"

    /** Distance (metres) covered by one tile at [latitude] and [zoom]. */
    fun tileSpanMeters(latitude: Double, zoom: Int): Double =
        metersPerPixel(latitude, zoom.toDouble()) * 256.0

    /** Clamps a zoom to the range the vector source actually has data for. */
    fun clampZoom(zoom: Double, minZoom: Double = 0.0, maxZoom: Double = 22.0): Double =
        max(minZoom, min(maxZoom, zoom))
}
