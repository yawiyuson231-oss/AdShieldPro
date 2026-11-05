package com.adshield.pro.gps.map

import android.content.Context
import android.graphics.Color
import android.util.Log
import com.adshield.pro.gps.data.OfflineMapPackEntity
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.traffic.CongestionLevel
import com.adshield.pro.gps.traffic.TrafficColours
import org.maplibre.android.camera.CameraPosition
import org.maplibre.android.camera.CameraUpdateFactory
import org.maplibre.android.geometry.LatLng
import org.maplibre.android.geometry.LatLngBounds
import org.maplibre.android.maps.MapLibreMap
import org.maplibre.android.maps.Style
import org.maplibre.android.offline.OfflineManager
import org.maplibre.android.offline.OfflineRegion
import org.maplibre.android.offline.OfflineRegionError
import org.maplibre.android.offline.OfflineRegionStatus
import org.maplibre.android.offline.OfflineTilePyramidRegionDefinition
import org.maplibre.android.style.expressions.Expression
import org.maplibre.android.style.layers.CircleLayer
import org.maplibre.android.style.layers.FillExtrusionLayer
import org.maplibre.android.style.layers.LineLayer
import org.maplibre.android.style.layers.PropertyFactory
import org.maplibre.android.style.layers.SymbolLayer
import org.maplibre.android.style.sources.GeoJsonSource
import org.maplibre.geojson.Feature
import org.maplibre.geojson.FeatureCollection
import org.maplibre.geojson.LineString
import org.maplibre.geojson.Point

/**
 * AdShield Pro — MapLibre engine.
 *
 * Owns every interaction with MapLibre so the Compose layer never touches the SDK directly:
 * style loading, the 3D building fill-extrusion layer, the route line, the travelled trail, the
 * traffic overlay and the camera behaviours (follow / overview / free).
 *
 * Layer order is fixed so the layers can be re-created after a style change without flicker:
 *   trail → route casing → route line → traffic casing → traffic coloured → incident circles
 *
 * MapLibre's own LocationComponent is deliberately *not* used: this module already has a validated,
 * integrity-checked fix stream, and feeding the marker from it keeps a single source of truth (and
 * avoids MapLibre silently accepting a mocked fix). The marker is a Compose overlay driven by
 * [com.adshield.pro.gps.engine.GpsFrame].
 */
class MapLibreEngine(
    private val context: Context
) {
    private var map: MapLibreMap? = null
    private var style: Style? = null
    private var currentStyleUrl: String? = null
    private var hasRouteLayers = false
    private var hasTrafficLayers = false

    /** Set when the map is ready and the style has loaded; every overlay call is a no-op before that. */
    val isReady: Boolean get() = map != null && style != null

    var onStyleLoaded: (() -> Unit)? = null
    var onCameraIdle: ((lat: Double, lon: Double, zoom: Double, bearing: Double, tilt: Double) -> Unit)? = null
    var onMapClick: ((GeoPoint) -> Unit)? = null

    fun attach(mapLibreMap: MapLibreMap) {
        map = mapLibreMap
        mapLibreMap.uiSettings.apply {
            isAttributionEnabled = true // Required by OSM/OpenFreeMap attribution terms.
            isLogoEnabled = false
            isCompassEnabled = false // The cyber HUD draws its own compass.
            isRotateGesturesEnabled = true
            isTiltGesturesEnabled = true
            isZoomGesturesEnabled = true
            isScrollGesturesEnabled = true
            isDoubleTapGesturesEnabled = true
            isQuickZoomGesturesEnabled = true
        }
        mapLibreMap.setMinZoomPreference(2.0)
        mapLibreMap.setMaxZoomPreference(19.5)
        mapLibreMap.addOnCameraIdleListener {
            mapLibreMap.cameraPosition?.let { position ->
                position.target?.let { target ->
                    onCameraIdle?.invoke(
                        target.latitude,
                        target.longitude,
                        position.zoom,
                        position.bearing,
                        position.tilt
                    )
                }
            }
        }
        mapLibreMap.addOnMapClickListener { latLng ->
            onMapClick?.invoke(GeoPoint(latLng.latitude, latLng.longitude))
            true
        }
    }

    fun detach() {
        map = null
        style = null
    }

    /**
     * Loads a style. Re-applying the same URL is a no-op, which matters because Compose recomposes
     * frequently and a style reload throws away the offline-cached tiles for a moment.
     */
    fun loadStyle(styleUrl: String) {
        val mapLibreMap = map ?: return
        if (styleUrl == currentStyleUrl && style != null) {
            onStyleLoaded?.invoke()
            return
        }
        currentStyleUrl = styleUrl
        style = null
        mapLibreMap.setStyle(styleUrl) { loaded ->
            style = loaded
            addTerrainAndBuildings(loaded)
            hasRouteLayers = false
            hasTrafficLayers = false
            onStyleLoaded?.invoke()
        }
    }

    /**
     * Adds the 3D building layer when the style's tile schema has the fields.
     *
     * OpenMapTiles (OpenFreeMap, self-hosted tilemaker output) exposes `render_height` /
     * `render_min_height` in the `building` source layer. A style without that schema simply skips
     * this and the app keeps a working 2D map — it does not fabricate building geometry.
     */
    private fun addTerrainAndBuildings(loaded: Style) {
        runCatching {
            if (loaded.getSource("openmaptiles") == null) {
                Log.i(TAG, "Style has no 'openmaptiles' source: 3D buildings unavailable")
                return
            }
            if (loaded.getLayer(LAYER_BUILDINGS_3D) != null) return
            val layer = FillExtrusionLayer(LAYER_BUILDINGS_3D, "openmaptiles")
            layer.sourceLayer = "building"
            layer.minZoom = 14f
            layer.setFilter(Expression.has("render_height"))
            layer.setProperties(
                PropertyFactory.fillExtrusionHeight(Expression.get("render_height")),
                PropertyFactory.fillExtrusionBase(
                    Expression.coalesce(Expression.get("render_min_height"), Expression.literal(0f))
                ),
                PropertyFactory.fillExtrusionColor(Color.parseColor("#1E3A5F")),
                PropertyFactory.fillExtrusionOpacity(0.85f)
            )
            loaded.addLayer(layer)
        }.onFailure { Log.w(TAG, "Could not add 3D buildings: ${it.message}") }
    }

    /** Forces a re-render of the offline database (used after a pack download completes). */
    fun refreshStyle() {
        val url = currentStyleUrl ?: return
        currentStyleUrl = null
        loadStyle(url)
    }

    // ---------------------------------------------------------------- camera
    fun moveTo(point: GeoPoint, zoom: Double = 15.5, bearing: Double = 0.0, tilt: Double = 0.0, animate: Boolean = true) {
        val mapLibreMap = map ?: return
        val target = LatLng(point.latitude, point.longitude)
        val update = if (bearing != 0.0 || tilt != 0.0) {
            CameraUpdateFactory.newCameraPosition(
                CameraPosition.Builder()
                    .target(target)
                    .zoom(zoom.coerceIn(2.0, 19.5))
                    .bearing(bearing)
                    .tilt(tilt.coerceIn(0.0, 60.0))
                    .build()
            )
        } else {
            CameraUpdateFactory.newLatLngZoom(target, zoom.coerceIn(2.0, 19.5))
        }
        if (animate) mapLibreMap.animateCamera(update, 450) else mapLibreMap.moveCamera(update)
    }

    /** Follow mode: keeps the vehicle at the centre, rotated to its bearing, with a driving tilt. */
    fun followVehicle(point: GeoPoint, bearing: Double, zoom: Double = 17.0, tilt: Double = 45.0) {
        val mapLibreMap = map ?: return
        mapLibreMap.animateCamera(
            CameraUpdateFactory.newCameraPosition(
                CameraPosition.Builder()
                    .target(LatLng(point.latitude, point.longitude))
                    .zoom(zoom.coerceIn(12.0, 19.5))
                    .bearing(bearing)
                    .tilt(tilt.coerceIn(0.0, 60.0))
                    .build()
            ),
            600
        )
    }

    fun showBounds(bounds: GeoBounds, paddingPx: Int = 96) {
        val mapLibreMap = map ?: return
        runCatching {
            val latLngBounds = LatLngBounds.Builder()
                .include(LatLng(bounds.north, bounds.west))
                .include(LatLng(bounds.south, bounds.east))
                .build()
            mapLibreMap.animateCamera(CameraUpdateFactory.newLatLngBounds(latLngBounds, paddingPx), 700)
        }
    }

    fun camera(): CameraSnapshot? {
        val position = map?.cameraPosition ?: return null
        val target = position.target ?: return null
        return CameraSnapshot(
            center = GeoPoint(target.latitude, target.longitude),
            zoom = position.zoom,
            bearing = position.bearing,
            tilt = position.tilt
        )
    }

    // -------------------------------------------------------------- overlays
    /**
     * Draws the planned route plus the travelled portion. Called on every accepted fix, so it only
     * touches the sources (`setGeoJson`) and never re-creates layers.
     */
    fun drawRoute(route: List<GeoPoint>, travelled: List<GeoPoint>) {
        val loaded = style ?: return
        runCatching {
            ensureRouteLayers(loaded)
            (loaded.getSource(SOURCE_ROUTE) as? GeoJsonSource)?.setGeoJson(lineFeature(route, "route"))
            (loaded.getSource(SOURCE_TRAVELLED) as? GeoJsonSource)?.setGeoJson(lineFeature(travelled, "travelled"))
        }.onFailure { Log.w(TAG, "drawRoute failed: ${it.message}") }
    }

    private fun ensureRouteLayers(loaded: Style) {
        if (hasRouteLayers) return
        if (loaded.getSource(SOURCE_ROUTE) == null) {
            loaded.addSource(GeoJsonSource(SOURCE_ROUTE, FeatureCollection.fromFeatures(emptyList())))
            loaded.addSource(GeoJsonSource(SOURCE_TRAVELLED, FeatureCollection.fromFeatures(emptyList())))
        }
        if (loaded.getLayer(LAYER_TRAVELLED) == null) {
            loaded.addLayer(
                LineLayer(LAYER_TRAVELLED, SOURCE_TRAVELLED).withProperties(
                    PropertyFactory.lineColor("#22D3EE"),
                    PropertyFactory.lineWidth(4f),
                    PropertyFactory.lineOpacity(0.45f),
                    PropertyFactory.lineCap("round"),
                    PropertyFactory.lineJoin("round")
                )
            )
        }
        if (loaded.getLayer(LAYER_ROUTE_CASING) == null) {
            loaded.addLayer(
                LineLayer(LAYER_ROUTE_CASING, SOURCE_ROUTE).withProperties(
                    PropertyFactory.lineColor("#0B2B66"),
                    PropertyFactory.lineWidth(11f),
                    PropertyFactory.lineCap("round"),
                    PropertyFactory.lineJoin("round")
                )
            )
        }
        if (loaded.getLayer(LAYER_ROUTE) == null) {
            loaded.addLayer(
                LineLayer(LAYER_ROUTE, SOURCE_ROUTE).withProperties(
                    PropertyFactory.lineColor("#2E7DFF"),
                    PropertyFactory.lineWidth(6f),
                    PropertyFactory.lineCap("round"),
                    PropertyFactory.lineJoin("round")
                )
            )
        }
        hasRouteLayers = true
    }

    /**
     * Traffic overlay: one GeoJSON source of segment lines, coloured by a `level` property with an
     * expression. Segments without observations are drawn grey and thin — visible as "no data"
     * rather than being hidden (hiding them would make the map look confident).
     */
    fun drawTraffic(segments: List<TrafficSegmentGeometry>) {
        val loaded = style ?: return
        runCatching {
            ensureTrafficLayers(loaded)
            val features = segments.map { segment ->
                Feature.fromGeometry(
                    LineString.fromLngLats(segment.points.map { Point.fromLngLat(it.longitude, it.latitude) })
                ).apply {
                    addStringProperty("level", segment.level.name)
                    addStringProperty("name", segment.name ?: "")
                    addNumberProperty("confidence", segment.confidence)
                    addStringProperty("age", segment.ageLabel)
                }
            }
            (loaded.getSource(SOURCE_TRAFFIC) as? GeoJsonSource)
                ?.setGeoJson(FeatureCollection.fromFeatures(features))
        }.onFailure { Log.w(TAG, "drawTraffic failed: ${it.message}") }
    }

    private fun ensureTrafficLayers(loaded: Style) {
        if (hasTrafficLayers) return
        // The traffic line is inserted *below* the route casing, so that layer must exist first.
        ensureRouteLayers(loaded)
        if (loaded.getSource(SOURCE_INCIDENTS) == null) {
            loaded.addSource(GeoJsonSource(SOURCE_INCIDENTS, FeatureCollection.fromFeatures(emptyList())))
        }
        if (loaded.getSource(SOURCE_TRAFFIC) == null) {
            loaded.addSource(GeoJsonSource(SOURCE_TRAFFIC, FeatureCollection.fromFeatures(emptyList())))
        }
        if (loaded.getLayer(LAYER_TRAFFIC) == null) {
            val levelExpression = Expression.switchCase(
                Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.FREE_FLOW.name)),
                Expression.literal(TrafficColours.GREEN),
                Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.LIGHT.name)),
                Expression.literal(TrafficColours.GREEN),
                Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.MODERATE.name)),
                Expression.literal(TrafficColours.ORANGE),
                Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.HEAVY.name)),
                Expression.literal(TrafficColours.RED),
                Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.STANDSTILL.name)),
                Expression.literal(TrafficColours.DEEP_RED),
                Expression.literal(TrafficColours.GREY)
            )
            loaded.addLayerBelow(
                LineLayer(LAYER_TRAFFIC, SOURCE_TRAFFIC).withProperties(
                    PropertyFactory.lineColor(levelExpression),
                    PropertyFactory.lineWidth(
                        Expression.switchCase(
                            Expression.eq(Expression.get("level"), Expression.literal(CongestionLevel.UNKNOWN.name)),
                            Expression.literal(3f),
                            Expression.literal(7f)
                        )
                    ),
                    PropertyFactory.lineOpacity(0.85f),
                    PropertyFactory.lineCap("round")
                ),
                LAYER_ROUTE_CASING
            )
        }
        if (loaded.getLayer(LAYER_INCIDENTS) == null) {
            val circle = CircleLayer(LAYER_INCIDENTS, SOURCE_INCIDENTS)
            circle.setProperties(
                PropertyFactory.circleRadius(9f),
                PropertyFactory.circleColor("#EF4444"),
                PropertyFactory.circleStrokeColor("#FCA5A5"),
                PropertyFactory.circleStrokeWidth(2f),
                PropertyFactory.circleOpacity(0.95f)
            )
            loaded.addLayer(circle)
        }
        hasTrafficLayers = true
    }

    fun drawIncidents(incidents: List<GeoPoint>) {
        val loaded = style ?: return
        runCatching {
            if (loaded.getSource(SOURCE_INCIDENTS) == null) {
                loaded.addSource(GeoJsonSource(SOURCE_INCIDENTS, FeatureCollection.fromFeatures(emptyList())))
            }
            val features = incidents.map { Feature.fromGeometry(Point.fromLngLat(it.longitude, it.latitude)) }
            (loaded.getSource(SOURCE_INCIDENTS) as? GeoJsonSource)
                ?.setGeoJson(FeatureCollection.fromFeatures(features))
        }.onFailure { Log.w(TAG, "drawIncidents failed: ${it.message}") }
    }

    private fun lineFeature(points: List<GeoPoint>, kind: String): FeatureCollection {
        if (points.size < 2) return FeatureCollection.fromFeatures(emptyList())
        val line = LineString.fromLngLats(points.map { Point.fromLngLat(it.longitude, it.latitude) })
        val feature = Feature.fromGeometry(line).apply { addStringProperty("kind", kind) }
        return FeatureCollection.fromFeatures(listOf(feature))
    }

    // --------------------------------------------------------------- offline
    /**
     * Creates a MapLibre offline region. Callbacks arrive on the main thread.
     *
     * The definition is a tile pyramid for the bounding box and zoom range, exactly what
     * [OfflinePlanner] counted, so the size estimate the user approved is the download that runs.
     */
    fun downloadRegion(
        packId: String,
        name: String,
        styleUrl: String,
        bounds: GeoBounds,
        minZoom: Int,
        maxZoom: Int,
        pixelRatio: Float,
        onCreated: (OfflineRegion) -> Unit,
        onError: (String) -> Unit
    ) {
        val manager = OfflineManager.getInstance(context)
        // MapLibre's own tile-count ceiling is lifted; the pack budget is enforced by OfflinePlanner
        // instead, because it is expressed in the units the free tile server's terms use.
        manager.setOfflineMapboxTileCountLimit(Long.MAX_VALUE)
        val definition = OfflineTilePyramidRegionDefinition(
            styleUrl,
            LatLngBounds.Builder()
                .include(LatLng(bounds.south, bounds.west))
                .include(LatLng(bounds.north, bounds.east))
                .build(),
            minZoom.toDouble(),
            maxZoom.toDouble(),
            pixelRatio
        )
        val metadata = packId.toByteArray(Charsets.UTF_8)
        manager.createOfflineRegion(definition, metadata, object : OfflineManager.CreateOfflineRegionCallback {
            override fun onCreate(offlineRegion: OfflineRegion) {
                offlineRegion.setObserver(object : OfflineRegion.OfflineRegionObserver {
                    override fun onStatusChanged(status: OfflineRegionStatus) {
                        OfflineProgressBus.publish(
                            packId,
                            OfflineRegionProgress(
                                completed = status.completedResourceCount,
                                required = status.requiredResourceCount,
                                bytes = status.completedResourceSize,
                                complete = status.isComplete,
                                requiredPrecise = status.isRequiredResourceCountPrecise
                            )
                        )
                    }

                    override fun onError(error: OfflineRegionError) {
                        OfflineProgressBus.publishError(packId, "${error.reason}: ${error.message}")
                    }

                    override fun mapboxTileCountLimitExceeded(limit: Long) {
                        OfflineProgressBus.publishError(packId, "Tile limit reached ($limit)")
                    }
                })
                offlineRegion.setDownloadState(OfflineRegion.STATE_ACTIVE)
                onCreated(offlineRegion)
            }

            override fun onError(error: String) {
                onError(error)
            }
        })
    }

    fun findRegion(regionId: Long, onFound: (OfflineRegion?) -> Unit) {
        OfflineManager.getInstance(context).getOfflineRegion(regionId, object : OfflineManager.GetOfflineRegionCallback {
            override fun onRegion(offlineRegion: OfflineRegion) = onFound(offlineRegion)
            override fun onRegionNotFound() = onFound(null)
            override fun onError(error: String) = onFound(null)
        })
    }

    fun pauseRegion(regionId: Long) {
        findRegion(regionId) { it?.setDownloadState(OfflineRegion.STATE_INACTIVE) }
    }

    fun resumeRegion(regionId: Long) {
        findRegion(regionId) { it?.setDownloadState(OfflineRegion.STATE_ACTIVE) }
    }

    fun deleteRegion(regionId: Long, onDeleted: () -> Unit) {
        OfflineManager.getInstance(context).getOfflineRegion(regionId, object : OfflineManager.GetOfflineRegionCallback {
            override fun onRegion(offlineRegion: OfflineRegion) {
                offlineRegion.delete(object : OfflineRegion.OfflineRegionDeleteCallback {
                    override fun onDelete() = onDeleted()
                    override fun onError(error: String) = onDeleted()
                })
            }

            override fun onRegionNotFound() = onDeleted()
            override fun onError(error: String) = onDeleted()
        })
    }

    /** Refreshes an existing pack so edited OSM data (new roads) is picked up. */
    fun updateRegion(regionId: Long, onDone: (Boolean) -> Unit) {
        findRegion(regionId) { region ->
            if (region == null) {
                onDone(false)
                return@findRegion
            }
            region.invalidate(object : OfflineRegion.OfflineRegionInvalidateCallback {
                override fun onInvalidate() {
                    region.setDownloadState(OfflineRegion.STATE_ACTIVE)
                    onDone(true)
                }

                override fun onError(error: String) = onDone(false)
            })
        }
    }

    fun listRegions(onResult: (List<Long>) -> Unit) {
        OfflineManager.getInstance(context).listOfflineRegions(object : OfflineManager.ListOfflineRegionsCallback {
            override fun onList(offlineRegions: Array<OfflineRegion>?) {
                onResult(offlineRegions?.map { it.id }.orEmpty())
            }

            override fun onError(error: String) = onResult(emptyList())
        })
    }

    companion object {
        private const val TAG = "MapLibreEngine"
        private const val SOURCE_ROUTE = "adshield-route"
        private const val SOURCE_TRAVELLED = "adshield-travelled"
        private const val SOURCE_TRAFFIC = "adshield-traffic"
        private const val SOURCE_INCIDENTS = "adshield-incidents"
        private const val LAYER_TRAVELLED = "adshield-travelled-line"
        private const val LAYER_ROUTE_CASING = "adshield-route-casing"
        private const val LAYER_ROUTE = "adshield-route-line"
        private const val LAYER_TRAFFIC = "adshield-traffic-line"
        private const val LAYER_INCIDENTS = "adshield-incidents-circle"
        private const val LAYER_BUILDINGS_3D = "adshield-buildings-3d"
    }
}

data class CameraSnapshot(
    val center: GeoPoint,
    val zoom: Double,
    val bearing: Double,
    val tilt: Double
)

data class TrafficSegmentGeometry(
    val points: List<GeoPoint>,
    val level: CongestionLevel,
    val name: String?,
    val confidence: Double,
    val ageLabel: String
)

data class OfflineRegionProgress(
    val completed: Long,
    val required: Long,
    val bytes: Long,
    val complete: Boolean,
    val requiredPrecise: Boolean
)

/**
 * Bridges MapLibre's main-thread callbacks to the ViewModel without an event-bus dependency of the
 * rest of the app. Only the GPS module observes it.
 */
object OfflineProgressBus {
    private val _progress = kotlinx.coroutines.flow.MutableSharedFlow<Pair<String, OfflineRegionProgress>>(
        extraBufferCapacity = 32,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST
    )
    val progress = _progress.asSharedFlow()

    private val _errors = kotlinx.coroutines.flow.MutableSharedFlow<Pair<String, String>>(extraBufferCapacity = 16)
    val errors = _errors.asSharedFlow()

    fun publish(packId: String, progress: OfflineRegionProgress) {
        _progress.tryEmit(packId to progress)
    }

    fun publishError(packId: String, message: String) {
        _errors.tryEmit(packId to message)
    }
}

/** Converts a Room pack row into the definition the engine needs. */
fun OfflineMapPackEntity.toBounds(): GeoBounds = GeoBounds(
    south = south,
    west = west,
    north = north,
    east = east
)
