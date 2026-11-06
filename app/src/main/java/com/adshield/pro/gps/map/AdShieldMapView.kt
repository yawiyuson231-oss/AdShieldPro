package com.adshield.pro.gps.map

import android.content.ComponentCallbacks2
import android.content.Context
import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.traffic.CongestionLevel
import org.maplibre.android.MapLibre
import org.maplibre.android.maps.MapView

/**
 * AdShield Pro — Compose host for `MapLibre MapView`.
 *
 * MapLibre is a classic `View` with its own lifecycle contract, so it is hosted through
 * `AndroidView` and every callback is forwarded from the Compose lifecycle owner. Skipping any of
 * `onStart`/`onResume`/`onPause`/`onStop`/`onLowMemory`/`onDestroy` leaks the native renderer
 * (the map keeps its GL context and threads alive), which is why they are all wired here.
 *
 * The engine is remembered per composition and detached on dispose so a configuration change does
 * not keep a stale map reference alive.
 */
@Composable
fun AdShieldMap(
    modifier: Modifier = Modifier,
    engine: MapLibreEngine,
    styleUrl: String,
    route: List<GeoPoint>,
    travelled: List<GeoPoint>,
    traffic: List<TrafficSegmentGeometry>,
    incidents: List<GeoPoint>,
    showTraffic: Boolean,
    onReady: () -> Unit = {},
    onCameraIdle: (CameraSnapshot) -> Unit = {},
    onMapClick: (GeoPoint) -> Unit = {}
) {
    val context: Context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnCameraIdle by rememberUpdatedState(onCameraIdle)
    val currentOnMapClick by rememberUpdatedState(onMapClick)
    val currentOnReady by rememberUpdatedState(onReady)

    // A MapView is bound to one GL surface and cannot be revived after onDestroy, so the instance is
    // keyed on something that changes if the host is genuinely rebuilt.
    val mapView = remember(lifecycleOwner) {
        // MapLibre must be initialised before a MapView is constructed. It is idempotent.
        MapLibre.getInstance(context)
        MapView(context)
    }
    val attached = remember(mapView) { mutableStateOf(false) }

    DisposableEffect(lifecycleOwner, mapView) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> mapView.onStart()
                Lifecycle.Event.ON_RESUME -> mapView.onResume()
                Lifecycle.Event.ON_PAUSE -> mapView.onPause()
                Lifecycle.Event.ON_STOP -> mapView.onStop()
                Lifecycle.Event.ON_DESTROY -> mapView.onDestroy()
                else -> Unit
            }
        }
        // MapLibre releases its large bitmap/GL caches from onLowMemory(); nothing in the lifecycle
        // delivers that, so it is forwarded from the application callback instead.
        val lowMemory = object : ComponentCallbacks2 {
            override fun onConfigurationChanged(newConfig: Configuration) = Unit
            override fun onLowMemory() = mapView.onLowMemory()
            override fun onTrimMemory(level: Int) = Unit
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        context.applicationContext.registerComponentCallbacks(lowMemory)
        mapView.onCreate(null)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            runCatching { context.applicationContext.unregisterComponentCallbacks(lowMemory) }
            engine.detach()
            mapView.onStop()
            mapView.onDestroy()
        }
    }

    AndroidView(
        modifier = modifier,
        factory = {
            engine.onCameraIdle = { lat, lon, zoom, bearing, tilt ->
                currentOnCameraIdle(CameraSnapshot(GeoPoint(lat, lon), zoom, bearing, tilt))
            }
            engine.onMapClick = { point -> currentOnMapClick(point) }
            mapView
        },
        update = { view ->
            // `update` runs on *every* recomposition. Calling getMapAsync each time re-registered the
            // camera/click listeners on the same map and re-ran `onReady`, so the caller saw a
            // "map ready" event several times a second and any one-shot work behind it repeated.
            // Attach once; style and overlays are handled by the effects below.
            if (!attached.value) {
                attached.value = true
                view.getMapAsync { map ->
                    engine.attach(map)
                    engine.loadStyle(styleUrl)
                    currentOnReady()
                }
            }
        }
    )

    // Style changes are applied without recreating the view.
    LaunchedEffect(styleUrl) {
        engine.loadStyle(styleUrl)
    }
    LaunchedEffect(route, travelled) {
        engine.drawRoute(route, travelled)
    }
    LaunchedEffect(traffic, showTraffic) {
        engine.drawTraffic(if (showTraffic) traffic else emptyList())
    }
    LaunchedEffect(incidents) {
        engine.drawIncidents(incidents)
    }
}

/** Convenience for the legend and the traffic screen. */
data class TrafficLegendEntry(val level: CongestionLevel, val hex: String)

fun trafficLegend(): List<TrafficLegendEntry> =
    com.adshield.pro.gps.traffic.TrafficColours.legend().map { (level, hex) -> TrafficLegendEntry(level, hex) }
