package com.adshield.pro.gps.nav

import android.content.Context
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.data.OfflineMapPackEntity
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.offline.OfflineRoadGraph
import com.adshield.pro.gps.offline.OfflineRouter
import com.adshield.pro.gps.routing.RoutePlan
import com.adshield.pro.gps.routing.RouteProgress
import com.adshield.pro.gps.routing.RouteRequest
import com.adshield.pro.gps.routing.RouteStep
import com.adshield.pro.gps.routing.RouteTracker
import com.adshield.pro.gps.routing.RoutingFailureReason
import com.adshield.pro.gps.routing.RoutingProvider
import com.adshield.pro.gps.routing.RoutingResult
import com.adshield.pro.gps.routing.ManeuverType
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — navigation session.
 *
 * Owns the state machine between "the user asked for a route" and "the driver arrived":
 *
 *   IDLE → CALCULATING → NAVIGATING → (OFF_ROUTE → REROUTING → NAVIGATING)* → ARRIVED
 *
 * Everything that decides *where to go next* lives here and is exposed as a [StateFlow], so the
 * Compose screen only renders. The class is an Android singleton but contains no platform logic
 * beyond Context for file access, which keeps the arithmetic testable through [RouteTracker].
 *
 * Offline behaviour is explicit: when routing fails because there is no network, the session tries
 * the imported offline graph, and only if that is absent does it report
 * [RoutingFailureReason.NO_OFFLINE_GRAPH]. It never falls back to a straight line.
 */
@Singleton
class NavigationSession @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: GpsPreferences,
    private val dao: GpsDao,
    private val routingClient: com.adshield.pro.gps.data.RoutingClient,
    private val voice: VoiceGuidanceApi
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val routeMutex = Mutex()

    private var tracker: RouteTracker? = null
    private var activePlan: RoutePlan? = null
    /**
     * Driven trail for the HUD overlay.
     *
     * Written by the fix collector ([onFrame]) **and** by the reroute coroutine, and copied by the
     * ViewModel on the main thread. A plain ArrayList raced: `toList()` could walk a list the
     * collector was concurrently shrinking with `removeAt(0)`, which is where a
     * ConcurrentModificationException on a long trip came from. Every access is now under [trailLock].
     */
    private val travelled = ArrayList<GeoPoint>()
    private val trailLock = Any()

    /** Trail sampling interval. Promoted from a magic number so the rule is testable. */
    private object Trail {
        const val MIN_SPACING_METERS = 8.0
    }
    private var lastRerouteAtMs = 0L
    private var offlineRouter: OfflineRouter? = null
    private var offlineGraphRegion: String? = null

    private val _state = kotlinx.coroutines.flow.MutableStateFlow(NavigationState())
    val state: kotlinx.coroutines.flow.StateFlow<NavigationState> = _state

    private val _progress = kotlinx.coroutines.flow.MutableStateFlow<RouteProgress?>(null)
    val progress: kotlinx.coroutines.flow.StateFlow<RouteProgress?> = _progress

    val currentPlan: RoutePlan? get() = activePlan
    val routeGeometry: List<GeoPoint> get() = activePlan?.geometry.orEmpty()

    /**
     * Everything the map must fit: the plan *and* the driven trail.
     *
     * The ViewModel used to fit only [routeGeometry]. As soon as the driver deviated from the route
     * the trail left the fitted box and the "fit route" button cropped the path already driven.
     */
    fun geometryIncludingTrail(): List<GeoPoint> =
        activePlan?.geometry.orEmpty() + travelledGeometry()
    fun travelledGeometry(): List<GeoPoint> = synchronized(trailLock) { travelled.toList() }

    /**
     * Requests a route. [provider] is the user's preference; an offline graph is used
     * automatically when the network route fails and a graph covers the area.
     */
    fun planRoute(
        origin: GeoPoint,
        destination: GeoPoint,
        destinationLabel: String?,
        provider: RoutingProvider,
        allowAlternatives: Boolean = true
    ) {
        if (_state.value.phase == NavigationPhase.CALCULATING) return
        _state.value = _state.value.copy(
            phase = NavigationPhase.CALCULATING,
            message = "Calculating route…",
            failureReason = null,
            destinationLabel = destinationLabel ?: "Destination"
        )
        scope.launch {
            routeMutex.withLock {
                val request = RouteRequest(origin = origin, destination = destination, alternatives = allowAlternatives)
                val result = routingClient.route(request, provider)
                when (result) {
                    is RoutingResult.Success -> {
                        val plan = result.primary
                        if (plan == null) {
                            _state.value = _state.value.copy(
                                phase = NavigationPhase.FAILED,
                                message = "The router returned no usable route",
                                failureReason = RoutingFailureReason.NO_ROUTE_FOUND
                            )
                            return@withLock
                        }
                        val labelled = plan.copy(
                            destinationLabel = destinationLabel,
                            originLabel = null,
                            advisories = plan.advisories + result.warnings
                        )
                        activate(labelled)
                    }

                    is RoutingResult.Failure -> {
                        val offline = tryOffline(origin, destination, destinationLabel)
                        if (offline != null) {
                            activate(
                                offline.copy(
                                    advisories = offline.advisories + "${result.detail} Routed offline instead."
                                )
                            )
                        } else {
                            _state.value = _state.value.copy(
                                phase = NavigationPhase.FAILED,
                                message = result.detail,
                                failureReason = result.reason
                            )
                        }
                    }
                }
            }
        }
    }

    private fun activate(plan: RoutePlan) {
        activePlan = plan
        tracker = RouteTracker(plan)
        synchronized(trailLock) { travelled.clear() }
        lastRerouteAtMs = 0L
        _state.value = NavigationState(
            phase = NavigationPhase.NAVIGATING,
            message = "Navigating — ${plan.distanceMeters.let { com.adshield.pro.gps.geo.Geodesy.formatDistance(it) }}",
            destinationLabel = plan.destinationLabel ?: "Destination",
            providerLabel = plan.provider.label,
            isOffline = plan.isOffline,
            totalDistanceMeters = plan.distanceMeters,
            totalDurationSeconds = plan.durationSeconds,
            advisories = plan.advisories
        )
        _progress.value = null
    }

    /** Called for every accepted fix while navigating. */
    fun onFrame(frame: GpsFrame) {
        val plan = activePlan ?: return
        val fix = frame.fix ?: return
        val currentTracker = tracker ?: return

        val progress = currentTracker.progressAt(fix)
        _progress.value = progress
        synchronized(trailLock) {
            if (shouldAppendTrailPoint(travelled.lastOrNull(), progress.snappedPosition)) {
                travelled += progress.snappedPosition
                if (travelled.size > MAX_TRAIL_POINTS) travelled.removeAt(0)
            }
        }
        voice.announce(progress)

        val destination = plan.geometry.lastOrNull()
        if (progress.finished || (destination != null && com.adshield.pro.gps.geo.Geodesy.distanceMeters(fix.position, destination) <= 25.0)) {
            _state.value = _state.value.copy(
                phase = NavigationPhase.ARRIVED,
                message = "You have arrived"
            )
            voice.announceArrival()
            tracker = null
            return
        }

        if (currentTracker.shouldReroute(progress, fix.position)) {
            val now = System.currentTimeMillis()
            if (now - lastRerouteAtMs > 12_000L) {
                lastRerouteAtMs = now
                reroute(from = progress.snappedPosition)
            } else {
                _state.value = _state.value.copy(
                    phase = NavigationPhase.OFF_ROUTE,
                    message = "Off route — ${progress.offRouteDistanceMeters.toInt()} m from the planned road"
                )
            }
        } else if (progress.offRoute) {
            _state.value = _state.value.copy(
                phase = NavigationPhase.OFF_ROUTE,
                message = "Off route — recalculating in ${(progress.offRouteSeconds.coerceAtMost(6)).let { 6 - it }} s"
            )
        } else if (_state.value.phase == NavigationPhase.OFF_ROUTE) {
            _state.value = _state.value.copy(phase = NavigationPhase.NAVIGATING, message = "Back on route")
        }
    }

    /** Recalculates from the snapped position to the original destination. */
    fun reroute(from: GeoPoint) {
        val plan = activePlan ?: return
        val destination = plan.geometry.lastOrNull() ?: return
        _state.value = _state.value.copy(phase = NavigationPhase.REROUTING, message = "Recalculating…")
        scope.launch {
            routeMutex.withLock {
                val result = routingClient.route(
                    RouteRequest(from, destination, alternatives = false),
                    RoutingProvider.OSRM
                )
                val newPlan = when (result) {
                    is RoutingResult.Success -> result.primary
                    is RoutingResult.Failure -> tryOffline(from, destination, plan.destinationLabel)
                }
                if (newPlan != null) {
                    val previousTravelled = synchronized(trailLock) { travelled.toList() }
                    activate(newPlan.copy(destinationLabel = plan.destinationLabel))
                    synchronized(trailLock) {
                        travelled.clear()
                        travelled.addAll(previousTravelled)
                    }
                    voice.onReroute(newPlan.steps.getOrNull(1)?.instruction)
                } else {
                    _state.value = _state.value.copy(
                        phase = NavigationPhase.OFF_ROUTE,
                        message = (result as? RoutingResult.Failure)?.detail ?: "Could not recalculate the route"
                    )
                }
            }
        }
    }

    fun stop() {
        activePlan = null
        tracker = null
        synchronized(trailLock) { travelled.clear() }
        _progress.value = null
        _state.value = NavigationState(phase = NavigationPhase.IDLE)
        voice.stop()
    }

    /** Loads the offline graph of a downloaded pack. Returns a human status line. */
    fun loadOfflineGraph(pack: OfflineMapPackEntity, file: File): String {
        return runCatching {
            val graph = OfflineRoadGraph.readFile(file)
            offlineRouter = OfflineRouter(graph)
            offlineGraphRegion = pack.name
            "Offline routing ready for ${pack.name}: ${graph.nodesSummary()}"
        }.getOrElse { error ->
            offlineRouter = null
            offlineGraphRegion = null
            "Offline graph could not be loaded: ${error.message ?: error.javaClass.simpleName}"
        }
    }

    fun clearOfflineGraph() {
        offlineRouter = null
        offlineGraphRegion = null
    }

    val offlineGraphName: String? get() = offlineGraphRegion

    private fun tryOffline(origin: GeoPoint, destination: GeoPoint, label: String?): RoutePlan? {
        val router = offlineRouter ?: return null
        return router.route(origin, destination)?.copy(
            destinationLabel = label,
            originLabel = null
        )
    }

    fun userStoppedVoice() = voice.stop()

    companion object {
        const val MAX_TRAIL_POINTS = 4_000

        /**
         * Whether a new snapped position belongs in the trail.
         *
         * The trail is a 4 000-point ring; appending a point every fix would push the start of a
         * long trip out of the overlay within the hour. Spacing is measured against the newest point
         * actually kept, and a stationary vehicle therefore adds nothing.
         */
        fun shouldAppendTrailPoint(last: GeoPoint?, next: GeoPoint): Boolean =
            last == null ||
                com.adshield.pro.gps.geo.Geodesy.distanceMeters(last, next) > Trail.MIN_SPACING_METERS
    }
}

/** Voice facade so the session does not need Android's TTS class in a unit test. */
interface VoiceGuidanceApi {
    fun announce(progress: RouteProgress): String?
    fun onReroute(announcement: String?): String?
    fun announceArrival()
    fun stop()
}

/** Next maneuver summary for the HUD banner. */
data class ManeuverHint(
    val distanceMeters: Double,
    val maneuver: ManeuverType,
    val instruction: String?,
    val roadName: String?
)

fun RouteProgress.hint(plan: RoutePlan?): ManeuverHint? {
    val step: RouteStep? = plan?.steps?.getOrNull(if (finished) -1 else currentStepIndex)
    return ManeuverHint(
        distanceMeters = distanceToNextManeuverMeters,
        maneuver = nextManeuver ?: step?.maneuver ?: ManeuverType.CONTINUE,
        instruction = nextInstruction ?: step?.instruction,
        roadName = step?.roadName
    )
}

enum class NavigationPhase {
    IDLE,
    CALCULATING,
    NAVIGATING,
    OFF_ROUTE,
    REROUTING,
    ARRIVED,
    FAILED
}

data class NavigationState(
    val phase: NavigationPhase = NavigationPhase.IDLE,
    val message: String = "No active route",
    val destinationLabel: String = "",
    val providerLabel: String = "",
    val isOffline: Boolean = false,
    val totalDistanceMeters: Double = 0.0,
    val totalDurationSeconds: Double = 0.0,
    val failureReason: RoutingFailureReason? = null,
    val advisories: List<String> = emptyList()
) {
    val isActive: Boolean
        get() = phase == NavigationPhase.NAVIGATING ||
            phase == NavigationPhase.OFF_ROUTE ||
            phase == NavigationPhase.REROUTING
}

private fun OfflineRoadGraph.nodesSummary(): String =
    "${describe()} · ${approximateRoadKilometers.toInt()} km of road"
