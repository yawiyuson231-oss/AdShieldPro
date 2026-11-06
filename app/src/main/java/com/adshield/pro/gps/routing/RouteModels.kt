package com.adshield.pro.gps.routing

import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import kotlin.math.abs
import java.util.Locale

/**
 * AdShield Pro — navigation routing models.
 *
 * A [RoutePlan] is always the result of a real routing response (OSRM or Valhalla over public
 * open data, or the on-device offline graph). Nothing here invents a route: when no router is
 * reachable and no offline graph covers the area, the caller gets a `RoutingResult.Failure` and the
 * UI shows that, rather than a straight line.
 */

enum class RoutingProvider(val label: String, val attribution: String) {
    OSRM("OSRM", "Routes: OSRM / OpenStreetMap contributors"),
    VALHALLA("Valhalla", "Routes: Valhalla / OpenStreetMap contributors"),
    OFFLINE("Offline graph", "Routes: offline OpenStreetMap extract")
}

enum class ManeuverType(val label: String) {
    DEPART("Depart"),
    ARRIVE("Arrive"),
    TURN_LEFT("Turn left"),
    TURN_RIGHT("Turn right"),
    TURN_SHARP_LEFT("Sharp left"),
    TURN_SHARP_RIGHT("Sharp right"),
    TURN_SLIGHT_LEFT("Keep left"),
    TURN_SLIGHT_RIGHT("Keep right"),
    CONTINUE("Continue"),
    UTURN("Make a U-turn"),
    ROUNDABOUT("Enter the roundabout"),
    EXIT_ROUNDABOUT("Leave the roundabout"),
    MERGE("Merge"),
    FORK_LEFT("Keep left at the fork"),
    FORK_RIGHT("Keep right at the fork"),
    RAMP("Take the ramp"),
    HIGHWAY_ENTRY("Enter the motorway"),
    HIGHWAY_EXIT("Leave the motorway"),
    FERRY("Take the ferry"),
    WAYPOINT("Waypoint"),
    UNKNOWN("Continue")
}

data class RouteStep(
    val index: Int,
    val maneuver: ManeuverType,
    val instruction: String,
    val roadName: String?,
    val distanceMeters: Double,
    val durationSeconds: Double,
    val geometry: List<GeoPoint>,
    val maneuverLocation: GeoPoint,
    val exitNumber: Int? = null,
    val speedLimitKmh: Double? = null,
    /** Stable OSM segment ids covered by this step, when the router exposes node ids. */
    val segmentIds: List<String> = emptyList()
)

data class RoutePlan(
    val id: String,
    val provider: RoutingProvider,
    val requestAtMs: Long,
    val geometry: List<GeoPoint>,
    val steps: List<RouteStep>,
    val distanceMeters: Double,
    val durationSeconds: Double,
    val bounds: GeoBounds,
    val originLabel: String? = null,
    val destinationLabel: String? = null,
    val alternatives: List<RouteAlternative> = emptyList(),
    val isOffline: Boolean = false,
    val advisories: List<String> = emptyList()
) {
    val isUsable: Boolean get() = geometry.size >= 2 && distanceMeters > 0.0

    /** Rough free-flow speed of the route, used when the driver's own speed is unusable. */
    val averageSpeedKmh: Double
        get() = if (durationSeconds <= 0) 0.0 else distanceMeters / 1000.0 / (durationSeconds / 3600.0)

    fun withAdvisories(extra: List<String>): RoutePlan =
        copy(advisories = (advisories + extra).distinct())

    companion object {
        const val ID_PREFIX = "route"
    }
}

data class RouteAlternative(
    val distanceMeters: Double,
    val durationSeconds: Double,
    val geometry: List<GeoPoint>,
    val label: String
)

/** Outcome of asking any router for a plan. Failures are typed so the UI can explain them. */
sealed interface RoutingResult {
    data class Success(val plans: List<RoutePlan>, val warnings: List<String> = emptyList()) : RoutingResult {
        val primary: RoutePlan? get() = plans.firstOrNull()
    }

    data class Failure(val reason: RoutingFailureReason, val detail: String) : RoutingResult
}

enum class RoutingFailureReason(val label: String) {
    NO_NETWORK("No network connection"),
    NO_PROVIDER_CONFIGURED("No routing endpoint configured"),
    NO_ROUTE_FOUND("No route found"),
    INVALID_REQUEST("Invalid request"),
    RATE_LIMITED("Public router rate limit hit"),
    SERVER_ERROR("Router error"),
    PARSE_ERROR("Unreadable router response"),
    NO_OFFLINE_GRAPH("No offline routing graph for this area"),
    OFFLINE_GRAPH_UNSUPPORTED("Offline graph present but not supported by this build"),
    PERMISSION_MISSING("Location permission missing"),
    CANCELLED("Cancelled")
}

/** One turn-by-turn state for the current position. */
data class RouteProgress(
    val snappedPosition: GeoPoint,
    val snappedBearingDegrees: Double,
    val distanceAlongRouteMeters: Double,
    val remainingDistanceMeters: Double,
    val remainingSeconds: Double,
    val currentStepIndex: Int,
    val distanceToNextManeuverMeters: Double,
    val nextManeuver: ManeuverType?,
    val nextInstruction: String?,
    val offRoute: Boolean,
    val offRouteDistanceMeters: Double,
    val offRouteSeconds: Long,
    val fractionComplete: Double
) {
    val finished: Boolean get() = remainingDistanceMeters <= 5.0
}

/**
 * Matches real GNSS positions to a route and produces turn-by-turn progress.
 *
 * The "snapping" is a windowed nearest-segment search around the last known position (not the whole
 * route) because a route can legitimately double back on itself; searching globally would teleport
 * the marker onto a parallel stretch of road.
 */
class RouteTracker(
    private val route: RoutePlan,
    private val windowMeters: Double = 350.0,
    private val offRouteThresholdMeters: Double = 42.0,
    private val rerouteAfterSeconds: Long = 6L,
    private val rerouteMinDisplacementMeters: Double = 90.0
) {
    private val cumulative = DoubleArray(route.geometry.size)
    private var cursorIndex = 0
    private var offRouteSince: Long? = null
    private var offRouteAnchor: GeoPoint? = null

    init {
        for (index in 1 until route.geometry.size) {
            cumulative[index] = cumulative[index - 1] + Geodesy.distanceMeters(
                route.geometry[index - 1],
                route.geometry[index]
            )
        }
    }

    val totalDistanceMeters: Double get() = cumulative.lastOrNull() ?: 0.0

    fun reset() {
        cursorIndex = 0
        offRouteSince = null
        offRouteAnchor = null
    }

    fun progressAt(fix: com.adshield.pro.gps.engine.GnssFix): RouteProgress {
        val point = fix.position
        if (route.geometry.size < 2) {
            return RouteProgress(
                snappedPosition = point,
                snappedBearingDegrees = fix.bearingDegrees?.toDouble() ?: 0.0,
                distanceAlongRouteMeters = 0.0,
                remainingDistanceMeters = route.distanceMeters,
                remainingSeconds = route.durationSeconds,
                currentStepIndex = 0,
                distanceToNextManeuverMeters = route.distanceMeters,
                nextManeuver = route.steps.firstOrNull()?.maneuver,
                nextInstruction = route.steps.firstOrNull()?.instruction,
                offRoute = false,
                offRouteDistanceMeters = 0.0,
                offRouteSeconds = 0L,
                fractionComplete = 0.0
            )
        }

        val windowStart = findWindowStart(point)
        var bestDistance = Double.MAX_VALUE
        var bestIndex = windowStart
        var bestFraction = 0.0
        var bestPoint = route.geometry[windowStart]
        var bestAlong = cumulative[windowStart]

        // Allow a small backwards window so a slightly noisy fix does not pin the cursor forward.
        val from = maxOf(0, windowStart - 4)
        val to = minOf(route.geometry.size - 2, windowStart + 60)
        for (index in from..to) {
            val projection = Geodesy.projectOnSegment(point, route.geometry[index], route.geometry[index + 1])
            // Prefer a nearer segment; on a tie prefer the one further along the route.
            val candidateAlong = cumulative[index] +
                (cumulative[index + 1] - cumulative[index]) * projection.fraction
            val tieBreak = candidateAlong > bestAlong
            if (projection.distanceMeters < bestDistance - 0.5 || (abs(projection.distanceMeters - bestDistance) <= 0.5 && tieBreak)) {
                bestDistance = projection.distanceMeters
                bestIndex = index
                bestFraction = projection.fraction
                bestPoint = projection.closest
                bestAlong = candidateAlong
            }
        }
        if (bestIndex >= cursorIndex) cursorIndex = bestIndex

        val segmentBearing = Geodesy.bearingDegrees(route.geometry[bestIndex], route.geometry[bestIndex + 1])
        val total = totalDistanceMeters.coerceAtLeast(1.0)
        val remaining = (total - bestAlong).coerceAtLeast(0.0)
        val currentStep = stepIndexAt(bestAlong)
        val step = route.steps.getOrNull(currentStep)
        val nextStep = route.steps.getOrNull(currentStep + 1)

        val maneuverDistance = when {
            step == null -> remaining
            else -> {
                val stepStartAlong = cumulative.getOrNull(stepStartIndex(step)) ?: 0.0
                val stepEndAlong = stepStartAlong + step.distanceMeters
                if (bestAlong >= stepEndAlong - 0.5) {
                    nextStep?.distanceMeters ?: 0.0
                } else {
                    (stepEndAlong - bestAlong).coerceAtLeast(0.0)
                }
            }
        }

        val offending = bestDistance > offRouteThresholdMeters
        val now = fix.timeMs
        if (offending) {
            if (offRouteSince == null) {
                offRouteSince = now
                offRouteAnchor = point
            }
        } else {
            offRouteSince = null
            offRouteAnchor = null
        }
        val offRouteSeconds = offRouteSince?.let { ((now - it) / 1000L).coerceAtLeast(0L) } ?: 0L

        val remainingSeconds = route.averageSpeedKmh.takeIf { it > 0.0 }?.let {
            remaining / 1000.0 / it * 3600.0
        } ?: route.durationSeconds

        return RouteProgress(
            snappedPosition = bestPoint,
            snappedBearingDegrees = segmentBearing,
            distanceAlongRouteMeters = bestAlong,
            remainingDistanceMeters = remaining,
            remainingSeconds = remainingSeconds,
            currentStepIndex = currentStep,
            distanceToNextManeuverMeters = maneuverDistance,
            nextManeuver = if (bestAlong >= (cumulative.getOrNull(stepStartIndex(step)) ?: 0.0) + (step?.distanceMeters ?: 0.0) - 0.5) {
                nextStep?.maneuver
            } else {
                step?.maneuver
            },
            nextInstruction = if (bestAlong >= (cumulative.getOrNull(stepStartIndex(step)) ?: 0.0) + (step?.distanceMeters ?: 0.0) - 0.5) {
                nextStep?.instruction
            } else {
                step?.instruction
            },
            offRoute = offending,
            offRouteDistanceMeters = bestDistance,
            offRouteSeconds = offRouteSeconds,
            fractionComplete = (bestAlong / total).coerceIn(0.0, 1.0)
        )
    }

    /**
     * A reroute is only requested once the driver has been off-route long enough *and* has actually
     * moved away, so a single bad fix does not trigger a new route.
     */
    fun shouldReroute(progress: RouteProgress, current: GeoPoint): Boolean {
        if (!progress.offRoute) return false
        if (progress.offRouteSeconds < rerouteAfterSeconds) return false
        val anchor = offRouteAnchor ?: return true
        return Geodesy.distanceMeters(anchor, current) >= rerouteMinDisplacementMeters
    }

    private fun findWindowStart(point: GeoPoint): Int {
        val anchorIndex = cursorIndex.coerceIn(0, route.geometry.size - 2)
        val anchorPoint = route.geometry[anchorIndex]
        if (Geodesy.distanceMeters(anchorPoint, point) <= windowMeters) return anchorIndex

        // The driver is far from the cursor: scan the whole route for the closest vertex, which is
        // cheaper than projecting every segment and is only done when the window fails.
        var bestIndex = 0
        var bestDistance = Double.MAX_VALUE
        for (index in 0 until route.geometry.size - 1) {
            val distance = Geodesy.distanceMeters(route.geometry[index], point)
            if (distance < bestDistance) {
                bestDistance = distance
                bestIndex = index
            }
        }
        return bestIndex
    }

    private fun stepStartIndex(step: RouteStep?): Int {
        if (step == null) return 0
        var accumulated = 0.0
        for (candidate in route.steps) {
            if (candidate.index >= step.index) return vertexIndexAt(accumulated)
            accumulated += candidate.distanceMeters
        }
        return route.geometry.size - 2
    }

    private fun vertexIndexAt(alongMeters: Double): Int {
        for (index in cumulative.indices) {
            if (cumulative[index] >= alongMeters) return index.coerceAtMost(route.geometry.size - 2)
        }
        return route.geometry.size - 2
    }

    private fun stepIndexAt(alongMeters: Double): Int {
        var accumulated = 0.0
        for (step in route.steps) {
            accumulated += step.distanceMeters
            if (alongMeters <= accumulated) return step.index
        }
        return route.steps.lastOrNull()?.index ?: 0
    }
}

/** Off-route state machine without a full route object — used by the offline router. */
class OffRouteMonitor(
    private val thresholdMeters: Double = 45.0,
    private val requiredSeconds: Long = 6L
) {
    private var since: Long? = null

    fun update(distanceFromRouteMeters: Double, nowMs: Long): Boolean {
        if (distanceFromRouteMeters > thresholdMeters) {
            val start = since ?: nowMs.also { since = it }
            return (nowMs - start) / 1000L >= requiredSeconds
        }
        since = null
        return false
    }

    fun reset() {
        since = null
    }
}

/** Turns a [RouteStep] into the sentence Android TextToSpeech speaks. */
object NavigationPhrases {

    fun forStep(step: RouteStep, distanceMeters: Double): String {
        val distance = spokenDistance(distanceMeters)
        val road = step.roadName?.takeIf { it.isNotBlank() }?.let { " onto $it" } ?: ""
        return when (step.maneuver) {
            ManeuverType.ARRIVE -> "In $distance, you have arrived at your destination"
            ManeuverType.DEPART -> step.instruction
            ManeuverType.TURN_LEFT -> "In $distance, turn left$road"
            ManeuverType.TURN_RIGHT -> "In $distance, turn right$road"
            ManeuverType.TURN_SHARP_LEFT -> "In $distance, make a sharp left$road"
            ManeuverType.TURN_SHARP_RIGHT -> "In $distance, make a sharp right$road"
            ManeuverType.TURN_SLIGHT_LEFT, ManeuverType.FORK_LEFT -> "In $distance, keep left$road"
            ManeuverType.TURN_SLIGHT_RIGHT, ManeuverType.FORK_RIGHT -> "In $distance, keep right$road"
            ManeuverType.CONTINUE -> "In $distance, continue$road"
            ManeuverType.UTURN -> "In $distance, make a U-turn"
            ManeuverType.ROUNDABOUT -> {
                val exit = step.exitNumber?.let { " and take exit $it" } ?: ""
                "In $distance, enter the roundabout$exit"
            }
            ManeuverType.EXIT_ROUNDABOUT -> "In $distance, leave the roundabout$road"
            ManeuverType.MERGE -> "In $distance, merge$road"
            ManeuverType.RAMP -> "In $distance, take the ramp$road"
            ManeuverType.HIGHWAY_ENTRY -> "In $distance, join the motorway$road"
            ManeuverType.HIGHWAY_EXIT -> "In $distance, take the motorway exit$road"
            ManeuverType.FERRY -> "In $distance, take the ferry$road"
            ManeuverType.WAYPOINT -> "In $distance, you reach a waypoint"
            else -> "In $distance, ${step.instruction.lowercase()}"
        }
    }

    /** Speech-friendly distances: 30 metres / 200 metres / 1 kilometre. */
    fun spokenDistance(meters: Double): String = when {
        meters < 20 -> "20 metres"
        meters < 100 -> "${(meters / 10).toInt().coerceAtLeast(2) * 10} metres"
        meters < 1000 -> "${(meters / 50).toInt().coerceAtLeast(1) * 50} metres"
        else -> {
            val km = meters / 1000.0
            if (km < 10) String.format(Locale.US, "%.1f kilometres", km) else "${km.toInt()} kilometres"
        }
    }

    /** Announcements are throttled by distance bands, not by a timer, so they are predictable. */
    fun announcementBand(metersToManeuver: Double): Int? = when {
        metersToManeuver <= 25 -> 0
        metersToManeuver <= 120 -> 1
        metersToManeuver <= 400 -> 2
        metersToManeuver <= 1000 -> 3
        else -> null
    }
}
