package com.adshield.pro.gps.routing

import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * AdShield Pro — routing codecs.
 *
 * Decoders for the two free, self-hostable, no-API-key routing engines the module supports:
 *  - OSRM (`/route/v1/driving/...?geometries=polyline&steps=true&alternatives=true`)
 *  - Valhalla (`/route` with `shape_format=polyline6`)
 *
 * Both are pure functions over the response body, so the exact JSON the public demo servers return
 * can be replayed in a unit test. A malformed or truncated body produces a typed failure instead of
 * an exception escaping into the ViewModel.
 */

object PolylineCodec {

    /** Decodes a Google-encoded polyline (OSRM uses precision 5, Valhalla polyline6 precision 6). */
    fun decode(encoded: String, precision: Int = 5): List<GeoPoint> {
        if (encoded.isEmpty()) return emptyList()
        val factor = if (precision == 6) 1e6 else 1e5
        val points = ArrayList<GeoPoint>(encoded.length / 4)
        var index = 0
        var lat = 0
        var lon = 0
        while (index < encoded.length) {
            var shift = 0
            var result = 0
            var byte: Int
            do {
                if (index >= encoded.length) return points
                byte = encoded[index].code - 63
                index++
                result = result or ((byte and 0x1f) shl shift)
                shift += 5
            } while (byte >= 0x20)
            lat += if ((result and 1) != 0) (result shr 1).inv() else (result shr 1)

            shift = 0
            result = 0
            do {
                if (index >= encoded.length) return points
                byte = encoded[index].code - 63
                index++
                result = result or ((byte and 0x1f) shl shift)
                shift += 5
            } while (byte >= 0x20)
            lon += if ((result and 1) != 0) (result shr 1).inv() else (result shr 1)

            val latitude = lat / factor
            val longitude = lon / factor
            if (latitude in -90.0..90.0 && longitude in -180.0..180.0) {
                points += GeoPoint(latitude, longitude)
            }
        }
        return points
    }

    /** Encodes a polyline. Used by the offline router cache and by round-trip tests. */
    fun encode(points: List<GeoPoint>, precision: Int = 5): String {
        val factor = if (precision == 6) 1e6 else 1e5
        val builder = StringBuilder()
        var previousLat = 0
        var previousLon = 0
        points.forEach { point ->
            val lat = Math.round(point.latitude * factor).toInt()
            val lon = Math.round(point.longitude * factor).toInt()
            encodeValue(lat - previousLat, builder)
            encodeValue(lon - previousLon, builder)
            previousLat = lat
            previousLon = lon
        }
        return builder.toString()
    }

    private fun encodeValue(value: Int, builder: StringBuilder) {
        var shifted = if (value < 0) (value shl 1).inv() else (value shl 1)
        while (shifted >= 0x20) {
            builder.append(((0x20 or (shifted and 0x1f)) + 63).toChar())
            shifted = shifted shr 5
        }
        builder.append((shifted + 63).toChar())
    }
}

/** What the user asked for. Kept small so it can be logged without leaking precise history. */
data class RouteRequest(
    val origin: GeoPoint,
    val destination: GeoPoint,
    val alternatives: Boolean = true,
    val language: String = "en"
)

private val lenientJson = Json {
    ignoreUnknownKeys = true
    isLenient = true
    allowTrailingComma = true
}

private fun JsonElement?.objectOrNull(): JsonObject? = (this as? JsonObject)
private fun JsonElement?.arrayOrNull(): JsonArray? = (this as? JsonArray)
private fun JsonElement?.stringOrNull(): String? =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonElement?.numberOrNull(): Double? =
    (this as? JsonPrimitive)?.doubleOrNull

private fun JsonElement?.intOrNullSafe(): Int? =
    (this as? JsonPrimitive)?.intOrNull

object OsrmMapper {

    /**
     * Parses an OSRM `/route` response. Returns [RoutingResult.Failure] for `code != "Ok"` so the
     * caller can distinguish "no route" from "router unreachable".
     */
    fun parse(
        body: String,
        request: RouteRequest,
        provider: RoutingProvider = RoutingProvider.OSRM,
        originLabel: String? = null,
        destinationLabel: String? = null,
        receivedAtMs: Long = System.currentTimeMillis()
    ): RoutingResult {
        val root = runCatching { lenientJson.parseToJsonElement(body) }.getOrNull()?.objectOrNull()
            ?: return RoutingResult.Failure(RoutingFailureReason.PARSE_ERROR, "OSRM response is not a JSON object")

        val code = root["code"].stringOrNull() ?: "NoCode"
        if (code != "Ok") {
            val message = root["message"].stringOrNull() ?: code
            val reason = when (code) {
                "NoRoute", "NoSegment", "NoTrips" -> RoutingFailureReason.NO_ROUTE_FOUND
                "InvalidQuery", "InvalidValue", "InvalidOptions" -> RoutingFailureReason.INVALID_REQUEST
                "TooBig" -> RoutingFailureReason.RATE_LIMITED
                else -> RoutingFailureReason.SERVER_ERROR
            }
            return RoutingResult.Failure(reason, "OSRM said $code: $message")
        }

        val routes = root["routes"].arrayOrNull()
            ?: return RoutingResult.Failure(RoutingFailureReason.NO_ROUTE_FOUND, "OSRM returned no routes array")
        if (routes.isEmpty()) {
            return RoutingResult.Failure(RoutingFailureReason.NO_ROUTE_FOUND, "OSRM returned zero routes")
        }

        val plans = routes.mapIndexedNotNull { index, element ->
            val route = element.objectOrNull() ?: return@mapIndexedNotNull null
            val geometry = route["geometry"].stringOrNull()?.let { PolylineCodec.decode(it, 5) }.orEmpty()
            if (geometry.size < 2) return@mapIndexedNotNull null

            val legs = route["legs"].arrayOrNull()
            val steps = ArrayList<RouteStep>()
            var stepIndex = 0
            legs?.forEach { legElement ->
                val leg = legElement.objectOrNull() ?: return@forEach
                leg["steps"].arrayOrNull()?.forEach { stepElement ->
                    val step = stepElement.objectOrNull() ?: return@forEach
                    val maneuver = step["maneuver"].objectOrNull()
                    val location = maneuver?.get("location").arrayOrNull()
                    val lat = location?.getOrNull(1).numberOrNull()
                    val lon = location?.getOrNull(0).numberOrNull()
                    val maneuverLocation = if (lat != null && lon != null && lat in -90.0..90.0) {
                        GeoPoint(lat, lon)
                    } else {
                        geometry.getOrNull(stepIndex) ?: geometry.first()
                    }
                    val type = maneuver?.get("type").stringOrNull() ?: "continue"
                    val modifier = maneuver?.get("modifier").stringOrNull()
                    val roadName = step["name"].stringOrNull()?.takeIf { it.isNotBlank() }
                        ?: step["ref"].stringOrNull()?.takeIf { it.isNotBlank() }
                    val stepGeometry = step["geometry"].stringOrNull()?.let { PolylineCodec.decode(it, 5) }
                        ?.takeIf { it.size >= 2 }
                        ?: listOf(maneuverLocation)

                    val maneuverType = mapOsrmManeuver(type, modifier)
                    steps += RouteStep(
                        index = stepIndex,
                        maneuver = maneuverType,
                        instruction = OsrmInstructions.describe(maneuverType, roadName, maneuver?.get("exit").intOrNullSafe()),
                        roadName = roadName,
                        distanceMeters = step["distance"].numberOrNull() ?: 0.0,
                        durationSeconds = step["duration"].numberOrNull() ?: 0.0,
                        geometry = stepGeometry,
                        maneuverLocation = maneuverLocation,
                        exitNumber = maneuver?.get("exit").intOrNullSafe()
                    )
                    stepIndex++
                }
            }

            RoutePlan(
                id = "${RoutePlan.ID_PREFIX}-${provider.name.lowercase()}-$receivedAtMs-$index",
                provider = provider,
                requestAtMs = receivedAtMs,
                geometry = geometry,
                steps = normalizeSteps(steps, geometry),
                distanceMeters = route["distance"].numberOrNull() ?: 0.0,
                durationSeconds = route["duration"].numberOrNull() ?: 0.0,
                bounds = GeoBounds.of(geometry) ?: GeoBounds.of(listOf(request.origin, request.destination))!!,
                originLabel = originLabel,
                destinationLabel = destinationLabel,
                isOffline = false
            )
        }

        if (plans.isEmpty()) {
            return RoutingResult.Failure(RoutingFailureReason.PARSE_ERROR, "OSRM geometry could not be decoded")
        }
        val warnings = buildList {
            plans.forEach { plan ->
                if (plan.distanceMeters <= 0.0) add("Router reported a zero-length route.")
                if (plan.steps.size < 2) add("Router returned no turn-by-turn steps for this route.")
            }
        }
        return RoutingResult.Success(plans, warnings.distinct())
    }

    private fun List<GeoPoint>?.orEmptyFallback(fallback: GeoPoint): GeoPoint = this?.firstOrNull() ?: fallback

    internal fun mapOsrmManeuver(type: String, modifier: String?): ManeuverType {
        val mod = modifier?.lowercase()
        return when (type.lowercase()) {
            "depart" -> ManeuverType.DEPART
            "arrive" -> ManeuverType.ARRIVE
            "roundabout", "rotary" -> ManeuverType.ROUNDABOUT
            "exit roundabout", "exit rotary" -> ManeuverType.EXIT_ROUNDABOUT
            "merge" -> ManeuverType.MERGE
            "on ramp" -> ManeuverType.RAMP
            "off ramp" -> ManeuverType.RAMP
            "fork" -> when {
                mod == "left" || mod == "slight left" -> ManeuverType.FORK_LEFT
                mod == "right" || mod == "slight right" -> ManeuverType.FORK_RIGHT
                else -> ManeuverType.CONTINUE
            }
            "end of road" -> when {
                mod == "left" -> ManeuverType.TURN_LEFT
                mod == "right" -> ManeuverType.TURN_RIGHT
                else -> ManeuverType.CONTINUE
            }
            "continue", "new name", "notification" -> when (mod) {
                "left" -> ManeuverType.TURN_SLIGHT_LEFT
                "right" -> ManeuverType.TURN_SLIGHT_RIGHT
                "sharp left" -> ManeuverType.TURN_SHARP_LEFT
                "sharp right" -> ManeuverType.TURN_SHARP_RIGHT
                else -> ManeuverType.CONTINUE
            }
            "turn", "use lane" -> when (mod) {
                "left" -> ManeuverType.TURN_LEFT
                "right" -> ManeuverType.TURN_RIGHT
                "slight left" -> ManeuverType.TURN_SLIGHT_LEFT
                "slight right" -> ManeuverType.TURN_SLIGHT_RIGHT
                "sharp left" -> ManeuverType.TURN_SHARP_LEFT
                "sharp right" -> ManeuverType.TURN_SHARP_RIGHT
                "uturn" -> ManeuverType.UTURN
                else -> ManeuverType.CONTINUE
            }
            "uturn", "u-turn" -> ManeuverType.UTURN
            "ferry" -> ManeuverType.FERRY
            else -> ManeuverType.CONTINUE
        }
    }
}

internal object OsrmInstructions {
    fun describe(maneuver: ManeuverType, roadName: String?, exitNumber: Int?): String {
        val road = roadName?.takeIf { it.isNotBlank() }?.let { " onto $it" } ?: ""
        return when (maneuver) {
            ManeuverType.DEPART -> roadName?.let { "Head out on $it" } ?: "Depart"
            ManeuverType.ARRIVE -> "Arrive at your destination"
            ManeuverType.TURN_LEFT -> "Turn left$road"
            ManeuverType.TURN_RIGHT -> "Turn right$road"
            ManeuverType.TURN_SHARP_LEFT -> "Sharp left$road"
            ManeuverType.TURN_SHARP_RIGHT -> "Sharp right$road"
            ManeuverType.TURN_SLIGHT_LEFT -> "Keep left$road"
            ManeuverType.TURN_SLIGHT_RIGHT -> "Keep right$road"
            ManeuverType.CONTINUE -> roadName?.let { "Continue on $it" } ?: "Continue"
            ManeuverType.UTURN -> "Make a U-turn"
            ManeuverType.ROUNDABOUT -> exitNumber?.let { "Enter the roundabout, take exit $it" } ?: "Enter the roundabout"
            ManeuverType.EXIT_ROUNDABOUT -> "Leave the roundabout$road"
            ManeuverType.MERGE -> "Merge$road"
            ManeuverType.RAMP -> "Take the ramp$road"
            ManeuverType.FORK_LEFT -> "Keep left$road"
            ManeuverType.FORK_RIGHT -> "Keep right$road"
            ManeuverType.HIGHWAY_ENTRY -> "Join the motorway$road"
            ManeuverType.HIGHWAY_EXIT -> "Leave the motorway$road"
            ManeuverType.FERRY -> "Take the ferry"
            ManeuverType.WAYPOINT -> "Reach waypoint"
            ManeuverType.UNKNOWN -> "Continue"
        }
    }
}

object ValhallaMapper {

    fun parse(
        body: String,
        request: RouteRequest,
        provider: RoutingProvider = RoutingProvider.VALHALLA,
        originLabel: String? = null,
        destinationLabel: String? = null,
        receivedAtMs: Long = System.currentTimeMillis()
    ): RoutingResult {
        val root = runCatching { lenientJson.parseToJsonElement(body) }.getOrNull()?.objectOrNull()
            ?: return RoutingResult.Failure(RoutingFailureReason.PARSE_ERROR, "Valhalla response is not a JSON object")

        val error = root["error"].stringOrNull()
        if (error != null) {
            val code = root["error_code"].intOrNullSafe() ?: 0
            val reason = when (code) {
                171, 170, 442, 443 -> RoutingFailureReason.NO_ROUTE_FOUND
                400 -> RoutingFailureReason.INVALID_REQUEST
                429 -> RoutingFailureReason.RATE_LIMITED
                else -> RoutingFailureReason.SERVER_ERROR
            }
            return RoutingFailureReason.NO_ROUTE_FOUND.let { RoutingResult.Failure(reason, "Valhalla: $error") }
        }

        val trip = root["trip"].objectOrNull()
            ?: return RoutingResult.Failure(RoutingFailureReason.NO_ROUTE_FOUND, "Valhalla returned no trip")
        val legs = trip["legs"].arrayOrNull().orEmpty()
        if (legs.isEmpty()) {
            return RoutingResult.Failure(RoutingFailureReason.NO_ROUTE_FOUND, "Valhalla trip has no legs")
        }

        val geometry = ArrayList<GeoPoint>()
        val steps = ArrayList<RouteStep>()
        var stepIndex = 0
        var warnings = mutableListOf<String>()

        legs.forEach { legElement ->
            val leg = legElement.objectOrNull() ?: return@forEach
            val legShape = leg["shape"].stringOrNull()?.let { PolylineCodec.decode(it, 6) }.orEmpty()
            if (legShape.isEmpty()) {
                warnings += "Valhalla leg shape could not be decoded."
            } else {
                if (geometry.isNotEmpty() && legShape.isNotEmpty()) {
                    // Legs repeat the shared shape point; do not duplicate it.
                    val last = geometry.last()
                    if (last == legShape.first()) geometry.addAll(legShape.drop(1)) else geometry.addAll(legShape)
                } else {
                    geometry.addAll(legShape)
                }
            }

            leg["maneuvers"].arrayOrNull()?.forEach { maneuverElement ->
                val maneuver = maneuverElement.objectOrNull() ?: return@forEach
                val type = maneuver["type"].intOrNullSafe() ?: 0
                val beginIndex = maneuver["begin_shape_index"].intOrNullSafe() ?: 0
                val endIndex = maneuver["end_shape_index"].intOrNullSafe() ?: beginIndex
                val location = legShape.getOrNull(beginIndex)
                    ?: legShape.firstOrNull()
                    ?: geometry.firstOrNull()
                    ?: request.origin
                val stepGeometry = if (legShape.isNotEmpty() && endIndex > beginIndex) {
                    legShape.subList(beginIndex.coerceIn(0, legShape.size - 1), endIndex.coerceIn(0, legShape.size - 1) + 1)
                } else {
                    listOf(location)
                }
                val streetNames = maneuver["street_names"].arrayOrNull()
                    ?.mapNotNull { it.stringOrNull() }
                    .orEmpty()
                val roadName = streetNames.firstOrNull()?.takeIf { it.isNotBlank() }
                val maneuverType = mapValhallaManeuver(type)
                val instruction = maneuver["instruction"].stringOrNull()
                    ?: maneuver["verbal_pre_transition_instruction"].stringOrNull()
                    ?: OsrmInstructions.describe(maneuverType, roadName, maneuver["exit_number"].intOrNullSafe())
                val exitNumber = (maneuver["exit_number"] as? JsonPrimitive)?.intOrNull
                steps += RouteStep(
                    index = stepIndex,
                    maneuver = maneuverType,
                    instruction = instruction,
                    roadName = roadName,
                    distanceMeters = (maneuver["length"].numberOrNull() ?: 0.0) * 1000.0,
                    durationSeconds = maneuver["time"].numberOrNull() ?: 0.0,
                    geometry = stepGeometry,
                    maneuverLocation = location,
                    exitNumber = exitNumber,
                    speedLimitKmh = maneuver["speed"].numberOrNull()?.times(3.6)
                )
                stepIndex++
            }
        }

        if (geometry.size < 2) {
            return RoutingResult.Failure(RoutingFailureReason.PARSE_ERROR, "Valhalla route geometry is empty")
        }

        val summary = trip["summary"].objectOrNull()
        val plan = RoutePlan(
            id = "${RoutePlan.ID_PREFIX}-valhalla-$receivedAtMs-0",
            provider = provider,
            requestAtMs = receivedAtMs,
            geometry = geometry,
            steps = normalizeSteps(steps, geometry),
            distanceMeters = (summary?.get("length").numberOrNull() ?: 0.0) * 1000.0,
            durationSeconds = summary?.get("time").numberOrNull() ?: 0.0,
            bounds = GeoBounds.of(geometry) ?: GeoBounds.of(listOf(request.origin, request.destination))!!,
            originLabel = originLabel,
            destinationLabel = destinationLabel,
            isOffline = false
        )
        if (plan.distanceMeters <= 0.0) warnings += "Valhalla did not report a route length."
        return RoutingResult.Success(listOf(plan), warnings.distinct())
    }

    /** Valhalla's numeric maneuver taxonomy (docs/api/turn-by-turn/api-reference.md). */
    internal fun mapValhallaManeuver(type: Int): ManeuverType = when (type) {
        1, 2, 3 -> ManeuverType.DEPART
        4, 5, 6 -> ManeuverType.ARRIVE
        7, 8, 22 -> ManeuverType.CONTINUE
        9 -> ManeuverType.TURN_SLIGHT_RIGHT
        10 -> ManeuverType.TURN_RIGHT
        11 -> ManeuverType.TURN_SHARP_RIGHT
        12, 13 -> ManeuverType.UTURN
        14 -> ManeuverType.TURN_SHARP_LEFT
        15 -> ManeuverType.TURN_LEFT
        16 -> ManeuverType.TURN_SLIGHT_LEFT
        17, 18, 19 -> ManeuverType.RAMP
        20, 21 -> ManeuverType.HIGHWAY_EXIT
        23 -> ManeuverType.FORK_RIGHT
        24 -> ManeuverType.FORK_LEFT
        25 -> ManeuverType.MERGE
        26 -> ManeuverType.ROUNDABOUT
        27 -> ManeuverType.EXIT_ROUNDABOUT
        28 -> ManeuverType.FERRY
        29 -> ManeuverType.CONTINUE
        37, 38 -> ManeuverType.CONTINUE
        39 -> ManeuverType.MERGE
        40 -> ManeuverType.MERGE
        41, 42, 43, 44, 45 -> ManeuverType.CONTINUE
        46 -> ManeuverType.HIGHWAY_ENTRY
        47 -> ManeuverType.HIGHWAY_EXIT
        else -> ManeuverType.CONTINUE
    }
}

/**
 * Guarantees a route always has a DEPART and an ARRIVE step and that every step carries usable
 * geometry. Some routers omit the terminal maneuver, which would leave the banner showing the last
 * turn forever.
 */
internal fun normalizeSteps(steps: List<RouteStep>, geometry: List<GeoPoint>): List<RouteStep> {
    if (geometry.size < 2) return steps
    val normalized = ArrayList<RouteStep>(steps.size + 2)
    val sorted = steps.sortedBy { it.index }
    if (sorted.isEmpty() || sorted.first().maneuver != ManeuverType.DEPART) {
        normalized += RouteStep(
            index = 0,
            maneuver = ManeuverType.DEPART,
            instruction = "Depart",
            roadName = null,
            distanceMeters = 0.0,
            durationSeconds = 0.0,
            geometry = listOf(geometry.first()),
            maneuverLocation = geometry.first()
        )
    }
    normalized += sorted.filter { it.geometry.isNotEmpty() || it.distanceMeters > 0 }
    if (normalized.lastOrNull()?.maneuver != ManeuverType.ARRIVE) {
        normalized += RouteStep(
            index = normalized.size,
            maneuver = ManeuverType.ARRIVE,
            instruction = "Arrive at your destination",
            roadName = null,
            distanceMeters = 0.0,
            durationSeconds = 0.0,
            geometry = listOf(geometry.last()),
            maneuverLocation = geometry.last()
        )
    }
    return normalized.mapIndexed { index, step -> step.copy(index = index) }
}
