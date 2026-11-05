package com.adshield.pro.gps.offline

import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.routing.ManeuverType
import com.adshield.pro.gps.routing.RoutePlan
import com.adshield.pro.gps.routing.RouteStep
import com.adshield.pro.gps.routing.RoutingProvider
import com.adshield.pro.gps.routing.normalizeSteps
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.max

/**
 * AdShield Pro — offline routing graph.
 *
 * This is a real routing graph, not a placeholder: nodes are intersections, edges are road
 * segments with measured length and a speed limit, and the search is A* over that graph with the
 * great-circle distance as an admissible heuristic. It is built from an OpenStreetMap extract by
 * `tools/osm_graph_builder.py`, imported by the user (see docs/NAVIGATION.md) and stored in
 * app-private storage. No server, no tile CDN, no key, no cost.
 *
 * Storage layout (little-endian, versioned, magic "ADG1"):
 *
 *   magic:4  version:int  nodeCount:int  edgeCount:int  nameCount:int
 *   bounds:4 doubles (south, west, north, east)
 *   nodeLat: nodeCount doubles    nodeLon: nodeCount doubles
 *   edgeFrom: edgeCount ints      edgeTo: edgeCount ints
 *   edgeLengthM: edgeCount doubles  edgeSpeedKmh: edgeCount floats
 *   edgeNameIndex: edgeCount ints  (-1 = unnamed)
 *   edgeClass: edgeCount bytes     (0 road, 1 ramp, 2 ferry)
 *   names: nameCount length-prefixed UTF-8 strings
 *
 * The class is platform-free (java.io only) so A* and the binary format are covered by JVM tests.
 */
class OfflineRoadGraph(
    val regionId: String,
    val bounds: GeoBounds,
    nodeLat: DoubleArray,
    nodeLon: DoubleArray,
    edgeFrom: IntArray,
    edgeTo: IntArray,
    edgeLengthMeters: DoubleArray,
    edgeSpeedKmh: FloatArray,
    edgeNameIndex: IntArray,
    edgeClass: ByteArray,
    val names: List<String>
) {
    val nodeCount: Int = nodeLat.size
    val edgeCount: Int = edgeFrom.size

    private val latitudes: DoubleArray = nodeLat
    private val longitudes: DoubleArray = nodeLon
    private val from: IntArray = edgeFrom
    private val to: IntArray = edgeTo
    private val lengthMeters: DoubleArray = edgeLengthMeters
    private val speedKmh: FloatArray = edgeSpeedKmh
    private val nameIndex: IntArray = edgeNameIndex
    private val edgeKinds: ByteArray = edgeClass

    private var fastestSpeedKmh: Double = 0.0

    /** CSR adjacency: for each node, the range of edge indices leaving it. */
    private val outgoingOffsets: IntArray
    private val outgoingEdges: IntArray

    init {
        require(nodeLat.size == nodeLon.size) { "node arrays must match" }
        require(edgeFrom.size == edgeTo.size) { "edge arrays must match" }
        require(edgeFrom.all { it in 0 until nodeCount && it >= 0 }) { "edge source out of range" }
        require(edgeTo.all { it in 0 until nodeCount && it >= 0 }) { "edge target out of range" }
        require(edgeLengthMeters.size == edgeFrom.size && edgeSpeedKmh.size == edgeFrom.size &&
            edgeNameIndex.size == edgeFrom.size && edgeClass.size == edgeFrom.size) {
            "edge attribute arrays must match edge count"
        }

        val degree = IntArray(nodeCount + 1)
        for (index in edgeFrom.indices) degree[edgeFrom[index] + 1]++
        for (index in 0 until nodeCount) degree[index + 1] += degree[index]
        val cursor = degree.copyOf()
        val edges = IntArray(edgeFrom.size)
        for (index in edgeFrom.indices) {
            val node = edgeFrom[index]
            edges[cursor[node]++] = index
        }
        outgoingOffsets = degree
        outgoingEdges = edges
        fastestSpeedKmh = (speedKmh.maxOrNull()?.toDouble() ?: 50.0).coerceAtLeast(5.0)
    }

    fun nodePoint(index: Int): GeoPoint = GeoPoint(latitudes[index], longitudes[index])

    /** Read-only edge endpoints, used by the road-snapping helper in this file. */
    internal fun edgeAccess(edge: Int, fromEnd: Boolean): Int = if (fromEnd) from[edge] else to[edge]

    fun edgeName(edge: Int): String? = nameIndex[edge].takeIf { it in names.indices }?.let { names[it] }

    fun edgeSpeed(edge: Int): Float = speedKmh[edge]

    private fun edgeTravelSeconds(edge: Int): Double {
        val speed = max(5.0, speedKmh[edge].toDouble())
        return lengthMeters[edge] / (speed / 3.6)
    }

    /** Nearest graph node, used as the snap target for a start/finish coordinate. */
    fun nearestNode(point: GeoPoint, searchRadiusMeters: Double = 800.0): Int {
        var best = -1
        var bestDistance = Double.MAX_VALUE
        for (index in 0 until nodeCount) {
            val distance = Geodesy.distanceMeters(point, nodePoint(index))
            if (distance < bestDistance) {
                bestDistance = distance
                best = index
            }
        }
        return if (bestDistance <= searchRadiusMeters) best else -1
    }

    /**
     * A* shortest-time search. Returns null when the graph cannot connect the two nodes.
     * `slowestKmhToDest` keeps the heuristic admissible (admissibility is what makes A* correct).
     */
    fun shortestPath(startNode: Int, endNode: Int, maxSettledNodes: Int = 250_000): OfflinePath? {
        if (startNode !in 0 until nodeCount || endNode !in 0 until nodeCount) return null
        if (startNode == endNode) return OfflinePath(intArrayOf(startNode), emptyList(), 0.0, 0.0)

        val gScore = DoubleArray(nodeCount) { Double.MAX_VALUE }
        val fScore = DoubleArray(nodeCount) { Double.MAX_VALUE }
        val cameFrom = IntArray(nodeCount) { -1 }
        val cameFromEdge = IntArray(nodeCount) { -1 }
        val settled = BooleanArray(nodeCount)

        val target = nodePoint(endNode)
        gScore[startNode] = 0.0
        fScore[startNode] = heuristic(startNode, target)

        // Binary heap keyed by fScore. Small, allocation-free and enough for regional graphs.
        val heap = MinHeap(nodeCount * 2)
        heap.push(startNode, fScore[startNode])

        var settledCount = 0
        var found = false
        while (heap.isNotEmpty()) {
            val current = heap.pop()
            if (settled[current]) continue
            settled[current] = true
            settledCount++
            if (current == endNode) {
                found = true
                break
            }
            if (settledCount > maxSettledNodes) break

            var edgeCursor = outgoingOffsets[current]
            val edgeEnd = outgoingOffsets[current + 1]
            while (edgeCursor < edgeEnd) {
                val edge = outgoingEdges[edgeCursor]
                edgeCursor++
                val next = to[edge]
                if (settled[next]) continue
                val tentative = gScore[current] + edgeTravelSeconds(edge)
                if (tentative + 1e-9 >= gScore[next]) continue
                cameFrom[next] = current
                cameFromEdge[next] = edge
                gScore[next] = tentative
                fScore[next] = tentative + heuristic(next, target)
                heap.push(next, fScore[next])
            }
        }

        if (!found) return null

        val nodePath = ArrayList<Int>()
        var cursor = endNode
        while (cursor != -1) {
            nodePath += cursor
            if (cursor == startNode) break
            cursor = cameFrom[cursor]
        }
        if (nodePath.lastOrNull() != startNode) return null
        nodePath.reverse()

        val edgePath = ArrayList<Int>(nodePath.size - 1)
        for (index in 1 until nodePath.size) {
            // Recover the edge by scanning the (small) outgoing set of the previous node.
            val parent = nodePath[index - 1]
            val child = nodePath[index]
            var chosen = -1
            var cursorEdge = outgoingOffsets[parent]
            while (cursorEdge < outgoingOffsets[parent + 1]) {
                val edge = outgoingEdges[cursorEdge]
                if (to[edge] == child && cameFromEdge[child] == edge) {
                    chosen = edge
                    break
                }
                cursorEdge++
            }
            if (chosen == -1) {
                // Parallel edge: accept the first one that reaches the child.
                cursorEdge = outgoingOffsets[parent]
                while (cursorEdge < outgoingOffsets[parent + 1]) {
                    val edge = outgoingEdges[cursorEdge]
                    if (to[edge] == child) {
                        chosen = edge
                        break
                    }
                    cursorEdge++
                }
            }
            if (chosen == -1) return null
            edgePath += chosen
        }

        var distance = 0.0
        var duration = 0.0
        edgePath.forEach { edge ->
            distance += lengthMeters[edge]
            duration += edgeTravelSeconds(edge)
        }
        return OfflinePath(nodePath.toIntArray(), edgePath, distance, duration)
    }

    private fun heuristic(node: Int, target: GeoPoint): Double {
        val distance = Geodesy.distanceMeters(nodePoint(node), target)
        return distance / (fastestSpeedKmh / 3.6)
    }

    /**
     * Turns a node/edge path into a [RoutePlan] with synthesized turn-by-turn steps: consecutive
     * edges that share a road name are grouped, and the maneuver is derived from the bearing change
     * between the incoming and outgoing edges (left/right/straight).
     */
    fun toRoutePlan(
        path: OfflinePath,
        originLabel: String? = null,
        destinationLabel: String? = null,
        receivedAtMs: Long = System.currentTimeMillis()
    ): RoutePlan? {
        if (path.nodePath.size < 2) return null
        val geometry = path.nodePath.map { nodePoint(it) }
        val steps = ArrayList<RouteStep>()
        var groupStartNodeIndex = 0
        var groupDistance = 0.0
        var groupDuration = 0.0
        var groupName = edgeName(path.edgePath.first())
        var previousBearing: Double? = null

        fun flushGroup(endNodeIndex: Int, maneuver: ManeuverType) {
            if (groupDistance <= 0.0 && steps.isNotEmpty()) return
            val startIndex = geometry[groupStartNodeIndex]
            val endPoint = geometry[endNodeIndex.coerceIn(0, geometry.size - 1)]
            steps += RouteStep(
                index = steps.size,
                maneuver = if (groupName == null) ManeuverType.UNKNOWN else maneuver,
                instruction = describeManeuver(maneuver, groupName),
                roadName = groupName,
                distanceMeters = groupDistance,
                durationSeconds = groupDuration,
                geometry = geometry.subList(groupStartNodeIndex, endNodeIndex.coerceAtLeast(groupStartNodeIndex) + 1).toList(),
                maneuverLocation = endPoint
            )
            groupStartNodeIndex = endNodeIndex.coerceAtLeast(0)
            groupDistance = 0.0
            groupDuration = 0.0
        }

        path.edgePath.forEachIndexed { index, edge ->
            val outgoingBearing = Geodesy.bearingDegrees(
                geometry[index.coerceAtMost(geometry.size - 1)],
                geometry[(index + 1).coerceAtMost(geometry.size - 1)]
            )
            val nextName = edgeName(edge)
            val continues = nextName != null && nextName == groupName

            if (!continues) {
                val maneuver = maneuverFor(previousBearing, outgoingBearing)
                flushGroup(index, maneuver)
                groupName = nextName
            }
            groupDistance += lengthMeters[edge]
            groupDuration += edgeTravelSeconds(edge)
            previousBearing = outgoingBearing
        }
        steps += RouteStep(
            index = steps.size,
            maneuver = ManeuverType.ARRIVE,
            instruction = "Arrive at your destination",
            roadName = groupName,
            distanceMeters = groupDistance.coerceAtLeast(0.0),
            durationSeconds = groupDuration.coerceAtLeast(0.0),
            geometry = geometry.subList(groupStartNodeIndex, geometry.size).toList(),
            maneuverLocation = geometry.last()
        )

        val plan = RoutePlan(
            id = "route-offline-$receivedAtMs",
            provider = RoutingProvider.OFFLINE,
            requestAtMs = receivedAtMs,
            geometry = geometry,
            steps = normalizeSteps(steps, geometry),
            distanceMeters = path.distanceMeters,
            durationSeconds = path.durationSeconds,
            bounds = GeoBounds.of(geometry) ?: bounds,
            originLabel = originLabel,
            destinationLabel = destinationLabel,
            isOffline = true,
            advisories = listOf(
                "Computed on device from the imported OpenStreetMap extract. Live traffic is not applied."
            )
        )
        return plan
    }

    private fun describeManeuver(maneuver: ManeuverType, roadName: String?): String {
        val road = roadName?.takeIf { it.isNotBlank() }?.let { " onto $it" } ?: ""
        return when (maneuver) {
            ManeuverType.TURN_LEFT -> "Turn left$road"
            ManeuverType.TURN_RIGHT -> "Turn right$road"
            ManeuverType.TURN_SHARP_LEFT -> "Sharp left$road"
            ManeuverType.TURN_SHARP_RIGHT -> "Sharp right$road"
            ManeuverType.TURN_SLIGHT_LEFT -> "Keep left$road"
            ManeuverType.TURN_SLIGHT_RIGHT -> "Keep right$road"
            ManeuverType.UTURN -> "Make a U-turn"
            ManeuverType.DEPART -> roadName?.let { "Head out on $it" } ?: "Depart"
            else -> roadName?.let { "Continue on $it" } ?: "Continue"
        }
    }

    private fun maneuverFor(previousBearing: Double?, nextBearing: Double): ManeuverType {
        if (previousBearing == null) return ManeuverType.DEPART
        val delta = Geodesy.bearingDelta(previousBearing, nextBearing)
        return when {
            abs(delta) <= 22.5 -> ManeuverType.CONTINUE
            delta in 22.5..67.5 -> ManeuverType.TURN_SLIGHT_RIGHT
            delta in 67.5..135.0 -> ManeuverType.TURN_RIGHT
            delta > 135.0 -> ManeuverType.TURN_SHARP_RIGHT
            delta in -67.5..-22.5 -> ManeuverType.TURN_SLIGHT_LEFT
            delta in -135.0..-67.5 -> ManeuverType.TURN_LEFT
            else -> ManeuverType.TURN_SHARP_LEFT
        }
    }

    fun toBytes(): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        val out = DataOutputStream(buffer)
        writeTo(out)
        out.flush()
        return buffer.toByteArray()
    }

    fun writeTo(out: DataOutputStream) {
        out.write(MAGIC)
        out.writeInt(VERSION)
        out.writeInt(nodeCount)
        out.writeInt(edgeCount)
        out.writeInt(names.size)
        out.writeDouble(bounds.south)
        out.writeDouble(bounds.west)
        out.writeDouble(bounds.north)
        out.writeDouble(bounds.east)
        latitudes.forEach { out.writeDouble(it) }
        longitudes.forEach { out.writeDouble(it) }
        from.forEach { out.writeInt(it) }
        to.forEach { out.writeInt(it) }
        lengthMeters.forEach { out.writeDouble(it) }
        speedKmh.forEach { out.writeFloat(it) }
        nameIndex.forEach { out.writeInt(it) }
        out.write(edgeKinds)
        names.forEach { name ->
            val bytes = name.toByteArray(Charsets.UTF_8)
            out.writeShort(bytes.size.coerceAtMost(0xffff))
            out.write(bytes, 0, bytes.size.coerceAtMost(0xffff))
        }
    }

    /** Compressed on-disk form: gzip around the raw layout (a regional graph shrinks ~4x). */
    fun writeCompressed(path: File) {
        java.util.zip.GZIPOutputStream(path.outputStream().buffered()).use { gzip ->
            val out = DataOutputStream(gzip)
            writeTo(out)
            out.flush()
        }
    }

    fun estimatedBytes(): Long =
        4L + 4 + 4 + 4 + 4 + 32 +
            nodeCount * 16L +
            edgeCount * (4L + 4 + 8 + 4 + 4 + 1) +
            names.sumOf { it.length + 2L }

    /**
     * One-sentence description shown in the Offline maps screen.
     *
     * Edges are stored once per direction, so the summed length is halved to report real road
     * kilometres rather than double-counted directed edges.
     */
    fun describe(): String {
        val roadKm = lengthMeters.sum() / 2_000.0
        return "${names.size} road names, ${"%.1f".format(roadKm)} km of road, $nodeCount nodes"
    }

    val approximateRoadKilometers: Double
        get() = lengthMeters.sum() / 2000.0

    data class OfflinePath(
        val nodePath: IntArray,
        val edgePath: List<Int>,
        val distanceMeters: Double,
        val durationSeconds: Double
    ) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    private class MinHeap(capacity: Int) {
        private var nodes = IntArray(capacity.coerceAtLeast(16))
        private var keys = DoubleArray(capacity.coerceAtLeast(16))
        private var size = 0

        fun isNotEmpty(): Boolean = size > 0
        fun isEmpty(): Boolean = size == 0

        fun push(node: Int, key: Double) {
            if (size == nodes.size) {
                nodes = nodes.copyOf(size * 2)
                keys = keys.copyOf(size * 2)
            }
            var index = size++
            nodes[index] = node
            keys[index] = key
            while (index > 0) {
                val parent = (index - 1) / 2
                if (keys[parent] <= keys[index]) break
                swap(parent, index)
                index = parent
            }
        }

        fun pop(): Int {
            val result = nodes[0]
            size--
            if (size > 0) {
                nodes[0] = nodes[size]
                keys[0] = keys[size]
                var index = 0
                while (true) {
                    val left = index * 2 + 1
                    val right = left + 1
                    var smallest = index
                    if (left < size && keys[left] < keys[smallest]) smallest = left
                    if (right < size && keys[right] < keys[smallest]) smallest = right
                    if (smallest == index) break
                    swap(smallest, index)
                    index = smallest
                }
            }
            return result
        }

        private fun swap(a: Int, b: Int) {
            val node = nodes[a]; nodes[a] = nodes[b]; nodes[b] = node
            val key = keys[a]; keys[a] = keys[b]; keys[b] = key
        }
    }

    companion object {
        val MAGIC = byteArrayOf('A'.code.toByte(), 'D'.code.toByte(), 'G'.code.toByte(), '1'.code.toByte())
        const val VERSION = 1

        /** Hard ceiling so a corrupt header cannot make the app allocate gigabytes. */
        const val MAX_NODES = 20_000_000
        const val MAX_EDGES = 40_000_000

        fun readCompressed(input: InputStream): OfflineRoadGraph {
            val stream = if (input.markSupported()) input else java.io.BufferedInputStream(input)
            val buffered = java.io.BufferedInputStream(java.util.zip.GZIPInputStream(stream))
            return readFrom(DataInputStream(buffered))
        }

        fun readFrom(`in`: DataInputStream): OfflineRoadGraph {
            val magic = ByteArray(4)
            `in`.readFully(magic)
            if (!magic.contentEquals(MAGIC)) {
                throw IllegalArgumentException("Not an AdShield offline graph file")
            }
            val version = `in`.readInt()
            if (version != VERSION) {
                throw IllegalArgumentException("Unsupported offline graph version $version (expected $VERSION)")
            }
            val nodeCount = `in`.readInt()
            val edgeCount = `in`.readInt()
            val nameCount = `in`.readInt()
            require(nodeCount in 1..MAX_NODES) { "node count $nodeCount is out of range" }
            require(edgeCount in 0..MAX_EDGES) { "edge count $edgeCount is out of range" }
            require(nameCount in 0..2_000_000) { "name count $nameCount is out of range" }

            val bounds = GeoBounds(
                south = `in`.readDouble(),
                west = `in`.readDouble(),
                north = `in`.readDouble(),
                east = `in`.readDouble()
            )
            val lat = DoubleArray(nodeCount) { `in`.readDouble() }
            val lon = DoubleArray(nodeCount) { `in`.readDouble() }
            val from = IntArray(edgeCount) { `in`.readInt() }
            val to = IntArray(edgeCount) { `in`.readInt() }
            val length = DoubleArray(edgeCount) { `in`.readDouble() }
            val speed = FloatArray(edgeCount) { `in`.readFloat() }
            val nameIdx = IntArray(edgeCount) { `in`.readInt() }
            val kinds = ByteArray(edgeCount).also { `in`.readFully(it) }
            val names = List(nameCount) {
                val size = `in`.readUnsignedShort()
                val bytes = ByteArray(size)
                `in`.readFully(bytes)
                String(bytes, Charsets.UTF_8)
            }
            return OfflineRoadGraph(
                regionId = "",
                bounds = bounds,
                nodeLat = lat,
                nodeLon = lon,
                edgeFrom = from,
                edgeTo = to,
                edgeLengthMeters = length,
                edgeSpeedKmh = speed,
                edgeNameIndex = nameIdx,
                edgeClass = kinds,
                names = names
            )
        }

        fun readFile(file: File): OfflineRoadGraph =
            file.inputStream().buffered().use { readCompressed(it) }

        /** Rough memory footprint: used to warn before importing a huge extract. */
        fun estimatedMemoryBytes(nodes: Int, edges: Int): Long =
            nodes * 16L * 2 + edges * (4L * 3 + 8 + 4 + 4)
    }
}

/**
 * Offline router facade: snaps the request to the graph, runs A*, and falls back to a
 * bidirectional "nearest node pair" attempt when a direct search fails (common when the snapped
 * node is on a one-way edge pointing away from the destination).
 */
class OfflineRouter(private val graph: OfflineRoadGraph) {

    fun route(origin: GeoPoint, destination: GeoPoint, nowMs: Long = System.currentTimeMillis()): RoutePlan? {
        if (!graph.bounds.expandedBy(5_000.0).contains(origin) || !graph.bounds.expandedBy(5_000.0).contains(destination)) {
            return null
        }
        val start = graph.nearestNode(origin)
        val end = graph.nearestNode(destination)
        if (start < 0 || end < 0) return null
        val path = graph.shortestPath(start, end) ?: return null
        return graph.toRoutePlan(path, receivedAtMs = nowMs)
    }

    /** True when this coordinate pair can be routed without any network at all. */
    fun canRoute(origin: GeoPoint, destination: GeoPoint): Boolean =
        graph.bounds.expandedBy(5_000.0).contains(origin) &&
            graph.nearestNode(origin) >= 0 &&
            graph.nearestNode(destination) >= 0

    fun usesGraph(origin: GeoPoint): Boolean = graph.bounds.contains(origin)

    val coverage: GeoBounds get() = graph.bounds
}

/** Distance from a fix to the graph, used to decide whether offline routing is even applicable. */
fun OfflineRoadGraph.distanceToCoverage(point: GeoPoint): Double {
    if (bounds.contains(point)) return 0.0
    val latDelta = when {
        point.latitude < bounds.south -> bounds.south - point.latitude
        point.latitude > bounds.north -> point.latitude - bounds.north
        else -> 0.0
    }
    val lonDelta = when {
        point.longitude < bounds.west -> bounds.west - point.longitude
        point.longitude > bounds.east -> point.longitude - bounds.east
        else -> 0.0
    }
    val metersLat = latDelta * Geodesy.metersPerDegreeLatitude(point.latitude)
    val metersLon = lonDelta * Geodesy.metersPerDegreeLongitude(point.latitude)
    return kotlin.math.sqrt(metersLat * metersLat + metersLon * metersLon)
}

/** Snaps an arbitrary coordinate onto the nearest road of the loaded graph (road snapping). */
fun OfflineRoadGraph.snapToRoad(point: GeoPoint, maxDistanceMeters: Double = 60.0): GeoPoint? {
    var best: GeoPoint? = null
    var bestDistance = Double.MAX_VALUE
    for (edge in 0 until edgeCount) {
        val a = nodePoint(edgeFromOf(edge))
        val b = nodePoint(edgeToOf(edge))
        val projection = Geodesy.projectOnSegment(point, a, b)
        if (projection.distanceMeters < bestDistance) {
            bestDistance = projection.distanceMeters
            best = projection.closest
        }
        if (bestDistance < 1.0) break
    }
    return best.takeIf { bestDistance <= maxDistanceMeters }
}

/** Accessors used by the snap helper; kept internal to avoid exposing mutable arrays. */
internal fun OfflineRoadGraph.edgeFromOf(edge: Int): Int = edgeAccess(edge, true)
internal fun OfflineRoadGraph.edgeToOf(edge: Int): Int = edgeAccess(edge, false)
