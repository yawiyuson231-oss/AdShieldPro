package com.adshield.pro

import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.offline.OfflineRoadGraph
import com.adshield.pro.gps.offline.OfflineRouter
import com.adshield.pro.gps.offline.distanceToCoverage
import com.adshield.pro.gps.offline.snapToRoad
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AdShield Pro — offline routing graph (`ADG1`) and the `ADSE1` encrypted container.
 *
 * `OfflineRoadGraph` is written with `java.io` only on purpose, so the binary format, the A* search
 * and the road-snapping helper are all exercised here with no emulator and no Android framework.
 * These are the parts of the offline module that a JVM test *can* own; the Keystore-backed file
 * store and the MapLibre tile cache still need a device.
 */
class GpsOfflineGraphTest {

    // A tiny hand-built L-shaped network, in metres-friendly degrees near Manila:
    //
    //   0 (14.6000, 121.0000) --edge0--> 1 (14.6000, 121.0100) --edge1--> 2 (14.6050, 121.0100)
    //   and the same roads back again as edges 2 and 3, so the graph is bidirectional.
    //
    // North–south leg: 0.0100° of longitude at 14.6° ≈ 1 074 m.
    // East–west leg:  0.0050° of latitude ≈ 555 m.
    private fun network(regionId: String = "manila-test") = OfflineRoadGraph(
        regionId = regionId,
        bounds = GeoBounds(south = 14.5990, west = 120.9990, north = 14.6060, east = 121.0110),
        nodeLat = doubleArrayOf(14.6000, 14.6000, 14.6050),
        nodeLon = doubleArrayOf(121.0000, 121.0100, 121.0100),
        edgeFrom = intArrayOf(0, 1, 1, 0),
        edgeTo = intArrayOf(1, 2, 0, 1),
        edgeLengthMeters = doubleArrayOf(1_074.0, 555.0, 1_074.0, 555.0),
        edgeSpeedKmh = floatArrayOf(40f, 30f, 40f, 30f),
        edgeNameIndex = intArrayOf(0, 1, 0, 1),
        edgeClass = byteArrayOf(0, 0, 0, 0),
        names = listOf("Rizal Avenue", "Session Road")
    )

    private fun nearlyEquals(expected: Double, actual: Double, tolerance: Double, message: String) =
        assertTrue("$message (expected $expected ± $tolerance, was $actual)", kotlin.math.abs(expected - actual) <= tolerance)

    // ------------------------------------------------------------------ binary format

    @Test
    fun testGraphRoundTripsThroughTheBinaryFormat() {
        val original = network()
        val reloaded = OfflineRoadGraph.readFrom(java.io.DataInputStream(original.toBytes().inputStream()))

        assertEquals(original.nodeCount, reloaded.nodeCount)
        assertEquals(original.edgeCount, reloaded.edgeCount)
        assertEquals(original.names, reloaded.names)
        assertEquals(original.bounds, reloaded.bounds)
        for (node in 0 until original.nodeCount) {
            assertEquals(original.nodePoint(node), reloaded.nodePoint(node))
        }
        for (edge in 0 until original.edgeCount) {
            assertEquals(original.edgeSpeed(edge), reloaded.edgeSpeed(edge), 0.0001f)
            assertEquals(original.edgeName(edge), reloaded.edgeName(edge))
        }
    }

    @Test
    fun testRegionIdIsNotPartOfTheFileSoTheCallerSuppliesIt() {
        // The on-disk header carries geometry only; a reloaded graph has no region id until the
        // importer assigns one. That is deliberate: the region id belongs to the pack manifest.
        val reloaded = OfflineRoadGraph.readFrom(java.io.DataInputStream(network().toBytes().inputStream()))
        assertEquals("", reloaded.regionId)
    }

    @Test
    fun testCompressedFileRoundTripOnDisk() {
        val file = java.io.File.createTempFile("adg1-test", ".adg.gz")
        try {
            network().writeCompressed(file)
            assertTrue("the compressed graph must actually be written", file.length() > 0)
            val reloaded = OfflineRoadGraph.readFile(file)
            assertEquals(3, reloaded.nodeCount)
            assertEquals(4, reloaded.edgeCount)
            assertEquals("Rizal Avenue", reloaded.edgeName(0))
        } finally {
            file.delete()
        }
    }

    @Test
    fun testForeignFileIsRejectedWithAReason() {
        val bytes = "NOTANADG".toByteArray(Charsets.US_ASCII)
        val failure = runCatching {
            OfflineRoadGraph.readFrom(java.io.DataInputStream(bytes.inputStream()))
        }.exceptionOrNull()
        assertTrue("a foreign file must be rejected", failure is IllegalArgumentException)
        assertTrue(
            "the message must name the format, got: ${failure?.message}",
            failure?.message?.contains("AdShield") == true
        )
    }

    @Test
    fun testWrongVersionIsRejectedInsteadOfParsedAnyway() {
        // Same magic, but a future format version: reading it would misinterpret every byte after
        // the header, so it has to fail loudly.
        val bytes = network().toBytes()
        // magic (4) + version (4): overwrite the version int with 99.
        bytes[4] = 0; bytes[5] = 0; bytes[6] = 0; bytes[7] = 99
        val failure = runCatching {
            OfflineRoadGraph.readFrom(java.io.DataInputStream(bytes.inputStream()))
        }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
        assertTrue(
            "the message must state the version mismatch, got: ${failure?.message}",
            failure?.message?.contains("version") == true
        )
    }

    @Test
    fun testTruncatedFileFailsInsteadOfProducingAPartialGraph() {
        val full = network().toBytes()
        val truncated = full.copyOf(full.size / 2)
        assertNotNull(
            "a half-written graph must not load",
            runCatching { OfflineRoadGraph.readFrom(java.io.DataInputStream(truncated.inputStream())) }
                .exceptionOrNull()
        )
    }

    @Test
    fun testCorruptNodeCountIsBounded() {
        // Header claims 200 million nodes in a 250-byte file: the reader must refuse on the count
        // instead of trying to allocate the arrays first.
        val bytes = network().toBytes()
        val absurd = 200_000_000 // above OfflineRoadGraph.MAX_NODES
        bytes[8] = (absurd ushr 24).toByte(); bytes[9] = (absurd ushr 16).toByte()
        bytes[10] = (absurd ushr 8).toByte(); bytes[11] = absurd.toByte()
        assertNotNull(
            runCatching { OfflineRoadGraph.readFrom(java.io.DataInputStream(bytes.inputStream())) }
                .exceptionOrNull()
        )
    }

    // ------------------------------------------------------------------ routing

    @Test
    fun testShortestPathFindsTheLShapedRoute() {
        val graph = network()
        val path = graph.shortestPath(0, 2)
        assertNotNull("the network is connected, a path must exist", path)
        // Time-optimal, so the reference lengths written into the edges are what the search uses.
        val expectedSeconds = 1_074.0 / (40.0 / 3.6) + 555.0 / (30.0 / 3.6)
        nearlyEquals(expectedSeconds, path!!.durationSeconds, 0.5, "A* must use both legs")
        nearlyEquals(1_629.0, path.distanceMeters, 1.0, "the reported distance is the sum of the legs")
        assertEquals(listOf(0, 1, 2), path.nodePath.toList())
    }

    @Test
    fun testShortestPathIsDirectionAwareAcrossTheOneWayPair() {
        // Edge 3 only runs 1 -> 0, so 2 -> 0 must use 2 -> 1 then 1 -> 0 and cost the same as 0 -> 2.
        val graph = network()
        val forward = graph.shortestPath(0, 2)!!
        val backward = graph.shortestPath(2, 0)!!
        nearlyEquals(forward.distanceMeters, backward.distanceMeters, 1.0, "reversed route must mirror the forward one")
        assertEquals(listOf(2, 1, 0), backward.nodePath.toList())
    }

    @Test
    fun testOfflineRouterProducesATurnByTurnPlan() {
        val router = OfflineRouter(network())
        val plan = router.route(GeoPoint(14.6000, 121.0000), GeoPoint(14.6050, 121.0100), nowMs = 5_000L)
        assertNotNull("a covered origin/destination pair must route offline", plan)
        assertTrue("the plan must be usable (geometry + distance)", plan!!.isUsable)
        assertTrue("the plan must be labelled offline", plan.isOffline)
        assertEquals(com.adshield.pro.gps.routing.RoutingProvider.OFFLINE, plan.provider)
        assertTrue(
            "an offline plan must still carry steps the TTS engine can speak",
            plan.steps.isNotEmpty() && plan.steps.all { it.instruction.isNotBlank() }
        )
        assertEquals(
            "the last step of every route is the arrival",
            com.adshield.pro.gps.routing.ManeuverType.ARRIVE,
            plan.steps.last().maneuver
        )
        assertTrue("the L-shaped route is longer than a straight line", plan.distanceMeters > 1_500.0)
    }

    @Test
    fun testRoutingOutsideTheDownloadedRegionIsRefusedNotApproximated() {
        val router = OfflineRouter(network())
        // Cebu City: nowhere near this pack. The honest answer is "no", not a 600 km straight line.
        assertNull(router.route(GeoPoint(10.3157, 123.8854), GeoPoint(14.6050, 121.0100)))
        assertFalse(router.canRoute(GeoPoint(10.3157, 123.8854), GeoPoint(14.6050, 121.0100)))
        assertFalse(router.usesGraph(GeoPoint(10.3157, 123.8854)))
    }

    @Test
    fun testNearestNodeSnapsAnOffRoadCoordinate() {
        val graph = network()
        val nearest = graph.nearestNode(GeoPoint(14.6003, 121.0048))
        assertTrue("a point beside the first leg must snap to node 0 or 1, got $nearest", nearest == 0 || nearest == 1)
    }

    @Test
    fun testSnapToRoadLandsOnTheSegmentNotOnANode() {
        val graph = network()
        val snapped = graph.snapToRoad(GeoPoint(14.60015, 121.0050))
        assertNotNull("a point 15 m off the road must snap onto it", snapped)
        nearlyEquals(14.6000, snapped!!.latitude, 1e-5, "snapping must move the point onto the road")
        nearlyEquals(121.0050, snapped.longitude, 1e-3, "the longitude along the segment must be kept")
    }

    @Test
    fun testSnapToRoadReturnsNullBeyondItsSearchRadius() {
        // 300 m north of the network: too far to pretend this is "on the road".
        assertNull(network().snapToRoad(GeoPoint(14.6027, 121.0050), maxDistanceMeters = 60.0))
    }

    @Test
    fun testDistanceToCoverageIsZeroInsideAndPositiveOutside() {
        val graph = network()
        assertEquals(0.0, graph.distanceToCoverage(GeoPoint(14.6010, 121.0050)), 0.0001)
        val outside = graph.distanceToCoverage(GeoPoint(14.6100, 121.0050))
        // 0.004° of latitude north of the 14.6060 boundary ≈ 444 m.
        nearlyEquals(444.0, outside, 20.0, "distance outside the pack must be reported in metres")
    }

    @Test
    fun testEstimatedSizeGrowsWithTheGraph() {
        val small = network().estimatedBytes()
        val bigger = network().toBytes().size.toLong()
        assertTrue("the estimator must be in the same order of magnitude as the real file", small > 0 && bigger > 0)
        assertTrue(
            "the estimator is an upper bound on the uncompressed layout, not a wild guess",
            small >= bigger * 0.5
        )
    }

    @Test
    fun testDescribeReportsRealRoadKilometresNotEdgeCounts() {
        val description = network().describe()
        assertTrue("names must be reported: $description", description.contains("2 road names"))
        assertTrue("nodes must be reported: $description", description.contains("3 nodes"))
        // 1 629 m of road stored in both directions must read 1.6 km, not "2 km".
        assertTrue("real road length must be reported: $description", description.contains("1.6 km of road"))
    }
}
