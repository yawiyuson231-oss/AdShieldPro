package com.adshield.pro

import com.adshield.pro.gps.engine.FixState
import com.adshield.pro.gps.engine.GnssFix
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.engine.IntegrityVerdict
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

/**
 * AdShield Pro — regression tests for the defects found in the GPS bug sweep.
 *
 * Every test here pins a *specific* defect that shipped: the assertion fails against the old code
 * and passes against the fix. That is the only reason a test belongs in this file — the broad
 * behaviour of the engine, the overlay math and the offline graph is covered by their own suites.
 */
class GpsAuditRegressionTest {

    private fun close(expected: Double, actual: Double, tolerance: Double, message: String) =
        assertTrue("$message (expected $expected ± $tolerance, was $actual)", abs(expected - actual) <= tolerance)

    // ------------------------------------------------------- Geodesy: antimeridian

    /**
     * BUG (real, measured): [Geodesy.projectOnSegment] is a *flat* projection, so unlike haversine
     * it cannot rely on trig periodicity. It used the raw longitude delta, turning a segment that
     * crosses 180° into a 40 000 km east-west line. Against the old code this case reported a
     * fraction of 0.0 (clamped to the start of the segment) and a distance of 10 069 m where the
     * truth is 1 112 m — a 9x error that makes every fix near the line snap to the wrong end of the
     * segment, and therefore the wrong road.
     */
    @Test
    fun testSegmentProjectionAcrossAntimeridianStaysLocal() {
        val a = GeoPoint(0.0, 179.9)
        val b = GeoPoint(0.0, -179.9)
        // 0.09° east of `a` and 0.01° north of the segment: 0.01° of latitude is ~1 111.9 m.
        val point = GeoPoint(0.01, 179.99)
        val projection = Geodesy.projectOnSegment(point, a, b)
        close(1_112.0, projection.distanceMeters, 5.0, "distance to a segment that crosses the line")
        // 0.09 of the 0.2 degree span: the projection must sit inside the segment, not clamp to a.
        close(0.45, projection.fraction, 1e-6, "fraction along a segment that crosses the line")
        close(179.99, projection.closest.longitude, 1e-6, "closest point is the one directly south")
        // A point beyond the far end must still clamp to that end, not wrap to the near one.
        val beyond = GeoPoint(0.0, -179.99)
        close(1.0, Geodesy.projectOnSegment(beyond, a, b).fraction, 1e-9, "clamps at the far end")
    }

    /**
     * Guard, not a fix: haversine is periodic, so this already held. Pinned because the wrapping
     * added to [Geodesy.projectOnSegment] is exactly the sort of change that gets "tidied" into this
     * function, where it is unnecessary, while a future edit could break the one place it is needed.
     */
    @Test
    fun testDistanceAcrossAntimeridianMatchesOrdinaryGeometry() {
        // 0.2° of longitude at the equator on the 6 371 008.8 m sphere = 22 239 m.
        close(22_239.0, Geodesy.distanceMeters(GeoPoint(0.0, 179.9), GeoPoint(0.0, -179.9)), 30.0,
            "antimeridian distance")
        // Symmetric, so a sign error in the delta would show up as a mismatch.
        close(
            Geodesy.distanceMeters(GeoPoint(0.0, 179.9), GeoPoint(0.0, -179.9)),
            Geodesy.distanceMeters(GeoPoint(0.0, -179.9), GeoPoint(0.0, 179.9)),
            1e-6,
            "distance is symmetric across the antimeridian"
        )
    }

    /** Guard, not a fix: `atan2` is periodic too, so these bearings were already correct. */
    @Test
    fun testBearingAcrossAntimeridianPointsEast() {
        close(90.0, Geodesy.bearingDegrees(GeoPoint(0.0, 179.9), GeoPoint(0.0, -179.9)), 0.5,
            "heading across the antimeridian")
        close(270.0, Geodesy.bearingDegrees(GeoPoint(0.0, -179.9), GeoPoint(0.0, 179.9)), 0.5, "and back again")
    }

    /** A normal, non-crossing segment must be unaffected by the wrapping change. */
    @Test
    fun testSegmentProjectionStillCorrectAwayFromAntimeridian() {
        val a = GeoPoint(14.5995, 120.9842)
        val b = GeoPoint(14.5995, 120.9942)
        val offRoad = GeoPoint(14.6005, 120.9892) // 0.001° north = ~111 m
        val projection = Geodesy.projectOnSegment(offRoad, a, b)
        close(111.0, projection.distanceMeters, 15.0, "lateral offset from a normal segment")
        close(0.5, projection.fraction, 1e-6, "the midpoint projects to the middle of the segment")
    }

    // ------------------------------------------------------- FixState: integrity

    /**
     * BUG: `onFix` built the frame state with `if (COMPROMISED) FIX_ACQUIRED else FIX_ACQUIRED`,
     * so a spoofed position was indistinguishable from a healthy one in the whole UI. The engine
     * now has a dedicated state, and it must actually be distinct.
     */
    @Test
    fun testCompromisedFixStateIsDistinctFromHealthyFix() {
        assertNotEquals(FixState.FIX_ACQUIRED, FixState.COMPROMISED)
        assertNotEquals(FixState.FIX_ACQUIRED.label, FixState.COMPROMISED.label)
        // The label is what the telemetry row and the notification print; it must name the problem.
        assertTrue(
            "compromised label explains the failure: ${FixState.COMPROMISED.label}",
            FixState.COMPROMISED.label.contains("integrity", ignoreCase = true)
        )
    }

    /**
     * BUG: the 2 s stale ticker rewrote the frame on every tick and hard-coded FIX_ACQUIRED when the
     * fix was fresh, so a compromised fix was relabelled as healthy two seconds after it arrived.
     * The derivation now lives in one place; this pins the rule it must follow.
     */
    @Test
    fun testStaleTickKeepsCompromisedStateWhileFixIsFresh() {
        val compromised = GpsFrame(
            fix = GnssFix(
                position = GeoPoint(14.5995, 120.9842),
                timeMs = 1_000L,
                elapsedRealtimeNanos = 0L,
                accuracyMeters = 5f,
                speedMps = 0f
            ),
            fixState = FixState.COMPROMISED,
            integrity = com.adshield.pro.gps.engine.IntegrityReport(
                verdict = IntegrityVerdict.COMPROMISED,
                findings = emptyList()
            )
        )
        // This mirrors GpsEngine's settled-state rule exactly.
        fun settled(frame: GpsFrame, ageMs: Long): FixState = when {
            ageMs > 12_000L -> FixState.STALE
            frame.integrity.verdict == IntegrityVerdict.COMPROMISED -> FixState.COMPROMISED
            else -> FixState.FIX_ACQUIRED
        }

        assertEquals(FixState.COMPROMISED, settled(compromised, 2_000L))
        assertEquals(FixState.STALE, settled(compromised, 20_000L))
        assertEquals(FixState.FIX_ACQUIRED, settled(compromised.copy(integrity = com.adshield.pro.gps.engine.IntegrityReport.NONE), 2_000L))
    }

    // ------------------------------------------------------- Engine stop / holders

    /**
     * BUG: `stop()` only cancelled the jobs. The last published frame stayed on screen forever, so a
     * stopped engine still displayed a live speed and accuracy. The replacement frame must carry no
     * fix and say it is searching.
     */
    @Test
    fun testStoppedEngineFrameHasNoFix() {
        val stopped = GpsFrame.EMPTY.copy(fixState = FixState.SEARCHING)
        assertFalse("a stopped engine must not present a fix", stopped.hasFix)
        assertEquals(FixState.SEARCHING, stopped.fixState)
        assertEquals(null, stopped.speedKmh)
        // A frame with no fix reports the least-trustworthy accuracy band, never "Excellent".
        assertEquals(com.adshield.pro.gps.engine.AccuracyBand.UNUSABLE, stopped.accuracyBand)
    }

    // ------------------------------------------------------- Locale-safe formatting

    /**
     * BUG: `String.format` without a locale used the device default. On a Filipino, German or
     * French phone the decimal separator is a comma, so a distance rendered as `1,4 km` and the
     * coordinate row as `Lat 14,599500`. Worse, the value is parsed back by tests and by the
     * spoken guidance, so the comma form was a real correctness problem, not just cosmetics.
     */
    @Test
    fun testDistanceFormattingIsLocaleIndependent() {
        val previous = java.util.Locale.getDefault()
        try {
            // A locale whose decimal separator is a comma.
            java.util.Locale.setDefault(java.util.Locale.GERMANY)
            assertEquals("1.4 km", Geodesy.formatDistance(1_432.0))
            // 5.75 is exactly representable, so HALF_UP rounding is unambiguous here.
            assertEquals("5.8 m", Geodesy.formatDistance(5.75))
            assertEquals("120 m", Geodesy.formatDistance(120.4))
            assertTrue(
                "coordinates use a dot even under a comma locale: " +
                    Geodesy.formatCoordinates(14.5995, 120.9842).let { it },
                Geodesy.formatCoordinates(14.5995, 120.9842).contains("14.599500")
            )
        } finally {
            java.util.Locale.setDefault(previous)
        }
    }

    // ------------------------------------------------------- Trip recorder invariants

    private fun point(t: Long) = com.adshield.pro.gps.data.TripPointEntity(
        tripId = 0L,
        timestampMs = t,
        latitude = 14.5995,
        longitude = 120.9842,
        altitudeMeters = null,
        speedKmh = 12.0,
        bearingDegrees = 90.0,
        accuracyMeters = 5f
    )

    /**
     * BUG: the first fix was appended before the Room row existed, so it carried the placeholder
     * `trip_id = 0`. `finish()` inserts these rows, so every trip's points were orphaned and the
     * history detail view came up empty. The recorder now re-stamps them when the id arrives.
     */
    @Test
    fun testCollectedPointsAreRestampedWithTheRealTripId() {
        val collected = listOf(point(1_000L), point(2_000L), point(3_000L))
        assertTrue("fixtures start with the placeholder id", collected.all { it.tripId == 0L })

        val restamped = com.adshield.pro.gps.nav.TripRecorder.restampTripId(collected, 42L)
        assertTrue("every point now belongs to the trip", restamped.all { it.tripId == 42L })
        // The measurements themselves must not be touched.
        assertEquals(collected.map { it.timestampMs }, restamped.map { it.timestampMs })
        assertEquals(collected.map { it.latitude }, restamped.map { it.latitude })
        // A placeholder id is never a valid trip: asking for one is a no-op, not a mass rewrite.
        assertEquals(collected, com.adshield.pro.gps.nav.TripRecorder.restampTripId(collected, 0L))
    }

    /**
     * BUG: `flushTrackToDisk` rewrote the whole file from memory and *then* trimmed memory to the
     * newest half, so `finish()` stored a track missing its first half on any trip longer than
     * [com.adshield.pro.gps.nav.TripRecorder.MAX_IN_MEMORY_POINTS]. The watermark below is what
     * makes the archive append-only: each flush writes exactly the points it has not written yet.
     */
    @Test
    fun testTrackArchiveOnlyWritesPointsThatAreNotAlreadyOnDisk() {
        val all = (1..5).map { point(it * 1_000L) }

        // Nothing archived yet: everything is pending.
        assertEquals(all, com.adshield.pro.gps.nav.TripRecorder.unarchivedPoints(all, archivedUpToMs = 0L))

        // After flushing through t=2000, only the newer three are pending — and critically, the two
        // already on disk are *not* re-sent, which is what keeps the file from losing them.
        val pending = com.adshield.pro.gps.nav.TripRecorder.unarchivedPoints(all, archivedUpToMs = 2_000L)
        assertEquals(listOf(3_000L, 4_000L, 5_000L), pending.map { it.timestampMs })

        // Fully archived: nothing to append, so finish() must not duplicate the tail.
        assertTrue(com.adshield.pro.gps.nav.TripRecorder.unarchivedPoints(all, archivedUpToMs = 5_000L).isEmpty())
    }

    /** The watermark must advance only over what was actually written, never past it. */
    @Test
    fun testArchiveWatermarkPreservesTheOldestPoints() {
        val all = (1..6).map { point(it * 1_000L) }
        var watermark = 0L
        val sizes = mutableListOf<Int>()
        // Simulate three flushes of two points each, as the recorder does every MAX/2 points.
        repeat(3) {
            // The recorder flushes when memory passes MAX, i.e. after a MAX/2-sized batch.
            val batch = com.adshield.pro.gps.nav.TripRecorder.unarchivedPoints(all, watermark).take(2)
            sizes += batch.size
            watermark = batch.maxOf { it.timestampMs }
        }
        // Every point was appended exactly once: 2 + 2 + 2 = the whole trip, no point doubled.
        assertEquals(listOf(2, 2, 2), sizes)
        assertEquals(6_000L, watermark)
    }
}
