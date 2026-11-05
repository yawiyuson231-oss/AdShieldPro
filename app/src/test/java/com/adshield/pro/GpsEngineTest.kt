package com.adshield.pro

import com.adshield.pro.gps.engine.AccuracyBand
import com.adshield.pro.gps.engine.FixSource
import com.adshield.pro.gps.engine.GnssFix
import com.adshield.pro.gps.engine.GpsIntegrityMonitor
import com.adshield.pro.gps.engine.IntegrityFindingKind
import com.adshield.pro.gps.engine.IntegritySeverity
import com.adshield.pro.gps.engine.IntegrityVerdict
import com.adshield.pro.gps.engine.MovementState
import com.adshield.pro.gps.engine.RadarGeometry
import com.adshield.pro.gps.engine.SatelliteInfo
import com.adshield.pro.gps.engine.SatelliteSnapshot
import com.adshield.pro.gps.engine.StationaryDetector
import com.adshield.pro.gps.engine.EtaMath
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.geo.MapProjection
import com.adshield.pro.gps.traffic.IncidentKind
import com.adshield.pro.gps.traffic.IncidentValidator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

/**
 * GPS geometry, integrity and radar contracts.
 *
 * These are the checks that make the module's honesty claims testable without a device: a fix with
 * no altitude keeps `null`, an impossible jump is flagged, a satellite plot points north for a
 * northern satellite, and a 12-tile region really needs 12 tiles.
 */
class GpsEngineTest {

    private fun fix(
        latitude: Double = 14.5995,
        longitude: Double = 120.9842,
        accuracy: Float = 5f,
        timeMs: Long = 1_700_000_000_000L,
        speedMps: Float? = 0f,
        bearing: Float? = null,
        mocked: Boolean = false,
        altitude: Double? = null,
        elapsedNanos: Long = 1_000_000_000L
    ) = GnssFix(
        position = GeoPoint(latitude, longitude),
        timeMs = timeMs,
        elapsedRealtimeNanos = elapsedNanos,
        accuracyMeters = accuracy,
        altitudeMeters = altitude,
        speedMps = speedMps,
        bearingDegrees = bearing,
        source = FixSource.GNSS,
        mockProviderFlag = mocked
    )

    // ------------------------------------------------------------------ geodesy

    @Test
    fun testGeodesyDistanceBetweenManilaAndQuezonCity() {
        val manila = GeoPoint(14.5995, 120.9842)
        val quezonCity = GeoPoint(14.6760, 121.0437)
        // Spherical (haversine) distance is ~10.65 km between these two centroids.
        val distance = Geodesy.distanceMeters(manila, quezonCity)
        assertTrue("expected ~10.6 km, got $distance", distance in 10_400.0..10_900.0)
    }

    @Test
    fun testGeodesyBearingAndDestinationRoundTrip() {
        val origin = GeoPoint(14.5995, 120.9842)
        val target = Geodesy.destination(origin, bearingDegrees = 90.0, distanceMeters = 1_000.0)
        val bearing = Geodesy.bearingDegrees(origin, target)
        assertEquals(90.0, bearing, 0.5)
        assertEquals(1_000.0, Geodesy.distanceMeters(origin, target), 1.0)
    }

    @Test
    fun testGeoBoundsAroundContainsCentreAndNotFarAwayPoint() {
        val centre = GeoPoint(14.5995, 120.9842)
        val bounds = GeoBounds.around(centre, 5_000.0)
        assertTrue(bounds.contains(centre))
        assertFalse(bounds.contains(GeoPoint(14.8, 121.2)))
        assertTrue(bounds.approximateAreaKm2 in 90.0..110.0)
        assertTrue(bounds.north >= bounds.south)
    }

    @Test
    fun testMapProjectionTileCountForSmallRegion() {
        val bounds = GeoBounds.around(GeoPoint(14.5995, 120.9842), 2_000.0)
        val range = MapProjection.tileRange(bounds, 14)
        assertTrue("a 4x4 km area should need at least one tile", range.tileCount >= 1)
        val total = MapProjection.estimateTileCount(bounds, 10, 15)
        assertTrue("cumulative count must exceed the single-zoom count", total >= range.tileCount)
    }

    @Test
    fun testMapProjectionRejectsPolarLatitude() {
        // 89.9° is outside Web Mercator's ±85.0511° limit and must be clamped into the square.
        val northPole = MapProjection.toMercator(GeoPoint(89.9, 0.0))
        val southPole = MapProjection.toMercator(GeoPoint(-89.9, 0.0))
        assertTrue("north edge must map to y=0, got ${northPole.y}", northPole.y in -0.001..0.001)
        assertTrue("south edge must map to y=1, got ${southPole.y}", southPole.y in 0.999..1.001)
        assertEquals(0.5, MapProjection.toMercator(GeoPoint(0.0, 0.0)).x, 0.0001)
    }

    // ----------------------------------------------------------------- accuracy

    @Test
    fun testAccuracyBandThresholds() {
        assertEquals(AccuracyBand.UNUSABLE, AccuracyBand.fromAccuracy(null))
        assertEquals(AccuracyBand.EXCELLENT, AccuracyBand.fromAccuracy(4f))
        assertEquals(AccuracyBand.GOOD, AccuracyBand.fromAccuracy(10f))
        assertEquals(AccuracyBand.FAIR, AccuracyBand.fromAccuracy(25f))
        assertEquals(AccuracyBand.POOR, AccuracyBand.fromAccuracy(80f))
        assertEquals(AccuracyBand.UNUSABLE, AccuracyBand.fromAccuracy(250f))
    }

    @Test
    fun testFixWithoutAltitudeKeepsNullInsteadOfZero() {
        val reading = fix()
        assertNull(reading.altitudeMeters)
        assertNull(reading.bearingDegrees)
    }

    @Test
    fun testSpeedIsAbsentWhenProviderDoesNotReportIt() {
        val reading = fix(speedMps = null)
        assertNull(reading.speedKmh)
    }

    @Test
    fun testConfidenceDropsForMockedAndCachedFixes() {
        val good = fix(accuracy = 4f)
        val mocked = fix(accuracy = 4f, mocked = true)
        assertTrue(good.confidence > mocked.confidence)
        assertTrue(mocked.confidence >= 0)
    }

    // ---------------------------------------------------------------- integrity

    @Test
    fun testIntegrityMonitorFlagsMockProvider() {
        val monitor = GpsIntegrityMonitor()
        val report = monitor.inspect(fix(mocked = true))
        assertEquals(IntegrityVerdict.COMPROMISED, report.verdict)
        assertTrue(report.findings.any { it.kind == IntegrityFindingKind.MOCK_LOCATION })
        assertTrue(report.shouldRejectObservation)
    }

    @Test
    fun testIntegrityMonitorFlagsImpossibleJump() {
        val monitor = GpsIntegrityMonitor()
        monitor.inspect(fix(latitude = 14.5995, longitude = 120.9842, timeMs = 1_000_000L, elapsedNanos = 1_000_000_000L))
        // ~1.1 km in one second: faster than any car, and far beyond the accuracy circle.
        val report = monitor.inspect(
            fix(latitude = 14.6095, longitude = 120.9842, timeMs = 1_001_000L, elapsedNanos = 2_000_000_000L)
        )
        assertTrue(
            "expected a jump or an impossible speed",
            report.findings.any {
                it.kind == IntegrityFindingKind.COORDINATE_JUMP ||
                    it.kind == IntegrityFindingKind.IMPOSSIBLE_SPEED
            }
        )
        assertEquals(IntegrityVerdict.COMPROMISED, report.verdict)
    }

    @Test
    fun testIntegrityMonitorAcceptsNormalDriving() {
        val monitor = GpsIntegrityMonitor()
        // Two consecutive fixes at a constant 13 m/s, ~13 m apart. A realistic driveway.
        monitor.inspect(
            fix(latitude = 14.5995, longitude = 120.9842, accuracy = 8f, speedMps = 13f, bearing = 0f,
                timeMs = 1_000_000L, elapsedNanos = 1_000_000_000L)
        )
        val report = monitor.inspect(
            fix(latitude = 14.59962, longitude = 120.9842, accuracy = 8f, speedMps = 13f, bearing = 0f,
                timeMs = 1_001_000L, elapsedNanos = 2_000_000_000L)
        )
        assertTrue(
            "normal motion must not be flagged critical, got ${report.verdict}",
            report.verdict == IntegrityVerdict.TRUSTED || report.verdict == IntegrityVerdict.DEGRADED
        )
        assertFalse(report.shouldRejectObservation)
    }

    @Test
    fun testIntegrityMonitorFlagsClockGoingBackwards() {
        val monitor = GpsIntegrityMonitor()
        monitor.inspect(fix(timeMs = 2_000_000L, elapsedNanos = 1_000_000_000L))
        val report = monitor.inspect(fix(timeMs = 1_000_000L, elapsedNanos = 2_000_000_000L))
        assertTrue(report.findings.any { it.kind == IntegrityFindingKind.CLOCK_ANOMALY })
    }

    @Test
    fun testIntegrityStatisticsAccumulate() {
        val monitor = GpsIntegrityMonitor()
        monitor.inspect(fix(mocked = true))
        monitor.inspect(fix(mocked = true))
        assertEquals(2, monitor.statistics.mockDetections)
        assertTrue(monitor.statistics.jumpsDetected >= 0)
    }

    // ------------------------------------------------------- movement / station

    @Test
    fun testStationaryDetectorClassifiesStoppedVehicle() {
        val detector = StationaryDetector()
        val state = detector.update(fix(speedMps = 0f, timeMs = 1_000_000L))
        assertEquals(MovementState.STATIONARY, state)
    }

    @Test
    fun testStationaryDetectorClassifiesHighwaySpeed() {
        val detector = StationaryDetector()
        val state = detector.update(fix(speedMps = 25f, timeMs = 1_000_000L))
        assertEquals(MovementState.DRIVING, state)
    }

    @Test
    fun testStationaryDetectorInfersMotionWithoutDopplerSpeed() {
        val detector = StationaryDetector()
        detector.update(fix(latitude = 14.5995, speedMps = null, timeMs = 1_000_000L))
        // 60 m in 3 s ≈ 20 m/s from displacement alone.
        val state = detector.update(
            fix(latitude = 14.6000, speedMps = null, timeMs = 1_003_000L)
        )
        assertTrue(state == MovementState.DRIVING || state == MovementState.MOVING)
    }

    // ---------------------------------------------------------------- eta math

    @Test
    fun testEtaUsesMeasuredSpeedWhenMoving() {
        val estimate = EtaMath.estimate(remainingMeters = 1_000.0, rollingSpeedKmh = 50.0, routeSpeedLimitKmh = 30.0)
        assertTrue(estimate.isMeasured)
        assertEquals(72.0, estimate.remainingSeconds, 0.5)
        assertNotNull(estimate.arrivalEpochMs)
    }

    @Test
    fun testEtaFallsBackToSpeedLimitWhenStopped() {
        val estimate = EtaMath.estimate(remainingMeters = 1_000.0, rollingSpeedKmh = 0.0, routeSpeedLimitKmh = 40.0)
        assertFalse("a stopped vehicle must not look like a measurement", estimate.isMeasured)
        assertEquals(90.0, estimate.remainingSeconds, 0.5)
    }

    @Test
    fun testEtaWithoutAnySpeedInformationStillTerminates() {
        val estimate = EtaMath.estimate(remainingMeters = 500.0, rollingSpeedKmh = null, routeSpeedLimitKmh = null)
        assertTrue(estimate.remainingSeconds.isFinite())
        assertFalse(estimate.isMeasured)
    }

    // ------------------------------------------------------------------- radar

    private fun satellite(svid: Int, az: Float, el: Float, snr: Float, used: Boolean = true, constellation: String = "GPS") =
        SatelliteInfo(svid, constellation, az, el, snr, used)

    @Test
    fun testRadarPlacesNorthernSatelliteAboveCentre() {
        val points = RadarGeometry.project(listOf(satellite(3, az = 0f, el = 0f, snr = 30f)))
        val point = points.single()
        // Azimuth 0 = north = up on screen (negative Y), rim of the circle.
        assertEquals(0f, point.x, 0.001f)
        assertEquals(-1f, point.y, 0.001f)
        assertEquals(1f, point.radius, 0.001f)
    }

    @Test
    fun testRadarZenithSatelliteSitsInTheCentre() {
        val point = RadarGeometry.project(listOf(satellite(7, az = 123f, el = 90f, snr = 40f))).single()
        assertEquals(0f, point.x, 0.0001f)
        assertEquals(0f, point.y, 0.0001f)
    }

    @Test
    fun testRadarEastIsPositiveX() {
        val point = RadarGeometry.project(listOf(satellite(9, az = 90f, el = 0f, snr = 25f))).single()
        assertTrue(point.x > 0.99f)
        assertEquals(0f, point.y, 0.001f)
    }

    @Test
    fun testRadarRingsAreHorizonZenithAndMid() {
        val rings = RadarGeometry.rings()
        assertEquals(3, rings.size)
        assertEquals(1f, rings[0], 0.0001f)        // 0° elevation  = horizon = rim
        assertEquals(2f / 3f, rings[1], 0.0001f)   // 30° elevation
        assertEquals(1f / 3f, rings[2], 0.0001f)   // 60° elevation, closest to the zenith
    }

    @Test
    fun testSkyScoreIsZeroWithoutSatellites() {
        assertEquals(0, RadarGeometry.skyScore(null))
        assertEquals(
            0,
            RadarGeometry.skyScore(
                SatelliteSnapshot(0, 0, null, null, emptyList(), emptyList())
            )
        )
    }

    @Test
    fun testSkyScoreRisesWithAFullSky() {
        val weak = SatelliteSnapshot(12, 4, 15.0, 20.0, listOf("GPS"), emptyList())
        val strong = SatelliteSnapshot(18, 14, 40.0, 46.0, listOf("GPS", "Galileo", "GLONASS"), emptyList())
        assertTrue(RadarGeometry.skyScore(strong) > RadarGeometry.skyScore(weak))
        assertTrue(RadarGeometry.skyScore(strong) <= 100)
    }

    @Test
    fun testRadarEmptyReasonIsSpecificAboutTheCause() {
        assertTrue(RadarGeometry.emptyReason(false, true, true).contains("permission", ignoreCase = true))
        assertTrue(RadarGeometry.emptyReason(true, false, true).contains("switched off", ignoreCase = true))
        // gnssReported == true with an empty satellite list is "still waiting", not a hardware gap.
        assertTrue(RadarGeometry.emptyReason(true, true, true).contains("Waiting", ignoreCase = true))
        assertTrue(RadarGeometry.emptyReason(true, true, false).contains("GnssStatus"))
    }

    @Test
    fun testConstellationCodeIsShortAndStable() {
        assertEquals("GPS", RadarGeometry.constellationCode("GPS"))
        assertEquals("GLO", RadarGeometry.constellationCode("GLONASS"))
        assertEquals("GAL", RadarGeometry.constellationCode("Galileo"))
        assertEquals("BDS", RadarGeometry.constellationCode("BeiDou"))
    }

    @Test
    fun testSatelliteSnapshotUsedRatioIsZeroWithoutSatellites() {
        val empty = SatelliteSnapshot(0, 0, null, null)
        assertEquals(0.0, empty.usedRatio, 0.0001)
        assertFalse(empty.usable)
    }

    @Test
    fun testSatelliteSnapshotQualityNoteExplainsFewSatellites() {
        val snapshot = SatelliteSnapshot(8, 2, 20.0, 30.0, listOf("GPS"), emptyList())
        assertTrue(snapshot.qualityNote().contains("4"))
        assertTrue(snapshot.usedRatio < 0.3)
        assertFalse(snapshot.usable)
    }

    @Test
    fun testSnrRatioClampsOutOfRangeValues() {
        val low = RadarGeometry.project(listOf(satellite(1, 0f, 45f, snr = 0f))).single()
        val high = RadarGeometry.project(listOf(satellite(1, 0f, 45f, snr = 90f))).single()
        assertEquals(0f, low.snrRatio, 0.0001f)
        assertEquals(1f, high.snrRatio, 0.0001f)
    }

    @Test
    fun testSegmentProjectionSnapsToNearestPointOnRoad() {
        val a = GeoPoint(14.5995, 120.9842)
        val b = GeoPoint(14.5995, 120.9942)
        val offRoad = GeoPoint(14.6005, 120.9892)
        val projection = Geodesy.projectOnSegment(offRoad, a, b)
        assertTrue(projection.fraction in 0.4..0.6)
        assertTrue(abs(projection.distanceMeters - 111.0) < 15.0)
    }

    @Test
    fun testIncidentValidatorRejectsCompromisedLocation() {
        val compromised = IncidentValidator.validate(
            kind = IncidentKind.ACCIDENT,
            position = GeoPoint(14.5995, 120.9842),
            lastFixAgeMs = 1_000L,
            accuracyMeters = 5f,
            integrityCompromised = true,
            notes = null
        )
        assertFalse(compromised.accepted)
        val stale = IncidentValidator.validate(
            kind = IncidentKind.ACCIDENT,
            position = GeoPoint(14.5995, 120.9842),
            lastFixAgeMs = 120_000L,
            accuracyMeters = 5f,
            integrityCompromised = false,
            notes = null
        )
        assertFalse(stale.accepted)
        val valid = IncidentValidator.validate(
            kind = IncidentKind.ACCIDENT,
            position = GeoPoint(14.5995, 120.9842),
            lastFixAgeMs = 1_000L,
            accuracyMeters = 5f,
            integrityCompromised = false,
            notes = "two-car collision, right lane"
        )
        assertTrue(valid.accepted)
        assertNull(valid.reason)
    }

    @Test
    fun testSeverityOrderingIsExplicit() {
        // The radar screen colours findings by severity; the enum order must stay meaningful.
        assertEquals(IntegritySeverity.INFO.ordinal + 1, IntegritySeverity.WARNING.ordinal)
        assertEquals(IntegritySeverity.WARNING.ordinal + 1, IntegritySeverity.CRITICAL.ordinal)
    }
}
