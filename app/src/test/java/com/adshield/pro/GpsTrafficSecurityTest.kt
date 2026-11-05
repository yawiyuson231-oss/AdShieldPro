package com.adshield.pro

import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.offline.OfflinePlanner
import com.adshield.pro.gps.security.EmergencyShareBuilder
import com.adshield.pro.gps.security.HistoryGuard
import com.adshield.pro.gps.security.LocationPrivacyPolicy
import com.adshield.pro.gps.security.PermissionAudit
import com.adshield.pro.gps.security.TelemetryGate
import com.adshield.pro.gps.traffic.CongestionLevel
import com.adshield.pro.gps.traffic.IncidentDeduplicator
import com.adshield.pro.gps.traffic.IncidentKind
import com.adshield.pro.gps.traffic.IncidentValidator
import com.adshield.pro.gps.traffic.RoadSegment
import com.adshield.pro.gps.traffic.SpeedObservation
import com.adshield.pro.gps.traffic.TokenBucketRateLimiter
import com.adshield.pro.gps.traffic.TrafficAggregator
import com.adshield.pro.gps.traffic.TrafficColours
import com.adshield.pro.gps.traffic.TrafficIncident
import com.adshield.pro.gps.traffic.formatAge
import com.adshield.pro.gps.traffic.formatConfidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Traffic honesty, privacy defaults and offline budget contracts.
 *
 * The point of these tests is the negative space: a segment with no observations must be UNKNOWN
 * (never FREE_FLOW), a kill-switched policy must refuse to build an emergency link, and a download
 * request above the free server's published limits must be rejected *before* any network call.
 */
class GpsTrafficSecurityTest {

    private fun segment(
        id: String = "seg-1",
        limit: Double? = 60.0,
        startLat: Double = 14.5995,
        endLat: Double = 14.6095
    ) = RoadSegment(
        id = id,
        name = "Test Avenue",
        start = GeoPoint(startLat, 120.9842),
        end = GeoPoint(endLat, 120.9842),
        speedLimitKmh = limit
    )

    private fun observation(speed: Double, ageMinutes: Long = 1L, token: String = "tok-a", segmentId: String = "seg-1") =
        SpeedObservation(
            segmentId = segmentId,
            speedKmh = speed,
            timestampMs = System.currentTimeMillis() - ageMinutes * 60_000L,
            accuracyMeters = 8f,
            headingDegrees = 0.0,
            reporterToken = token
        )

    // ---------------------------------------------------------------- honesty

    @Test
    fun testSegmentWithNoObservationsIsUnknownNotGreen() {
        val aggregate = TrafficAggregator.aggregate(segment(), emptyList())
        assertEquals(CongestionLevel.UNKNOWN, aggregate.level)
        assertNull(aggregate.averageSpeedKmh)
        assertEquals(0, aggregate.sampleCount)
        assertEquals(0.0, aggregate.confidence, 0.0001)
        assertEquals(TrafficColours.GREY, TrafficColours.hexFor(CongestionLevel.UNKNOWN))
    }

    @Test
    fun testSingleNoisySampleStaysUnknownBecauseConfidenceIsTooLow() {
        // One sample very close to free-flow would classify as FREE_FLOW, but confidence must keep
        // UNKNOWN until enough evidence exists.
        val aggregate = TrafficAggregator.aggregate(segment(), listOf(observation(speed = 58.0)))
        assertTrue(aggregate.confidence < TrafficAggregator.MIN_CONFIDENCE_FOR_LEVEL)
        assertEquals(CongestionLevel.UNKNOWN, aggregate.level)
        assertNotNull("the measured speed may still be shown", aggregate.averageSpeedKmh)
    }

    @Test
    fun testFreeFlowingTrafficIsGreenWithEnoughSamples() {
        val observations = (0 until 6).map { observation(speed = 58.0, token = "tok-$it") }
        val aggregate = TrafficAggregator.aggregate(segment(), observations)
        assertEquals(CongestionLevel.FREE_FLOW, aggregate.level)
        assertTrue(aggregate.confidence >= TrafficAggregator.MIN_CONFIDENCE_FOR_LEVEL)
        assertEquals(TrafficColours.GREEN, TrafficColours.hexFor(CongestionLevel.FREE_FLOW))
    }

    @Test
    fun testStandstillTrafficIsRed() {
        val observations = (0 until 6).map { observation(speed = 4.0, token = "tok-$it") }
        val aggregate = TrafficAggregator.aggregate(segment(), observations)
        assertEquals(CongestionLevel.STANDSTILL, aggregate.level)
        assertEquals(TrafficColours.DEEP_RED, TrafficColours.hexFor(CongestionLevel.STANDSTILL))
    }

    @Test
    fun testObservationsOutsideTheWindowAreIgnored() {
        val observations = (0 until 6).map { observation(speed = 70.0, ageMinutes = 120L, token = "tok-$it") }
        val aggregate = TrafficAggregator.aggregate(segment(), observations)
        assertEquals(CongestionLevel.UNKNOWN, aggregate.level)
        assertEquals(0, aggregate.sampleCount)
    }

    @Test
    fun testObservationsForAnotherSegmentAreIgnored() {
        val observations = (0 until 6).map { observation(speed = 10.0, token = "tok-$it", segmentId = "other") }
        assertEquals(CongestionLevel.UNKNOWN, TrafficAggregator.aggregate(segment(), observations).level)
    }

    @Test
    fun testConfidenceDecaysWithAge() {
        val fresh = TrafficAggregator.confidence(6, 3, 0.0, listOf(50.0, 51.0, 49.0))
        val old = TrafficAggregator.confidence(6, 3, 40.0, listOf(50.0, 51.0, 49.0))
        assertTrue(old < fresh)
    }

    @Test
    fun testAgreementFactorPunishesScatteredSpeeds() {
        val tight = TrafficAggregator.agreementFactor(listOf(50.0, 51.0, 49.0))
        val scattered = TrafficAggregator.agreementFactor(listOf(5.0, 50.0, 120.0))
        assertTrue(scattered < tight)
    }

    @Test
    fun testFreeFlowUsesPostedLimitThenEightyFifthPercentile() {
        assertEquals(60.0, TrafficAggregator.freeFlowSpeed(segment(limit = 60.0)), 0.001)
        val noLimit = segment(limit = null)
        assertEquals(TrafficAggregator.DEFAULT_FREE_FLOW_KMH, TrafficAggregator.freeFlowSpeed(noLimit), 0.001)
        val historical = listOf(30.0, 40.0, 42.0, 45.0, 48.0, 55.0)
        val derived = TrafficAggregator.freeFlowSpeed(noLimit, historical)
        assertTrue("85th percentile of real traffic, got $derived", derived in 48.0..56.0)
    }

    // ------------------------------------------------------------ rate limiting

    @Test
    fun testTokenBucketStopsBurstBeyondCapacity() {
        val limiter = TokenBucketRateLimiter(capacity = 3, refillPerMinute = 3)
        assertTrue(limiter.tryAcquire())
        assertTrue(limiter.tryAcquire())
        assertTrue(limiter.tryAcquire())
        assertFalse("fourth call in the same instant must fail", limiter.tryAcquire())
    }

    // --------------------------------------------------------- deduplication

    @Test
    fun testDuplicateIncidentIsRejectedAndNearbyOneIsMerged() {
        val deduplicator = IncidentDeduplicator()
        val now = System.currentTimeMillis()
        val base = TrafficIncident(
            id = "i-1",
            kind = IncidentKind.ACCIDENT,
            position = GeoPoint(14.5995, 120.9842),
            roadName = "Test Avenue",
            segmentId = "seg-1",
            reportedAtMs = now,
            expiresAtMs = now + 60 * 60_000L,
            reporterToken = "tok-a"
        )
        deduplicator.record(base)
        val sameSpot = deduplicator.evaluate(IncidentKind.ACCIDENT, base.position, "tok-b", listOf(base))
        assertTrue("same type on the same spot should merge", sameSpot.confirmation || !sameSpot.accepted)
        val farAway = deduplicator.evaluate(
            IncidentKind.ACCIDENT,
            GeoPoint(14.7000, 121.1000),
            "tok-b",
            listOf(base)
        )
        assertTrue(farAway.accepted)
    }

    // ------------------------------------------------------- telemetry gate

    @Test
    fun testTelemetryGateBlocksEverythingWhenSharingIsOff() {
        val decision = TelemetryGate.evaluate(
            policy = LocationPrivacyPolicy(),  // defaults: contributeTraffic = false
            integrityCompromised = false,
            mockFlagged = false,
            accuracyMeters = 5f,
            speedKmh = 60.0,
            segmentId = "seg-1",
            alreadySentSegment = false
        )
        assertFalse(decision.allowed)
    }

    @Test
    fun testTelemetryGateBlocksMockAndPoorAccuracy() {
        val optedIn = LocationPrivacyPolicy(contributeTraffic = true)
        val mock = TelemetryGate.evaluate(optedIn, true, false, 5f, 60.0, "seg-1", false)
        assertFalse(mock.allowed)
        val poorAccuracy = TelemetryGate.evaluate(optedIn, false, false, 120f, 60.0, "seg-1", false)
        assertFalse(poorAccuracy.allowed)
        val stationary = TelemetryGate.evaluate(optedIn, false, false, 5f, 1.0, "seg-1", false)
        assertFalse(stationary.allowed)
        val noSegment = TelemetryGate.evaluate(optedIn, false, false, 5f, 60.0, null, false)
        assertFalse(noSegment.allowed)
        val good = TelemetryGate.evaluate(optedIn, false, false, 5f, 60.0, "seg-1", false)
        assertTrue(good.allowed)
    }

    // ----------------------------------------------------------- privacy policy

    @Test
    fun testPrivacyDefaultsAreAllOff() {
        val policy = LocationPrivacyPolicy()
        assertFalse(policy.contributeTraffic)
        assertFalse(policy.recordTripHistory)
        assertFalse(policy.allowEmergencySharing)
        assertFalse(policy.allowIncidentReporting)
        assertTrue("coarse history is the safe default", policy.coarseHistoryOnly)
        assertFalse(policy.canShareEmergencyLocation)
    }

    @Test
    fun testKillSwitchOverridesEmergencyAllowance() {
        val allowed = LocationPrivacyPolicy(allowEmergencySharing = true)
        assertTrue(allowed.canShareEmergencyLocation)
        val killed = allowed.withEmergencyKillSwitch(true)
        assertFalse(killed.canShareEmergencyLocation)
        assertFalse(killed.allowEmergencySharing)
    }

    @Test
    fun testEmergencyShareRefusesWithoutPermission() {
        val refused = EmergencyShareBuilder.build(
            position = GeoPoint(14.5995, 120.9842),
            accuracyMeters = 5f,
            policy = LocationPrivacyPolicy()
        )
        assertTrue(refused.isFailure)
        val blocked = EmergencyShareBuilder.build(
            position = GeoPoint(14.5995, 120.9842),
            accuracyMeters = 5f,
            policy = LocationPrivacyPolicy(allowEmergencySharing = true, emergencySharingDisabled = true)
        )
        assertTrue(blocked.isFailure)
    }

    @Test
    fun testEmergencyShareContainsRealCoordinatesAndFreeMapLink() {
        val result = EmergencyShareBuilder.build(
            position = GeoPoint(14.5995, 120.9842),
            accuracyMeters = 6f,
            policy = LocationPrivacyPolicy(allowEmergencySharing = true),
            label = "Test share"
        )
        val payload = result.getOrNull()
        assertNotNull(payload)
        val text = payload!!.text
        assertTrue(text.contains("14.599"))
        assertTrue(text.contains("120.984"))
        assertTrue(text.contains("openstreetmap.org"))
        assertTrue("accuracy should be stated", text.contains("6"))
        assertTrue(payload.precise)
    }

    @Test
    fun testHistoryGuardRoundsCoordinatesWhenCoarse() {
        val coarse = LocationPrivacyPolicy(recordTripHistory = true, coarseHistoryOnly = true)
        val precise = coarse.copy(coarseHistoryOnly = false)
        val point = GeoPoint(14.599512, 120.984234)
        val stored = HistoryGuard.persistedPoint(point, coarse)
        assertNotEquals(point.latitude, stored.latitude)
        assertEquals(14.6, stored.latitude, 0.0006)
        assertEquals(point, HistoryGuard.persistedPoint(point, precise))
        assertTrue(HistoryGuard.precisionLabel(coarse).contains("1 km"))
        assertTrue(HistoryGuard.retentionLabel(precise).contains("days"))
        assertFalse(HistoryGuard.mayPersist(LocationPrivacyPolicy()))
    }

    @Test
    fun testHistoryGuardExpiresOldTimestamps() {
        val policy = LocationPrivacyPolicy(recordTripHistory = true, historyRetentionDays = 7)
        val now = 1_700_000_000_000L
        val day = 24L * 3600_000L
        val timestamps = listOf(now, now - 3 * day, now - 30 * day)
        assertEquals(1, HistoryGuard.expiredPoints(timestamps, now, policy))
    }

    @Test
    fun testPermissionAuditReportsApproximateOnlyAsAFinding() {
        val audit = PermissionAudit(
            fineLocationGranted = false,
            coarseLocationGranted = true,
            backgroundLocationGranted = false,
            notificationPermissionGranted = false,
            locationEnabled = true,
            mockLocationApps = emptyList(),
            mockSettingApp = null,
            locationProvidersEnabled = listOf("network")
        )
        assertTrue(audit.anyGranted)
        assertTrue(audit.findings().any { it.contains("approximate", ignoreCase = true) })
    }

    @Test
    fun testPermissionAuditWithNothingGrantedSaysModuleIsDisabled() {
        val audit = PermissionAudit(
            fineLocationGranted = false,
            coarseLocationGranted = false,
            backgroundLocationGranted = false,
            notificationPermissionGranted = false,
            locationEnabled = false,
            mockLocationApps = emptyList(),
            mockSettingApp = null,
            locationProvidersEnabled = emptyList()
        )
        assertFalse(audit.anyGranted)
        assertTrue(audit.findings().any { it.contains("fully disabled") })
    }

    @Test
    fun testPermissionAuditFlagsMockLocationApp() {
        val audit = PermissionAudit(
            fineLocationGranted = true,
            coarseLocationGranted = true,
            backgroundLocationGranted = false,
            notificationPermissionGranted = true,
            locationEnabled = true,
            mockLocationApps = listOf("com.example.fakegps"),
            mockSettingApp = "com.example.fakegps",
            locationProvidersEnabled = listOf("gps")
        )
        assertTrue(audit.findings().any { it.contains("Mock location", ignoreCase = true) })
    }

    // --------------------------------------------------------- incident reports

    @Test
    fun testIncidentValidatorRejectsControlCharactersAndLongNotes() {
        val base = { notes: String? ->
            IncidentValidator.validate(
                kind = IncidentKind.HAZARD,
                position = GeoPoint(14.5995, 120.9842),
                lastFixAgeMs = 500L,
                accuracyMeters = 10f,
                integrityCompromised = false,
                notes = notes
            )
        }
        assertTrue(base("debris on the hard shoulder").accepted)
        assertFalse(base("bad\u0007note").accepted)
        assertFalse(base("x".repeat(300)).accepted)
        assertTrue(base(null).accepted)
    }

    @Test
    fun testIncidentKindsHaveBoundedLifetimes() {
        IncidentKind.entries.forEach { kind ->
            assertTrue("${kind.label} must expire", kind.defaultLifetimeMinutes in 1..1440)
            assertTrue(kind.label.isNotBlank())
        }
    }

    @Test
    fun testAgeAndConfidenceFormattingNeverInventsPrecision() {
        assertEquals("no data", formatAge(null))
        assertEquals("just now", formatAge(0))
        assertEquals("5 min ago", formatAge(5))
        assertEquals("2 h ago", formatAge(120))
        assertEquals("0%", formatConfidence(0.0))
        assertEquals("49%", formatConfidence(0.494))
    }

    // ---------------------------------------------------------------- offline

    @Test
    fun testOfflinePlanRejectsRegionAboveTheFreeTileBudget() {
        // A country-sized box at street zoom is far beyond 3 000 tiles.
        val huge = GeoBounds(south = 4.0, west = 116.0, north = 21.0, east = 127.0)
        val plan = OfflinePlanner.plan(huge, minZoom = 6, maxZoom = 16)
        assertFalse(plan.withinLimits)
        assertNotNull(plan.limitReason)
        assertTrue(plan.limitReason!!.contains("limit"))
    }

    @Test
    fun testOfflinePlanAcceptsASmallNeighbourhood() {
        val small = GeoBounds.around(GeoPoint(14.5995, 120.9842), 1_500.0)
        val plan = OfflinePlanner.plan(small, minZoom = 12, maxZoom = 15)
        assertTrue(plan.withinLimits)
        assertTrue(plan.tileCount in 1..GpsPreferences.MAX_OFFLINE_TILES_PER_PACK.toLong())
        assertTrue(plan.estimatedBytes > 0)
        assertTrue(plan.summary().contains("tiles"))
    }

    @Test
    fun testOfflineAutoFitFindsAZoomRangeInsideTheBudget() {
        val area = GeoBounds.around(GeoPoint(14.5995, 120.9842), 12_000.0)
        val plan = OfflinePlanner.autoFit(area)
        assertTrue(plan.withinLimits)
        assertTrue(plan.maxZoom <= 16)
        assertTrue(plan.tileCount <= GpsPreferences.MAX_OFFLINE_TILES_PER_PACK)
    }

    @Test
    fun testOfflineCorridorCoversTheWholeRoute() {
        val route = listOf(
            GeoPoint(14.5995, 120.9842),
            GeoPoint(14.6500, 121.0500),
            GeoPoint(14.7000, 121.1200)
        )
        val corridor = OfflinePlanner.corridorBounds(route, marginMeters = 1_000.0)
        assertNotNull(corridor)
        route.forEach { point -> assertTrue("corridor must contain $point", corridor!!.contains(point)) }
    }

    @Test
    fun testOfflinePolicyLineStatesTheLimits() {
        val line = OfflinePlanner.policyLine()
        assertTrue(line.contains("3,000") || line.contains("3000"))
        assertTrue(line.contains("50"))
        assertTrue(line.contains("User-Agent"))
    }

    @Test
    fun testOfflineEstimateGrowsWithZoomRange() {
        val area = GeoBounds.around(GeoPoint(14.5995, 120.9842), 3_000.0)
        val shallow = OfflinePlanner.plan(area, 10, 13)
        val deep = OfflinePlanner.plan(area, 10, 15)
        assertTrue(deep.tileCount > shallow.tileCount)
        assertTrue(deep.estimatedBytes > shallow.estimatedBytes)
    }

    @Test
    fun testDegenerateBoundsAreRejectedWithAReason() {
        val point = GeoBounds(south = 14.6, west = 120.9, north = 14.6, east = 120.9)
        val plan = OfflinePlanner.plan(point, 12, 15)
        assertFalse(plan.withinLimits)
        assertTrue(plan.limitReason!!.contains("single point"))
    }

    @Test
    fun testDistanceFormattingIsHumanReadable() {
        assertTrue(Geodesy.formatDistance(450.0).contains("m"))
        assertTrue(Geodesy.formatDistance(2_500.0).contains("km"))
        assertTrue(Geodesy.formatDuration(3_600.0).contains("h") || Geodesy.formatDuration(3_600.0).contains("60"))
    }
}
