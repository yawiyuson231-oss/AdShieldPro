package com.adshield.pro

import com.adshield.pro.engine.location.DeviceLocationContext
import com.adshield.pro.engine.location.DeviceSettingTarget
import com.adshield.pro.engine.location.FactState
import com.adshield.pro.engine.location.FixSource
import com.adshield.pro.engine.location.GeoPoint
import com.adshield.pro.engine.location.LocationAnalyzer
import com.adshield.pro.engine.location.LocationFix
import com.adshield.pro.engine.location.LocationPermission
import com.adshield.pro.engine.location.LocationQuality
import com.adshield.pro.engine.location.LocationSafetyAdvisor
import com.adshield.pro.engine.location.ShareMode
import java.util.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AdShield Pro — Safe GPS JVM suite.
 *
 * The geolocation hardware cannot run here, so the parts that decide what the user is told are
 * pure Kotlin and tested directly: validation, convergence, consistency, mock detection, privacy
 * rounding, the device checklist and the exact share text. Every claim the screen makes about a
 * pin is asserted here.
 */
class SafeGpsTestSuite {

    private var clock = 1_700_000_000_000L

    private fun fix(
        lat: Double,
        lon: Double,
        accuracy: Double,
        elapsedMs: Long = 0,
        source: FixSource = FixSource.GNSS,
        mock: Boolean = false,
        speed: Float? = null
    ) = LocationFix(
        latitude = lat,
        longitude = lon,
        accuracyMeters = accuracy,
        elapsedRealtimeMs = elapsedMs,
        wallClockMs = clock + elapsedMs,
        speedMetersPerSecond = speed,
        source = source,
        mock = mock
    )

    // ---------------------------------------------------------------- validation

    @Test
    fun usableFixRejectsImpossibleInput() {
        assertTrue(LocationAnalyzer.isUsable(fix(14.6, 121.0, 10.0)))
        assertFalse("latitude out of range", LocationAnalyzer.isUsable(fix(91.0, 121.0, 10.0)))
        assertFalse("longitude out of range", LocationAnalyzer.isUsable(fix(14.6, 181.0, 10.0)))
        assertFalse("zero accuracy is not a fix", LocationAnalyzer.isUsable(fix(14.6, 121.0, 0.0)))
        assertFalse("negative accuracy", LocationAnalyzer.isUsable(fix(14.6, 121.0, -4.0)))
        assertFalse("NaN accuracy", LocationAnalyzer.isUsable(fix(14.6, 121.0, Double.NaN)))
        assertFalse("beyond the accepted radius", LocationAnalyzer.isUsable(fix(14.6, 121.0, 25_000.0)))
        assertFalse("null", LocationAnalyzer.isUsable(null))
        assertFalse(
            "coarser than the caller's limit",
            LocationAnalyzer.isUsable(fix(14.6, 121.0, 900.0), maxAccuracyMeters = 500.0)
        )
    }

    @Test
    fun haversineMatchesTheSizeOfADegreeOfLatitude() {
        val distance = LocationAnalyzer.haversineMeters(GeoPoint(0.0, 0.0), GeoPoint(1.0, 0.0))
        assertTrue("expected ~111.2 km, got $distance", Math.abs(distance - 111_195.0) < 60.0)
        assertEquals(0.0, LocationAnalyzer.haversineMeters(GeoPoint(5.0, 5.0), GeoPoint(5.0, 5.0)), 0.0001)
    }

    @Test
    fun accuracyCirclesOnlyOverlapWhenBothFixesCanBeTrue() {
        val a = fix(14.6000, 121.0000, 10.0)
        assertTrue("~5.5 m apart with ±10 m each", LocationAnalyzer.circlesOverlap(a, fix(14.60005, 121.0000, 10.0)))
        assertFalse("~111 m apart cannot both be ±10 m", LocationAnalyzer.circlesOverlap(a, fix(14.6010, 121.0000, 10.0)))
    }

    @Test
    fun tightFixesDominateTheWeightedCentre() {
        val centre = LocationAnalyzer.weightedCentroid(
            listOf(fix(14.0, 121.0, 100.0), fix(15.0, 122.0, 5.0), fix(15.0, 122.0, 5.0))
        )
        assertNotNull(centre)
        assertTrue("latitude drifted to ${centre!!.latitude}", Math.abs(centre.latitude - 15.0) < 0.01)
        assertTrue("longitude drifted to ${centre.longitude}", Math.abs(centre.longitude - 122.0) < 0.01)
        assertNull(LocationAnalyzer.weightedCentroid(emptyList()))
        assertNull("invalid fixes must not produce a centre", LocationAnalyzer.weightedCentroid(listOf(fix(999.0, 0.0, 5.0))))
    }

    @Test
    fun medianPositionSurvivesOneWildOutlier() {
        assertEquals(2.0, LocationAnalyzer.median(listOf(3.0, 1.0, 2.0)), 0.0)
        assertEquals(2.5, LocationAnalyzer.median(listOf(4.0, 1.0, 2.0, 3.0)), 0.0)
        assertEquals(5.0, LocationAnalyzer.median(listOf(Double.NaN, 5.0, Double.NaN)), 0.0)
        val median = LocationAnalyzer.medianPoint(
            listOf(fix(14.0, 121.0, 10.0), fix(14.00001, 121.0, 10.0), fix(20.0, 130.0, 10.0))
        )
        assertNotNull(median)
        assertTrue("one outlier must not move the median", median!!.latitude < 14.1)
    }

    @Test
    fun bestFixIsTheTightestAndTheNewestOnATie() {
        val best = LocationAnalyzer.bestFix(
            listOf(fix(1.0, 1.0, 30.0, 10), fix(2.0, 2.0, 8.0, 20), fix(3.0, 3.0, 8.0, 30), fix(9.0, 9.0, 500.0, 40))
        )
        assertEquals("equal accuracy resolves to the newer fix", 3.0, best!!.latitude, 0.0)
        assertNull(LocationAnalyzer.bestFix(listOf(fix(0.0, 0.0, -1.0))))
    }

    // ---------------------------------------------------------------- convergence

    @Test
    fun convergingSessionReportsTheMeasuredImprovement() {
        val analysis = LocationAnalyzer.analyse(
            listOf(fix(14.6000, 121.0000, 60.0, 1_000), fix(14.60002, 121.00001, 25.0, 3_000), fix(14.60003, 121.00002, 9.0, 6_000)),
            targetAccuracyMeters = 10.0
        )
        assertEquals(3, analysis.count)
        assertEquals(9.0, analysis.bestAccuracyMeters!!, 0.0)
        assertEquals(60.0, analysis.firstAccuracyMeters!!, 0.0)
        assertEquals(51.0, analysis.improvementMeters!!, 0.0)
        assertTrue("target must be reported as met", analysis.targetMet)
        assertTrue(analysis.consistent)
        assertEquals(LocationQuality.HIGH, analysis.quality)
        assertTrue("headline must quote the measured figure: ${analysis.headline}", analysis.headline.contains("±9.0 m"))
    }

    @Test
    fun singleTightFixIsUsableButNotCalledHighQuality() {
        val analysis = LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 3.0)))
        assertEquals(LocationQuality.MEDIUM, analysis.quality)
        assertTrue("one fix cannot be called converged", !analysis.headline.contains("Converged"))
    }

    @Test
    fun disagreeingFixesAreRefusedInsteadOfAveraged() {
        val analysis = LocationAnalyzer.analyse(
            listOf(fix(14.6000, 121.0000, 10.0, 1_000), fix(14.8000, 121.4000, 10.0, 2_000)),
            targetAccuracyMeters = 10.0
        )
        assertFalse("a ~30 km disagreement is not consistent", analysis.consistent)
        assertEquals(LocationQuality.LOW, analysis.quality)
        assertTrue("must say so: ${analysis.detail}", analysis.headline.contains("disagree"))
    }

    @Test
    fun networkOnlyFixIsDescribedAsCoarseRatherThanPrecise() {
        val analysis = LocationAnalyzer.analyse(
            listOf(fix(14.6, 121.0, 1_500.0, 1_000, FixSource.NETWORK), fix(14.6, 121.0, 900.0, 2_000, FixSource.NETWORK))
        )
        assertEquals(LocationQuality.COARSE, analysis.quality)
        assertFalse(analysis.targetMet)
        assertTrue("network positioning must be named: ${analysis.detail}", analysis.detail.contains("network positioning"))
    }

    @Test
    fun emptyWindowSaysSoInsteadOfInventingAPosition() {
        val analysis = LocationAnalyzer.analyse(emptyList())
        assertEquals(0, analysis.count)
        assertNull(analysis.best)
        assertNull(analysis.centroid)
        assertFalse(analysis.hasFix)
        assertEquals(LocationQuality.NONE, analysis.quality)
        assertTrue(analysis.headline.contains("No usable fix"))
        assertEquals(1, LocationAnalyzer.analyse(listOf(fix(999.0, 0.0, 5.0))).rejected)
    }

    // ---------------------------------------------------------------- honesty

    @Test
    fun mockedFixIsFlaggedAndNeverPresentedAsReal() {
        val analysis = LocationAnalyzer.analyse(
            listOf(fix(14.6, 121.0, 4.0, 1_000, mock = true), fix(14.6, 121.0, 4.0, 2_000, mock = true), fix(14.6, 121.0, 4.0, 3_000, mock = true))
        )
        assertTrue(analysis.anyMocked)
        assertEquals(LocationQuality.LOW, analysis.quality)
        assertTrue("mock must be called out: ${analysis.headline}", analysis.headline.contains("Simulated"))
        assertTrue(
            "must explain the developer-options cause",
            analysis.detail.contains("simulated") || analysis.detail.contains("mock")
        )
    }

    @Test
    fun implausibleMovementIsAHintNotAProof() {
        val teleport = LocationAnalyzer.analyse(
            listOf(fix(14.6000, 121.0000, 5.0, 0), fix(15.6000, 121.0000, 5.0, 20_000))
        )
        assertTrue("~111 km in 20 s is not a person", teleport.implausibleMovement)
        assertTrue(teleport.impliedSpeedMetersPerSecond!! > 250.0)
        val walk = LocationAnalyzer.analyse(
            listOf(fix(14.6000, 121.0000, 5.0, 0), fix(14.60010, 121.0000, 5.0, 20_000))
        )
        assertFalse("11 m in 20 s is a walk", walk.implausibleMovement)
        assertNull("one fix cannot imply movement", LocationAnalyzer.impliedSpeedMetersPerSecond(listOf(fix(1.0, 1.0, 5.0))))
    }

    @Test
    fun accuracyFormatterStaysHonestAtEveryScale() {
        assertEquals("<1 m", LocationAnalyzer.formatMeters(0.4))
        assertEquals("9.4 m", LocationAnalyzer.formatMeters(9.44))
        assertEquals("46 m", LocationAnalyzer.formatMeters(45.6))
        assertEquals("2.4 km", LocationAnalyzer.formatMeters(2_400.0))
        assertEquals("—", LocationAnalyzer.formatMeters(null))
        assertEquals("—", LocationAnalyzer.formatMeters(Double.NaN))
        assertEquals("14.59953, 120.98422", LocationAnalyzer.formatCoordinates(14.59953, 120.98422))
        assertEquals("—", LocationAnalyzer.formatCoordinates(Double.NaN, 120.0))
    }

    @Test
    fun spokenReferenceCanBeReadAloudOverAPhoneCall() {
        val sentence = LocationAnalyzer.spokenReference(fix(14.59953, 120.98422, 12.4))
        assertTrue(sentence.contains("North"))
        assertTrue(sentence.contains("East"))
        assertTrue(sentence.contains("14.59953"))
        assertTrue(sentence.contains("about 12 metres"))
        assertEquals("No position available.", LocationAnalyzer.spokenReference(null))
    }

    // ---------------------------------------------------------------- privacy rounding

    @Test
    fun roundingBoundsTheDisplacementAndDropsTheExactFix() {
        val exact = fix(14.59953, 120.98422, 9.0)
        val rounded = LocationAnalyzer.round(exact, 250)
        assertNotNull(rounded)
        assertNotEquals("rounding must move the point", exact.latitude, rounded!!.point.latitude)
        assertTrue(
            "displacement ${rounded.displacementMeters} m must stay inside the ${rounded.worstCaseMeters} m bound",
            rounded.displacementMeters <= rounded.worstCaseMeters + 0.001
        )
        assertEquals(250, rounded.gridMeters)

        val town = LocationAnalyzer.round(exact, 5_000)
        assertEquals(5_000, town!!.gridMeters)
        assertTrue(town.displacementMeters <= town.worstCaseMeters + 0.001)

        assertEquals("clamped low", 25, LocationAnalyzer.round(exact, 1)!!.gridMeters)
        assertEquals("clamped high", 5_000, LocationAnalyzer.round(exact, 999_999)!!.gridMeters)
        assertNull(LocationAnalyzer.round(fix(999.0, 0.0, 5.0), 250))
    }

    @Test
    fun precisionLanguageSeparatesFindableFromIdentified() {
        val tight = LocationSafetyAdvisor.describePrecision(LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 8.0))))
        assertTrue("entrance-level precision must warn: $tight", tight.contains("entrance"))
        val street = LocationSafetyAdvisor.describePrecision(LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 40.0))))
        assertTrue(street.contains("Street level"))
        val coarse = LocationSafetyAdvisor.describePrecision(LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 4_000.0))))
        assertTrue("coarse fixes must be named: $coarse", coarse.contains("Coarse"))
        assertEquals("No fix — nothing to share yet.", LocationSafetyAdvisor.describePrecision(LocationAnalyzer.analyse(emptyList())))
    }

    // ---------------------------------------------------------------- sharing

    @Test
    fun everydayShareIsAFixedPinThatDisclosesItsRadius() {
        val analysis = LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 12.0, 0), fix(14.6, 121.0, 11.0, 1_000), fix(14.6, 121.0, 10.0, 2_000)))
        val plan = LocationSafetyAdvisor.buildSharePlan(
            analysis = analysis,
            mode = ShareMode.EVERYDAY,
            gridMeters = 0,
            nowWallClockMs = 1_760_000_000_000L,
            timeZoneLabel = "PST",
            mapUrl = LocationSafetyAdvisor.openStreetMapUrl(analysis.best!!.point)
        )
        assertFalse(plan.blocked)
        assertTrue("must state the accuracy it knows: ${plan.text}", plan.text.contains("±10 m"))
        assertTrue("must say it is not live tracking", plan.text.contains("does not update"))
        assertTrue(plan.text.contains("openstreetmap.org"))
        assertTrue(plan.text.contains("14.60000, 121.00000"))
        assertTrue("an SMS URI must be produced", plan.smsUri.startsWith("sms:?body="))
        assertEquals(10.0, plan.worstCaseMeters, 0.0)
    }

    @Test
    fun noPinIsProducedWhileFixesContradictEachOther() {
        val contradictory = LocationAnalyzer.analyse(
            listOf(fix(14.6, 121.0, 10.0, 0), fix(14.9, 121.5, 10.0, 1_000))
        )
        val everyday = LocationSafetyAdvisor.buildSharePlan(contradictory, ShareMode.EVERYDAY)
        assertTrue("everyday sharing must be withheld", everyday.blocked)
        assertTrue("no text may be produced for a refused pin", everyday.text.isEmpty())
        assertTrue(everyday.blockReason!!.contains("disagree"))

        val emergency = LocationSafetyAdvisor.buildSharePlan(contradictory, ShareMode.EMERGENCY)
        assertTrue("an emergency pin must be withheld too", emergency.blocked)
        assertTrue(emergency.blockReason!!.contains("emergency"))

        val nothing = LocationSafetyAdvisor.buildSharePlan(LocationAnalyzer.analyse(emptyList()))
        assertTrue(nothing.blocked)
        assertTrue(nothing.blockReason!!.contains("Locate"))
    }

    @Test
    fun roundedShareNeverContainsTheExactLatitude() {
        val exact = fix(14.59953, 120.98422, 9.0)
        val analysis = LocationAnalyzer.analyse(listOf(exact, exact.copy(elapsedRealtimeMs = 1_000), exact.copy(elapsedRealtimeMs = 2_000)))
        val plan = LocationSafetyAdvisor.buildSharePlan(analysis, ShareMode.EVERYDAY, gridMeters = 1_000)
        assertFalse(plan.blocked)
        assertNotNull(plan.rounded)
        assertFalse("exact latitude must not leak: ${plan.text}", plan.text.contains("14.59953"))
        assertTrue(plan.text.contains("1 km") || plan.text.contains("1000 m"))
        assertTrue(
            "the disclosed radius must cover the rounding, not just the GPS figure",
            plan.worstCaseMeters >= plan.rounded!!.worstCaseMeters
        )
    }

    @Test
    fun emergencyMessageTellsTheReceiverWhatToDo() {
        val analysis = LocationAnalyzer.analyse(listOf(fix(14.59953, 120.98422, 12.0)))
        val plan = LocationSafetyAdvisor.buildSharePlan(
            analysis,
            mode = ShareMode.EMERGENCY,
            nowWallClockMs = 1_760_000_000_000L,
            timeZoneLabel = "PST",
            emergencyNumber = "911"
        )
        assertFalse(plan.blocked)
        assertTrue(plan.text.startsWith("EMERGENCY"))
        assertTrue("must say the pin does not update: ${plan.text}", plan.text.contains("does not update"))
        assertTrue("must name the emergency number", plan.text.contains("911"))
        assertTrue("must instruct a bystander", plan.text.contains("call it for me"))
    }

    @Test
    fun shareWarningsNameTheRealRiskForEachPrecision() {
        val tight = LocationSafetyAdvisor.shareWarnings(
            LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 8.0), fix(14.6, 121.0, 8.0, 1_000))), 8.0
        )
        assertTrue("doorway-level pins must warn", tight.any { it.contains("doorway") })

        val mocked = LocationSafetyAdvisor.shareWarnings(
            LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 5.0, 0, mock = true), fix(14.6, 121.0, 5.0, 1_000, mock = true))), 5.0
        )
        assertTrue("mock fixes must warn before sending", mocked.any { it.contains("simulated") })

        val town = LocationSafetyAdvisor.shareWarnings(LocationAnalyzer.analyse(listOf(fix(14.6, 121.0, 3_000.0))), 3_000.0)
        assertTrue("town-level pins must suggest a landmark", town.any { it.contains("landmark") })
    }

    // ---------------------------------------------------------------- device checklist

    @Test
    fun checklistReportsUnknownInsteadOfAssumingHealthy() {
        val facts = LocationSafetyAdvisor.deviceChecklist(DeviceLocationContext())
        val byId = facts.associateBy { it.id }
        assertEquals("all seven checks must be present", 7, facts.size)
        assertEquals(FactState.WARN, byId.getValue("permission").state)
        assertEquals("an unread switch must be UNKNOWN, never OK", FactState.UNKNOWN, byId.getValue("system-location").state)
        assertEquals(FactState.UNKNOWN, byId.getValue("mock-provider").state)
        assertEquals("screen lock is not readable by an app", FactState.UNKNOWN, byId.getValue("screen-lock").state)
        assertTrue(
            "unknown must be explained",
            byId.getValue("screen-lock").detail.contains("does not expose")
        )
    }

    @Test
    fun checklistPointsAtTheExactSettingThatIsBlocking() {
        val facts = LocationSafetyAdvisor.deviceChecklist(
            DeviceLocationContext(
                permission = LocationPermission.DENIED_PERMANENTLY,
                systemLocationEnabled = false,
                precisePermissionGranted = false,
                wifiScanningEnabled = false,
                mockProvidersEnabled = true,
                encryptedNetworkAvailable = false,
                screenLockKnown = true
            )
        )
        val byId = facts.associateBy { it.id }
        assertEquals(FactState.BAD, byId.getValue("permission").state)
        assertEquals(DeviceSettingTarget.APP_LOCATION_PERMISSIONS, byId.getValue("permission").setting)
        assertEquals(FactState.BAD, byId.getValue("system-location").state)
        assertEquals(DeviceSettingTarget.LOCATION_SOURCE, byId.getValue("system-location").setting)
        assertEquals("approximate-only must be a blocker, not a note", FactState.BAD, byId.getValue("precise").state)
        assertEquals(DeviceSettingTarget.LOCATION_SCAN, byId.getValue("wifi-scan").setting)
        assertEquals(FactState.BAD, byId.getValue("mock-provider").state)
        assertEquals(DeviceSettingTarget.DEVELOPER_OPTIONS, byId.getValue("mock-provider").setting)
        assertEquals(FactState.WARN, byId.getValue("secure-network").state)
        assertEquals(FactState.OK, byId.getValue("screen-lock").state)
    }

    @Test
    fun aHealthyDeviceReportsNoBlockers() {
        val facts = LocationSafetyAdvisor.deviceChecklist(
            DeviceLocationContext(
                permission = LocationPermission.GRANTED,
                systemLocationEnabled = true,
                precisePermissionGranted = true,
                wifiScanningEnabled = true,
                mockProvidersEnabled = false,
                encryptedNetworkAvailable = true,
                screenLockKnown = true
            )
        )
        assertTrue("nothing may be BAD on a healthy device", facts.none { it.state == FactState.BAD })
        assertTrue("no setting shortcut is needed when nothing is wrong", facts.none { it.setting != null })
    }

    // ---------------------------------------------------------------- helpers

    @Test
    fun uriHelpersEncodeWhatTheyMustAndNothingElse() {
        val uri = LocationSafetyAdvisor.smsUri("My location: 14.6, 121.0 ±10 m & more")
        assertTrue(uri.startsWith("sms:?body="))
        assertFalse("spaces must be encoded", uri.contains(" "))
        assertTrue("plus-minus is not ASCII and must be encoded", uri.contains("%C2%B1"))
        assertTrue("ampersand must be encoded", uri.contains("%26"))

        val geo = LocationSafetyAdvisor.geoUri(GeoPoint(14.59953, 120.98422), "My location")
        assertTrue(geo.startsWith("geo:14.599530,120.984220?q="))
        val osm = LocationSafetyAdvisor.openStreetMapUrl(GeoPoint(14.59953, 120.98422))
        assertTrue(osm.contains("mlat=14.599530"))
        assertFalse("URL must not contain spaces", osm.contains(" "))
    }

    @Test
    fun radiusLabelStatesTheAreaASearchWouldCover() {
        val label = LocationSafetyAdvisor.radiusLabel(12.0)
        assertTrue(label.contains("12 m"))
        assertTrue("area must be stated: $label", label.contains("m²"))
        assertEquals("radius unknown", LocationSafetyAdvisor.radiusLabel(null))
    }

    @Test
    fun timeIsPrintedInTheGivenZoneSoTheReceiverIsNotConfused() {
        val utc = TimeZone.getTimeZone("UTC")
        assertEquals("2025-10-09 08:53", LocationSafetyAdvisor.formatTime(1_760_000_000_000L, utc))
    }
}
