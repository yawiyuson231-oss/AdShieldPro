package com.adshield.pro

import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.map.MapOverlayMath
import com.adshield.pro.gps.map.ScreenPoint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

/**
 * AdShield Pro — screen-space math for the map HUD.
 *
 * The vehicle marker and its accuracy circle are Compose overlays on top of the native MapLibre
 * surface, so the numbers that place them are computed here and nowhere else. A sign error in this
 * file puts the marker on the wrong side of the road, which is the kind of bug that is invisible in
 * a screenshot on a symmetric street.
 */
class GpsMapOverlayTest {

    private val manila = GeoPoint(14.5995, 120.9842)

    private fun close(expected: Double, actual: Double, tolerance: Double, message: String) =
        assertTrue("$message (expected $expected ± $tolerance, was $actual)", abs(expected - actual) <= tolerance)

    // ------------------------------------------------------------------ scale

    @Test
    fun testPixelsPerMeterMatchesWebMercatorGroundResolution() {
        // At zoom 17 and latitude 14.6 the ground resolution is 1.154 m/px, so 10 m is 8.66 px.
        close(8.662, MapOverlayMath.pixelsPerMeter(14.6, 17.0) * 10.0, 0.01, "zoom 17 scale")
        // One zoom level doubles the scale, exactly.
        val z17 = MapOverlayMath.pixelsPerMeter(14.6, 17.0)
        val z18 = MapOverlayMath.pixelsPerMeter(14.6, 18.0)
        close(2.0, z18 / z17, 1e-9, "each zoom level doubles the pixel density")
        // Equator has the largest scale; a higher latitude compresses it by cos(lat).
        assertTrue(MapOverlayMath.pixelsPerMeter(0.0, 15.0) > MapOverlayMath.pixelsPerMeter(60.0, 15.0))
    }

    @Test
    fun testAccuracyCircleGrowsWithZoomAndWithReportedError() {
        val tight = MapOverlayMath.accuracyRadiusPx(5f, 14.6, 17.0)
        val loose = MapOverlayMath.accuracyRadiusPx(30f, 14.6, 17.0)
        assertTrue("a 30 m error must draw a bigger circle than 5 m", loose > tight)
        close(6.0, loose / tight, 1e-6, "radius is linear in the reported accuracy")

        val zoomedIn = MapOverlayMath.accuracyRadiusPx(5f, 14.6, 19.0)
        close(4.0, zoomedIn / tight, 1e-6, "two zoom levels in is four times the pixel radius")
    }

    @Test
    fun testUnknownAccuracyDrawsNoCircle() {
        // A receiver that does not report its accuracy must not get an invented circle.
        assertEquals(0f, MapOverlayMath.accuracyRadiusPx(null, 14.6, 17.0))
        assertEquals(0f, MapOverlayMath.accuracyRadiusPx(Float.NaN, 14.6, 17.0))
        assertEquals(0f, MapOverlayMath.accuracyRadiusPx(0f, 14.6, 17.0))
        assertEquals(0f, MapOverlayMath.accuracyRadiusPx(-3f, 14.6, 17.0))
    }

    // ------------------------------------------------------------------ offsets

    @Test
    fun testPointNorthOfCentreIsAboveTheCentreOnScreen() {
        val north = GeoPoint(manila.latitude + 0.001, manila.longitude)
        val offset = MapOverlayMath.offsetFromCentre(north, manila, cameraBearingDegrees = 0.0, zoom = 15.0)
        assertTrue("north must be up, i.e. negative y was ${offset.y}", offset.y < 0)
        close(0.0, offset.x, 1e-6, "a due-north point has no horizontal offset")
        // 0.001° of latitude is 111.2 m; at zoom 15 and 14.6° the ground resolution is 4.62 m/px.
        close(24.08, abs(offset.y), 0.6, "offset must be the real distance divided by the real scale")
    }

    @Test
    fun testPointEastOfCentreIsToTheRightOnScreen() {
        val east = GeoPoint(manila.latitude, manila.longitude + 0.001)
        val offset = MapOverlayMath.offsetFromCentre(east, manila, cameraBearingDegrees = 0.0, zoom = 15.0)
        assertTrue("east must be right, i.e. positive x was ${offset.x}", offset.x > 0)
        close(0.0, offset.y, 1e-6, "a due-east point has no vertical offset")
    }

    @Test
    fun testCameraBearingRotatesTheWholeScene() {
        val north = GeoPoint(manila.latitude + 0.001, manila.longitude)
        val northUp = MapOverlayMath.offsetFromCentre(north, manila, cameraBearingDegrees = 0.0, zoom = 15.0)
        // Bearing 90 means the camera looks east, so north appears on the left of the screen.
        val eastUp = MapOverlayMath.offsetFromCentre(north, manila, cameraBearingDegrees = 90.0, zoom = 15.0)
        assertTrue("with the camera facing east, north must move to the left (was ${eastUp.x})", eastUp.x < 0)
        close(abs(northUp.y), abs(eastUp.x), 0.5, "a pure rotation must preserve the distance from centre")
    }

    @Test
    fun testCentreMapsToZeroOffset() {
        val offset = MapOverlayMath.offsetFromCentre(manila, manila, cameraBearingDegrees = 37.0, zoom = 16.0)
        assertEquals(0.0, offset.x, 1e-9)
        assertEquals(0.0, offset.y, 1e-9)
    }

    @Test
    fun testAntimeridianIsCrossedTheShortWay() {
        // Across ±180° the two points are 0.002° apart, not almost a whole world apart.
        val west = GeoPoint(0.0, 179.999)
        val east = GeoPoint(0.0, -179.999)
        val offset = MapOverlayMath.offsetFromCentre(east, west, cameraBearingDegrees = 0.0, zoom = 10.0)
        assertTrue("the crossing must be 1.5 px to the right, not a whole world away (was ${offset.x})", offset.x > 0)
        close(1.456, offset.x, 0.01,
            "0.002° of longitude at the equator is 222.4 m, which is 1.456 px at zoom 10")
    }

    // ------------------------------------------------------------------ viewport clamping

    @Test
    fun testOffscreenTargetIsClampedToTheEdge() {
        val far = ScreenPoint(x = 10_000.0, y = 40.0)
        val clamped = MapOverlayMath.clampToViewport(far, viewportWidthPx = 1080f, viewportHeightPx = 1920f, marginPx = 28f)
        close(1080.0 / 2.0 - 28.0, clamped.x, 0.5, "x must sit on the inset edge")
        assertTrue(clamped.y <= far.y, "clamping must not move a point further out")
    }

    @Test
    fun testVisibleTargetIsNotMoved() {
        val near = ScreenPoint(x = 12.0, y = -30.0)
        val clamped = MapOverlayMath.clampToViewport(near, viewportWidthPx = 1080f, viewportHeightPx = 1920f)
        assertEquals(near, clamped)
    }

    @Test
    fun testClampKeepsTheDirectionOfTheTarget() {
        // A target far to the bottom-right must stay on the bottom-right diagonal, otherwise the
        // arrow points the wrong way.
        val clamped = MapOverlayMath.clampToViewport(
            ScreenPoint(3_000.0, 6_000.0),
            viewportWidthPx = 1000f,
            viewportHeightPx = 2000f,
            marginPx = 0f
        )
        close(2.0, clamped.y / clamped.x, 1e-6, "the clamped point must stay on the same ray")
        assertFalse("a clamped arrow must be inside the viewport", abs(clamped.x) > 500.0)
    }

    @Test
    fun testArrowBearingIsScreenRelativeNotGeographic() {
        val north = GeoPoint(manila.latitude + 0.01, manila.longitude)
        val east = GeoPoint(manila.latitude, manila.longitude + 0.01)
        // North-up camera: screen direction equals the compass bearing.
        close(0.0, MapOverlayMath.arrowBearingDegrees(manila, north, 0.0, 15.0), 0.05, "north is up")
        close(90.0, MapOverlayMath.arrowBearingDegrees(manila, east, 0.0, 15.0), 0.05, "east is right")

        // Camera facing east: north is now on the left of the screen, i.e. 270° clockwise from up.
        close(
            270.0,
            MapOverlayMath.arrowBearingDegrees(manila, north, 90.0, 15.0),
            0.05,
            "a rotated camera must move the arrow, not just the map"
        )
    }

    @Test
    fun testArrowBearingIsUndefinedAtTheCentre() {
        // The target is exactly under the camera: there is no direction to point at.
        close(0.0, MapOverlayMath.arrowBearingDegrees(manila, manila, 42.0, 16.0), 1e-9, "centre has no direction")
    }

    @Test
    fun testDegenerateViewportIsStillBounded() {
        // A zero-sized surface (first frame, before layout) must not divide by zero.
        val clamped = MapOverlayMath.clampToViewport(ScreenPoint(50.0, 50.0), 0f, 0f, marginPx = 28f)
        assertTrue(clamped.x.isFinite() && clamped.y.isFinite())
    }
}
