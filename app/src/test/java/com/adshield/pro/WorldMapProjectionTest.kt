package com.adshield.pro

import com.adshield.pro.ui.cybershield.WorldMapData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The map is a real projection of real geography: land sampling must hit continents and miss
 * oceans, and every marker centroid must land inside the canvas. No marker may be placed for a
 * country the geometry does not know.
 */
class WorldMapProjectionTest {

    private val width = 800f
    private val height = 390f

    @Test
    fun projection_cornersAndCenterAreCorrect() {
        val topLeft = WorldMapData.project(-180f, WorldMapData.MAX_LAT, width, height)
        assertEquals(0f, topLeft.x, 0.01f)
        assertEquals(0f, topLeft.y, 0.01f)
        val bottomRight = WorldMapData.project(180f, WorldMapData.MIN_LAT, width, height)
        assertEquals(width, bottomRight.x, 0.01f)
        assertEquals(height, bottomRight.y, 0.01f)
        val center = WorldMapData.project(0f, (WorldMapData.MAX_LAT + WorldMapData.MIN_LAT) / 2f, width, height)
        assertEquals(width / 2f, center.x, 0.01f)
        assertEquals(height / 2f, center.y, 0.01f)
    }

    @Test
    fun projection_clampsOutOfRangeCoordinates() {
        val point = WorldMapData.project(400f, 95f, width, height)
        assertTrue(point.x in 0f..width)
        assertTrue(point.y in 0f..height)
    }

    @Test
    fun landSampling_hitsContinentsAndMissesOceans() {
        // Continents.
        assertTrue("Paris should be land", WorldMapData.isLand(2.35f, 48.85f))
        assertTrue("Sahara should be land", WorldMapData.isLand(10f, 23f))
        assertTrue("Brazil should be land", WorldMapData.isLand(-51.9f, -14.2f))
        assertTrue("Siberia should be land", WorldMapData.isLand(100f, 60f))
        assertTrue("Australia should be land", WorldMapData.isLand(133.8f, -25.3f))
        assertTrue("USA should be land", WorldMapData.isLand(-98.5f, 39.8f))
        // Oceans.
        assertFalse("Mid-Atlantic should be ocean", WorldMapData.isLand(-35f, 10f))
        assertFalse("Central Pacific should be ocean", WorldMapData.isLand(-150f, 0f))
        assertFalse("Southern Indian Ocean should be ocean", WorldMapData.isLand(80f, -45f))
    }

    @Test
    fun landDots_areInsideCanvasAndNotEmpty() {
        val dots = WorldMapData.landDots(width, height, 10f)
        assertTrue("a world map must have land dots", dots.size > 200)
        assertTrue(dots.all { it.x in 0f..width && it.y in 0f..height })
    }

    @Test
    fun landDots_degenerateSizesProduceNothing() {
        assertTrue(WorldMapData.landDots(0f, 100f, 5f).isEmpty())
        assertTrue(WorldMapData.landDots(100f, 100f, 0f).isEmpty())
    }

    @Test
    fun everyCountryCentroid_projectsInsideTheCanvas() {
        WorldMapData.countryCentroids.forEach { (code, geo) ->
            val point = WorldMapData.project(geo.lon, geo.lat, width, height)
            assertTrue("$code centroid outside canvas", point.x in 0f..width && point.y in 0f..height)
        }
    }

    @Test
    fun countryDisplayNames_fallBackToCodeForUnknownCountries() {
        assertEquals("Germany", WorldMapData.displayName("DE"))
        assertEquals("XX", WorldMapData.displayName("XX"))
    }

    @Test
    fun continents_haveClosedNonDegeneratePolygons() {
        assertTrue(WorldMapData.continents.size >= 8)
        WorldMapData.continents.forEach { polygon ->
            assertTrue("polygon too small: ${polygon.size}", polygon.size >= 5)
        }
    }
}
