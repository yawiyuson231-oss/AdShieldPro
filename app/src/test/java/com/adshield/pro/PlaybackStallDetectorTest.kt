package com.adshield.pro

import com.adshield.pro.engine.filter.PlaybackStallDetector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PlaybackStallDetectorTest {

    @Test
    fun testTheThirdAskInsideTheWindowIsTheSignal() {
        var now = 1_000L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        assertNull(detector.record("com.example.player", "ads.example.net", now))
        now += 2_000L
        assertNull(detector.record("com.example.player", "ads.example.net", now))
        now += 2_000L
        val signal = detector.record("com.example.player", "ads.example.net", now)
        assertNotNull("third ask inside the window must signal", signal)
        assertEquals(3, signal!!.attempts)
        assertEquals("ads.example.net", signal.domain)
        assertEquals("com.example.player", signal.appPackage)
    }

    @Test
    fun testAsksSpreadBeyondTheWindowNeverSignal() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        repeat(6) {
            assertNull(detector.record("app", "ads.example.net", now))
            now += PlaybackStallDetector.WINDOW_MS + 1
        }
    }

    @Test
    fun testDifferentAppsAndDifferentZonesAreNotCombined() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        assertNull(detector.record("app.one", "ads.example.net", now))
        assertNull(detector.record("app.two", "ads.example.net", now))
        assertNull(detector.record("app.one", "other.example.net", now))
        now += 1_000L
        assertNull(detector.record("app.one", "ads.example.net", now))
        now += 1_000L
        assertNotNull("the pair that repeated three times does signal", detector.record("app.one", "ads.example.net", now))
    }

    @Test
    fun testAMissingAppIsTrackedAsUnknownRatherThanCrashing() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        assertNull(detector.record(null, "ads.example.net"))
        assertNull(detector.record(null, "ads.example.net"))
        val signal = detector.record(null, "ads.example.net")
        assertNotNull(signal)
        assertNull(signal!!.appPackage)
    }

    @Test
    fun testTheCaseAndTrailingDotOfTheQueryDoNotSplitTheCount() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        assertNull(detector.record("app", "ADS.Example.NET."))
        assertNull(detector.record("app", "ads.example.net"))
        assertNotNull(detector.record("app", "Ads.Example.Net."))
    }

    @Test
    fun testTrackingStaysBounded() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        repeat(PlaybackStallDetector.MAX_TRACKED + 50) { index ->
            now += 1
            detector.record("app", "zone$index.example.net")
        }
        assertEquals(
            "the map must not grow without limit",
            PlaybackStallDetector.MAX_TRACKED,
            detector.trackedCount()
        )
    }

    @Test
    fun testForgetAndClearDropTheHistory() {
        var now = 0L
        val detector = PlaybackStallDetector().apply { clock = { now } }
        detector.record("app", "ads.example.net")
        detector.record("app", "ads.example.net")
        detector.forget("app", "ads.example.net")
        assertNull("after forget, the count starts again", detector.record("app", "ads.example.net"))
        detector.clear()
        assertEquals(0, detector.trackedCount())
    }
}
