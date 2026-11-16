package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.VideoAdNetworkCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The built-in video-advert baseline has to be both useful and safe: it must block real ad
 * infrastructure in every mode, and it must be structurally incapable of removing playback.
 */
class VideoAdNetworkCatalogTest {

    @Test
    fun testSafeAdInfrastructureIsBlockedInEveryMode() {
        val hosts = listOf(
            "googleads.g.doubleclick.net",
            "securepubads.g.doubleclick.net",
            "s0.2mdn.net",
            "pagead2.googlesyndication.com",
            "secure.adsafeprotected.com",
            "e.criteo.com",
            "cdn.taboola.com",
            "ads.tiktok.com"
        )
        hosts.forEach { host ->
            val match = VideoAdNetworkCatalog.matchForEnforcement(host, allowConditional = false)
            assertNotNull("expected a catalogue entry for $host", match)
            assertTrue("$host must be blocked", match!!.blocked)
        }
    }

    @Test
    fun testConditionalTierNeedsTheAggressiveModes() {
        val host = "cdn.freewheel.tv"
        val balanced = VideoAdNetworkCatalog.matchForEnforcement(host, allowConditional = false)
        assertNotNull(balanced)
        assertFalse("balanced modes must not block a player-adjacent ad server", balanced!!.blocked)
        assertTrue(balanced.reason.contains("Strict and Custom"))

        val aggressive = VideoAdNetworkCatalog.matchForEnforcement(host, allowConditional = true)
        assertNotNull(aggressive)
        assertTrue(aggressive!!.blocked)
    }

    @Test
    fun testModeFlagsMatchTheDocumentedTiering() {
        assertTrue(ProtectionMode.STRICT.enforceConditionalVideoAds)
        assertTrue(ProtectionMode.CUSTOM.enforceConditionalVideoAds)
        assertFalse(ProtectionMode.STANDARD.enforceConditionalVideoAds)
        assertFalse(ProtectionMode.PRIVACY.enforceConditionalVideoAds)
    }

    @Test
    fun testNoCatalogueZoneCanBePlaybackInfrastructure() {
        VideoAdNetworkCatalog.ENTRIES.forEach { entry ->
            assertFalse(
                "${entry.suffix} is a protected playback zone",
                DnsMediaPlaybackGuard.PROTECTED_REGISTRABLE_DOMAINS.contains(entry.suffix)
            )
            assertFalse(
                "${entry.suffix} is a shared CDN zone",
                DnsMediaPlaybackGuard.SHARED_CDN_ZONES.contains(entry.suffix)
            )
            assertFalse(
                "${entry.suffix} is entity-level",
                DnsMediaPlaybackGuard.ENTITY_LEVEL_DOMAINS.contains(entry.suffix)
            )
            // Every zone must be something the playback guard is happy to block on its own.
            assertFalse(
                "${entry.suffix} is treated as playback infrastructure by the media guard",
                DnsMediaPlaybackGuard.isProtectedPlaybackHost(entry.suffix)
            )
        }
        assertEquals(
            "catalogue zones must be unique",
            VideoAdNetworkCatalog.ENTRIES.size,
            VideoAdNetworkCatalog.ENTRIES.map { it.suffix }.distinct().size
        )
    }

    @Test
    fun testPlaybackHostsAreNeverMatchedThroughAMediaDomain() {
        // A per-node media host is not in the catalogue at all.
        assertNull(VideoAdNetworkCatalog.matchForEnforcement("rr1---sn-abc.googlevideo.com", allowConditional = true))
        assertNull(VideoAdNetworkCatalog.matchForEnforcement("nflxvideo.net", allowConditional = true))
        // And a media zone that carries an advert label is still blocked: it is an ad slot.
        val tiktok = VideoAdNetworkCatalog.matchForEnforcement("ads.tiktok.com", allowConditional = true)
        assertNotNull(tiktok)
        assertTrue(tiktok!!.blocked)
    }

    @Test
    fun testMatchingRespectsLabelBoundariesAndNormalisesInput() {
        assertNull(VideoAdNetworkCatalog.entryFor("notdoubleclick.net"))
        assertNull(VideoAdNetworkCatalog.entryFor("doubleclick.net.example.com"))
        assertNull(VideoAdNetworkCatalog.entryFor(""))
        assertEquals(
            "doubleclick.net",
            VideoAdNetworkCatalog.entryFor("HTTPS://Static.DoubleClick.NET:443/ads?x=1")?.suffix
        )
        assertEquals("doubleclick.net", VideoAdNetworkCatalog.entryFor("doubleclick.net")?.suffix)
    }
}
