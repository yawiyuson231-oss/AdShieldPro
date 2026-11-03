package com.adshield.pro

import com.adshield.pro.engine.adskip.AdSkipDecisionEngine
import com.adshield.pro.engine.adskip.NotificationAdClassifier
import com.adshield.pro.engine.firewall.SniFirewall
import com.adshield.pro.engine.firewall.TlsSniInspector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OmniShield X — In-App Ad Defense tests (non-DNS mechanisms):
 * YouTube auto-skip decisions, notification ad classification, TLS SNI parsing.
 */
class InAppAdDefenseTest {

    // --- YouTube Auto-Skip decision engine ---

    private fun node(
        id: String? = null,
        text: String? = null,
        desc: String? = null,
        clickable: Boolean = true,
        pkg: String = "com.google.android.youtube"
    ) = AdSkipDecisionEngine.NodeInfo(id, text, desc, clickable, pkg)

    @Test
    fun autoSkip_clicksSkipButtonByIdAndText_andIgnoresNormalControls() {
        // Real skip button by resource id
        val byId = AdSkipDecisionEngine.decide(node(id = "com.google.android.youtube:id/skip_ad"), "com.google.android.youtube")
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_SKIP, byId.type)

        // Text fallback ("Skip Ad" localized label)
        val byText = AdSkipDecisionEngine.decide(node(text = "Skip Ad"), "com.google.android.youtube")
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_SKIP, byText.type)

        // Countdown variant ("Skip in 5s")
        val countdown = AdSkipDecisionEngine.decide(node(text = "Skip in 5s"), "com.google.android.youtube")
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_SKIP, countdown.type)

        // UNIVERSAL SAFETY: bare "Skip" / "✕" / "Close" in unknown contexts are NOT ads
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Skip to content"), "com.any.app").type)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(desc = "Close"), "com.any.app").type)
        // The ad's own call-to-action is never tapped (that helps the advertiser)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Download now"), "com.google.android.youtube").type)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Shop now"), "com.google.android.youtube").type)

        // Overlay close control
        val close = AdSkipDecisionEngine.decide(node(id = "com.google.android.youtube:id/overlay_close"), "com.google.android.youtube")
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_CLOSE, close.type)

        // Normal playback controls must NEVER be touched
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Play"), "com.google.android.youtube").type)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Pause"), "com.google.android.youtube").type)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(id = "com.google.android.youtube:id/player_control_play"), "com.google.android.youtube").type)
        // Non-clickable skip button is not clicked (the container is, not the label)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Skip Ad", clickable = false), "com.google.android.youtube").type)
        // Other packages are out of scope
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, AdSkipDecisionEngine.decide(node(text = "Skip Ad"), "com.instagram.android").type)
    }

    @Test
    fun autoSkip_skipBeatsClose_andThrottlePreventsFlooding() {
        val candidates = listOf(
            node(id = "app:id/overlay_close") to AdSkipDecisionEngine.Action(AdSkipDecisionEngine.ActionType.CLICK_CLOSE, "id"),
            node(id = "app:id/skip_ad") to AdSkipDecisionEngine.Action(AdSkipDecisionEngine.ActionType.CLICK_SKIP, "id")
        )
        val best = AdSkipDecisionEngine.pickBest(candidates)
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_SKIP, best!!.second.type)

        val throttle = AdSkipDecisionEngine.Throttle(900L)
        assertTrue(throttle.tryAcquire(1_000L))
        assertFalse(throttle.tryAcquire(1_500L)) // inside window
        assertTrue(throttle.tryAcquire(1_950L)) // after window
    }

    // --- Notification Ad Shield classifier ---

    @Test
    fun notifier_adsFlaggedWithTwoSignals_messagingNeverDismissed() {
        val ad = NotificationAdClassifier.classify(
            NotificationAdClassifier.Input("com.some.shop", "FLASH SALE", "50% off everything — limited time, buy now!")
        )
        assertEquals(NotificationAdClassifier.Verdict.LIKELY_AD, ad.verdict)
        assertTrue(ad.signals.size >= 2)

        val kept = NotificationAdClassifier.classify(
            NotificationAdClassifier.Input("com.notes.app", "Weekly digest", "Your notes were synced")
        )
        assertEquals(NotificationAdClassifier.Verdict.KEEP, kept.verdict)

        // Messaging apps are NEVER dismissed even if text looks promotional
        val protectedMsg = NotificationAdClassifier.classify(
            NotificationAdClassifier.Input("com.whatsapp", "Mom", "Check this deal of the day % off coupon")
        )
        assertEquals(NotificationAdClassifier.Verdict.KEEP, protectedMsg.verdict)
        assertTrue(protectedMsg.signals.first().contains("protected package"))
    }

    // --- TLS SNI inspector + firewall decision ---

    /** Builds a minimal TLS ClientHello with an SNI extension. */
    private fun buildClientHello(sni: String): ByteArray {
        val sniBytes = sni.toByteArray(Charsets.US_ASCII)
        val listBody = byteArrayOf(
            (sniBytes.size + 5 shr 8).toByte(), (sniBytes.size + 5).toByte(), // server_name_list length
            0x00, // host_name entry type
            (sniBytes.size shr 8).toByte(), sniBytes.size.toByte(), // name length
            *sniBytes
        )
        // Full extension entry: type 0x0000 (SNI) + extension length + list body
        val extData = byteArrayOf(
            0x00, 0x00, // extension type = server_name
            (listBody.size shr 8).toByte(), listBody.size.toByte(), // extension length
            *listBody
        )
        val body = java.io.ByteArrayOutputStream()
        body.write(0x03); body.write(0x03) // client version TLS1.2
        val random = ByteArray(32); java.util.Random(7).nextBytes(random)
        body.write(random, 0, random.size)
        body.write(0x00) // session id len
        body.write(0x00); body.write(0x02); body.write(0x13); body.write(0x01) // cipher suites len + 1 suite
        body.write(0x01); body.write(0x00) // compression methods
        body.write((extData.size shr 8).toInt()); body.write(extData.size) // extensions len
        body.write(extData)

        val handshake = java.io.ByteArrayOutputStream()
        handshake.write(0x01) // ClientHello
        handshake.write((body.size() shr 16).toInt()); handshake.write((body.size() shr 8).toInt()); handshake.write(body.size())
        handshake.write(body.toByteArray())

        val record = java.io.ByteArrayOutputStream()
        record.write(0x16); record.write(0x03); record.write(0x01)
        record.write((handshake.size() shr 8).toInt()); record.write(handshake.size())
        record.write(handshake.toByteArray())
        return record.toByteArray()
    }

    @Test
    fun sniInspector_parsesRealClientHelloShape_garbageSafe() {
        assertEquals("pubads.g.doubleclick.net", TlsSniInspector.extractSni(buildClientHello("pubads.g.doubleclick.net")))
        assertEquals("ads.mychannel.tv", TlsSniInspector.extractSni(buildClientHello("ads.mychannel.tv")))
        assertNull(TlsSniInspector.extractSni(ByteArray(32)))
        assertNull(TlsSniInspector.extractSni("GET / HTTP/1.1\r\nHost: x.com\r\n\r\n".toByteArray()))
    }

    @Test
    fun sniFirewall_blocksAdConnections_allowsContent() {
        val firewall = SniFirewall { it.endsWith("doubleclick.net") || it == "ads.mychannel.tv" }
        val blocked = firewall.inspect(buildClientHello("pubads.g.doubleclick.net"))
        assertTrue(blocked.blocked)
        assertEquals("pubads.g.doubleclick.net", blocked.sni)

        val allowed = firewall.inspect(buildClientHello("r1---sn-x.googlevideo.com"))
        assertFalse(allowed.blocked)
        assertEquals("r1---sn-x.googlevideo.com", allowed.sni)

        // No-SNI flows are allowed (fail-open — never break connectivity)
        assertFalse(firewall.inspect(ByteArray(24)).blocked)
    }
}
