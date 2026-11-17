package com.adshield.pro

import com.adshield.pro.data.cloud.CloudBackupCodec
import com.adshield.pro.data.cloud.CloudBackupManager
import com.adshield.pro.data.cloud.CloudVault
import com.adshield.pro.data.cloud.VaultStorage
import com.adshield.pro.data.cloud.encodeB2HeaderFileName
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.IpPacketFraming
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.download.DirectMediaInspector
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.onion.OnionRoutingManager
import com.adshield.pro.engine.storage.WebDavXml
import com.adshield.pro.engine.worldmonitor.NewsFeedParser
import com.adshield.pro.engine.worldmonitor.WorldMonitorAssetAndTileServer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class SecurityAndReliabilityRegressionTest {

    @Test
    fun browserCosmeticScriptBlocksTemplateLiteralAndCssBreakoutInjection() {
        val blocker = BrowserContentBlocker(FilterRuleEngine())
        val script = blocker.buildCosmeticFilterScript(
            pageHost = "news.example.com",
            allowlistedSites = emptySet(),
            customSelectors = setOf(
                ".legit-sponsored-slot",
                ".bad\${alert(1)}",
                "body { display: block !important; } .x",
                "@import url(https://evil.example/x.css)",
                "[data-track=\${window.pwn}]"
            )
        )
        assertNotNull(script)
        val js = script!!
        assertTrue(js.contains(".legit-sponsored-slot"))
        // Template placeholder must be escaped as \${ so JS never evaluates it.
        assertFalse(js.contains(".bad\${alert(1)}"))
        assertTrue(js.contains("\\\${window.pwn}"))
        assertFalse(js.contains("body { display: block"))
        assertFalse(js.contains("@import"))
    }

    @Test
    fun dnsPacketCodecRejectsHeaderPointerNonQueryOpcodeAndFindsMinTtlAcrossChain() {
        // Header compression pointer (0xC0 0x00 -> offset 0 inside 12-byte header) must fail.
        val badPtr = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0.toByte(), 0x00, 0x00, 0x01, 0x00, 0x01
        )
        assertNull(DnsPacketCodec.parseQuery(badPtr))

        // OPCODE = 1 (IQUERY, flags = 0x0900) must be rejected.
        val badOpcode = byteArrayOf(
            0x12, 0x34, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'a'.code.toByte(), 'd'.code.toByte(), 's'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01
        )
        assertNull(DnsPacketCodec.parseQuery(badOpcode))

        // CNAME TTL = 3600s followed by A TTL = 25s -> extractResponseTtlSeconds must return 25s.
        val resp = ByteArrayOutputStream().apply {
            // Header: QR=1, ANCOUNT=2, QDCOUNT=1
            write(byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00))
            // Question: a.example (offset 12)
            write(byteArrayOf(1, 'a'.code.toByte(), 7))
            write("example".toByteArray(Charsets.US_ASCII))
            write(byteArrayOf(0, 0x00, 0x01, 0x00, 0x01))
            // Answer 1: CNAME (type 5), TTL 3600 (0x00000E10), RDATA = b.example (1 + 1 + 7 + 1 + 1 = 11 bytes)
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x0B))
            write(byteArrayOf(1, 'b'.code.toByte(), 7))
            write("example".toByteArray(Charsets.US_ASCII))
            write(byteArrayOf(0))
            // Answer 2: A (type 1), TTL 25 (0x00000019), RDATA = 93.184.216.34
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x04))
            write(byteArrayOf(93, 184.toByte(), 216.toByte(), 34))
        }.toByteArray()
        assertEquals(25, DnsPacketCodec.extractResponseTtlSeconds(resp))
    }

    @Test
    fun ipPacketFramingRejectsNonFirstIpv6FragmentsAndAllowsFirstFragment() {
        fun buildIpv6FragmentedUdp(fragOffsetUnits: Int): ByteArray {
            val udpPayload = ByteArray(12)
            val udpLen = 8 + udpPayload.size
            val payloadLen = 8 + udpLen // 8-byte fragment header + UDP
            val pkt = ByteArray(40 + payloadLen)
            pkt[0] = 0x60 // IPv6
            pkt[4] = ((payloadLen ushr 8) and 0xFF).toByte()
            pkt[5] = (payloadLen and 0xFF).toByte()
            pkt[6] = 44 // Fragment header
            pkt[7] = 64 // Hop limit
            // Fragment header at offset 40: nextHeader = UDP (17), fragOffset in upper 13 bits of bytes 42..43
            pkt[40] = IpPacketFraming.PROTOCOL_UDP.toByte()
            val fragField = ((fragOffsetUnits and 0x1FFF) shl 3) or 0x01
            pkt[42] = ((fragField ushr 8) and 0xFF).toByte()
            pkt[43] = (fragField and 0xFF).toByte()
            // UDP header at offset 48: srcPort=53000, dstPort=53
            pkt[48] = 0xCF.toByte()
            pkt[49] = 0x08
            pkt[50] = 0x00
            pkt[51] = 0x35
            pkt[52] = 0x00
            pkt[53] = udpLen.toByte()
            return pkt
        }

        val first = IpPacketFraming.parseIpPacket(buildIpv6FragmentedUdp(0))
        assertNotNull(first)
        assertEquals(53, first!!.destinationPort)
        assertNull(IpPacketFraming.parseIpPacket(buildIpv6FragmentedUdp(1)))
    }

    @Test
    fun dnsCacheKeyIsolatesDnssecModesAndVideoSafetyProtectsSharedCdns() {
        val raw = byteArrayOf(
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01
        )
        val query = DnsPacketCodec.parseQuery(raw)!!
        val reportOnly = DnsResolverConfig(dnssecMode = DnssecMode.REPORT_ONLY)
        val strict = DnsResolverConfig(dnssecMode = DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS)
        assertNotEquals(
            UpstreamDnsResolver.buildCacheKey(query, reportOnly),
            UpstreamDnsResolver.buildCacheKey(query, strict)
        )

        // Allowlist rules are never flagged unsafe; wildcard CDN/entity/TLD rules are refused.
        assertNull(DnsMediaPlaybackGuard.explainUnsafe("@@||googlevideo.com^"))
        assertNull(DnsMediaPlaybackGuard.explainUnsafe("*.telemetry.*"))
        assertEquals("SHARED_CDN_BLANKET", DnsMediaPlaybackGuard.explainUnsafe("*.akamaized.net")?.code)
        assertEquals("ENTITY_LEVEL_RULE", DnsMediaPlaybackGuard.explainUnsafe("*.google.com")?.code)
        assertEquals("WILDCARD_TOO_BROAD", DnsMediaPlaybackGuard.explainUnsafe("*.com")?.code)
    }

    @Test
    fun worldMonitorTileServerScopesS3ToElevationBucketAndNewsParserResistsDoubleDecode() {
        assertTrue(WorldMonitorAssetAndTileServer.isAllowedTileHost("s3.amazonaws.com"))
        assertTrue(
            WorldMonitorAssetAndTileServer.isAllowedTileRequest(
                "s3.amazonaws.com",
                "/elevation-tiles-prod/terrarium/4/8/5.png"
            )
        )
        assertTrue(
            WorldMonitorAssetAndTileServer.isAllowedTileRequest(
                "elevation-tiles-prod.s3.amazonaws.com",
                "/terrarium/4/8/5.png"
            )
        )
        assertFalse(
            WorldMonitorAssetAndTileServer.isAllowedTileRequest(
                "s3.amazonaws.com",
                "/untrusted-bucket/tracker.js"
            )
        )
        assertFalse(
            WorldMonitorAssetAndTileServer.isAllowedTileRequest(
                "s3.amazonaws.com",
                "/elevation-tiles-prod/../untrusted-bucket/x.png"
            )
        )

        // &amp;#60; must decode once to literal &#60;, never to `<`.
        assertEquals("&#60;script&#62;", NewsFeedParser.decode("&amp;#60;script&amp;#62;"))
        // Surrogate code points must be dropped safely.
        assertEquals("ok", NewsFeedParser.decode("o&#xD800;k"))
        // Tag/attribute boundaries and scheme safety.
        val atom = """
            <feed>
              <entry>
                <title-short>Wrong</title-short>
                <title>Real Headline</title>
                <link href="javascript:alert(1)"/>
                <link rel="alternate" href="https://example.org/story"/>
                <media:content data-url="https://evil.example/pixel.png" url="https://cdn.example.org/photo.jpg"/>
              </entry>
            </feed>
        """.trimIndent()
        val items = NewsFeedParser.parse(atom)
        assertEquals(1, items.size)
        assertEquals("Real Headline", items[0].title)
        assertEquals("https://example.org/story", items[0].link)
        assertEquals("https://cdn.example.org/photo.jpg", items[0].imageUrl)
    }

    @Test
    fun cloudOnionWebDavAndDirectMediaHardeningInvariantsHold() {
        // Onion charset parser
        assertEquals("UTF-8", OnionRoutingManager.extractCharset("text/html; charset=\"UTF-8\""))
        assertNull(OnionRoutingManager.extractCharset("image/webp"))

        // Cloud backup verification, rule normalization, B2 header encoding & empty AES-GCM payload
        val sample = "payload".toByteArray()
        assertFalse(CloudBackupCodec.verify(sample, ""))
        assertTrue(CloudBackupCodec.verify(sample, CloudBackupCodec.sha256(sample)))
        assertEquals("ads.example.com", CloudBackupManager.normalizeBackupRulePattern("@@||ads.example.com^\$important"))
        assertEquals(
            "u/user-1/nd_1/My%20Photo%20%281%29.jpg",
            encodeB2HeaderFileName("u/user-1/nd_1/My Photo (1).jpg")
        )
        val memStorage = object : VaultStorage {
            var s: ByteArray? = null
            var v: ByteArray? = null
            var iters: Int = 2_000
            override fun salt() = s
            override fun verifier() = v
            override fun iterations() = iters
            override fun save(salt: ByteArray, verifier: ByteArray, iterations: Int) {
                s = salt; v = verifier; iters = iterations
            }
        }
        val vault = CloudVault(memStorage)
        assertTrue(vault.setup("correct-horse-battery-staple".toCharArray(), iterations = 2_000))
        val emptyCipher = vault.encrypt(ByteArray(0))
        assertArrayEquals(ByteArray(0), vault.decrypt(emptyCipher))

        // WebDAV preserves literal `+` while decoding %20
        assertEquals("/dav/C++ Notes+2026.pdf", WebDavXml.percentDecodePath("/dav/C++%20Notes+2026.pdf"))

        // DirectMediaInspector rejects private/loopback SSRF targets and decodes RFC 5987 filenames
        for (bad in listOf(
            "https://localhost/a.mp4",
            "https://127.0.0.1/a.mp4",
            "https://10.0.0.5/a.mp4",
            "https://172.20.1.2/a.mp4",
            "https://192.168.1.10/a.mp4",
            "https://169.254.169.254/a.mp4",
            "https://[::1]/a.mp4"
        )) {
            assertThrows(IllegalArgumentException::class.java) { DirectMediaInspector.httpsUrl(bad) }
        }
        assertEquals("https://cdn.example.com/a.mp4", DirectMediaInspector.httpsUrl("https://cdn.example.com/a.mp4").toString())
        assertEquals(
            "my clip+1.mp4",
            DirectMediaInspector.parseDispositionFileName("attachment; filename*=UTF-8''my%20clip%2B1.mp4")
        )
    }
}
