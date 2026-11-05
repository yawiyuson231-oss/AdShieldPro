package com.adshield.pro

import com.adshield.pro.cloud.CloudConfig
import com.adshield.pro.cloud.CloudFileKind
import com.adshield.pro.cloud.CloudWire
import com.adshield.pro.cloud.DnsBackupSerializer
import com.adshield.pro.cloud.QuotaManager
import com.adshield.pro.engine.browser.SearchProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM coverage for the cloud module's pure logic: quota enforcement, signed-URL validation,
 * duplicate detection, file-type gating, backup integrity and the extended private-search
 * providers. Everything here runs without a device or a network.
 */
class CloudEngineTestSuite {

    // --- QuotaManager ---

    @Test
    fun testQuotaState_thresholds() {
        val quota = 1000L
        assertEquals(QuotaManager.QuotaState.OK, QuotaManager.stateFor(0L, quota))
        assertEquals(QuotaManager.QuotaState.OK, QuotaManager.stateFor(799L, quota))
        assertEquals(QuotaManager.QuotaState.WARNING, QuotaManager.stateFor(800L, quota))
        assertEquals(QuotaManager.QuotaState.BLOCKED, QuotaManager.stateFor(950L, quota))
        assertEquals(QuotaManager.QuotaState.BLOCKED, QuotaManager.stateFor(1000L, quota))
        assertEquals(QuotaManager.QuotaState.UNKNOWN, QuotaManager.stateFor(10L, 0L))
    }

    @Test
    fun testCanUpload_blocksWhenItWouldExceedQuota() {
        val quota = 1000L
        assertTrue(QuotaManager.canUpload(100L, 500L, quota).isSuccess)
        val tooBig = QuotaManager.canUpload(600L, 500L, quota)
        assertTrue(tooBig.isFailure)
        assertTrue(tooBig.exceptionOrNull()!!.message!!.contains("Not enough cloud storage"))
    }

    @Test
    fun testCanUpload_blocksAtGuardFractionEvenIfBytesRemain() {
        // 940 used of 1000, uploading 40 more would land at 98% -> blocked by the 95% guard
        val result = QuotaManager.canUpload(40L, 940L, 1000L)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("95%"))
    }

    @Test
    fun testCanUpload_rejectsOversizeAndUnknownQuota() {
        assertTrue(QuotaManager.canUpload(CloudConfig.CLIENT_SIDE_MAX_FILE_BYTES + 1, 0L, 10L * CloudConfig.CLIENT_SIDE_MAX_FILE_BYTES).isFailure)
        assertTrue(QuotaManager.canUpload(1L, 0L, 0L).isFailure)
        assertTrue(QuotaManager.canUpload(0L, 0L, 1000L).isFailure)
    }

    @Test
    fun testFormatBytes_humanReadable() {
        assertEquals("0 B", QuotaManager.formatBytes(0L))
        assertEquals("512 B", QuotaManager.formatBytes(512L))
        assertEquals("1.0 KB", QuotaManager.formatBytes(1024L))
        assertEquals("10.0 GB", QuotaManager.formatBytes(CloudConfig.R2_FREE_TIER_BYTES))
    }

    // --- CloudWire ---

    @Test
    fun testSignedUrl_expiryParsingAndValidation() {
        val nowMs = 1_700_000_000_000L
        val nowSec = nowMs / 1000L
        val valid = "https://worker.example/api/content?exp=${nowSec + 600}&sig=abc"
        val expired = "https://worker.example/api/content?exp=${nowSec - 1}&sig=abc"
        val noExp = "https://worker.example/api/content?sig=abc"
        val tooLong = "https://worker.example/api/content?exp=${nowSec + CloudConfig.MAX_SIGNED_URL_TTL_SECONDS + 1}&sig=abc"
        assertEquals(nowSec + 600, CloudWire.signedUrlExpiryEpochSec(valid))
        assertNull(CloudWire.signedUrlExpiryEpochSec(noExp))
        assertTrue(CloudWire.isSignedUrlValid(valid, nowMs))
        assertFalse(CloudWire.isSignedUrlValid(expired, nowMs))
        assertFalse(CloudWire.isSignedUrlValid(noExp, nowMs))
        assertFalse(CloudWire.isSignedUrlValid(tooLong, nowMs))
    }

    @Test
    fun testDedupeKey_combinesHashAndSize() {
        assertEquals("abc:100", CloudWire.dedupeKey("abc", 100L))
        assertNotEquals(CloudWire.dedupeKey("abc", 100L), CloudWire.dedupeKey("abc", 101L))
        assertNotEquals(CloudWire.dedupeKey("abc", 100L), CloudWire.dedupeKey("abd", 100L))
    }

    @Test
    fun testFileTypeGate_blocksExecutablesAndActiveContent() {
        assertFalse(CloudWire.isAllowedFileType("virus.apk", "application/vnd.android.package-archive"))
        assertFalse(CloudWire.isAllowedFileType("page.html", "text/html"))
        assertFalse(CloudWire.isAllowedFileType("icon.svg", "image/svg+xml"))
        assertTrue(CloudWire.isAllowedFileType("photo.jpg", "image/jpeg"))
        assertTrue(CloudWire.isAllowedFileType("notes.txt", "text/plain"))
        assertTrue(CloudWire.isAllowedFileType("dns.adshield-backup", "application/x-adshield-backup"))
    }

    @Test
    fun testFileKind_classification() {
        assertEquals(CloudFileKind.PHOTO, CloudFileKind.fromMime("image/png"))
        assertEquals(CloudFileKind.VIDEO, CloudFileKind.fromMime("video/mp4"))
        assertEquals(CloudFileKind.MUSIC, CloudFileKind.fromMime("audio/mpeg"))
        assertEquals(CloudFileKind.DOCUMENT, CloudFileKind.fromMime("application/pdf"))
        assertEquals(CloudFileKind.BACKUP, CloudFileKind.fromMime("application/x-adshield-backup"))
        assertEquals(CloudFileKind.OTHER, CloudFileKind.fromMime("application/octet-stream"))
    }

    // --- DnsBackupSerializer ---

    @Test
    fun testDnsBackup_roundTripAndTamperDetection() {
        val inner = """{"protectionMode":"STANDARD","customRules":[]}"""
        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val backup = json.encodeToString(
            DnsBackupSerializer.DnsCloudBackup.serializer(),
            DnsBackupSerializer.DnsCloudBackup(createdAtEpochMs = 1L, appVersion = "2.7.0", payloadJson = inner)
        )
        assertEquals(inner, DnsBackupSerializer.parseBackup(backup))
        // tampering with the inner payload changes the returned settings (the caller detects it via SHA-256)
        assertNotEquals(inner, DnsBackupSerializer.parseBackup(backup.replace("STANDARD", "STRICT")))
        // wrong format/version or garbage must be rejected outright
        assertNull(DnsBackupSerializer.parseBackup("""{"format":"other","version":1,"createdAtEpochMs":1,"appVersion":"x","payloadJson":"{}"}"""))
        assertNull(DnsBackupSerializer.parseBackup("not json at all"))
    }

    @Test
    fun testDnsBackup_sha256IsStableAndSensitive() {
        val a = DnsBackupSerializer.sha256Hex("adshield")
        assertEquals(a, DnsBackupSerializer.sha256Hex("adshield"))
        assertEquals(64, a.length)
        assertNotEquals(a, DnsBackupSerializer.sha256Hex("adshield2"))
    }

    // --- Private search providers ---

    @Test
    fun testSearchProviders_extendedSetEncodesOnce() {
        val q = "a & b=1"
        for (provider in SearchProvider.entries) {
            val url = provider.searchUrl(q)
            assertTrue("$provider: $url", url.startsWith("https://"))
            assertTrue("$provider must percent-encode & and =", !url.contains("& b") && url.contains("%26"))
        }
        assertEquals(
            "https://search.brave.com/search?q=a%20%26%20b%3D1",
            SearchProvider.BRAVE.searchUrl(q)
        )
        assertTrue(SearchProvider.DUCKDUCKGO_ONION.homeUrl.contains(".onion"))
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName("garbage"))
        assertEquals(SearchProvider.BRAVE, SearchProvider.fromName("brave"))
    }
}
