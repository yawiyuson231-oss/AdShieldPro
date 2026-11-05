package com.adshield.pro

import com.adshield.pro.domain.model.SearchProvider
import com.adshield.pro.domain.model.StorageProvider
import com.adshield.pro.domain.model.StorageProviderHealth
import com.adshield.pro.domain.model.StorageProviderKind
import com.adshield.pro.domain.model.InfinityCapacityCalculator
import com.adshield.pro.engine.aether.SecurityReportExplainer
import com.adshield.pro.engine.browser.PrivateSearch
import com.adshield.pro.engine.download.DirectMediaInspector
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.storage.WebDavClient
import com.adshield.pro.engine.storage.WebDavPath
import com.adshield.pro.engine.storage.WebDavXml
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class InfinityCoreTestSuite {
    @Test
    fun testCapacityAggregation_countsOnlyOnlineProvidersWithMeasuredQuota() {
        val online = provider(id = "a", health = StorageProviderHealth.ONLINE, total = 1_000, available = 400)
        val offline = provider(id = "b", health = StorageProviderHealth.OFFLINE, total = 5_000, available = 4_000)
        val unreported = provider(id = "c", health = StorageProviderHealth.ONLINE, total = null, available = null)
        val checking = provider(id = "d", health = StorageProviderHealth.CHECKING, total = 9_000, available = 8_000)

        val result = InfinityCapacityCalculator.aggregate(listOf(online, offline, unreported, checking))

        assertEquals(1_000, result.provisionedBytes)
        assertEquals(400, result.availableBytes)
        assertEquals(600, result.usedBytes)
        assertEquals(1, result.verifiedProviders)
        assertEquals(2, result.unavailableProviders)
        assertEquals(1, result.unreportedProviders)
    }

    @Test
    fun testCapacityAggregation_sumsMultipleVerifiedServersWithoutAssumedCapacity() {
        val result = InfinityCapacityCalculator.aggregate(
            listOf(
                provider("private", StorageProviderHealth.ONLINE, 1_000, 250),
                provider("provider-a", StorageProviderHealth.ONLINE, 4_000, 1_000),
                provider("provider-b", StorageProviderHealth.ONLINE, 5_000, 2_500)
            )
        )
        assertEquals(10_000, result.provisionedBytes)
        assertEquals(3_750, result.availableBytes)
        assertEquals(6_250, result.usedBytes)
        assertEquals(3, result.verifiedProviders)
    }

    @Test
    fun testWebDavPaths_rejectTraversalAndBuildSafeChildren() {
        assertEquals("Documents/report.pdf", WebDavPath.normalize("/Documents/report.pdf/"))
        assertEquals("Documents/report.pdf", WebDavPath.child("Documents", "report.pdf"))
        assertEquals("", WebDavPath.parent("report.pdf"))
        assertThrows(IllegalArgumentException::class.java) { WebDavPath.normalize("../secret") }
        assertThrows(IllegalArgumentException::class.java) { WebDavPath.child("Documents", "nested/name") }
        assertThrows(IllegalArgumentException::class.java) { WebDavPath.normalize("Documents\\..\\secret") }
    }

    @Test
    fun testWebDavXml_parsesRealMultistatusEntriesAndQuota() {
        val xml = """
            <?xml version="1.0"?>
            <d:multistatus xmlns:d="DAV:">
              <d:response>
                <d:href>/remote.php/dav/files/alice/</d:href>
                <d:propstat><d:prop>
                  <d:quota-available-bytes>400</d:quota-available-bytes>
                  <d:quota-used-bytes>1000</d:quota-used-bytes>
                </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
              </d:response>
              <d:response>
                <d:href>/remote.php/dav/files/alice/Documents/</d:href>
                <d:propstat><d:prop><d:displayname>Documents</d:displayname><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat>
              </d:response>
              <d:response>
                <d:href>/remote.php/dav/files/alice/Documents/report.pdf</d:href>
                <d:propstat><d:prop>
                  <d:displayname>Quarterly report.pdf</d:displayname><d:getcontentlength>1234</d:getcontentlength>
                  <d:getlastmodified>Wed, 04 Nov 2026 01:02:03 GMT</d:getlastmodified><d:getetag>"abc"</d:getetag><d:resourcetype/>
                </d:prop></d:propstat>
              </d:response>
            </d:multistatus>
        """.trimIndent()

        val result = WebDavXml.parseListing(
            xml.byteInputStream(), "provider-a", "https://cloud.example/remote.php/dav/files/alice/".toHttpUrl()
        )

        assertEquals(1_400L, result.quota.totalBytes)
        assertEquals(400L, result.quota.availableBytes)
        assertEquals(1_000L, result.quota.usedBytes)
        assertEquals(2, result.objects.size)
        assertTrue(result.objects[0].isDirectory)
        assertEquals("Documents", result.objects[0].path)
        assertEquals("Documents/report.pdf", result.objects[1].path)
        assertEquals("Quarterly report.pdf", result.objects[1].name)
        assertEquals(1_234L, result.objects[1].sizeBytes)
        assertEquals("abc", result.objects[1].etag)
    }

    @Test
    fun testWebDavXml_parsesOnlyHttpsNextcloudShareLinks() {
        val valid = "<ocs><data><url>https://cloud.example/s/token</url></data></ocs>"
        assertEquals("https://cloud.example/s/token", WebDavXml.parseShareUrl(valid.byteInputStream()))
        val insecure = "<ocs><data><url>http://cloud.example/s/token</url></data></ocs>"
        assertThrows(IllegalArgumentException::class.java) { WebDavXml.parseShareUrl(insecure.byteInputStream()) }
    }

    @Test
    fun testStorageEndpoints_requireHttpsAndRejectEmbeddedCredentials() {
        assertThrows(IllegalArgumentException::class.java) { WebDavClient.endpoint("http://cloud.example/dav") }
        assertThrows(IllegalArgumentException::class.java) { WebDavClient.endpoint("https://user:secret@cloud.example/dav") }
        assertEquals("https://cloud.example/dav", WebDavClient.endpoint("https://cloud.example/dav").toString())
    }

    @Test
    fun testPrivateSearch_selectsProviderAndUpgradesCleartextNavigation() {
        assertEquals(
            "https://duckduckgo.com/?q=private%20search",
            PrivateSearch.navigationTarget("private search", SearchProvider.DUCKDUCKGO)
        )
        assertEquals(
            "https://www.google.com/search?q=private%20search",
            PrivateSearch.navigationTarget("private search", SearchProvider.GOOGLE)
        )
        assertEquals("https://example.com/path", PrivateSearch.navigationTarget("example.com/path", SearchProvider.GOOGLE))
        assertEquals("https://example.com/", PrivateSearch.navigationTarget("http://example.com/", SearchProvider.GOOGLE))
        assertTrue(PrivateSearch.navigationTarget("javascript:alert(1)", SearchProvider.DUCKDUCKGO).startsWith("https://duckduckgo.com/"))
    }

    @Test
    fun testDirectMediaInput_enforcesHttpsAndSafeFileNames() {
        assertThrows(IllegalArgumentException::class.java) { DirectMediaInspector.httpsUrl("http://example.com/movie.mp4") }
        assertThrows(IllegalArgumentException::class.java) { DirectMediaInspector.httpsUrl("https://user:pass@example.com/movie.mp4") }
        assertEquals("movie.mp4", DirectMediaInspector.sanitizeFileName("../../movie.mp4"))
        assertEquals("name.mp4", DirectMediaInspector.sanitizeFileName("bad/name.mp4"))
        assertFalse(DirectMediaInspector.sanitizeFileName("..").contains(".."))
    }

    @Test
    fun testAetherReportExplainer_usesOnlyRecordedEvidenceAndCannotAuthorizeDeletion() {
        val dangerous = scan(SecurityLevel.DANGEROUS, 90, "suspicious.apk", "Dangerous permission stack")
        val clean = scan(SecurityLevel.CLEAN, 0, "photo.jpg", "")
        val summary = SecurityReportExplainer.summarize(listOf(dangerous, clean))

        assertTrue(summary.headline.contains("1 high-severity"))
        assertTrue(summary.explanation.contains("suspicious.apk"))
        assertTrue(summary.explanation.contains("Dangerous permission stack"))
        assertEquals(2, summary.evidenceCount)
        assertTrue(summary.recommendedActions.first().contains("confirmation"))
    }

    @Test
    fun testAetherReportExplainer_emptyHistoryDoesNotInventThreats() {
        val summary = SecurityReportExplainer.summarize(emptyList())
        assertEquals(0, summary.evidenceCount)
        assertTrue(summary.headline.contains("No scan evidence"))
        assertFalse(summary.explanation.contains("malware detected", true))
    }

    private fun provider(id: String, health: StorageProviderHealth, total: Long?, available: Long?) = StorageProvider(
        id = id,
        name = id,
        kind = StorageProviderKind.NEXTCLOUD,
        baseUrl = "https://cloud.example/dav/",
        username = "alice",
        health = health,
        lastCheckedEpochMs = 1L,
        lastError = null,
        totalBytes = total,
        availableBytes = available,
        usedBytes = if (total != null && available != null) total - available else null
    )

    private fun scan(level: SecurityLevel, score: Int, target: String, finding: String) = SecurityScanRecord(
        id = if (level == SecurityLevel.CLEAN) 2L else 1L,
        kind = ScanKind.FILE,
        target = target,
        threatLevel = level,
        riskScore = score,
        threatName = finding.ifBlank { null },
        findings = listOfNotNull(finding.ifBlank { null }),
        recommendation = "Review evidence",
        timestampEpochMs = 1L
    )
}
