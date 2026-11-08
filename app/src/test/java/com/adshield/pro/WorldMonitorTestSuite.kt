package com.adshield.pro

import com.adshield.pro.engine.world.WorldMonitorPolicy
import com.adshield.pro.engine.world.WorldMonitorPolicy.string
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Native policy and packaging contracts. Shared monitor behaviours run in the web CI suite. */
class WorldMonitorTestSuite {
    private fun root(): File = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
        .first { File(it, "world/providers.json").isFile }
    private fun source(relative: String) = File(root(), relative).readText()
    private fun export(name: String = "omnishield-world-test.json", text: String = "{}", mime: String = "application/json") = buildJsonObject {
        put("filename", name); put("content", text); put("mime", mime)
    }.toString()

    @Test
    fun testTrustedOriginRequiresExactHttpsMainFrame() {
        assertTrue(WorldMonitorPolicy.trustedOrigin(WorldMonitorPolicy.ORIGIN, true))
        assertFalse(WorldMonitorPolicy.trustedOrigin(WorldMonitorPolicy.ORIGIN, false))
        for (url in listOf("http://appassets.androidplatform.net", "https://appassets.androidplatform.net.evil.example", "https://evil@appassets.androidplatform.net", "https://appassets.androidplatform.net/path", "https://example.org", "https://appassets.androidplatform.net:8443")) {
            assertFalse(url, WorldMonitorPolicy.trustedOrigin(url, true))
        }
    }

    @Test
    fun testExternalLinksArePublicHttpsOnly() {
        assertTrue(WorldMonitorPolicy.publicHttps("https://earthquake.usgs.gov/report"))
        assertTrue(WorldMonitorPolicy.publicHttps("https://example.org/path?a=b"))
        for (url in listOf("javascript:alert(1)", "file:///etc/passwd", "content://provider/data", "http://example.org", "https://127.0.0.1", "https://10.0.0.1", "https://192.168.1.1", "https://172.20.1.1", "https://[::1]", "https://localhost", "https://a.localhost", "https://box.local", "https://name:password@example.org", WorldMonitorPolicy.ENTRY_URL)) {
            assertFalse(url, WorldMonitorPolicy.publicHttps(url))
        }
    }

    @Test
    fun testExportPolicyAcceptsOnlyBoundedSafeDocuments() {
        val accepted = WorldMonitorPolicy.exportRequest(export(text = "<script>this stays text</script>"))
        assertNotNull(accepted)
        assertEquals("<script>this stays text</script>", accepted?.content)
        assertEquals("omnishield-world-test.json", accepted?.filename)
        assertNotNull(WorldMonitorPolicy.exportRequest(export("omnishield-world-2026-11-08.csv", "a,b", "text/csv")))
        assertNotNull(WorldMonitorPolicy.exportRequest(export("omnishield-world-brief.md", "# Brief", "text/markdown")))
        assertNull(WorldMonitorPolicy.exportRequest("not JSON"))
        assertNull(WorldMonitorPolicy.exportRequest("{}"))
    }

    @Test
    fun testExportRejectsTraversalExecutableMimeAndUtf8Oversize() {
        for (name in listOf("../escape.json", "omnishield-world-../secret.txt", "other-file.json", "omnishield-world-a/b.json")) {
            assertNull(name, WorldMonitorPolicy.exportRequest(export(name)))
        }
        assertNull(WorldMonitorPolicy.exportRequest(export(mime = "text/html")))
        assertNull(WorldMonitorPolicy.exportRequest(export(text = "界".repeat(2_700_000))))
    }

    @Test
    fun testSnapshotReaderEnforcesByteLimitWhileStreaming() {
        assertEquals("Hi 世界", WorldMonitorPolicy.readBoundedUtf8("Hi 世界".byteInputStream(), 9))
        var rejected = false
        try { WorldMonitorPolicy.readBoundedUtf8("界".repeat(100).byteInputStream(), 10) }
        catch (_: IllegalArgumentException) { rejected = true }
        assertTrue("A multibyte snapshot cannot bypass the byte bound", rejected)
    }

    @Test
    fun testScheduledSourcesAreDeduplicatedAndAllowlisted() {
        val data = Json.parseToJsonElement("""{"sources":["usgs","usgs","kev","unknown","https://evil.example",null]}""").jsonObject
        assertEquals(setOf("usgs", "kev"), WorldMonitorPolicy.scheduledSources(data, setOf("usgs", "kev", "eonet")))
        assertTrue(WorldMonitorPolicy.scheduledSources(Json.parseToJsonElement("{}").jsonObject, setOf("usgs")).isEmpty())
    }

    @Test
    fun testAllTwelveBackgroundFormatsHaveRealShapeGuards() {
        val formats = mapOf(
            "usgs" to """{"type":"FeatureCollection","features":[]}""",
            "geonet" to """{"type":"FeatureCollection","features":[]}""",
            "emsc" to """{"type":"FeatureCollection","features":[]}""",
            "gdacs" to """{"type":"FeatureCollection","features":[]}""",
            "nws" to """{"type":"FeatureCollection","features":[]}""",
            "eonet" to """{"events":[]}""",
            "kev" to """{"vulnerabilities":[]}""",
            "advisories" to "[]",
            "noaa" to "[]",
            "gdelt" to """{"articles":[]}""",
            "github-status" to """{"incidents":[]}""",
            "cloudflare-status" to """{"incidents":[]}"""
        )
        assertEquals(12, formats.size)
        formats.forEach { (format, data) ->
            assertTrue(format, WorldMonitorPolicy.validFeedShape(format, data))
            assertFalse(format, WorldMonitorPolicy.validFeedShape(format, "<html>portal</html>"))
            assertFalse(format, WorldMonitorPolicy.validFeedShape(format, """{"error":"denied"}"""))
        }
        assertFalse(WorldMonitorPolicy.validFeedShape("unknown", "[]"))
    }

    @Test
    fun testPackagedProviderRegistryIsDistinctAndHttpsOnly() {
        val root = Json.parseToJsonElement(source("world/providers.json")).jsonObject
        val providers = root["sources"] as JsonArray
        assertEquals(12, providers.size)
        val urls = providers.map { it.jsonObject.string("url")!! }
        assertEquals(urls.size, urls.toSet().size)
        assertTrue(urls.all { WorldMonitorPolicy.publicHttps(it) })
        assertEquals(12, providers.map { it.jsonObject.string("id") }.toSet().size)
    }

    @Test
    fun testWorldAssetsArePackagedAndScreenIsNavigable() {
        val build = source("app/build.gradle.kts")
        assertTrue(build.contains("prepareWorldMonitorAssets"))
        assertTrue(build.contains("world/**"))
        assertTrue(build.contains("assets/country-boundaries.json"))
        assertTrue(build.contains("addGeneratedSourceDirectory(prepareWorldMonitorAssets, WorldMonitorAssetSync::outputDirectory)"))
        val shell = source("app/src/main/java/com/adshield/pro/MainActivity.kt")
        assertTrue(shell.contains("WORLD(\"World\""))
        assertTrue(shell.contains("MainNavDestination.WORLD -> WorldMonitorScreen()"))
        for (file in listOf("world/embed.html", "world/embed.js", "world/view.js", "ui/world.css", "assets/world-land.svg", "assets/country-boundaries.json")) {
            assertTrue(file, File(root(), file).length() > 100)
        }
    }

    @Test
    fun testHostHasNoUnrestrictedJavascriptOrFilesystemInterface() {
        val host = source("app/src/main/java/com/adshield/pro/ui/screens/world/WorldMonitorScreen.kt")
        assertFalse(host.contains("addJavascriptInterface"))
        assertFalse(host.contains("allowFileAccess = true"))
        assertTrue(host.contains("MIXED_CONTENT_NEVER_ALLOW"))
        assertTrue(host.contains("setGeolocationEnabled(false)"))
        assertTrue(host.contains("setOf(WorldMonitorPolicy.ORIGIN)"))
        assertTrue(host.contains("trustedOrigin(origin.toString(), mainFrame)"))
        assertTrue(host.contains("Intent.ACTION_CREATE_DOCUMENT"))
    }

    @Test
    fun testDailyUpdatesAreOptInConstrainedAndKeepPreviousEvidence() {
        val worker = source("app/src/main/java/com/adshield/pro/worker/WorldMonitorWorker.kt")
        assertTrue(worker.contains("getBoolean(ENABLED, false)"))
        assertTrue(worker.contains("NetworkType.CONNECTED"))
        assertTrue(worker.contains("setRequiresBatteryNotLow(true)"))
        assertTrue(worker.contains("24, TimeUnit.HOURS"))
        assertTrue(worker.contains("manager.cancelUniqueWork(UNIQUE_NAME)"))
        assertTrue(worker.contains("previous?.get(\"data\")"))
        assertTrue(worker.contains("file.finishWrite(output)"))
        assertTrue(worker.contains("MAX_FEED_BYTES"))
        assertTrue(worker.contains("followRedirects(false)"))
    }

    @Test
    fun testEmbeddedCspPermitsOnlyPackagedCode() {
        val page = source("world/embed.html")
        assertTrue(page.contains("script-src 'self'"))
        assertTrue(page.contains("frame-src 'none'"))
        assertTrue(page.contains("object-src 'none'"))
        assertFalse(page.contains("<script src=\"https:"))
        assertTrue(source("world/embed.js").contains("WorldMonitorView"))
    }

    @Test
    fun testCountryDirectoryHasExplicitCoverageAndAttribution() {
        val countries = source("world/countries-data.js")
        assertEquals(250, Regex("\"code\":\"[A-Z]{2}\"").findAll(countries).count())
        assertTrue(countries.contains("ODbL-1.0"))
        val ui = source("world/country-view.js")
        assertTrue(ui.contains("no separate polygon"))
        assertTrue(ui.contains("not an absence of hazards"))
        assertTrue(ui.contains("not your GPS position"))
    }
}
