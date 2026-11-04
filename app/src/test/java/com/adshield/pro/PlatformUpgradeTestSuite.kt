package com.adshield.pro

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.DnsAnomalyScorer
import com.adshield.pro.engine.aether.LiveNetworkModel
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.browser.PrivateSearchEngine
import com.adshield.pro.engine.browser.SearchProvider
import com.adshield.pro.engine.dns.DnsLeakDetector
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.downloader.MediaDownloaderEngine
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.platform.DeviceCompatibility
import com.adshield.pro.engine.platform.DiagnosticReportBuilder
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.FileThreatScanner
import com.adshield.pro.engine.security.SecurityEngine
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanHistoryStore
import com.adshield.pro.engine.security.SystemScannerEngine
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.engine.storage.PrivateCloudBoxEngine
import com.adshield.pro.engine.storage.UniversalFileManager
import com.adshield.pro.engine.storage.VaultCrypto
import com.adshield.pro.service.AdShieldVpnService
import com.adshield.pro.worker.BatteryAlertWorker
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * End-to-end verification suite for all upgraded Android platform capabilities:
 * - On-device DNS Leak & Bypass Auditor
 * - Deterministic Shannon-entropy / DGA DNS Anomaly Scorer & Rule Suggestions
 * - Private Search Engine (DuckDuckGo + Google Search, HTTPS auto-upgrade, redirect unwrapping)
 * - Universal Video & Music Downloader (HTTP Range 206 pause/resume, HTML5 & HLS probing, DRM/platform guardrails)
 * - Complete 6-Module System Scanner + Persistent Scan History Store
 * - Battery Thermal & Charge-Complete Alert Worker cooldown logic
 * - AES-256-GCM VaultCrypto + PBKDF2-HMAC-SHA256 PIN verification
 * - Private Cloud Storage Box + real loopback WebDAV sync (`MKCOL`, `PUT`, `GET`, `DELETE`)
 * - Universal File & APK Manager + magic-byte MIME spoof detection
 * - Privacy-scrubbed DiagnosticReportBuilder
 * - Batch 1 engine bug-fix regressions
 */
class PlatformUpgradeTestSuite {

    @Test
    fun testDnsLeakDetector_flagsPrivateDnsAndUnencryptedUpstreams() {
        val protectedInput = DnsLeakDetector.LeakAuditInput(
            vpnTunnelConnected = true,
            vpnDnsServers = listOf(AdShieldVpnService.VIRTUAL_IPV4_DNS, AdShieldVpnService.VIRTUAL_IPV6_DNS),
            physicalDnsServers = listOf("192.168.1.1"),
            systemPrivateDnsActive = false,
            systemPrivateDnsHost = null,
            hasIpv6Connectivity = true,
            resolverConfig = DnsResolverConfig(
                preset = DnsProviderPreset.CLOUDFLARE,
                protocol = DnsProtocol.DOH,
                enableIpv6 = true
            ),
            liveProbeSucceeded = true,
            liveProbeProtocol = "DOH",
            liveProbeLatencyMs = 28
        )
        val protectedReport = DnsLeakDetector.evaluateAudit(protectedInput)
        assertEquals(DnsLeakDetector.AuditVerdict.PROTECTED, protectedReport.verdict)
        assertTrue(protectedReport.encryptedUpstream)
        assertTrue(protectedReport.tunnelCapturesDns)

        // Android System Private DNS active -> BYPASS_RISK
        val privateDnsBypass = DnsLeakDetector.evaluateAudit(
            protectedInput.copy(systemPrivateDnsActive = true, systemPrivateDnsHost = "dns.google")
        )
        assertEquals(DnsLeakDetector.AuditVerdict.BYPASS_RISK, privateDnsBypass.verdict)
        assertTrue(privateDnsBypass.findings.any { it.contains("Private DNS", ignoreCase = true) })

        // Unencrypted UDP/TCP upstream -> BYPASS_RISK
        val unencrypted = DnsLeakDetector.evaluateAudit(
            protectedInput.copy(
                resolverConfig = protectedInput.resolverConfig.copy(protocol = DnsProtocol.UDP_TCP)
            )
        )
        assertEquals(DnsLeakDetector.AuditVerdict.BYPASS_RISK, unencrypted.verdict)
        assertFalse(unencrypted.encryptedUpstream)

        // Disconnected VPN -> UNPROTECTED
        val disconnected = DnsLeakDetector.evaluateAudit(
            protectedInput.copy(vpnTunnelConnected = false)
        )
        assertEquals(DnsLeakDetector.AuditVerdict.UNPROTECTED, disconnected.verdict)
    }

    @Test
    fun testDnsAnomalyScorer_scoresHighEntropyDgaAndSuggestsRules() {
        val benign = DnsAnomalyScorer.scoreDomain("www.wikipedia.org")
        assertFalse("Benign domain should not be flagged anomalous: ${benign.reasons}", benign.isAnomalous)

        val dga = DnsAnomalyScorer.scoreDomain("x9q7k2m8z4p1w6r3v5t0b8n.sub1.sub2.sub3.example.net")
        assertTrue("High-entropy numeric/consonant DGA host must be flagged anomalous, got ${dga.anomalyScore}", dga.isAnomalous)
        assertTrue(dga.reasons.isNotEmpty())

        val now = 1_730_000_000_000L
        val logs = (1..8).map { i ->
            DnsActivityRecord(
                id = i.toLong(),
                timestampEpochMs = now + i * 1000L,
                domain = "x9q7k2m8z4p1w6r3v5t0b8n.sub1.sub2.sub3.example.net",
                queryType = "A",
                isBlocked = false,
                category = null,
                matchedRule = null,
                sourceList = "Allowed",
                latencyMs = 20,
                protocolUsed = "DOH"
            )
        }
        val suggestions = DnsAnomalyScorer.suggestRulesFromLogs(logs)
        assertTrue(suggestions.any { it.domain.startsWith("x9q7k2m8z4p1w6r3v5t0b8n") && it.suggestedRuleType == RuleType.BLOCK })
    }

    @Test
    fun testPrivateSearchEngine_supportsDuckDuckGoAndGoogleWithHttpsAndTrackerStripping() {
        val ddgUrl = PrivateSearchEngine.buildSearchUrl("android dns privacy", SearchProvider.DUCKDUCKGO, safeSearchStrict = true)
        assertTrue(ddgUrl.startsWith("https://duckduckgo.com/?q=android%20dns%20privacy"))
        assertTrue(ddgUrl.contains("kp=1"))

        val googleUrl = PrivateSearchEngine.buildSearchUrl("android dns privacy", SearchProvider.GOOGLE, safeSearchStrict = true)
        assertTrue(googleUrl.startsWith("https://www.google.com/search?q=android%20dns%20privacy"))
        assertTrue(googleUrl.contains("pws=0"))
        assertTrue(googleUrl.contains("safe=active"))

        // Plaintext HTTP domain auto-upgrades to HTTPS
        val upgraded = PrivateSearchEngine.resolveNavigationInput(
            rawInput = "http://example.org/docs?id=7&utm_source=newsletter&gclid=abc123",
            provider = SearchProvider.DUCKDUCKGO,
            upgradeHttpToHttps = true
        )
        assertEquals("https://example.org/docs?id=7", upgraded)

        // Unwraps DuckDuckGo & Google redirect tracker wrappers
        val unwrappedDdg = PrivateSearchEngine.sanitizeAndUnwrapUrl(
            "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fdeveloper.android.com%2Fguide%3Ffbclid%3D999%26topic%3Dvpn"
        )
        assertEquals("https://developer.android.com/guide?topic=vpn", unwrappedDdg)

        val unwrappedGoogle = PrivateSearchEngine.sanitizeAndUnwrapUrl(
            "https://www.google.com/url?q=https%3A%2F%2Fkotlinlang.org%2Fdocs%3Futm_medium%3Dcpc&sa=U&ved=2ahUKE"
        )
        assertEquals("https://kotlinlang.org/docs", unwrappedGoogle)

        // Dangerous javascript: scheme is neutralized into a safe search query
        val blockedJs = PrivateSearchEngine.resolveNavigationInput("javascript:alert(1)", SearchProvider.DUCKDUCKGO)
        assertTrue(blockedJs.startsWith("https://duckduckgo.com/?q="))

        val headers = PrivateSearchEngine.privacyRequestHeaders()
        assertEquals("1", headers["DNT"])
        assertEquals("1", headers["Sec-GPC"])
    }

    @Test
    fun testMediaDownloader_probesFormatsSupportsPauseResumeAndRejectsDrm() = runBlocking {
        val rootDir = Files.createTempDirectory("adshield_dl_test").toFile()
        val firstChunkDelivered = CountDownLatch(1)
        val allowRemainingChunks = CountDownLatch(1)

        // Build a synthetic valid MP4 header ("....ftypisom") + deterministic 128 KB payload
        val mp4Payload = ByteArray(128 * 1024).also { buf ->
            val ftyp = byteArrayOf(0, 0, 0, 24, 'f'.code.toByte(), 't'.code.toByte(), 'y'.code.toByte(), 'p'.code.toByte(), 'i'.code.toByte(), 's'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte())
            System.arraycopy(ftyp, 0, buf, 0, ftyp.size)
            for (i in ftyp.size until buf.size) {
                buf[i] = ((i * 31 + 7) and 0xFF).toByte()
            }
        }
        val expectedMp4Sha256 = MessageDigest.getInstance("SHA-256")
            .digest(mp4Payload)
            .joinToString("") { "%02x".format(it) }

        val hlsSeg1 = ByteArray(2048) { 0x47 } // MPEG-TS sync byte 0x47
        val hlsSeg2 = ByteArray(2048) { (0x47 xor (it and 0x0F)).toByte() }

        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.executor = Executors.newCachedThreadPool()
        val port = server.address.port
        val baseUrl = "http://127.0.0.1:$port"

        server.createContext("/video/sample.mp4") { exchange ->
            val rangeHeader = exchange.requestHeaders.getFirst("Range")
            exchange.responseHeaders.add("Content-Type", "video/mp4")
            exchange.responseHeaders.add("Accept-Ranges", "bytes")
            exchange.responseHeaders.add("ETag", "\"v1-sample-mp4\"")

            if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
                val spec = rangeHeader.removePrefix("bytes=")
                val start = spec.substringBefore('-').toInt()
                val endSpec = spec.substringAfter('-', "")
                val isProbeRange = endSpec == "65535"
                val end = if (endSpec.isNotEmpty()) minOf(endSpec.toInt(), mp4Payload.size - 1) else mp4Payload.size - 1
                val length = end - start + 1
                exchange.responseHeaders.add("Content-Range", "bytes $start-$end/${mp4Payload.size}")
                exchange.sendResponseHeaders(206, length.toLong())
                exchange.responseBody.use { out ->
                    if (isProbeRange || start > 0) {
                        out.write(mp4Payload, start, length)
                    } else {
                        out.write(mp4Payload, 0, 32 * 1024)
                        out.flush()
                        firstChunkDelivered.countDown()
                        allowRemainingChunks.await(3, TimeUnit.SECONDS)
                        out.write(mp4Payload, 32 * 1024, length - 32 * 1024)
                    }
                }
            } else {
                exchange.sendResponseHeaders(200, mp4Payload.size.toLong())
                exchange.responseBody.use { out ->
                    out.write(mp4Payload, 0, 32 * 1024)
                    out.flush()
                    firstChunkDelivered.countDown()
                    allowRemainingChunks.await(3, TimeUnit.SECONDS)
                    out.write(mp4Payload, 32 * 1024, mp4Payload.size - 32 * 1024)
                }
            }
        }

        server.createContext("/page.html") { exchange ->
            val html = """
                <html><head><title>Open Creative Commons Lecture</title></head>
                <body>
                  <video>
                    <source src="$baseUrl/video/sample.mp4" type="video/mp4" label="1080p" />
                  </video>
                </body></html>
            """.trimIndent().toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "text/html; charset=utf-8")
            exchange.sendResponseHeaders(200, html.size.toLong())
            exchange.responseBody.use { it.write(html) }
        }

        server.createContext("/live/playlist.m3u8") { exchange ->
            val m3u8 = """
                #EXTM3U
                #EXT-X-VERSION:3
                #EXTINF:4.0,
                $baseUrl/live/seg1.ts
                #EXTINF:4.0,
                $baseUrl/live/seg2.ts
                #EXT-X-ENDLIST
            """.trimIndent().toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "application/vnd.apple.mpegurl")
            exchange.sendResponseHeaders(200, m3u8.size.toLong())
            exchange.responseBody.use { it.write(m3u8) }
        }
        server.createContext("/live/seg1.ts") { ex ->
            ex.responseHeaders.add("Content-Type", "video/mp2t")
            ex.sendResponseHeaders(200, hlsSeg1.size.toLong())
            ex.responseBody.use { it.write(hlsSeg1) }
        }
        server.createContext("/live/seg2.ts") { ex ->
            ex.responseHeaders.add("Content-Type", "video/mp2t")
            ex.sendResponseHeaders(200, hlsSeg2.size.toLong())
            ex.responseBody.use { it.write(hlsSeg2) }
        }

        server.createContext("/drm/encrypted.m3u8") { ex ->
            val drmM3u8 = "#EXTM3U\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"skd://drm\"\n#EXTINF:4.0,\nseg1.ts\n".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/vnd.apple.mpegurl")
            ex.sendResponseHeaders(200, drmM3u8.size.toLong())
            ex.responseBody.use { it.write(drmM3u8) }
        }

        server.createContext("/drm/stream.mpd") { ex ->
            val mpd = "<MPD><Period><AdaptationSet><ContentProtection schemeIdUri=\"urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\"/></AdaptationSet></Period></MPD>".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/dash+xml")
            ex.sendResponseHeaders(200, mpd.size.toLong())
            ex.responseBody.use { it.write(mpd) }
        }

        server.start()
        try {
            val engine = MediaDownloaderEngine(
                defaultDownloadDir = File(rootDir, "downloads"),
                stateStoreFile = File(rootDir, "history.json"),
                httpClient = OkHttpClient(),
                allowLoopbackHttpForTesting = true
            )

            // 1. Copyright / Terms-restricted streaming platforms & DRM manifests MUST be rejected
            assertTrue(engine.probeUrl("https://www.youtube.com/watch?v=dQw4w9WgXcQ").isFailure)
            assertTrue(engine.probeUrl("https://open.spotify.com/track/12345").isFailure)
            assertTrue(engine.probeUrl("$baseUrl/drm/encrypted.m3u8").isFailure)
            assertTrue(engine.probeUrl("$baseUrl/drm/stream.mpd").isFailure)

            // 2. HTML5 open media page probe discovers MP4 video + M4A audio demux option
            val htmlProbe = engine.probeUrl("$baseUrl/page.html").getOrThrow()
            assertEquals("Open Creative Commons Lecture", htmlProbe.title)
            assertTrue(htmlProbe.formats.any { it.containerFormat == "MP4" })

            // 3. Direct MP4 probe + Pause + HTTP Range 206 Resume + SHA-256 verification
            val mp4Probe = engine.probeUrl("$baseUrl/video/sample.mp4").getOrThrow()
            val mp4Format = mp4Probe.formats.first { it.containerFormat == "MP4" && !it.extractAudioOnlyFromMp4 }
            assertTrue(mp4Format.supportsRangeResume)

            val task = engine.startDownload(mp4Probe, mp4Format)
            assertTrue("First chunk should arrive before pause", firstChunkDelivered.await(3, TimeUnit.SECONDS))
            engine.pauseDownload(task.id)
            allowRemainingChunks.countDown()
            engine.awaitTaskSettlement(task.id)

            val pausedState = engine.tasks.value.first { it.id == task.id }
            assertEquals(MediaDownloaderEngine.DownloadStatus.PAUSED, pausedState.status)
            assertTrue("Partial bytes must be preserved on disk", File("${pausedState.outputFilePath}.part").length() >= 32 * 1024L)

            engine.resumeDownload(task.id)
            engine.awaitTaskSettlement(task.id)

            val completedState = engine.tasks.value.first { it.id == task.id }
            assertEquals(MediaDownloaderEngine.DownloadStatus.COMPLETED, completedState.status)
            assertEquals(expectedMp4Sha256, completedState.sha256)
            assertArrayEquals(mp4Payload, File(completedState.outputFilePath).readBytes())

            // 4. Unencrypted HLS (.m3u8) segment download & concatenation
            val hlsProbe = engine.probeUrl("$baseUrl/live/playlist.m3u8").getOrThrow()
            val hlsTask = engine.startDownload(hlsProbe, hlsProbe.formats.first())
            engine.awaitTaskSettlement(hlsTask.id)
            val finishedHls = engine.tasks.value.first { it.id == hlsTask.id }
            assertEquals(MediaDownloaderEngine.DownloadStatus.COMPLETED, finishedHls.status)
            assertEquals((hlsSeg1.size + hlsSeg2.size).toLong(), File(finishedHls.outputFilePath).length())
        } finally {
            allowRemainingChunks.countDown()
            server.stop(0)
            rootDir.deleteRecursively()
        }
    }

    @Test
    fun testSystemScanner_runsAllSixModulesReportsProgressFindingsErrorsAndPersistsHistory() = runBlocking {
        val tempDir = Files.createTempDirectory("adshield_sysscan").toFile()
        try {
            val scanFolder = File(tempDir, "downloads").apply { mkdirs() }
            File(scanFolder, "readme.txt").writeText("Clean document content")
            File(scanFolder, "eicar_test.com").writeBytes(
                FileThreatScanner.EICAR_STRING.toByteArray(Charsets.ISO_8859_1)
            )

            val progressUpdates = ArrayList<SystemScannerEngine.SystemScanProgress>()
            val scanner = SystemScannerEngine()
            val report = scanner.runCompleteScan(
                inputs = SystemScannerEngine.ScanInputs(
                    vpnConnected = false,
                    protectionMode = ProtectionMode.STANDARD,
                    dnsProtocol = DnsProtocol.UDP_TCP,
                    threatSignatureCount = 500,
                    httpsUpgradeEnabled = true,
                    blockThirdPartyCookies = true,
                    auditAppsProvider = {
                        listOf(
                            AppRiskAuditor().audit(
                                AppRiskAuditor.AppSecurityProfile(
                                    packageName = "com.example.clean",
                                    appName = "Clean Utility",
                                    versionName = "1.0",
                                    targetSdkVersion = 35,
                                    requestedPermissions = listOf("android.permission.INTERNET"),
                                    installerPackageName = "com.android.vending",
                                    isSystemApp = false,
                                    isUpdatedSystemApp = false,
                                    firstInstallTimeEpochMs = 1_700_000_000_000L
                                )
                            )
                        )
                    },
                    scanDirectories = listOf(scanFolder),
                    storageUsedPercent = 62f,
                    storageAvailableBytes = 32L * 1024 * 1024 * 1024,
                    recoverableJunkBytes = 12L * 1024 * 1024,
                    ramUsagePercent = 58f,
                    isLowMemory = false,
                    sdkInt = 35,
                    supportedPlatform = true,
                    batteryTempCelsius = 33.0f,
                    batteryHealthGood = true,
                    enabledFilterListCount = 4,
                    totalLoadedRules = 85_000,
                    ruleConflictCount = 0,
                    lastFilterSyncEpochMs = System.currentTimeMillis()
                ),
                onProgress = { progressUpdates.add(it) }
            )

            assertEquals(6, report.modules.size)
            assertTrue("Progress callbacks must fire across all modules", progressUpdates.size >= 6)
            assertEquals(SecurityLevel.DANGEROUS, report.overallLevel)
            assertTrue(report.totalFindings >= 2)
            assertTrue(report.toDetailedReportText().contains("EICAR"))

            val historyFile = File(tempDir, "security_scan_history.json")
            val store = SecurityScanHistoryStore(historyFile)
            store.recordSystemScan(report)

            val reloadedStore = SecurityScanHistoryStore(historyFile)
            assertEquals(1, reloadedStore.getSystemReports().size)
            assertEquals(report.id, reloadedStore.getSystemReports().first().id)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testBatteryAlertWorker_triggersOnOverheatAndFullChargeWithCooldown() {
        val now = 1_730_000_000_000L

        // 1. Overheating >= 45.0°C triggers alert 7101
        val overheat = BatteryAlertWorker.evaluateAlertDecision(
            tempCelsius = 46.2f,
            levelPercent = 70,
            isCharging = true,
            isFull = false,
            lastThermalAlertMs = 0L,
            lastFullChargeAlertMs = 0L,
            nowEpochMs = now
        )
        assertNotNull(overheat)
        assertEquals(7101, overheat!!.notificationId)

        // 2. Within 2-hour cooldown, overheating does NOT spam a duplicate notification
        val suppressedByCooldown = BatteryAlertWorker.evaluateAlertDecision(
            tempCelsius = 46.5f,
            levelPercent = 72,
            isCharging = true,
            isFull = false,
            lastThermalAlertMs = now - 600_000L,
            lastFullChargeAlertMs = 0L,
            nowEpochMs = now
        )
        assertNull(suppressedByCooldown)

        // 3. Full charge (100% while charging) triggers alert 7102
        val fullCharge = BatteryAlertWorker.evaluateAlertDecision(
            tempCelsius = 32.0f,
            levelPercent = 100,
            isCharging = true,
            isFull = true,
            lastThermalAlertMs = 0L,
            lastFullChargeAlertMs = 0L,
            nowEpochMs = now
        )
        assertNotNull(fullCharge)
        assertEquals(7102, fullCharge!!.notificationId)
    }

    @Test
    fun testVaultCrypto_aes256GcmEncryptDecryptDetectsTamperingAndVerifiesPin() {
        val key = VaultCrypto.generateRandomAes256Key()
        val plaintext = "Confidential private vault payload — zero cloud exposure".toByteArray(StandardCharsets.UTF_8)

        val encrypted = VaultCrypto.encryptBytes(plaintext, key)
        assertTrue(VaultCrypto.isEncryptedEnvelope(encrypted))
        assertArrayEquals(plaintext, VaultCrypto.decryptBytes(encrypted, key))

        // Flip 1 bit in the GCM authentication tag -> decryption MUST throw AEADBadTagException
        val tampered = encrypted.copyOf()
        tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x01).toByte()
        val tamperFailed = runCatching { VaultCrypto.decryptBytes(tampered, key) }.isFailure
        assertTrue("AES-256-GCM must reject tampered ciphertext", tamperFailed)

        // PBKDF2-HMAC-SHA256 PIN verification
        val verifier = VaultCrypto.createPinVerifier("482910")
        assertTrue(VaultCrypto.verifyPin("482910", verifier))
        assertFalse(VaultCrypto.verifyPin("999999", verifier))
    }

    @Test
    fun testPrivateCloudBox_uploadOrganizePreviewDeletePinAndWebDavSync() = runBlocking {
        val tempRoot = Files.createTempDirectory("adshield_vault_test").toFile()
        val davStorage = ConcurrentHashMap<String, ByteArray>()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val port = server.address.port

        server.createContext("/dav") { exchange ->
            val auth = exchange.requestHeaders.getFirst("Authorization").orEmpty()
            if (!auth.startsWith("Basic ")) {
                exchange.sendResponseHeaders(401, -1)
                exchange.close()
                return@createContext
            }
            val path = exchange.requestURI.path
            when (exchange.requestMethod.uppercase()) {
                "MKCOL" -> exchange.sendResponseHeaders(201, -1)
                "PUT" -> {
                    val body = exchange.requestBody.readBytes()
                    davStorage[path] = body
                    exchange.sendResponseHeaders(201, -1)
                }
                "GET" -> {
                    val body = davStorage[path]
                    if (body == null) {
                        exchange.sendResponseHeaders(404, -1)
                    } else {
                        exchange.sendResponseHeaders(200, body.size.toLong())
                        exchange.responseBody.use { it.write(body) }
                    }
                }
                "DELETE" -> {
                    davStorage.remove(path)
                    exchange.sendResponseHeaders(204, -1)
                }
                else -> exchange.sendResponseHeaders(405, -1)
            }
            exchange.close()
        }
        server.start()

        try {
            val secretKey = VaultCrypto.generateRandomAes256Key()
            val vault = PrivateCloudBoxEngine(
                rootDir = tempRoot,
                secretKeyProvider = { secretKey },
                httpClient = OkHttpClient(),
                allowLoopbackHttpForTesting = true
            )

            // 1. Upload document, verify encrypted at rest, preview text, move folder
            val docBytes = "Top secret tax notes 2026 — encrypted locally.".toByteArray(StandardCharsets.UTF_8)
            val uploaded = vault.uploadStream(
                inputStream = ByteArrayInputStream(docBytes),
                displayName = "tax_notes_2026.txt",
                mimeType = "text/plain"
            ).getOrThrow()

            assertEquals(PrivateCloudBoxEngine.VaultCategory.DOCUMENTS, uploaded.category)
            assertTrue(uploaded.encryptedAtRest)

            val preview = vault.buildPreview(uploaded.id).getOrThrow() as PrivateCloudBoxEngine.VaultPreview.TextPreview
            assertEquals("Top secret tax notes 2026 — encrypted locally.", preview.text)

            vault.createFolder("Taxes").getOrThrow()
            val moved = vault.moveItemToFolder(uploaded.id, "Taxes").getOrThrow()
            assertEquals("Taxes", moved.folder)

            // 2. Configure WebDAV sync and verify cloud server receives ONLY AES-256-GCM ciphertext
            vault.configureCloudEndpoint(
                PrivateCloudBoxEngine.CloudEndpointConfig(
                    serverBaseUrl = "http://127.0.0.1:$port/dav",
                    username = "alice",
                    passwordOrToken = "app-token-secret",
                    uploadEncryptedEnvelope = true
                )
            ).getOrThrow()

            val synced = vault.syncItemToCloud(moved.id).getOrThrow()
            assertNotNull(synced.cloudSyncedAtEpochMs)
            assertEquals(1, davStorage.size)
            val remoteBytes = davStorage.values.first()
            assertTrue("Cloud server must receive encrypted ADSV1 envelope", VaultCrypto.isEncryptedEnvelope(remoteBytes))
            assertFalse("Cloud server must never see plaintext", String(remoteBytes, StandardCharsets.ISO_8859_1).contains("Top secret"))

            // 3. Delete local blob and prove downloadToStream restores & verifies SHA-256 from WebDAV
            File(tempRoot, "blobs/${moved.id}.enc").delete()
            val restoredOut = ByteArrayOutputStream()
            vault.downloadToStream(moved.id, restoredOut).getOrThrow()
            assertArrayEquals(docBytes, restoredOut.toByteArray())

            // 4. PIN lock hides items until unlocked
            vault.setOrUpdatePin("7391").getOrThrow()
            vault.lockVault()
            assertTrue(vault.storageSummary().isLocked)
            assertTrue(vault.listItems().isEmpty())
            assertFalse(vault.unlockVault("0000"))
            assertTrue(vault.unlockVault("7391"))
            assertEquals(1, vault.listItems().size)

            // 5. Delete item locally + remotely
            vault.deleteItem(moved.id, deleteRemoteToo = true).getOrThrow()
            assertTrue(vault.listItems().isEmpty())
            assertTrue(davStorage.isEmpty())
        } finally {
            server.stop(0)
            tempRoot.deleteRecursively()
        }
    }

    @Test
    fun testUniversalFileManager_importsClassifiesDetectsMimeSpoofAndInspectsApks() = runBlocking {
        val dir = Files.createTempDirectory("adshield_ufm_test").toFile()
        try {
            val manager = UniversalFileManager(workspaceDir = dir)

            // 1. Valid PNG header classified as PHOTO + CLEAN
            val pngHeader = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + ByteArray(64)
            val pngItem = manager.importStream(ByteArrayInputStream(pngHeader), "vacation.png", "image/png").getOrThrow()
            assertEquals(UniversalFileManager.ManagedMediaKind.PHOTO, pngItem.kind)
            assertEquals(SecurityLevel.CLEAN, pngItem.securityLevel)
            assertNull(pngItem.mimeMismatchWarning)

            // 2. Windows PE executable ("MZ") disguised as "invoice.jpg" -> MIME spoof warning + SUSPICIOUS
            val spoofedExe = byteArrayOf(0x4D, 0x5A, 0x90.toByte(), 0x00) + ByteArray(128)
            val spoofItem = manager.importStream(ByteArrayInputStream(spoofedExe), "invoice.jpg", "image/jpeg").getOrThrow()
            assertNotNull("Magic-byte spoof must be detected", spoofItem.mimeMismatchWarning)
            assertTrue(spoofItem.riskScore >= 45)
            assertTrue(spoofItem.securityLevel != SecurityLevel.CLEAN)

            // 3. Minimal ZIP/APK container classified as APK
            val zipBytes = ByteArrayOutputStream().apply {
                ZipOutputStream(this).use { zos ->
                    zos.putNextEntry(ZipEntry("classes.dex"))
                    zos.write("dex\n035\u0000".toByteArray())
                    zos.closeEntry()
                }
            }.toByteArray()
            val apkItem = manager.importStream(ByteArrayInputStream(zipBytes), "sample.apk", "application/vnd.android.package-archive").getOrThrow()
            assertEquals(UniversalFileManager.ManagedMediaKind.APK, apkItem.kind)
            assertEquals(3, manager.listManagedFiles().size)
            assertTrue(manager.deleteManagedItem(pngItem.id))
            assertEquals(2, manager.listManagedFiles().size)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun testDiagnosticReportBuilder_scrubsCustomEndpointsAndSerializesCleanly() {
        val customResolver = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.DOH,
            customDohUrl = "https://dns.nextdns.io/secret-profile-abc123?device=my-phone"
        )
        val json = DiagnosticReportBuilder.buildJson(
            versionName = "2.6.0",
            versionCode = 20600,
            deviceProfile = null,
            vpnState = VpnRuntimeState(
                status = VpnStatus.CONNECTED,
                resolverConfig = customResolver,
                loadedRuleCount = 42_000
            ),
            batteryLevelPercent = 82,
            batteryTempCelsius = 31.4f,
            batteryHealthLabel = "Good"
        )
        assertTrue(json.contains("\"https://dns.nextdns.io/<redacted-custom-path>\""))
        assertFalse("Secret profile path/token must never leak into diagnostic export", json.contains("secret-profile-abc123"))
        assertFalse(json.contains("my-phone"))
    }

    @Test
    fun testBatch1Fixes_filterEngineRuleTypeUpdateCosmeticQuoteEscapeAndCustomSecondaryDns() {
        val engine = FilterRuleEngine()
        // Changing an existing rule's RuleType (BLOCK -> ALLOW) on `||ads.example.com^` must Strip `@@` / `||` cleanly
        val parsedAllow = engine.validateAndParseRuleInput(
            rawInput = "||ads.example.com^",
            forcedType = RuleType.ALLOW,
            forcedMatchType = RuleMatchType.SUBDOMAIN
        ).getOrThrow()
        assertEquals(RuleType.ALLOW, parsedAllow.ruleType)
        assertEquals("ads.example.com", parsedAllow.normalizedPattern)

        // BrowserContentBlocker escapes double quotes in attribute selectors safely
        val blocker = BrowserContentBlocker(engine)
        val script = blocker.buildCosmeticFilterScript(
            pageHost = "news.example.com",
            allowlistedSites = emptySet(),
            customSelectors = setOf("""div[data-ad-slot="top"]""")
        )
        assertNotNull(script)
        assertTrue(script!!.contains("""div[data-ad-slot=\"top\"]"""))

        // Custom secondary IPv4 is honoured in UpstreamDnsResolver
        val customCfg = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.UDP_TCP,
            customPrimaryIpv4 = "192.0.2.10",
            customSecondaryIpv4 = "192.0.2.20",
            enableIpv6 = false
        )
        assertEquals(listOf("192.0.2.10", "192.0.2.20"), UpstreamDnsResolver.upstreamUdpTcpServers(customCfg))

        // SecurityEngine threat lookup honours user ALLOW rule over MALWARE filter list
        val batch = engine.parseFilterListContent("||evil.example.net^", RuleCategory.MALWARE, "TIF").getOrThrow()
        engine.updateFilterListRules(batch.subdomainRules, batch.exactRules, batch.wildcardRules, batch.allowSubdomains)
        assertTrue(SecurityEngine.evaluateThreatBlocklistSnapshot("sub.evil.example.net", engine.getCurrentSnapshot()))
        val userAllow = engine.validateAndParseRuleInput("@@||evil.example.net^").getOrThrow()
        engine.updateCustomRules(listOf(userAllow))
        assertFalse(SecurityEngine.evaluateThreatBlocklistSnapshot("sub.evil.example.net", engine.getCurrentSnapshot()))

        // UrlThreatScannerKnownThreatHostLookup full-host evaluation & DeviceCompatibility MAX_TRACKED_SDK
        val scanner = UrlThreatScanner(
            object : UrlThreatScanner.KnownThreatHostLookup {
                override fun isKnownThreatHost(host: String): Boolean = false
                override fun evaluateFullHost(host: String): Boolean = host == "a.b.c.d.e.f.g.evil.test"
            }
        )
        assertTrue(scanner.scan("https://a.b.c.d.e.f.g.evil.test/login").isKnownThreat)
        assertTrue(DeviceCompatibility.isSupportedPlatform(36))
        assertTrue(DeviceCompatibility.isSupportedPlatform(37))

        // LiveNetworkModel does not fabricate latency when all queries were 0ms cache hits
        val zeroLatencyLogs = listOf(
            DnsActivityRecord(
                timestampEpochMs = 1_730_000_000_000L,
                domain = "cached.example.org",
                queryType = "A",
                isBlocked = false,
                category = null,
                matchedRule = null,
                sourceList = "Cache",
                latencyMs = 0,
                protocolUsed = "CACHE"
            )
        )
        val snap = LiveNetworkModel.snapshot(VpnRuntimeState(status = VpnStatus.CONNECTED), zeroLatencyLogs, emptyList(), emptyList())
        assertEquals(0, snap.averageLatencyMs)
    }
}
