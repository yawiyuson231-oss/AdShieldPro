package com.adshield.pro

import com.adshield.pro.data.cloud.BackupFirewall
import com.adshield.pro.data.cloud.BackupSettings
import com.adshield.pro.data.cloud.ByteArrayUploadSource
import com.adshield.pro.data.cloud.CloudApiClient
import com.adshield.pro.data.cloud.CloudBackupCodec
import com.adshield.pro.data.cloud.CloudBackupPayload
import com.adshield.pro.data.cloud.CloudException
import com.adshield.pro.data.cloud.CloudFileKind
import com.adshield.pro.data.cloud.CloudNodeDto
import com.adshield.pro.data.cloud.CloudUploadEngine
import com.adshield.pro.data.cloud.CloudVault
import com.adshield.pro.data.cloud.InMemoryUploadJobStore
import com.adshield.pro.data.cloud.UploadRequest
import com.adshield.pro.data.cloud.UploadState
import com.adshield.pro.data.cloud.VaultStorage
import com.adshield.pro.data.cloud.fileKind
import com.adshield.pro.data.cloud.formatCloudBytes
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Cloud platform tests.
 *
 * The API tests run the real [CloudApiClient] against an OkHttp interceptor, so the request paths,
 * query parameters and JSON decoding are the shipping ones. The upload tests run the real
 * [CloudUploadEngine], which means the bytes that arrive at the storage endpoint are hashed and
 * compared against the original file — a truncated or corrupted transfer fails the suite.
 */
class CloudPlatformTestSuite {

    // ---------------------------------------------------------------- api

    @Test
    fun cloudApiBuildsTheDocumentedPathsAndParsesRealResponses() {
        val backend = FakeCloudBackend()
        backend.route("/v1/health") { """{"ok":true,"provider":"backblaze-b2","mode":"production","freeTier":{"storageBytes":10737418240,"note":"10 GB"}}""" }
        backend.route("/v1/account") {
            """{"account":{"id":"u1","email":"a@b.c","createdAt":1,"quotaBytes":10737418240,"usedBytes":2048,"retentionDays":30},""" +
                """"usage":{"quotaBytes":10737418240,"usedBytes":2048,"remainingBytes":10737416192,"percentUsed":0.1,"trashedFiles":2,"trashedBytes":512},""" +
                """"warning":{"level":"ok","message":"Within the free allowance."},"apiRequestsLast24h":42,"limits":{"hourlyRequests":2000,"note":"free tier"}}"""
        }
        backend.route("/v1/nodes") {
            """{"nodes":[{"id":"nd1","parentId":null,"kind":"folder","name":"Holidays","sizeBytes":null,"contentType":null,"sha1":null},""" +
                """{"id":"nd2","parentId":"p","kind":"file","name":"a.jpg","sizeBytes":10,"contentType":"image/jpeg","sha1":"abc"}]}"""
        }
        val api = apiFor(backend)

        runBlocking {
            val health = api.health()
            assertTrue(health.ok)
            assertEquals("backblaze-b2", health.provider)
            assertEquals(10L * 1024 * 1024 * 1024, health.freeTier.storageBytes)

            val account = api.account()
            assertEquals("a@b.c", account.account.email)
            assertEquals(2048L, account.usage.usedBytes)
            assertEquals(10737416192L, account.usage.remainingBytes)
            assertEquals(2, account.usage.trashedFiles)
            assertEquals("ok", account.warning.level)
            assertEquals(42L, account.apiRequestsLast24h)
            assertEquals(2000L, account.limits.hourlyRequests)

            val nodes = api.nodes(parentId = "p", kind = "photo", search = "hol", recursive = true)
            assertEquals(2, nodes.size)
            assertEquals("Holidays", nodes[0].name)
            assertTrue(nodes[0].isFolder)
            assertEquals(0L, nodes[0].size)
            assertEquals(CloudFileKind.PHOTO, nodes[1].fileKind())
            assertTrue(backend.requests.any { it.contains("search=hol") })
            assertTrue(backend.requests.any { it.contains("recursive=1") })
            assertTrue(backend.requests.any { it.contains("kind=photo") })
        }
    }

    @Test
    fun cloudApiSendsAuthenticationAndTurnsServerErrorsIntoExceptionsWithTheServerMessage() {
        val backend = FakeCloudBackend()
        backend.route("/v1/account/register", status = 403) { """{"error":"bot protection failed"}""" }
        backend.route("/v1/backups/init", status = 413) {
            """{"error":"quota exceeded","detail":{"requestedBytes":100,"remainingBytes":20,"quotaBytes":10737418240,"usedBytes":10737418220}}"""
        }
        val api = apiFor(backend, token = "jwt-token")

        runBlocking {
            val refused = runCatching { api.register("turnstile") }
            assertTrue(
                "register should throw CloudException, got ${refused.exceptionOrNull()}",
                refused.exceptionOrNull() is CloudException
            )
            val first = refused.exceptionOrNull() as CloudException
            assertEquals(403, first.status)
            assertEquals("bot protection failed", first.code)

            val overQuota = runCatching { api.initBackup("full_config", "label", 100L) }
            val second = overQuota.exceptionOrNull() as CloudException
            assertEquals(413, second.status)
            assertEquals("quota exceeded", second.code)
            assertTrue(second.detail?.contains("remainingBytes") == true)
        }
        assertTrue("non-POST request: ${backend.requests}", backend.requests.all { it.startsWith("POST") })
        assertTrue(
            "missing auth header on: ${backend.seenHeaders.filterValues { !it.containsKey("Authorization") }.keys}",
            backend.seenHeaders.values.all { headers -> headers.containsKey("Authorization") }
        )
        assertEquals("Bearer jwt-token", backend.seenHeaders.values.first()["Authorization"])
    }

    // ---------------------------------------------------------------- uploads

    @Test
    fun uploadEngineStreamsEveryPartWithItsRealSha1AndCompletes() {
        val file = ByteArray(3 * 1024 * 1024) { (it % 251).toByte() }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        val engine = engineFor(backend)

        val job = runBlocking {
            engine.run(UploadRequest(source = ByteArrayUploadSource(file), name = "movie.bin", contentType = "video/mp4"))
        }

        assertEquals(UploadState.COMPLETED, job.state)
        assertEquals(file.size.toLong(), job.uploadedBytes)
        assertEquals(listOf(1, 2, 3), job.uploadedParts)
        // The bytes that reached the storage endpoint are the original file, part for part.
        assertArrayEquals(file, backend.assembledBytes())
        assertEquals(0, backend.sha1Mismatches)
        assertTrue(backend.requests.any { it.contains("/v1/uploads/up_1/complete") })
    }

    @Test
    fun uploadEngineResumesOnlyThePartsTheServerIsStillMissing() {
        val file = ByteArray(3 * 1024 * 1024) { (it % 97).toByte() }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        backend.failParts = setOf(2)
        val engine = engineFor(backend)
        val source = ByteArrayUploadSource(file)
        val request = UploadRequest(source = source, name = "movie.bin")

        runBlocking {
            val failed = engine.run(request)
            assertEquals(UploadState.FAILED, failed.state)
            assertEquals(1, failed.uploadedParts.size)
            assertEquals(3, backend.partAttempts[2]) // three attempts, then the job gives up
        }

        backend.failParts = emptySet()
        runBlocking {
            val resumed = engine.run(request)
            assertEquals(UploadState.COMPLETED, resumed.state)
        }
        assertEquals(1, backend.partAttempts[1]) // part 1 was never re-sent
        // The failed run stopped at part 2, so the resume sends part 3 for the first time.
        assertEquals(1, backend.partAttempts[3])
        assertArrayEquals(file, backend.assembledBytes())
    }

    @Test
    fun uploadEngineRetriesATransientPartFailureAndThenSucceeds() {
        val file = ByteArray(2 * 1024 * 1024) { (it % 31).toByte() }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        val engine = engineFor(backend)
        backend.failOnce = 2 // the first attempt at part 2 fails, the retry succeeds

        val job = runBlocking {
            engine.run(UploadRequest(source = ByteArrayUploadSource(file), name = "doc.pdf"))
        }
        assertEquals("upload failed: ${job.lastError}", UploadState.COMPLETED, job.state)
        assertEquals(2, backend.partAttempts[2])
        assertArrayEquals(file, backend.assembledBytes())
    }

    @Test
    fun uploadEngineCancelsCleanlyAndTellsTheServerToCancelTheSession() {
        val file = ByteArray(3 * 1024 * 1024) { 7 }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        backend.partDelayMs = 120
        val engine = engineFor(backend)
        val request = UploadRequest(source = ByteArrayUploadSource(file), name = "big.bin")

        runBlocking {
            val jobId = engine.launch(request)
            delay(60)
            engine.cancel(jobId)
            val state = waitFor(engine, jobId) { it == UploadState.CANCELLED || it == UploadState.COMPLETED }
            assertEquals(
                "cancel failed: ${engine.snapshot(jobId)?.lastError}",
                UploadState.CANCELLED,
                state
            )
        }
        assertTrue(backend.requests.any { it.contains("/v1/uploads/up_1/cancel") })
        assertFalse(backend.requests.any { it.contains("/complete") })
    }

    @Test
    fun uploadEnginePausesAndResumesWithoutLosingTheBytesAlreadyStored() {
        val file = ByteArray(3 * 1024 * 1024) { (it % 13).toByte() }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        backend.partDelayMs = 120
        val engine = engineFor(backend)
        val request = UploadRequest(source = ByteArrayUploadSource(file), name = "pause.bin")

        runBlocking {
            val jobId = engine.launch(request)
            delay(60)
            engine.pause(jobId)
            val paused = waitFor(engine, jobId) { it == UploadState.PAUSED || it == UploadState.COMPLETED }
            assertEquals(UploadState.PAUSED, paused)
            backend.partDelayMs = 0
            engine.resume(jobId)
            val finished = waitFor(engine, jobId) { it == UploadState.COMPLETED || it == UploadState.FAILED }
            assertEquals(UploadState.COMPLETED, finished)
        }
        assertArrayEquals(file, backend.assembledBytes())
    }

    @Test
    fun uploadEngineReportsProgressAsBytesAreCommitted() {
        val file = ByteArray(2 * 1024 * 1024) { 5 }
        val backend = multipartBackend(file.size, partSize = 1024 * 1024)
        val engine = engineFor(backend)
        runBlocking {
            val job = engine.run(UploadRequest(source = ByteArrayUploadSource(file), name = "progress.bin"))
            val progress = engine.progressFlow.value[job.id]
            assertNotNull(progress)
            assertEquals(1f, progress!!.fraction, 0.001f)
            assertEquals(2, progress.partsDone)
            assertEquals(2, progress.partsTotal)
        }
    }

    // ---------------------------------------------------------------- backups

    @Test
    fun backupCodecRoundTripsAndRefusesATamperedPayload() {
        val payload = CloudBackupPayload(
            createdAtEpochMs = 1_700_000_000_000L,
            appVersion = "2.8.0",
            device = "Pixel 9",
            settings = BackupSettings(protectionMode = "STRICT", logRetentionDays = 14),
            rules = listOf(
                com.adshield.pro.data.cloud.BackupRule(pattern = "ads.example", type = "BLOCK"),
                com.adshield.pro.data.cloud.BackupRule(pattern = "cdn.example", type = "ALLOW")
            ),
            sources = listOf(com.adshield.pro.data.cloud.BackupSource(id = "s1", name = "EasyList", url = "https://example/list.txt")),
            firewall = BackupFirewall(emergencyAllowlistOnly = false, appPolicies = emptyList()),
            allowlist = listOf("cdn.example"),
            denylist = listOf("ads.example")
        )
        val bytes = CloudBackupCodec.encode(payload)
        val hash = CloudBackupCodec.sha256(bytes)

        val decoded = CloudBackupCodec.decode(bytes)
        assertEquals("STRICT", decoded.settings.protectionMode)
        assertEquals(14, decoded.settings.logRetentionDays)
        assertEquals(2, decoded.rules.size)
        assertEquals(1, decoded.sources.size)
        assertEquals(listOf("cdn.example"), decoded.allowlist)
        assertTrue(CloudBackupCodec.verify(bytes, hash))

        val tampered = bytes.copyOf()
        tampered[tampered.size - 3] = (tampered[tampered.size - 3] + 1).toByte()
        assertFalse(CloudBackupCodec.verify(tampered, hash))
        assertEquals(64, hash.length)
    }

    @Test
    fun backupCodecSummaryAndSupportChecksReportTheTruth() {
        val payload = CloudBackupPayload(
            rules = List(3) { com.adshield.pro.data.cloud.BackupRule(pattern = "block$it") },
            sources = List(2) { com.adshield.pro.data.cloud.BackupSource(id = "s$it") },
            settings = BackupSettings(protectionMode = "STANDARD")
        )
        val summary = CloudBackupCodec.summary(payload)
        assertTrue(summary.contains("3 rules"))
        assertTrue(summary.contains("2 lists"))
        assertTrue(CloudBackupCodec.isSupported(payload))
        assertFalse(CloudBackupCodec.isSupported(payload.copy(schemaVersion = Int.MAX_VALUE)))
        assertEquals("1.0 MB", formatCloudBytes(1_048_576))
        assertEquals("512 B", formatCloudBytes(512))
        assertEquals("10 GB", formatCloudBytes(10L * 1024 * 1024 * 1024))
    }

    // ---------------------------------------------------------------- vault

    @Test
    fun vaultEncryptsWithTheRightPassphraseAndRefusesTheWrongOne() {
        val vault = CloudVault(InMemoryVaultStorage())
        assertTrue(vault.setup("correct horse battery".toCharArray(), iterations = 1_000))
        assertTrue(vault.isConfigured())
        assertTrue(vault.isUnlocked())

        val plain = CloudBackupCodec.encode(CloudBackupPayload(device = "Pixel"))
        val ciphertext = vault.encrypt(plain)
        assertFalse(String(ciphertext, Charsets.UTF_8).contains("Pixel"))
        assertArrayEquals(plain, vault.decrypt(ciphertext))

        vault.lock()
        assertFalse(vault.isUnlocked())
        assertFalse(vault.unlock("wrong passphrase".toCharArray()))
        assertTrue(vault.unlock("correct horse battery".toCharArray()))
        assertArrayEquals(plain, vault.decrypt(ciphertext))

        val tampered = ciphertext.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()
        val failed = runCatching { vault.decrypt(tampered) }
        assertTrue(failed.isFailure)
    }

    // ---------------------------------------------------------------- helpers

    private fun apiFor(backend: FakeCloudBackend, token: String? = null): CloudApiClient =
        CloudApiClient(clientFor(backend), "http://cloud.test", { token ?: "" })

    private fun engineFor(backend: FakeCloudBackend): CloudUploadEngine =
        CloudUploadEngine(apiFor(backend), clientFor(backend), InMemoryUploadJobStore())

    private fun clientFor(backend: FakeCloudBackend): OkHttpClient =
        OkHttpClient.Builder().addInterceptor(backend).build()

    private fun multipartBackend(sizeBytes: Int, partSize: Int): FakeCloudBackend {
        val backend = FakeCloudBackend()
        val totalParts = (sizeBytes + partSize - 1) / partSize
        val tickets = (1..totalParts).joinToString(",") {
            """{"partNumber":$it,"uploadUrl":"http://part.test/part/$it","token":"tok-$it"}"""
        }
        backend.route("/v1/uploads/init", status = 201) {
            """{"sessionId":"up_1","nodeId":"nd_1","key":"u/u1/nd_1/file.bin","partSize":$partSize,"totalParts":$totalParts,"multipart":true,"parts":[$tickets]}"""
        }
        backend.route("/v1/uploads/up_1") {
            val done = backend.recordedParts()
            """{"session":{"id":"up_1","name":"file.bin","status":"open","declaredSize":$sizeBytes,"partSize":$partSize,"totalParts":$totalParts,"uploadedParts":[$done],"uploadedBytes":${done.size * partSize}},"partUrls":[$tickets]}"""
        }
        for (part in 1..totalParts) {
            backend.route("/v1/uploads/up_1/part/$part") {
                """{"partNumber":$part,"uploadedBytes":${backend.recordedParts().size * partSize}}"""
            }
        }
        backend.route("/v1/uploads/up_1/complete", status = 201) {
            """{"node":{"id":"nd_1","kind":"file","name":"file.bin","sizeBytes":$sizeBytes,"contentType":"application/octet-stream"},"replaced":false}"""
        }
        backend.route("/v1/uploads/up_1/cancel") { """{"cancelled":true}""" }
        return backend
    }

    private suspend fun waitFor(
        engine: CloudUploadEngine,
        jobId: String,
        predicate: (UploadState) -> Boolean
    ): UploadState {
        repeat(60) {
            val state = engine.snapshot(jobId)?.state
            if (state != null && predicate(state)) return state
            delay(50)
        }
        return engine.snapshot(jobId)?.state ?: UploadState.FAILED
    }
}

private class InMemoryVaultStorage : VaultStorage {
    private var salt: ByteArray? = null
    private var verifier: ByteArray? = null
    private var rounds = 1_000
    override fun salt(): ByteArray? = salt
    override fun verifier(): ByteArray? = verifier
    override fun iterations(): Int = rounds
    override fun save(salt: ByteArray, verifier: ByteArray, iterations: Int) {
        this.salt = salt
        this.verifier = verifier
        this.rounds = iterations
    }
}

/**
 * Stands in for the API worker and the storage endpoint. Part uploads are verified exactly the way
 * Backblaze verifies them: the declared SHA-1 must match the bytes that were actually sent.
 */
private class FakeCloudBackend : Interceptor {
    private val routes = HashMap<String, Pair<Int, (Request) -> String>>()
    private val partBodies = ConcurrentHashMap<Int, ByteArray>()
    val partAttempts = ConcurrentHashMap<Int, Int>()
    val requests = Collections.synchronizedList(mutableListOf<String>())
    val seenHeaders = Collections.synchronizedMap(mutableMapOf<String, Map<String, String>>())
    var failParts: Set<Int> = emptySet()
    var failOnce: Int? = null
    var partDelayMs = 0L
    var sha1Mismatches = 0

    fun route(path: String, status: Int = 200, body: () -> String) {
        routes[path] = status to { _: Request -> body() }
    }

    fun recordedParts(): List<Int> = partBodies.keys.sorted()

    fun assembledBytes(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        recordedParts().forEach { out.write(partBodies[it]!!) }
        return out.toByteArray()
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val path = request.url.encodedPath
        requests += "${request.method} ${request.url}"
        seenHeaders[request.url.toString()] = request.headers.toMultimap().mapValues { it.value.first() }
        val bytes = request.body?.let { body ->
            val buffer = Buffer()
            val contentLength = body.contentLength()
            body.writeTo(buffer)
            val read = buffer.readByteArray()
            check(contentLength < 0 || read.size.toLong() == contentLength) {
                "body length ${read.size} does not match the declared content length $contentLength"
            }
            read
        }

        val result: Pair<Int, String> = when {
            path.startsWith("/part/") -> handlePart(path, request, bytes ?: ByteArray(0))
            else -> routes[path]?.let { (status, handler) -> status to handler(request) }
                ?: (404 to """{"error":"no route for $path"}""")
        }
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(result.first)
            .message(if (result.first < 400) "OK" else "Error")
            .body(result.second.toResponseBody("application/json".toMediaType()))
            .build()
    }

    private fun handlePart(path: String, request: Request, bytes: ByteArray): Pair<Int, String> {
        val partNumber = path.removePrefix("/part/").toInt()
        val attempts = (partAttempts[partNumber] ?: 0) + 1
        partAttempts[partNumber] = attempts
        val declared = request.header("X-Bz-Content-Sha1")
            ?: return 400 to """{"error":"missing content sha1"}"""
        if (declared != sha1Hex(bytes)) {
            sha1Mismatches += 1
            return 400 to """{"error":"sha1 mismatch"}"""
        }
        if (partDelayMs > 0) Thread.sleep(partDelayMs)
        val shouldFail = partNumber in failParts || (failOnce == partNumber && attempts == 1)
        if (shouldFail) return 500 to """{"error":"simulated network failure"}"""
        partBodies[partNumber] = bytes
        return 200 to "{}"
    }

    private fun sha1Hex(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-1").digest(bytes)
        return digest.joinToString("") { String.format("%02x", it.toInt() and 0xFF) }
    }
}
