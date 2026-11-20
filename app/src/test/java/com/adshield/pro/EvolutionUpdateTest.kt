package com.adshield.pro

import com.adshield.pro.engine.evolution.EvolutionUpdateStager
import com.adshield.pro.engine.evolution.SignedEvolutionPackage as Package
import java.net.URL
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.Signature
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvolutionUpdateTest {
    companion object {
        private val publisher = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        private val keys = mapOf("publisher-1" to publisher.public)
        private const val NOW = 1_800_000_000L
    }
    private fun manifest(sequence: Long = 1) = Package.Manifest(
        "publisher-1", sequence, NOW - 60, NOW + 3600, 1, 100,
        listOf(Package.Indicator("a".repeat(64), "malware")))
    private fun signed(manifest: Package.Manifest = manifest()): ByteArray {
        val payload = Package.payload(manifest)
        val signature = Signature.getInstance("SHA256withRSA").run {
            initSign(publisher.private); update(payload); sign()
        }
        return Package.envelope(payload, signature)
    }
    private fun rejects(action: () -> Unit) {
        var rejected = false
        try { action() } catch (_: Exception) { rejected = true }
        assertTrue("Invalid update must fail closed", rejected)
    }

    @Test fun acceptsPublisherBoundCompatibleData() {
        assertEquals(manifest(), Package.verify(signed(), keys, 10, NOW))
    }
    @Test fun rejectsTamperingUnknownPublisherAndTrailingBytes() {
        val modified = signed().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        rejects { Package.verify(modified, keys, 10, NOW) }
        rejects { Package.verify(signed(), emptyMap(), 10, NOW) }
        rejects { Package.verify(signed() + byteArrayOf(0), keys, 10, NOW) }
    }
    @Test fun rejectsReplayFutureExpiryAndIncompatibleApp() {
        rejects { Package.verify(signed(), keys, 10, NOW, 1) }
        rejects { Package.verify(signed(manifest().copy(issuedAt = NOW + 1)), keys, 10, NOW) }
        rejects { Package.verify(signed(manifest().copy(expiresAt = NOW)), keys, 10, NOW) }
        rejects { Package.verify(signed(manifest().copy(expiresAt = NOW + 604801)), keys, 10, NOW) }
        rejects { Package.verify(signed(), keys, 101, NOW) }
    }
    @Test fun rejectsExecutablesInvalidHashesAndDuplicateEntries() {
        rejects { Package.verify(signed(manifest().copy(indicators = listOf(
            Package.Indicator("a".repeat(64), "execute")))), keys, 10, NOW) }
        rejects { Package.verify(signed(manifest().copy(indicators = listOf(
            Package.Indicator("not-a-hash", "malware")))), keys, 10, NOW) }
        rejects { Package.verify(signed(manifest().copy(indicators = manifest().indicators + manifest().indicators)), keys, 10, NOW) }
    }
    @Test fun rejectsTruncatedAndOversizeInputs() {
        for (size in listOf(0, 1, 4, 16, 64)) rejects {
            Package.verify(signed().copyOf(size), keys, 10, NOW)
        }
        rejects { Package.verify(ByteArray(Package.MAX_BYTES + 1), keys, 10, NOW) }
    }
    @Test fun persistsReplayWatermarkAcrossInstancesAndExpiry() {
        val directory = Files.createTempDirectory("evolution-test").toFile()
        try {
            fun stager(now: Long = NOW) = EvolutionUpdateStager(directory,
                URL("https://updates.example.invalid/reputation"), keys, 10) { now }
            assertEquals(1L, stager().stage(signed()).sequence)
            rejects { stager().stage(signed()) }
            rejects { stager(NOW + 7200).stage(signed()) }
            val next = manifest(2).copy(issuedAt = NOW + 7100, expiresAt = NOW + 10000)
            assertEquals(2L, stager(NOW + 7200).stage(signed(next)).sequence)
            val saved = directory.resolve("reviewed-reputation.evo").readBytes()
            rejects { stager(NOW + 7200).stage(signed(manifest(3))) }
            assertTrue(saved.contentEquals(directory.resolve("reviewed-reputation.evo").readBytes()))
        } finally { directory.deleteRecursively() }
    }
    @Test fun corruptedStoredStateDoesNotResetWatermark() {
        val directory = Files.createTempDirectory("evolution-corrupt").toFile()
        try {
            directory.resolve("reviewed-reputation.evo").writeText("corrupt")
            rejects { EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }.stage(signed()) }
        } finally { directory.deleteRecursively() }
    }
    @Test fun concurrentStagerCannotBypassSequenceCheck() {
        val directory = Files.createTempDirectory("evolution-lock").toFile()
        try {
            java.io.RandomAccessFile(directory.resolve("staging.lock"), "rw").use { file ->
                file.channel.lock().use {
                    rejects { EvolutionUpdateStager(directory,
                        URL("https://example.invalid/feed"), keys, 10) { NOW }.stage(signed()) }
                }
            }
            assertTrue(!directory.resolve("reviewed-reputation.evo").exists())
        } finally { directory.deleteRecursively() }
    }
    @Test fun advisoryReadRechecksExpiryAndExactDigest() {
        val directory = Files.createTempDirectory("evolution-read").toFile()
        try {
            var now = NOW
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { now }
            assertEquals(null, stager.lookupSha256("a".repeat(64)))
            stager.stage(signed())
            stager.activateLatest()
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
            assertEquals(null, stager.lookupSha256("b".repeat(64)))
            rejects { stager.lookupSha256("bad-hash") }
            now = NOW + 3600
            rejects { stager.lookupSha256("a".repeat(64)) }
        } finally { directory.deleteRecursively() }
    }
    @Test fun advisoryReadRejectsTamperedStoredData() {
        val directory = Files.createTempDirectory("evolution-read-tamper").toFile()
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }
            stager.stage(signed())
            stager.activateLatest()
            val target = directory.resolve("activation.evo")
            target.writeBytes(target.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
            rejects { stager.lookupSha256("a".repeat(64)) }
        } finally { directory.deleteRecursively() }
    }
    @Test fun identicalCurrentPackageIsDistinctFromConflictingReplay() {
        val directory = Files.createTempDirectory("evolution-noop").toFile()
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }
            val envelope = signed()
            stager.stage(envelope)
            stager.activateLatest()
            var unchanged = false
            try { stager.stage(envelope) } catch (_: EvolutionUpdateStager.AlreadyCurrent) { unchanged = true }
            assertTrue(unchanged)
            val conflicting = signed(manifest().copy(indicators = listOf(Package.Indicator("b".repeat(64), "malware"))))
            var falselyUnchanged = false
            try { stager.stage(conflicting) } catch (_: EvolutionUpdateStager.AlreadyCurrent) {
                falselyUnchanged = true
            } catch (_: IllegalArgumentException) { /* Expected conflicting sequence rejection. */ }
            assertTrue(!falselyUnchanged)
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
            assertEquals(null, stager.lookupSha256("b".repeat(64)))
        } finally { directory.deleteRecursively() }
    }
    @Test fun githubUsesDedicatedChannelAndRestrictedHttpsRedirects() {
        val channel = com.adshield.pro.engine.evolution.GitHubEvolutionChannel
        val initial = URL(channel.ENDPOINT)
        channel.validateEndpoint(initial)
        assertEquals("release-assets.githubusercontent.com", channel.redirect(initial, initial,
            "https://release-assets.githubusercontent.com/path/asset?signature=test", 0).host)
        rejects { channel.validateEndpoint(URL("https://github.com/yawiyuson231-oss/AdShieldPro/releases/latest/download/reputation.evo")) }
        rejects { channel.redirect(initial, initial, "http://release-assets.githubusercontent.com/asset", 0) }
        rejects { channel.redirect(initial, initial, "https://evil.example/asset", 0) }
        rejects { channel.redirect(initial, initial, "https://release-assets.githubusercontent.com.evil.example/asset", 0) }
        rejects { channel.redirect(initial, initial, "https://user@release-assets.githubusercontent.com/asset", 0) }
        rejects { channel.redirect(initial, initial, "https://release-assets.githubusercontent.com:444/asset", 0) }
        rejects { channel.redirect(initial, initial, "https://release-assets.githubusercontent.com/asset", 3) }
        rejects { channel.redirect(URL("https://example.invalid/feed"), initial,
            "https://release-assets.githubusercontent.com/asset", 0) }
    }
    @Test fun stagingIsNotActivation() {
        val directory = Files.createTempDirectory("evolution-staged-only").toFile()
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }
            stager.stage(signed())
            assertEquals(null, stager.lookupSha256("a".repeat(64)))
            assertTrue(stager.activateLatest())
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
        } finally { directory.deleteRecursively() }
    }
    @Test fun rollbackKeepsDownloadWatermarkAndQuarantinesRejectedSequence() {
        val directory = Files.createTempDirectory("evolution-rollback").toFile()
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }
            stager.stage(signed()); stager.activateLatest()
            stager.stage(signed(manifest(2).copy(indicators = listOf(Package.Indicator("b".repeat(64), "phishing")))))
            stager.activateLatest()
            assertTrue(stager.activeStatus()!!.canRollback)
            assertEquals("phishing", stager.lookupSha256("b".repeat(64)))
            assertTrue(stager.rollback())
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
            assertEquals(null, stager.lookupSha256("b".repeat(64)))
            assertTrue(!stager.activateLatest())
            rejects { stager.stage(signed(manifest(1))) }
            assertTrue(!stager.rollback())
            stager.stage(signed(manifest(3))); assertTrue(stager.activateLatest())
            assertEquals(3L, stager.activeStatus()!!.sequence)
        } finally { directory.deleteRecursively() }
    }
    @Test fun expiredFallbackCannotReplaceValidActiveData() {
        val directory = Files.createTempDirectory("evolution-expired-rollback").toFile()
        try {
            var now = NOW
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { now }
            stager.stage(signed(manifest().copy(expiresAt = NOW + 10))); stager.activateLatest()
            stager.stage(signed(manifest(2))); stager.activateLatest()
            now = NOW + 11
            rejects { stager.rollback() }
            assertEquals(2L, stager.activeStatus()!!.sequence)
        } finally { directory.deleteRecursively() }
    }
    @Test fun invalidStagedBytesCannotReplaceActiveRecord() {
        val directory = Files.createTempDirectory("evolution-atomic").toFile()
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), keys, 10) { NOW }
            stager.stage(signed()); stager.activateLatest()
            val before = directory.resolve("activation.evo").readBytes()
            directory.resolve("reviewed-reputation.evo").writeText("corrupt")
            rejects { stager.activateLatest() }
            assertTrue(before.contentEquals(directory.resolve("activation.evo").readBytes()))
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
        } finally { directory.deleteRecursively() }
    }
    @Test fun advisoryTextNeverTreatsMissingInvalidOrDisabledDataAsSafety() {
        val text = com.adshield.pro.engine.evolution.EvolutionAdvisoryText
        assertEquals(null, text.evaluate(false, "a".repeat(64)) { error("Must not query when disabled") }.finding)
        assertTrue(text.evaluate(true, null) { null }.limitation != null)
        assertTrue(text.evaluate(true, "a".repeat(64)) { null }.limitation!!.contains("does not establish safety"))
        assertTrue(text.evaluate(true, "a".repeat(64)) { error("expired") }.limitation != null)
        assertTrue(text.evaluate(true, "a".repeat(64)) { "malware" }.finding!!.contains("does not change the local verdict"))
    }
    @Test fun requiresHttpsAndExplicitTrustConfiguration() {
        val directory = Files.createTempDirectory("evolution-config").toFile()
        try {
            rejects { EvolutionUpdateStager(directory, URL("http://example.invalid/feed"), keys, 10) }
            rejects { EvolutionUpdateStager(directory, URL("https://example.invalid/feed"), emptyMap(), 10) }
            rejects { EvolutionUpdateStager(directory, URL("https://user@example.invalid/feed"), keys, 10) }
        } finally { directory.deleteRecursively() }
    }
}
