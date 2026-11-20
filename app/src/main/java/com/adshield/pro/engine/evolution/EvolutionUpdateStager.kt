package com.adshield.pro.engine.evolution

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.PublicKey
import javax.net.ssl.HttpsURLConnection

/**
 * Blocking IO: invoke only off the main thread. One process-local instance per private directory.
 * The default-off worker stages then separately activates verified data for exact-hash advisories.
 * No production key is bundled. Staging alone never activates data or proves detection improvement.
 */
internal class EvolutionUpdateStager(
    private val directory: File,
    private val endpoint: URL,
    trustedKeys: Map<String, PublicKey>,
    private val appVersion: Long,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 }
) {
    class AlreadyCurrent : IllegalStateException("Signed package already staged")

    private val keys = trustedKeys.toMap()
    init {
        GitHubEvolutionChannel.validateEndpoint(endpoint)
        require(keys.isNotEmpty()) { "Configure an independently controlled publisher key first" }
    }

    @Synchronized
    fun fetchAndStage(stillAllowed: () -> Boolean = { true }): SignedEvolutionPackage.Manifest {
        check(stillAllowed()) { "Update no longer allowed" }
        val connection = openDownload(stillAllowed)
        try {
            require(connection.contentLengthLong <= SignedEvolutionPackage.MAX_BYTES)
            val bytes = connection.inputStream.use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                val deadline = System.nanoTime() + 30_000_000_000L
                while (true) {
                    check(System.nanoTime() < deadline) { "Update transfer deadline exceeded" }
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= SignedEvolutionPackage.MAX_BYTES)
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            check(stillAllowed()) { "Update no longer allowed" }
            return stage(bytes)
        } finally {
            connection.disconnect()
        }
    }

    private fun openDownload(stillAllowed: () -> Boolean): HttpsURLConnection {
        var current = endpoint
        var redirects = 0
        while (true) {
            check(stillAllowed()) { "Update no longer allowed" }
            val connection = current.openConnection() as HttpsURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 10_000
                connection.readTimeout = 10_000
                connection.useCaches = false
                // No GitHub token, cookies or application identifiers are attached.
                connection.setRequestProperty("Accept", "application/octet-stream")
                val status = connection.responseCode
                if (status == 200) return connection
                require(status in setOf(301, 302, 303, 307, 308)) { "Update server rejected request" }
                current = GitHubEvolutionChannel.redirect(endpoint, current,
                    requireNotNull(connection.getHeaderField("Location")), redirects)
                redirects++
            } catch (failure: Exception) {
                connection.disconnect()
                throw failure
            }
            connection.disconnect()
        }
    }

    @Synchronized
    fun stage(bytes: ByteArray): SignedEvolutionPackage.Manifest {
        // Own the bytes so a caller cannot mutate them between verification and persistence.
        require(bytes.size <= SignedEvolutionPackage.MAX_BYTES)
        val snapshot = bytes.copyOf()
        return locked { persist(snapshot) }
    }

    /** Exact hash advisory only. Never an instruction to block, quarantine or execute anything. */
    @Synchronized
    fun lookupSha256(sha256: String): String? {
        require(sha256.matches(Regex("[0-9a-f]{64}")))
        val state = EvolutionActivationStore(directory).read() ?: return null
        // Verify current signature, compatibility and expiry on every read; no stale cache.
        val manifest = SignedEvolutionPackage.verify(state.current, keys, appVersion, nowSeconds())
        return manifest.indicators.firstOrNull { it.sha256 == sha256 }?.category
    }

    data class ActiveStatus(val sequence: Long, val expiresAt: Long, val canRollback: Boolean)

    fun activeStatus(): ActiveStatus? {
        val state = EvolutionActivationStore(directory).read() ?: return null
        val current = SignedEvolutionPackage.verify(state.current, keys, appVersion, nowSeconds())
        val canRollback = state.previous?.let { previous -> runCatching {
            SignedEvolutionPackage.verify(previous, keys, appVersion, nowSeconds())
        }.isSuccess } ?: false
        return ActiveStatus(current.sequence, current.expiresAt, canRollback)
    }

    /** Atomically activate verified data for advisory lookup, never a blocking/risk-score rule. */
    @Synchronized
    fun activateLatest(): Boolean = locked {
        val staged = File(directory, "reviewed-reputation.evo")
        require(staged.length() in 1..SignedEvolutionPackage.MAX_BYTES.toLong())
        val bytes = staged.readBytes()
        val candidate = SignedEvolutionPackage.verify(bytes, keys, appVersion, nowSeconds())
        val store = EvolutionActivationStore(directory)
        val old = store.read()
        if (old != null) {
            val current = SignedEvolutionPackage.verify(old.current, keys, appVersion, nowSeconds(),
                allowExpiredStoredRecord = true)
            if (candidate.sequence <= old.rejectedThrough) return@locked false
            if (candidate.sequence == current.sequence && bytes.contentEquals(old.current)) return@locked false
            require(candidate.sequence > current.sequence)
        }
        store.write(EvolutionActivationStore.State(bytes, old?.current, old?.rejectedThrough ?: 0))
        true
    }

    /** Local rollback never lowers the separately retained download sequence watermark. */
    @Synchronized
    fun rollback(): Boolean = locked {
        val store = EvolutionActivationStore(directory)
        val old = store.read() ?: return@locked false
        val previous = old.previous ?: return@locked false
        val current = SignedEvolutionPackage.verify(old.current, keys, appVersion, nowSeconds(),
            allowExpiredStoredRecord = true)
        val fallback = SignedEvolutionPackage.verify(previous, keys, appVersion, nowSeconds())
        require(fallback.sequence < current.sequence)
        store.write(EvolutionActivationStore.State(previous, null, maxOf(old.rejectedThrough, current.sequence)))
        true
    }

    private fun <T> locked(action: () -> T): T {
        check(directory.isDirectory || directory.mkdirs())
        return RandomAccessFile(File(directory, "staging.lock"), "rw").use { file ->
            val lock = checkNotNull(file.channel.tryLock()) { "Updater already in progress" }
            lock.use { action() }
        }
    }

    private fun persist(snapshot: ByteArray): SignedEvolutionPackage.Manifest {
        val target = File(directory, "reviewed-reputation.evo")
        val now = nowSeconds()
        val watermark = if (target.exists()) {
            require(target.length() <= SignedEvolutionPackage.MAX_BYTES)
            // Expiry does not erase replay protection. Corrupt/revoked state fails closed.
            SignedEvolutionPackage.verify(target.readBytes(), keys, appVersion, now,
                allowExpiredStoredRecord = true).sequence
        } else 0L
        val manifest = SignedEvolutionPackage.verify(snapshot, keys, appVersion, now)
        if (manifest.sequence == watermark && snapshot.contentEquals(target.readBytes())) {
            throw AlreadyCurrent()
        }
        require(manifest.sequence > watermark) { "Replayed or conflicting sequence" }
        val temporary = File.createTempFile("evolution-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(snapshot); it.fd.sync() }
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
        } finally {
            temporary.delete()
        }
        return manifest
    }
}
