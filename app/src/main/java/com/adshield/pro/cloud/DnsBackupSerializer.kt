package com.adshield.pro.cloud

import com.adshield.pro.data.repository.AdShieldRepository
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.MessageDigest

/**
 * Serialises the DNS / security configuration into a versioned, integrity-hashed backup payload
 * that is uploaded to the cloud as a normal file. The DNS blocker itself never depends on the
 * cloud: this only produces/consumes a portable JSON document, and restoring goes through the
 * same local restore path as Settings → Restore backup.
 */
object DnsBackupSerializer {

    private val json = Json { prettyPrint = false; ignoreUnknownKeys = true }

    @Serializable
    data class DnsCloudBackup(
        val format: String = "adshield-dns-backup",
        val version: Int = 1,
        val createdAtEpochMs: Long,
        val appVersion: String,
        val payloadJson: String
    )

    suspend fun buildBackupPayload(repository: AdShieldRepository, appVersion: String, nowEpochMs: Long): String {
        val payload = repository.createConfigurationBackupJson()
        return json.encodeToString(
            DnsCloudBackup(
                createdAtEpochMs = nowEpochMs,
                appVersion = appVersion,
                payloadJson = payload
            )
        )
    }

    /** SHA-256 hex of the payload — stored in D1 next to the backup and verified after download. */
    fun sha256Hex(content: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(content.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * Validates a downloaded backup document and returns the inner settings JSON.
     * Returns null when the document is not a genuine AdShield backup — the caller must then
     * refuse the restore rather than applying attacker-controlled settings.
     */
    fun parseBackup(raw: String): String? = runCatching {
        val backup = json.decodeFromString<DnsCloudBackup>(raw)
        if (backup.format != "adshield-dns-backup" || backup.version != 1) null
        else backup.payloadJson
    }.getOrNull()
}
