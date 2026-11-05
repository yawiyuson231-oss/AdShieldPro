package com.adshield.pro.cloud.backup

import com.adshield.pro.BuildConfig
import com.adshield.pro.cloud.data.CloudApiClient
import com.adshield.pro.cloud.data.CloudBackupDto
import com.adshield.pro.cloud.data.CloudBackupInitDto
import com.adshield.pro.cloud.data.CloudResult
import com.adshield.pro.cloud.data.ClientSideCipher
import com.adshield.pro.cloud.data.KeystoreBox
import com.adshield.pro.cloud.engine.CloudDownloadEngine
import com.adshield.pro.cloud.engine.CloudUploadEngine
import com.adshield.pro.cloud.engine.TransferControl
import com.adshield.pro.cloud.engine.TransferProgress
import com.adshield.pro.cloud.util.Hashing
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import dagger.hilt.android.qualifiers.ApplicationContext
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * DNS / firewall / preference backup built from the app's real configuration.
 *
 * The payload is encrypted on-device before it is uploaded, so the cloud provider only ever
 * stores ciphertext. Restores are idempotent and additive where it is safe (rules are merged,
 * never silently deleted) and explicit where it is destructive (settings are replaced).
 */
@Serializable
data class BackupRuleDto(
    val pattern: String,
    val type: String,
    val matchType: String,
    val enabled: Boolean,
    val comment: String
)

@Serializable
data class BackupSourceDto(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean
)

@Serializable
data class BackupSettingsDto(
    val protectionMode: String,
    val detailedLogging: Boolean,
    val logRetentionDays: Int,
    val autoUpdateFilters: Boolean,
    val updateIntervalHours: Int,
    val autoStartOnBoot: Boolean,
    val excludedApps: List<String>,
    val browserSiteExceptions: List<String>,
    val browserCosmeticFiltering: Boolean,
    val browserPopupBlocking: Boolean,
    val browserBlockThirdPartyCookies: Boolean,
    val browserJavaScriptEnabled: Boolean,
    val customCosmeticSelectors: List<String>,
    val smartAutoOptimize: Boolean,
    val junkCleanIntervalHours: Int,
    val excludedJunkPaths: List<String>,
    val gamingProfile: String,
    val batteryMode: String,
    val aetherEnabled: Boolean,
    val aetherPrivacyLevel: String,
    val aetherAutoBlockConfirmed: Boolean
)

@Serializable
data class BackupResolverDto(
    val preset: String,
    val protocol: String,
    val customDohUrl: String,
    val customDotHost: String,
    val customPrimaryIpv4: String,
    val customSecondaryIpv4: String,
    val enableIpv6: Boolean
)

@Serializable
data class DnsBackupPayload(
    val schema: Int = 1,
    val kind: String,
    @SerialName("generated_at") val generatedAt: Long = System.currentTimeMillis(),
    @SerialName("app_version") val appVersion: String = BuildConfig.VERSION_NAME,
    @SerialName("device") val device: String = "",
    val settings: BackupSettingsDto,
    val resolver: BackupResolverDto,
    val rules: List<BackupRuleDto>,
    val sources: List<BackupSourceDto>,
    @SerialName("allowlist") val allowlist: List<String>,
    @SerialName("denylist") val denylist: List<String>,
    val blocklist_domains: List<String>,
    val firewall: FirewallDto
)

@Serializable
data class FirewallDto(
    val protectionMode: String,
    val excludedPackages: List<String>,
    val vpnAutoStart: Boolean
)

data class BackupBundle(
    val kind: String,
    val label: String,
    val encryptedBytes: ByteArray,
    val plaintextSha256: String,
    val encryptedSha256: String,
    val payload: DnsBackupPayload,
    val passphraseUsed: Boolean
)

data class RestoreReport(
    val rulesAdded: Int,
    val rulesSkipped: Int,
    val sourcesApplied: Int,
    val settingsApplied: Boolean,
    val resolverApplied: Boolean,
    val kind: String,
    val generatedAt: Long
)

@Singleton
class DnsBackupManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val repository: AdShieldRepository,
    private val preferences: UserPreferencesRepository,
    private val api: CloudApiClient,
    private val uploadEngine: CloudUploadEngine,
    private val downloadEngine: CloudDownloadEngine,
    private val cipher: ClientSideCipher,
    private val keystoreBox: KeystoreBox
) {
    private val json = Json { prettyPrint = false; encodeDefaults = true; ignoreUnknownKeys = true }

    // ------------------------------------------------------------------ snapshot
    suspend fun buildPayload(kind: String): DnsBackupPayload = withContext(Dispatchers.IO) {
        val settings = preferences.getSettingsSnapshot()
        val rules = repository.customRulesFlow.first()
        val sources = repository.filterSourcesFlow.first()

        DnsBackupPayload(
            kind = kind,
            device = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim(),
            settings = BackupSettingsDto(
                protectionMode = settings.protectionMode.name,
                detailedLogging = settings.detailedDnsLoggingEnabled,
                logRetentionDays = settings.logRetentionDays,
                autoUpdateFilters = settings.autoUpdateFiltersEnabled,
                updateIntervalHours = settings.updateIntervalHours,
                autoStartOnBoot = settings.autoStartOnBoot,
                excludedApps = settings.excludedAppPackages.toList(),
                browserSiteExceptions = settings.browserSiteExceptions.toList(),
                browserCosmeticFiltering = settings.browserCosmeticFilteringEnabled,
                browserPopupBlocking = settings.browserPopupBlockingEnabled,
                browserBlockThirdPartyCookies = settings.browserBlockThirdPartyCookies,
                browserJavaScriptEnabled = settings.browserJavaScriptEnabled,
                customCosmeticSelectors = settings.customCosmeticSelectors.toList(),
                smartAutoOptimize = settings.smartAutoOptimizeEnabled,
                junkCleanIntervalHours = settings.autoJunkCleanIntervalHours,
                excludedJunkPaths = settings.excludedJunkPaths.toList(),
                gamingProfile = settings.gamingProfile.name,
                batteryMode = settings.batteryMode.name,
                aetherEnabled = settings.aetherEnabled,
                aetherPrivacyLevel = settings.aetherPrivacyLevel,
                aetherAutoBlockConfirmed = settings.aetherAutoBlockConfirmed
            ),
            resolver = BackupResolverDto(
                preset = settings.resolverConfig.preset.name,
                protocol = settings.resolverConfig.protocol.name,
                customDohUrl = settings.resolverConfig.customDohUrl,
                customDotHost = settings.resolverConfig.customDotHost,
                customPrimaryIpv4 = settings.resolverConfig.customPrimaryIpv4,
                customSecondaryIpv4 = settings.resolverConfig.customSecondaryIpv4,
                enableIpv6 = settings.resolverConfig.enableIpv6
            ),
            rules = rules.map { rule ->
                BackupRuleDto(
                    pattern = rule.rawPattern,
                    type = rule.ruleType.name,
                    matchType = rule.matchType.name,
                    enabled = rule.isEnabled,
                    comment = rule.comment
                )
            },
            sources = sources.map { source ->
                BackupSourceDto(id = source.id, name = source.name, url = source.url, enabled = source.isEnabled)
            },
            allowlist = rules.filter { it.ruleType == RuleType.ALLOW }.map { it.rawPattern },
            denylist = rules.filter { it.ruleType == RuleType.BLOCK }.map { it.rawPattern },
            blocklist_domains = sources.filter { it.isEnabled }.map { it.url },
            firewall = FirewallDto(
                protectionMode = settings.protectionMode.name,
                excludedPackages = settings.excludedAppPackages.toList(),
                vpnAutoStart = settings.autoStartOnBoot
            )
        )
    }

    /** Encrypts the snapshot. Without a passphrase a device-bound key is used. */
    suspend fun buildBundle(kind: String, label: String, passphrase: CharArray?): BackupBundle =
        withContext(Dispatchers.IO) {
            val payload = buildPayload(kind)
            val plaintext = json.encodeToString(DnsBackupPayload.serializer(), payload).toByteArray(Charsets.UTF_8)
            val key = if (passphrase != null && passphrase.isNotEmpty()) {
                passphrase
            } else {
                deviceKey().toCharArray()
            }
            val encrypted = cipher.encrypt(plaintext, key)
            if (key === passphrase) key.fill('\u0000')
            BackupBundle(
                kind = kind,
                label = label,
                encryptedBytes = encrypted.data,
                plaintextSha256 = encrypted.sha256OfPlaintext,
                encryptedSha256 = Hashing.sha256Hex(encrypted.data),
                payload = payload,
                passphraseUsed = passphrase != null && passphrase.isNotEmpty()
            )
        }

    /** A random per-device secret sealed by the Android Keystore (no user passphrase needed). */
    private fun deviceKey(): String {
        val prefs = context.getSharedPreferences("adshield_cloud_backup_key", Context.MODE_PRIVATE)
        val existing = prefs.getString("wrapped", null)?.let { keystoreBox.open(it) }
        if (!existing.isNullOrBlank()) return existing
        val generated = keystoreBox.newNonce(32).toHex()
        val wrapped = keystoreBox.seal(generated) ?: generated
        prefs.edit().putString("wrapped", wrapped).apply()
        return generated
    }

    private fun ByteArray.toHex(): String {
        val builder = StringBuilder(size * 2)
        for (byte in this) builder.append(((byte.toInt() and 0xFF) + 0x100).toString(16).substring(1))
        return builder.toString()
    }

    // ------------------------------------------------------------------ upload
    suspend fun uploadBackup(
        kind: String,
        label: String,
        passphrase: CharArray?,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ): CloudResult<CloudBackupDto> = withContext(Dispatchers.IO) {
        val bundle = buildBundle(kind, label, passphrase)
        onProgress(TransferProgress(0, bundle.encryptedBytes.size.toLong(), phase = "encrypting"))
        val init = api.initBackup(bundle.encryptedBytes.size.toLong(), bundle.encryptedSha256, kind, label)
        if (init !is CloudResult.Success) return@withContext init
        val session: CloudBackupInitDto = init.value
        val result = uploadEngine.uploadBytes(
            init = com.adshield.pro.cloud.data.CloudInitUploadDto(
                uploadId = session.uploadId,
                mode = session.mode,
                partSize = session.partSize,
                partsTotal = session.partsTotal,
                uploadToken = session.uploadToken,
                uploadUrl = session.uploadUrl
            ),
            bytes = bundle.encryptedBytes,
            mime = "application/x-adshield-backup",
            control = control,
            onProgress = onProgress
        )
        when (result) {
            is CloudResult.Success -> {
                val backupId = result.value.backupId
                    ?: return@withContext CloudResult.Failure("backup_not_recorded", "Server did not return a backup id")
                CloudResult.Success(
                    CloudBackupDto(
                        id = backupId,
                        kind = kind,
                        label = label,
                        size = bundle.encryptedBytes.size.toLong(),
                        sha256 = bundle.encryptedSha256,
                        encrypted = true,
                        appVersion = BuildConfig.VERSION_NAME,
                        ruleCount = bundle.payload.rules.size,
                        integrityOk = true,
                        createdAt = System.currentTimeMillis()
                    )
                )
            }
            is CloudResult.Failure -> result
            else -> CloudResult.Failure("upload_failed", "Backup upload did not complete")
        }
    }

    // ------------------------------------------------------------------ restore
    suspend fun restoreBackup(
        backup: CloudBackupDto,
        passphrase: CharArray?,
        control: TransferControl,
        onProgress: (TransferProgress) -> Unit
    ): CloudResult<RestoreReport> = withContext(Dispatchers.IO) {
        val ticket = api.backupRestoreTicket(backup.id)
        if (ticket !is CloudResult.Success) return@withContext ticket

        val download = downloadEngine.download(
            ticketUrl = ticket.value.url,
            fileName = "restore-${backup.id}.cshield",
            expectedSize = ticket.value.size,
            expectedSha256 = ticket.value.sha256,
            control = control,
            onProgress = onProgress
        )
        if (download !is CloudResult.Success) return@withContext download

        try {
            val bytes = download.value.readBytes()
            if (!cipher.looksEncrypted(bytes)) {
                return@withContext CloudResult.Failure(
                    "not_encrypted",
                    "This backup is not in the CyberShield encrypted container format."
                )
            }
            val key = if (passphrase != null && passphrase.isNotEmpty()) passphrase else deviceKey().toCharArray()
            val plaintext = try {
                cipher.decrypt(bytes, key)
            } catch (error: Throwable) {
                return@withContext CloudResult.Failure(
                    "decrypt_failed",
                    "Could not decrypt this backup. Check the passphrase — it must be the one used when the backup was created."
                )
            } finally {
                if (key === passphrase) key.fill('\u0000')
            }
            val payload = runCatching {
                json.decodeFromString(DnsBackupPayload.serializer(), String(plaintext, Charsets.UTF_8))
            }.getOrElse {
                return@withContext CloudResult.Failure("invalid_payload", "Backup content is not a recognised CyberShield snapshot")
            }
            val report = applyPayload(payload)
            api.markBackupRestored(backup.id)
            CloudResult.Success(report)
        } finally {
            download.value.delete()
        }
    }

    /** Applies a snapshot to the running configuration (merge rules, replace settings). */
    suspend fun applyPayload(payload: DnsBackupPayload): RestoreReport = withContext(Dispatchers.IO) {
        val resolver = DnsResolverConfig(
            preset = runCatching { com.adshield.pro.domain.model.DnsProviderPreset.valueOf(payload.resolver.preset) }
                .getOrDefault(com.adshield.pro.domain.model.DnsProviderPreset.CLOUDFLARE),
            protocol = runCatching { com.adshield.pro.domain.model.DnsProtocol.valueOf(payload.resolver.protocol) }
                .getOrDefault(com.adshield.pro.domain.model.DnsProtocol.DOH),
            customDohUrl = payload.resolver.customDohUrl,
            customDotHost = payload.resolver.customDotHost,
            customPrimaryIpv4 = payload.resolver.customPrimaryIpv4,
            customSecondaryIpv4 = payload.resolver.customSecondaryIpv4,
            enableIpv6 = payload.resolver.enableIpv6
        )
        preferences.updateResolverConfig(resolver)

        val existing = repository.customRulesFlow.first()
        val existingKeys = existing.map { "${it.normalizedPattern}:${it.ruleType}:${it.matchType}" }.toMutableSet()
        var added = 0
        var skipped = 0
        for (rule in payload.rules) {
            val matchType = runCatching { RuleMatchType.valueOf(rule.matchType) }.getOrDefault(RuleMatchType.SUBDOMAIN)
            val ruleType = runCatching { RuleType.valueOf(rule.type) }.getOrDefault(RuleType.BLOCK)
            val normalized = rule.pattern.trim().lowercase()
            val key = "$normalized:$ruleType:$matchType"
            if (key in existingKeys) {
                skipped += 1
                continue
            }
            val result = repository.addCustomRule(
                rawInput = rule.pattern,
                ruleType = ruleType,
                matchType = matchType,
                comment = rule.comment.ifBlank { "Restored from cloud backup" }
            )
            if (result.isSuccess) {
                existingKeys += key
                added += 1
            } else {
                skipped += 1
            }
        }

        val sources = repository.filterSourcesFlow.first()
        var sourcesApplied = 0
        for (saved in payload.sources) {
            val source = sources.firstOrNull { it.id == saved.id } ?: continue
            if (source.isEnabled != saved.enabled && !source.isPremiumOnly) {
                runCatching { repository.toggleFilterSourceEnabled(source, saved.enabled) }
                sourcesApplied += 1
            }
        }

        val settings = payload.settings
        preferences.setDetailedDnsLogging(settings.detailedLogging)
        preferences.setLogRetentionDays(settings.logRetentionDays)
        preferences.setAutoUpdateFilters(settings.autoUpdateFilters, settings.updateIntervalHours)
        preferences.setAutoStartOnBoot(settings.autoStartOnBoot)
        preferences.updateBrowserPrivacyOptions(
            settings.browserCosmeticFiltering,
            settings.browserPopupBlocking,
            settings.browserBlockThirdPartyCookies,
            settings.browserJavaScriptEnabled
        )
        settings.excludedApps.forEach { preferences.toggleExcludedAppPackage(it, true) }
        settings.browserSiteExceptions.forEach { preferences.toggleBrowserSiteException(it, true) }

        RestoreReport(
            rulesAdded = added,
            rulesSkipped = skipped,
            sourcesApplied = sourcesApplied,
            settingsApplied = true,
            resolverApplied = true,
            kind = payload.kind,
            generatedAt = payload.generatedAt
        )
    }

    /** Local, offline export used when the user has no cloud configured yet. */
    suspend fun exportLocalSnapshot(kind: String): File = withContext(Dispatchers.IO) {
        val payload = buildPayload(kind)
        val file = File(context.filesDir, "adshield-backup-${System.currentTimeMillis()}.json")
        file.writeText(json.encodeToString(DnsBackupPayload.serializer(), payload))
        file
    }
}
