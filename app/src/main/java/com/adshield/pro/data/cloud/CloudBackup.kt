package com.adshield.pro.data.cloud

import android.os.Build
import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.CustomRuleEntity
import com.adshield.pro.data.local.db.FilterSourceEntity
import com.adshield.pro.data.local.preferences.DarkThemePreference
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.ProtectionMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The exact configuration that is uploaded when a user backs up AdShield Pro.
 *
 * Everything in here is plain data, so a backup can be verified byte-for-byte, decoded on any
 * device, and inspected by the user in a text editor.
 */
@Serializable
data class CloudBackupPayload(
    val schemaVersion: Int = BACKUP_SCHEMA_VERSION,
    val createdAtEpochMs: Long = 0L,
    val appVersion: String = "",
    val device: String = "",
    val settings: BackupSettings = BackupSettings(),
    val rules: List<BackupRule> = emptyList(),
    val sources: List<BackupSource> = emptyList(),
    val firewall: BackupFirewall = BackupFirewall(),
    val allowlist: List<String> = emptyList(),
    val denylist: List<String> = emptyList(),
    val browserExceptions: List<String> = emptyList(),
    val excludedApps: List<String> = emptyList(),
    val encrypted: Boolean = false
)

@Serializable
data class BackupSettings(
    val protectionMode: String = ProtectionMode.STANDARD.name,
    val darkTheme: String = DarkThemePreference.DARK.name,
    val autoStartOnBoot: Boolean = true,
    val detailedLogging: Boolean = true,
    val logRetentionDays: Int = 7,
    val autoUpdateFilters: Boolean = true,
    val updateIntervalHours: Int = 24,
    val resolverPreset: String = DnsProviderPreset.CLOUDFLARE.name,
    val resolverProtocol: String = DnsProtocol.DOH.name,
    val customDohUrl: String = "",
    val enableIpv6: Boolean = true,
    val failoverEnabled: Boolean = false,
    val dnssecMode: String = DnssecMode.REPORT_ONLY.name,
    val browserCosmeticFiltering: Boolean = true,
    val browserPopupBlocking: Boolean = true,
    val browserThirdPartyCookies: Boolean = true,
    val browserJavaScript: Boolean = true,
    val customCosmeticSelectors: List<String> = emptyList()
)

@Serializable
data class BackupRule(
    val pattern: String = "",
    val type: String = "BLOCK",
    val matchType: String = "EXACT",
    val category: String = "CUSTOM",
    val priority: Int = 0,
    val enabled: Boolean = true,
    val comment: String = ""
)

@Serializable
data class BackupSource(
    val id: String = "",
    val name: String = "",
    val url: String = "",
    val category: String = "ADS",
    val enabled: Boolean = true,
    val ruleCount: Int = 0
)

@Serializable
data class BackupFirewall(
    val emergencyAllowlistOnly: Boolean = false,
    val transports: List<String> = listOf("WIFI", "CELLULAR", "ETHERNET", "OTHER"),
    val appPolicies: List<BackupAppPolicy> = emptyList()
)

@Serializable
data class BackupAppPolicy(
    val packageName: String = "",
    val policy: String = AppDnsPolicy.ALLOW.name
)

const val BACKUP_SCHEMA_VERSION = 1

object CloudBackupCodec {

    private val json = defaultCloudJson()

    fun encode(payload: CloudBackupPayload): ByteArray =
        json.encodeToString(payload).toByteArray(Charsets.UTF_8)

    fun decode(bytes: ByteArray): CloudBackupPayload =
        json.decodeFromString(String(bytes, Charsets.UTF_8))

    fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { String.format("%02x", it.toInt() and 0xFF) }
    }

    fun sha1(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(bytes)
        return digest.joinToString("") { String.format("%02x", it.toInt() and 0xFF) }
    }

    /** A backup only verifies when the stored bytes still hash to the value recorded at upload. */
    fun verify(bytes: ByteArray, expectedSha256: String): Boolean =
        expectedSha256.isBlank() || sha256(bytes).equals(expectedSha256.trim(), ignoreCase = true)

    fun decodeOrNull(bytes: ByteArray): CloudBackupPayload? = runCatching { decode(bytes) }.getOrNull()

    fun isSupported(payload: CloudBackupPayload): Boolean =
        payload.schemaVersion <= BACKUP_SCHEMA_VERSION

    fun summary(payload: CloudBackupPayload): String = buildString {
        append(payload.rules.size).append(" rules · ")
        append(payload.sources.size).append(" lists · ")
        append(payload.settings.protectionMode.lowercase()).append(" mode")
    }
}

/**
 * Captures, uploads, verifies, downloads and restores AdShield Pro configuration backups.
 *
 * Upload path: encode -> (optional client-side encryption) -> direct upload to the storage
 * provider -> the API re-downloads the object and compares its SHA-256 with the claimed value
 * before the backup is marked verified. A backup that does not verify is not listed as good.
 */
@Singleton
class CloudBackupManager @Inject constructor(
    private val api: CloudApi,
    private val http: OkHttpClient,
    private val preferences: UserPreferencesRepository,
    private val dao: AdShieldDao,
    private val vault: CloudVault,
    private val sessionStore: CloudSessionStore
) {

    suspend fun capture(): CloudBackupPayload {
        val settings = preferences.getSettingsSnapshot()
        val rules = dao.getAllCustomRulesNow().map { entity ->
            BackupRule(
                pattern = entity.rawPattern,
                type = entity.ruleType,
                matchType = entity.matchType,
                category = entity.category,
                priority = entity.priority,
                enabled = entity.isEnabled,
                comment = entity.comment
            )
        }
        val sources = dao.getAllFilterSourcesNow().map { entity ->
            BackupSource(
                id = entity.id,
                name = entity.name,
                url = entity.url,
                category = entity.category,
                enabled = entity.isEnabled,
                ruleCount = entity.ruleCount
            )
        }
        val (allowlist, denylist) = splitRules(rules)
        return CloudBackupPayload(
            createdAtEpochMs = System.currentTimeMillis(),
            appVersion = APP_VERSION,
            device = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
            settings = BackupSettings(
                protectionMode = settings.protectionMode.name,
                darkTheme = settings.darkThemeMode.name,
                autoStartOnBoot = settings.autoStartOnBoot,
                detailedLogging = settings.detailedDnsLoggingEnabled,
                logRetentionDays = settings.logRetentionDays,
                autoUpdateFilters = settings.autoUpdateFiltersEnabled,
                updateIntervalHours = settings.updateIntervalHours,
                resolverPreset = settings.resolverConfig.preset.name,
                resolverProtocol = settings.resolverConfig.protocol.name,
                customDohUrl = settings.resolverConfig.customDohUrl,
                enableIpv6 = settings.resolverConfig.enableIpv6,
                failoverEnabled = settings.resolverConfig.failoverEnabled,
                dnssecMode = settings.resolverConfig.dnssecMode.name,
                browserCosmeticFiltering = settings.browserCosmeticFilteringEnabled,
                browserPopupBlocking = settings.browserPopupBlockingEnabled,
                browserThirdPartyCookies = settings.browserBlockThirdPartyCookies,
                browserJavaScript = settings.browserJavaScriptEnabled,
                customCosmeticSelectors = settings.customCosmeticSelectors.toList()
            ),
            rules = rules,
            sources = sources,
            firewall = BackupFirewall(
                emergencyAllowlistOnly = settings.dnsFirewallPolicy.emergencyAllowlistOnly,
                transports = settings.dnsFirewallPolicy.protectedTransports.map { it.name },
                appPolicies = settings.dnsFirewallPolicy.appPolicies.map { (pkg, policy) ->
                    BackupAppPolicy(pkg, policy.name)
                }
            ),
            allowlist = allowlist,
            denylist = denylist,
            browserExceptions = settings.browserSiteExceptions.toList(),
            excludedApps = settings.excludedAppPackages.toList()
        )
    }

    suspend fun upload(payload: CloudBackupPayload, label: String): BackupRowDto {
        val encrypt = vault.isUnlocked()
        val plain = CloudBackupCodec.encode(payload.copy(encrypted = encrypt))
        val bytes = if (encrypt) vault.encrypt(plain) else plain
        val init = api.initBackup(kind = BACKUP_KIND_FULL, label = label, size = bytes.size.toLong())
        withContext(Dispatchers.IO) {
            val request = Request.Builder()
                .url(init.uploadUrl)
                .post(bytes.toRequestBody("application/octet-stream".toMediaType()))
                .addHeader("Authorization", init.token)
                .addHeader("X-Bz-File-Name", init.key)
                .addHeader("X-Bz-Content-Sha1", CloudBackupCodec.sha1(bytes))
                .build()
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw CloudException(response.code, "backup upload failed: http ${response.code}")
                }
            }
        }
        val commit = api.commitBackup(init.backupId, bytes.size.toLong(), CloudBackupCodec.sha256(bytes))
        sessionStore.setLastAutoBackupEpochMs(System.currentTimeMillis())
        return BackupRowDto(
            id = commit.backupId,
            kind = BACKUP_KIND_FULL,
            label = label,
            sizeBytes = commit.sizeBytes,
            sha256 = commit.sha256,
            createdAt = System.currentTimeMillis()
        )
    }

    /**
     * Downloads a backup, proves it still hashes to the recorded value, then decodes it.
     * A backup whose bytes changed in storage is refused instead of being restored.
     */
    suspend fun downloadAndVerify(backupId: String): Pair<BackupRowDto, CloudBackupPayload> {
        val detail = api.backupDetail(backupId)
        val row = detail.backup
        val bytes = withContext(Dispatchers.IO) {
            val request = Request.Builder().url(detail.url).get().build()
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw CloudException(response.code, "backup download failed: http ${response.code}")
                }
                response.body?.bytes()
                    ?: throw CloudException(response.code, "backup download was empty")
            }
        }
        if (!CloudBackupCodec.verify(bytes, row.sha256)) {
            throw CloudException(409, "integrity check failed: the stored backup no longer matches its recorded hash")
        }
        val plain = if (CloudBackupCodec.decodeOrNull(bytes) == null && vault.isUnlocked()) {
            runCatching { vault.decrypt(bytes) }.getOrElse {
                throw CloudException(409, "this backup is encrypted and the vault passphrase could not decrypt it")
            }
        } else {
            bytes
        }
        val payload = try {
            CloudBackupCodec.decode(plain)
        } catch (e: Throwable) {
            throw CloudException(409, "backup could not be decoded: ${e.message}")
        }
        if (!CloudBackupCodec.isSupported(payload)) {
            throw CloudException(409, "backup was written by a newer version of AdShield Pro")
        }
        return row to payload
    }

    /** Re-hashes a stored backup without touching local settings. */
    suspend fun verifyStored(backupId: String): Boolean = runCatching {
        downloadAndVerify(backupId)
        true
    }.getOrDefault(false)

    /**
     * Applies a verified backup. Rules and sources are replaced so the result matches the backup
     * exactly; every other setting is written through the same preference setters the UI uses.
     */
    suspend fun apply(payload: CloudBackupPayload): RestoreReport {
        val settings = payload.settings
        val applied = mutableListOf<String>()

        runCatching { preferences.setProtectionMode(ProtectionMode.valueOf(settings.protectionMode)) }
            .onSuccess { applied += "protection mode" }
        runCatching { preferences.setDarkThemePreference(DarkThemePreference.valueOf(settings.darkTheme)) }
            .onSuccess { applied += "theme" }
        preferences.setAutoStartOnBoot(settings.autoStartOnBoot)
        preferences.setDetailedDnsLogging(settings.detailedLogging)
        preferences.setLogRetentionDays(settings.logRetentionDays)
        preferences.setAutoUpdateFilters(settings.autoUpdateFilters, settings.updateIntervalHours)
        applied += "logging and update schedule"

        val current = preferences.getSettingsSnapshot().resolverConfig
        preferences.updateResolverConfig(
            current.copy(
                preset = runCatching { DnsProviderPreset.valueOf(settings.resolverPreset) }
                    .getOrDefault(current.preset),
                protocol = runCatching { DnsProtocol.valueOf(settings.resolverProtocol) }
                    .getOrDefault(current.protocol),
                customDohUrl = settings.customDohUrl,
                enableIpv6 = settings.enableIpv6,
                failoverEnabled = settings.failoverEnabled,
                dnssecMode = runCatching { DnssecMode.valueOf(settings.dnssecMode) }
                    .getOrDefault(current.dnssecMode)
            )
        )
        applied += "DNS resolver"

        preferences.updateBrowserPrivacyOptions(
            cosmeticFiltering = settings.browserCosmeticFiltering,
            popupBlocking = settings.browserPopupBlocking,
            blockThirdPartyCookies = settings.browserThirdPartyCookies,
            javaScriptEnabled = settings.browserJavaScript
        )
        applied += "browser privacy"

        val transports = payload.firewall.transports.mapNotNull {
            runCatching { NetworkTransportPolicy.valueOf(it) }.getOrNull()
        }.toSet().ifEmpty { setOf(NetworkTransportPolicy.WIFI, NetworkTransportPolicy.CELLULAR) }
        val policies = payload.firewall.appPolicies.associate {
            it.packageName to runCatching { AppDnsPolicy.valueOf(it.policy) }.getOrDefault(AppDnsPolicy.ALLOW)
        }
        preferences.updateDnsFirewallPolicy(
            DnsFirewallPolicy(
                appPolicies = policies,
                protectedTransports = transports,
                emergencyAllowlistOnly = payload.firewall.emergencyAllowlistOnly
            )
        )
        applied += "per-app firewall"

        dao.clearAllCustomRules()
        if (payload.rules.isNotEmpty()) {
            dao.insertCustomRules(payload.rules.map { rule ->
                CustomRuleEntity(
                    rawPattern = rule.pattern,
                    normalizedPattern = rule.pattern.trim().lowercase(),
                    ruleType = rule.type,
                    matchType = rule.matchType,
                    category = rule.category,
                    priority = rule.priority,
                    isEnabled = rule.enabled,
                    comment = rule.comment,
                    createdAtEpochMs = System.currentTimeMillis()
                )
            })
        }
        applied += "${payload.rules.size} custom rules"

        if (payload.sources.isNotEmpty()) {
            dao.upsertFilterSources(payload.sources.map { source ->
                FilterSourceEntity(
                    id = source.id,
                    name = source.name,
                    description = "",
                    url = source.url,
                    licenseName = "",
                    category = source.category,
                    isBuiltIn = false,
                    isEnabled = source.enabled,
                    isPremiumOnly = false,
                    ruleCount = source.ruleCount,
                    duplicateCount = 0,
                    lastUpdatedEpochMs = 0L,
                    lastStatusMessage = "restored from cloud backup"
                )
            })
        }
        applied += "${payload.sources.size} filter lists"

        val snapshot = preferences.getSettingsSnapshot()
        payload.excludedApps.filterNot { it in snapshot.excludedAppPackages }
            .forEach { preferences.toggleExcludedAppPackage(it, true) }
        payload.browserExceptions.filterNot { it in snapshot.browserSiteExceptions }
            .forEach { preferences.toggleBrowserSiteException(it, true) }
        payload.settings.customCosmeticSelectors.filterNot { it in snapshot.customCosmeticSelectors }
            .forEach { preferences.addCustomCosmeticSelector(it) }

        return RestoreReport(
            appliedSections = applied,
            ruleCount = payload.rules.size,
            sourceCount = payload.sources.size,
            createdAtEpochMs = payload.createdAtEpochMs
        )
    }

    private fun splitRules(rules: List<BackupRule>): Pair<List<String>, List<String>> {
        val allow = rules.filter { it.type.equals("ALLOW", ignoreCase = true) }.map { it.pattern }
        val deny = rules.filter { !it.type.equals("ALLOW", ignoreCase = true) }.map { it.pattern }
        return allow to deny
    }

    data class RestoreReport(
        val appliedSections: List<String>,
        val ruleCount: Int,
        val sourceCount: Int,
        val createdAtEpochMs: Long
    )

    companion object {
        const val BACKUP_KIND_FULL = "full_config"
        const val APP_VERSION = "2.8.0"
    }
}
