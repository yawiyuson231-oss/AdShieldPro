package com.adshield.pro.data.repository

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherDnsPolicyReview
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskModel
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.engine.dns.DnsResolverBenchmark
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.security.SecurityEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/** All agent actions are local except the explicitly approved, fixed-host DNS benchmark. */
@Singleton
class AetherSecurityTools @Inject constructor(
    @ApplicationContext private val context: Context,
    private val phoneReader: AetherPhoneAgentReader,
    private val security: SecurityEngine,
    private val preferences: UserPreferencesRepository,
    private val repository: AdShieldRepository,
    private val resolver: UpstreamDnsResolver
) {
    private val model by lazy {
        AetherTaskModel.read(context.assets.open("aether/task_model.tsv").reader(Charsets.UTF_8))
    }

    internal suspend fun suggest(request: String): AetherSecurityTask? = withContext(Dispatchers.IO) {
        model.suggest(request)
    }

    internal suspend fun run(
        approved: AetherTaskApproval.Approved,
        chosenFile: Uri? = null,
        onProgress: (AetherTaskProgress) -> Unit = {}
    ): AetherTaskResult = withContext(Dispatchers.IO) {
        when (approved.task) {
            AetherSecurityTask.CHECK_PHONE -> AetherTaskResult.Phone(phoneReader.check())
            AetherSecurityTask.AUDIT_APPS -> {
                onProgress(AetherTaskProgress.ReadingApps(0, 0))
                AetherTaskResult.Apps(AetherAppReview.from(readAppMetadata(onProgress)))
            }
            AetherSecurityTask.SECURITY_REVIEW -> AetherTaskResult.Review(AetherSecurityReview.run(
                readPhone = phoneReader::check,
                readDns = ::readDnsPolicy,
                readApps = { readAppMetadata(onProgress) },
                publish = onProgress
            ))
            AetherSecurityTask.SCAN_FILE -> scanSelectedFile(chosenFile, onProgress)
            AetherSecurityTask.SCAN_LINK -> {
                // Static analysis only. No HTTP requests, browser launch, query-string retention or journal write.
                val verdict = security.scanUrl(requireNotNull(approved.link))
                AetherTaskResult.Link(verdict.normalizedHost, verdict.threatLevel, verdict.findings)
            }
            AetherSecurityTask.BENCHMARK_DNS -> AetherTaskResult.Dns(DnsResolverBenchmark.run(
                resolver = resolver,
                config = repository.settingsFlow.first().resolverConfig,
                domainInput = DnsResolverBenchmark.DEFAULT_PROBE_DOMAIN
            ))
            AetherSecurityTask.ENABLE_ALIAS_SHIELD -> {
                preferences.setCnameUncloakingEnabled(true)
                resolver.clearCache()
                AetherTaskResult.AliasShieldOn
            }
        }
    }

    private suspend fun scanSelectedFile(uri: Uri?, onProgress: (AetherTaskProgress) -> Unit): AetherTaskResult {
        // Only the one transient content grant returned by the Android picker is eligible.
        if (uri?.scheme != "content") return AetherTaskResult.FileUnavailable
        onProgress(AetherTaskProgress.ReadingFile)
        val resolver = context.contentResolver
        val displayName = try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
        currentCoroutineContext().ensureActive()
        val label = displayName?.filterNot { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }
            ?.takeLast(100)?.ifBlank { null } ?: "Selected file"
        val suffix = label.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        return try {
            val temp = File.createTempFile("aether-scan-", "_$suffix", context.cacheDir)
            try {
                val fits = resolver.openInputStream(uri)?.use { input ->
                    temp.outputStream().use { output -> AetherFileInput.copy(input, output) }
                } ?: return AetherTaskResult.FileUnavailable
                currentCoroutineContext().ensureActive()
                if (!fits) return AetherTaskResult.FileTooLarge
                onProgress(AetherTaskProgress.InspectingFile)
                val inspection = security.inspectFile(temp)
                AetherTaskResult.ScannedFile(
                    record = inspection.record.copy(target = label, sourceUri = null),
                    bytes = inspection.bytes,
                    limitations = inspection.limitations
                )
            } finally {
                temp.delete()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            AetherTaskResult.FileUnavailable
        }
    }

    private suspend fun readDnsPolicy(): AetherDnsPolicyReview.Snapshot {
        val settings = repository.settingsFlow.first()
        return AetherDnsPolicyReview.inspect(
            config = settings.resolverConfig,
            policy = settings.dnsFirewallPolicy,
            excluded = settings.excludedAppPackages,
            aliasShieldOn = settings.cnameUncloakingEnabled
        )
    }

    private suspend fun readAppMetadata(onProgress: (AetherTaskProgress) -> Unit) =
        security.auditVisibleApps { processed, total, _ ->
            // Publish real counts without app names. Limit recompositions on large installations.
            if (processed == 1 || processed == total || processed % 8 == 0) {
                onProgress(AetherTaskProgress.ReadingApps(processed, total))
            }
        }
}
